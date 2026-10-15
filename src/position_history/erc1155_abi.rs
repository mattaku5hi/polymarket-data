//! Strict ERC-1155 event-field decoder shared by RPC observations and the
//! optional receipt-audit module. This parses bytes only; it assigns no receipt
//! provenance or asset identity.

use super::{TRANSFER_BATCH_TOPIC, TRANSFER_SINGLE_TOPIC};

pub(crate) const MAX_BATCH_ITEMS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodedTransfer {
    Single {
        operator: String,
        from: String,
        to: String,
        id: [u8; 32],
        amount: [u8; 32],
    },
    Batch {
        operator: String,
        from: String,
        to: String,
        ids: Vec<[u8; 32]>,
        amounts: Vec<[u8; 32]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    WrongTopicCount,
    IndexedAddressPadding,
    InvalidDataHex,
    WrongDataLength,
    InvalidBatchOffset,
    BatchLengthMismatch,
    BatchTooManyItems,
    NonCanonicalBatchLayout,
    BatchDataLengthMismatch,
}

pub(crate) fn decode_fields(
    topics: &[String],
    raw_data: &str,
) -> Result<DecodedTransfer, DecodeError> {
    match topics.first().map(String::as_str) {
        Some(TRANSFER_SINGLE_TOPIC) => decode_single(topics, raw_data),
        Some(TRANSFER_BATCH_TOPIC) => decode_batch(topics, raw_data),
        _ => Err(DecodeError::WrongTopicCount),
    }
}

fn decode_single(topics: &[String], raw_data: &str) -> Result<DecodedTransfer, DecodeError> {
    if topics.len() != 4 {
        return Err(DecodeError::WrongTopicCount);
    }
    let operator = indexed_address(&topics[1])?;
    let from = indexed_address(&topics[2])?;
    let to = indexed_address(&topics[3])?;
    let data = decode_data(raw_data)?;
    if data.len() != 64 {
        return Err(DecodeError::WrongDataLength);
    }
    Ok(DecodedTransfer::Single {
        operator,
        from,
        to,
        id: word(&data, 0).ok_or(DecodeError::WrongDataLength)?,
        amount: word(&data, 32).ok_or(DecodeError::WrongDataLength)?,
    })
}

fn decode_batch(topics: &[String], raw_data: &str) -> Result<DecodedTransfer, DecodeError> {
    if topics.len() != 4 {
        return Err(DecodeError::WrongTopicCount);
    }
    let operator = indexed_address(&topics[1])?;
    let from = indexed_address(&topics[2])?;
    let to = indexed_address(&topics[3])?;
    let data = decode_data(raw_data)?;
    if data.len() < 64 {
        return Err(DecodeError::BatchDataLengthMismatch);
    }
    let ids_offset = word_to_usize(&word(&data, 0).ok_or(DecodeError::InvalidBatchOffset)?)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    let amounts_offset = word_to_usize(&word(&data, 32).ok_or(DecodeError::InvalidBatchOffset)?)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    if ids_offset != 64 {
        return Err(DecodeError::NonCanonicalBatchLayout);
    }
    let ids_length =
        word_to_usize(&word(&data, ids_offset).ok_or(DecodeError::InvalidBatchOffset)?)
            .ok_or(DecodeError::InvalidBatchOffset)?;
    if ids_length > MAX_BATCH_ITEMS {
        return Err(DecodeError::BatchTooManyItems);
    }
    let ids_bytes = ids_length
        .checked_mul(32)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    let canonical_amounts_offset = 96_usize
        .checked_add(ids_bytes)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    if amounts_offset != canonical_amounts_offset {
        return Err(DecodeError::NonCanonicalBatchLayout);
    }
    let amounts_length =
        word_to_usize(&word(&data, amounts_offset).ok_or(DecodeError::InvalidBatchOffset)?)
            .ok_or(DecodeError::InvalidBatchOffset)?;
    if amounts_length > MAX_BATCH_ITEMS {
        return Err(DecodeError::BatchTooManyItems);
    }
    if amounts_length != ids_length {
        return Err(DecodeError::BatchLengthMismatch);
    }
    let amounts_bytes = amounts_length
        .checked_mul(32)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    let expected_end = amounts_offset
        .checked_add(32)
        .and_then(|offset| offset.checked_add(amounts_bytes))
        .ok_or(DecodeError::InvalidBatchOffset)?;
    if expected_end != data.len() {
        return Err(DecodeError::BatchDataLengthMismatch);
    }

    let ids_start = ids_offset
        .checked_add(32)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    let amounts_start = amounts_offset
        .checked_add(32)
        .ok_or(DecodeError::InvalidBatchOffset)?;
    let mut ids = Vec::with_capacity(ids_length);
    let mut amounts = Vec::with_capacity(amounts_length);
    for index in 0..ids_length {
        let offset = index
            .checked_mul(32)
            .ok_or(DecodeError::InvalidBatchOffset)?;
        ids.push(
            word(
                &data,
                ids_start
                    .checked_add(offset)
                    .ok_or(DecodeError::InvalidBatchOffset)?,
            )
            .ok_or(DecodeError::BatchDataLengthMismatch)?,
        );
        amounts.push(
            word(
                &data,
                amounts_start
                    .checked_add(offset)
                    .ok_or(DecodeError::InvalidBatchOffset)?,
            )
            .ok_or(DecodeError::BatchDataLengthMismatch)?,
        );
    }
    Ok(DecodedTransfer::Batch {
        operator,
        from,
        to,
        ids,
        amounts,
    })
}

fn indexed_address(topic: &str) -> Result<String, DecodeError> {
    let bytes = decode_hex(topic.strip_prefix("0x").unwrap_or(topic))
        .ok_or(DecodeError::IndexedAddressPadding)?;
    if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(DecodeError::IndexedAddressPadding);
    }
    Ok(format!("0x{}", encode_hex(&bytes[12..])))
}

fn decode_data(data: &str) -> Result<Vec<u8>, DecodeError> {
    decode_hex(data.strip_prefix("0x").unwrap_or(data)).ok_or(DecodeError::InvalidDataHex)
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn word(data: &[u8], offset: usize) -> Option<[u8; 32]> {
    let end = offset.checked_add(32)?;
    data.get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
}

fn word_to_usize(word: &[u8; 32]) -> Option<usize> {
    let mut value = 0_usize;
    for byte in word {
        value = value.checked_mul(256)?.checked_add(usize::from(*byte))?;
    }
    Some(value)
}
