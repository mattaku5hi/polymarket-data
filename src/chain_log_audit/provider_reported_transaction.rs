//! Shared binding and exact-order comparison for provider-reported receipt
//! projections. These observations remain ordinary provider data.

use alloy_primitives::{Address, U256};
use serde_json::Value;

use super::provider_reported_maker_fill::{
    normalize_provider_reported_log, parse_provider_reported_log_envelope_with_limit,
};
use super::{
    MAX_RESPONSE_BYTES, POLYGON_CHAIN_ID, encode_signed_transaction_with_sender_recovery, field,
    parse_hex_u64, validate_hex,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProviderTransactionLog {
    pub log_index: u64,
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BoundProviderTransaction {
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_index: u64,
    pub status: u64,
    pub to: String,
    pub input: Vec<u8>,
    pub recovered_from: Address,
    pub value: U256,
    pub logs: Vec<ProviderTransactionLog>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderTransactionBindingError {
    Transaction,
    Receipt,
}

pub(super) fn bind_provider_transaction(
    transaction: &Value,
    receipt: &Value,
) -> Result<BoundProviderTransaction, ProviderTransactionBindingError> {
    if serde_json::to_vec(transaction)
        .map_err(|_| ProviderTransactionBindingError::Transaction)?
        .len()
        > MAX_RESPONSE_BYTES
    {
        return Err(ProviderTransactionBindingError::Transaction);
    }
    if serde_json::to_vec(receipt)
        .map_err(|_| ProviderTransactionBindingError::Receipt)?
        .len()
        > MAX_RESPONSE_BYTES
    {
        return Err(ProviderTransactionBindingError::Receipt);
    }
    let encoded = encode_signed_transaction_with_sender_recovery(transaction, true)
        .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    let transaction_hash = validate_hex(
        field(transaction, "hash").map_err(|_| ProviderTransactionBindingError::Transaction)?,
        32,
    )
    .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    if format!("{:#x}", encoded.hash) != transaction_hash
        || encoded.eip155_chain_id != Some(U256::from(POLYGON_CHAIN_ID))
        || encoded.to.len() != 20
    {
        return Err(ProviderTransactionBindingError::Transaction);
    }
    let recovered_from = encoded
        .recovered_sender
        .ok_or(ProviderTransactionBindingError::Transaction)?;
    let reported_from = validate_hex(
        field(transaction, "from").map_err(|_| ProviderTransactionBindingError::Transaction)?,
        20,
    )
    .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    if format!("{recovered_from:#x}") != reported_from {
        return Err(ProviderTransactionBindingError::Transaction);
    }
    if let Some(chain_id) = transaction.get("chainId") {
        let expected_chain_id = format!("{:#x}", POLYGON_CHAIN_ID);
        if chain_id.as_str() != Some(expected_chain_id.as_str()) {
            return Err(ProviderTransactionBindingError::Transaction);
        }
    }
    let block_number = parse_hex_u64(
        field(transaction, "blockNumber")
            .map_err(|_| ProviderTransactionBindingError::Transaction)?,
    )
    .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    let block_hash = validate_hex(
        field(transaction, "blockHash")
            .map_err(|_| ProviderTransactionBindingError::Transaction)?,
        32,
    )
    .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    let transaction_index = parse_hex_u64(
        field(transaction, "transactionIndex")
            .map_err(|_| ProviderTransactionBindingError::Transaction)?,
    )
    .map_err(|_| ProviderTransactionBindingError::Transaction)?;
    let status = parse_hex_u64(
        field(receipt, "status").map_err(|_| ProviderTransactionBindingError::Receipt)?,
    )
    .map_err(|_| ProviderTransactionBindingError::Receipt)?;
    if validate_hex(
        field(receipt, "transactionHash").map_err(|_| ProviderTransactionBindingError::Receipt)?,
        32,
    )
    .map_err(|_| ProviderTransactionBindingError::Receipt)?
        != transaction_hash
        || parse_hex_u64(
            field(receipt, "blockNumber").map_err(|_| ProviderTransactionBindingError::Receipt)?,
        )
        .map_err(|_| ProviderTransactionBindingError::Receipt)?
            != block_number
        || validate_hex(
            field(receipt, "blockHash").map_err(|_| ProviderTransactionBindingError::Receipt)?,
            32,
        )
        .map_err(|_| ProviderTransactionBindingError::Receipt)?
            != block_hash
        || parse_hex_u64(
            field(receipt, "transactionIndex")
                .map_err(|_| ProviderTransactionBindingError::Receipt)?,
        )
        .map_err(|_| ProviderTransactionBindingError::Receipt)?
            != transaction_index
        || status != 1
        || parse_hex_u64(
            field(receipt, "type").map_err(|_| ProviderTransactionBindingError::Receipt)?,
        )
        .map_err(|_| ProviderTransactionBindingError::Receipt)?
            != u64::from(encoded.transaction_type)
    {
        return Err(ProviderTransactionBindingError::Receipt);
    }
    let raw_logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or(ProviderTransactionBindingError::Receipt)?;
    let mut logs = Vec::with_capacity(raw_logs.len());
    let mut previous_log_index = None;
    for raw_log in raw_logs {
        let envelope = parse_provider_reported_log_envelope_with_limit(raw_log, MAX_RESPONSE_BYTES)
            .map_err(|_| ProviderTransactionBindingError::Receipt)?;
        let normalized = normalize_provider_reported_log(envelope, MAX_RESPONSE_BYTES)
            .map_err(|_| ProviderTransactionBindingError::Receipt)?;
        if normalized.transaction_hash != transaction_hash
            || normalized.block_number != block_number
            || normalized.block_hash != block_hash
            || normalized.transaction_index != transaction_index
            || previous_log_index.is_some_and(|previous| normalized.log_index <= previous)
        {
            return Err(ProviderTransactionBindingError::Receipt);
        }
        previous_log_index = Some(normalized.log_index);
        logs.push(ProviderTransactionLog {
            log_index: normalized.log_index,
            address: normalized.address,
            topics: normalized.topics,
            data: normalized.data,
        });
    }
    Ok(BoundProviderTransaction {
        transaction_hash,
        block_number,
        block_hash,
        transaction_index,
        status,
        to: format!("0x{}", hex::encode(&encoded.to)),
        input: encoded.input,
        recovered_from,
        value: encoded.value,
        logs,
    })
}

pub(super) fn match_ordered_logs<E, A>(
    expected: &[E],
    actual: &[A],
    mut matches: impl FnMut(&E, &A) -> bool,
) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .all(|(expected, actual)| matches(expected, actual))
}
