//! Strict structural decoder for the pinned fifth Exchange `matchOrders` ABI.
//!
//! This target-only prototype is intended to sit under `chain_log_audit`; it
//! reuses that module's checked `abi_u256_word`, `abi_usize`, and `abi_address`
//! helpers. It does not validate signatures, fills, prices, or settlement.

use super::{abi_address, abi_u256_word, abi_usize};
use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};

pub const FIFTH_MATCH_ORDERS_SELECTOR: [u8; 4] = [0x0f, 0xb2, 0x5b, 0xa4];
pub const FIFTH_MATCH_ORDERS_MAX_MAKERS: usize = 128;
pub const FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES: usize = 2_048;
pub const FIFTH_MATCH_ORDERS_MAX_CALLDATA_BYTES: usize = 256 * 1_024;

const TOP_HEAD_BYTES: usize = 7 * 32;
const ORDER_HEAD_BYTES: usize = 12 * 32;
const ORDER_TYPEHASH: [u8; 32] = [
    0xbb, 0x86, 0x31, 0x8a, 0x21, 0x38, 0xf5, 0xfa, 0x8a, 0xe3, 0x2f, 0xbe, 0x8e, 0x65, 0x9f, 0x8f,
    0xcf, 0x13, 0xcc, 0x6a, 0xe4, 0x01, 0x4a, 0x70, 0x78, 0x93, 0x05, 0x54, 0x33, 0x81, 0x85, 0x89,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthOrderSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifthOrderSignatureType {
    Eoa,
    PolyProxy,
    PolyGnosisSafe,
    Poly1271,
}

/// One ABI-decoded order. The signature is retained as bytes but never
/// interpreted or validated by this structural codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthMatchOrder {
    pub salt: U256,
    pub maker: Address,
    pub signer: Address,
    pub token_id: U256,
    pub maker_amount: U256,
    pub taker_amount: U256,
    pub side: FifthOrderSide,
    pub signature_type: FifthOrderSignatureType,
    pub timestamp: U256,
    pub metadata: B256,
    pub builder: B256,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FifthTakerAmounts {
    pub taker_fill_amount: U256,
    pub taker_receive_amount: U256,
    pub taker_fee_amount: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifthMatchOrdersCall {
    pub taker_order: FifthMatchOrder,
    pub maker_orders: Vec<FifthMatchOrder>,
    pub maker_fill_amounts: Vec<U256>,
    pub maker_fee_amounts: Vec<U256>,
    pub taker_amounts: FifthTakerAmounts,
}

/// Decode only canonical bounded ABI for `matchOrders`. `None` means the
/// input is unsupported or malformed; it is never an economic verdict.
pub fn decode_fifth_match_orders_calldata(input: &[u8]) -> Option<FifthMatchOrdersCall> {
    if input.len() > FIFTH_MATCH_ORDERS_MAX_CALLDATA_BYTES
        || input.len() < 4 + TOP_HEAD_BYTES
        || input.get(..4)? != FIFTH_MATCH_ORDERS_SELECTOR
    {
        return None;
    }
    let args = input.get(4..)?;
    if args.len() % 32 != 0 {
        return None;
    }

    let taker_order_offset = word_usize(args, 0)?;
    let maker_orders_offset = word_usize(args, 32)?;
    let maker_fill_amounts_offset = word_usize(args, 64)?;
    let maker_fee_amounts_offset = word_usize(args, 96)?;
    if taker_order_offset != TOP_HEAD_BYTES {
        return None;
    }

    let taker_amounts = FifthTakerAmounts {
        taker_fill_amount: abi_u256_word(args, 4 * 32)?,
        taker_receive_amount: abi_u256_word(args, 5 * 32)?,
        taker_fee_amount: abi_u256_word(args, 6 * 32)?,
    };
    let (taker_order, taker_end) = decode_order_tuple(args, taker_order_offset)?;
    if maker_orders_offset != taker_end {
        return None;
    }
    let (maker_orders, makers_end) = decode_order_array(args, maker_orders_offset)?;
    if maker_fill_amounts_offset != makers_end {
        return None;
    }
    let (maker_fill_amounts, fills_end) =
        decode_u256_array(args, maker_fill_amounts_offset, maker_orders.len())?;
    if maker_fee_amounts_offset != fills_end {
        return None;
    }
    let (maker_fee_amounts, fees_end) =
        decode_u256_array(args, maker_fee_amounts_offset, maker_orders.len())?;
    if fees_end != args.len() {
        return None;
    }

    Some(FifthMatchOrdersCall {
        taker_order,
        maker_orders,
        maker_fill_amounts,
        maker_fee_amounts,
        taker_amounts,
    })
}

fn decode_order_array(args: &[u8], start: usize) -> Option<(Vec<FifthMatchOrder>, usize)> {
    let count = word_usize(args, start)?;
    if !(1..=FIFTH_MATCH_ORDERS_MAX_MAKERS).contains(&count) {
        return None;
    }
    let heads_start = start.checked_add(32)?;
    let heads_bytes = count.checked_mul(32)?;
    let mut cursor = heads_start.checked_add(heads_bytes)?;
    if cursor > args.len() {
        return None;
    }

    let mut orders = Vec::with_capacity(count);
    for index in 0..count {
        let head = heads_start.checked_add(index.checked_mul(32)?)?;
        let relative = word_usize(args, head)?;
        if relative != cursor.checked_sub(heads_start)? {
            return None;
        }
        let (order, end) = decode_order_tuple(args, cursor)?;
        orders.push(order);
        cursor = end;
    }
    Some((orders, cursor))
}

fn decode_u256_array(
    args: &[u8],
    start: usize,
    expected_count: usize,
) -> Option<(Vec<U256>, usize)> {
    let count = word_usize(args, start)?;
    if count != expected_count || count > FIFTH_MATCH_ORDERS_MAX_MAKERS {
        return None;
    }
    let values_start = start.checked_add(32)?;
    let values_bytes = count.checked_mul(32)?;
    let end = values_start.checked_add(values_bytes)?;
    if end > args.len() {
        return None;
    }
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let offset = values_start.checked_add(index.checked_mul(32)?)?;
        values.push(abi_u256_word(args, offset)?);
    }
    Some((values, end))
}

fn decode_order_tuple(args: &[u8], start: usize) -> Option<(FifthMatchOrder, usize)> {
    let head_end = start.checked_add(ORDER_HEAD_BYTES)?;
    if head_end > args.len() || word_usize(args, start.checked_add(11 * 32)?)? != ORDER_HEAD_BYTES {
        return None;
    }

    let salt = abi_u256_word(args, start)?;
    let maker = word_address(args, start.checked_add(32)?)?;
    let signer = word_address(args, start.checked_add(2 * 32)?)?;
    let token_id = abi_u256_word(args, start.checked_add(3 * 32)?)?;
    let maker_amount = abi_u256_word(args, start.checked_add(4 * 32)?)?;
    let taker_amount = abi_u256_word(args, start.checked_add(5 * 32)?)?;
    let side = match abi_u256_word(args, start.checked_add(6 * 32)?)? {
        value if value == U256::ZERO => FifthOrderSide::Buy,
        value if value == U256::from(1) => FifthOrderSide::Sell,
        _ => return None,
    };
    let signature_type = match abi_u256_word(args, start.checked_add(7 * 32)?)? {
        value if value == U256::ZERO => FifthOrderSignatureType::Eoa,
        value if value == U256::from(1) => FifthOrderSignatureType::PolyProxy,
        value if value == U256::from(2) => FifthOrderSignatureType::PolyGnosisSafe,
        value if value == U256::from(3) => FifthOrderSignatureType::Poly1271,
        _ => return None,
    };
    let timestamp = abi_u256_word(args, start.checked_add(8 * 32)?)?;
    let metadata = word_b256(args, start.checked_add(9 * 32)?)?;
    let builder = word_b256(args, start.checked_add(10 * 32)?)?;

    let signature_length = word_usize(args, head_end)?;
    if signature_length > FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES {
        return None;
    }
    let padded_length = signature_length
        .checked_add(31)?
        .checked_div(32)?
        .checked_mul(32)?;
    let signature_start = head_end.checked_add(32)?;
    let end = signature_start.checked_add(padded_length)?;
    if end > args.len() {
        return None;
    }
    let signature_end = signature_start.checked_add(signature_length)?;
    if args.get(signature_end..end)?.iter().any(|byte| *byte != 0) {
        return None;
    }

    Some((
        FifthMatchOrder {
            salt,
            maker,
            signer,
            token_id,
            maker_amount,
            taker_amount,
            side,
            signature_type,
            timestamp,
            metadata,
            builder,
            signature: args.get(signature_start..signature_end)?.to_vec(),
        },
        end,
    ))
}

fn word_usize(args: &[u8], offset: usize) -> Option<usize> {
    abi_usize(abi_u256_word(args, offset)?)
}

fn word_address(args: &[u8], offset: usize) -> Option<Address> {
    let canonical = abi_address(abi_u256_word(args, offset)?)?;
    let bytes = hex::decode(canonical.strip_prefix("0x")?).ok()?;
    Some(Address::from_slice(&bytes))
}

fn word_b256(args: &[u8], offset: usize) -> Option<B256> {
    let end = offset.checked_add(32)?;
    Some(B256::from_slice(args.get(offset..end)?))
}

/// EIP-712 struct hash from the source's exact eleven-field schema. This is a
/// hash primitive only; it does not establish deployed code or signature
/// validity. Callers must bind the supplied verifying proxy and version.
pub fn fifth_order_struct_hash(order: &FifthMatchOrder) -> B256 {
    let mut encoded = Vec::with_capacity(12 * 32);
    encoded.extend_from_slice(&ORDER_TYPEHASH);
    append_u256(&mut encoded, order.salt);
    append_address(&mut encoded, order.maker);
    append_address(&mut encoded, order.signer);
    append_u256(&mut encoded, order.token_id);
    append_u256(&mut encoded, order.maker_amount);
    append_u256(&mut encoded, order.taker_amount);
    append_u256(
        &mut encoded,
        U256::from(match order.side {
            FifthOrderSide::Buy => 0_u8,
            FifthOrderSide::Sell => 1_u8,
        }),
    );
    append_u256(
        &mut encoded,
        U256::from(match order.signature_type {
            FifthOrderSignatureType::Eoa => 0_u8,
            FifthOrderSignatureType::PolyProxy => 1_u8,
            FifthOrderSignatureType::PolyGnosisSafe => 2_u8,
            FifthOrderSignatureType::Poly1271 => 3_u8,
        }),
    );
    append_u256(&mut encoded, order.timestamp);
    encoded.extend_from_slice(order.metadata.as_slice());
    encoded.extend_from_slice(order.builder.as_slice());
    keccak256(&encoded)
}

/// Compute the proxy-context EIP-712 order digest for Polygon chain 137.
/// Under delegatecall the verifying contract is the Exchange proxy, never its
/// implementation. This function is not an identity or signature proof.
pub fn fifth_order_eip712_hash(order: &FifthMatchOrder, exchange_proxy: Address) -> B256 {
    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(b"Polymarket CTF Exchange");
    let version_hash = keccak256(b"3");
    let mut domain = Vec::with_capacity(5 * 32);
    domain.extend_from_slice(domain_typehash.as_slice());
    domain.extend_from_slice(name_hash.as_slice());
    domain.extend_from_slice(version_hash.as_slice());
    append_u256(&mut domain, U256::from(137_u64));
    append_address(&mut domain, exchange_proxy);
    let domain_separator = keccak256(&domain);

    let mut typed = Vec::with_capacity(66);
    typed.extend_from_slice(&[0x19, 0x01]);
    typed.extend_from_slice(domain_separator.as_slice());
    typed.extend_from_slice(fifth_order_struct_hash(order).as_slice());
    keccak256(&typed)
}

fn append_u256(out: &mut Vec<u8>, value: U256) {
    out.extend_from_slice(&value.to_be_bytes::<32>());
}

fn append_address(out: &mut Vec<u8>, value: Address) {
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(value.as_slice());
}

fn keccak256(bytes: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(bytes))
}

#[cfg(test)]
pub(in crate::chain_log_audit) mod tests {
    use super::*;

    const EXCHANGE_PROXY: &str = "0xe3333700ca9d93003f00f0f71f8515005f6c00aa";

    fn word(value: U256) -> [u8; 32] {
        value.to_be_bytes::<32>()
    }

    fn address_word(value: Address) -> [u8; 32] {
        let mut word = [0; 32];
        word[12..].copy_from_slice(value.as_slice());
        word
    }

    fn encode_order(order: &FifthMatchOrder) -> Vec<u8> {
        let mut tuple = Vec::new();
        tuple.extend_from_slice(&word(order.salt));
        tuple.extend_from_slice(&address_word(order.maker));
        tuple.extend_from_slice(&address_word(order.signer));
        tuple.extend_from_slice(&word(order.token_id));
        tuple.extend_from_slice(&word(order.maker_amount));
        tuple.extend_from_slice(&word(order.taker_amount));
        tuple.extend_from_slice(&word(U256::from(match order.side {
            FifthOrderSide::Buy => 0_u8,
            FifthOrderSide::Sell => 1_u8,
        })));
        tuple.extend_from_slice(&word(U256::from(match order.signature_type {
            FifthOrderSignatureType::Eoa => 0_u8,
            FifthOrderSignatureType::PolyProxy => 1_u8,
            FifthOrderSignatureType::PolyGnosisSafe => 2_u8,
            FifthOrderSignatureType::Poly1271 => 3_u8,
        })));
        tuple.extend_from_slice(&word(order.timestamp));
        tuple.extend_from_slice(order.metadata.as_slice());
        tuple.extend_from_slice(order.builder.as_slice());
        tuple.extend_from_slice(&word(U256::from(ORDER_HEAD_BYTES)));
        tuple.extend_from_slice(&word(U256::from(order.signature.len())));
        tuple.extend_from_slice(&order.signature);
        while tuple.len() % 32 != 0 {
            tuple.push(0);
        }
        tuple
    }

    fn encode_u256_array(values: &[U256]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(32 + values.len() * 32);
        encoded.extend_from_slice(&word(U256::from(values.len())));
        for value in values {
            encoded.extend_from_slice(&word(*value));
        }
        encoded
    }

    fn encode_order_array(orders: &[FifthMatchOrder]) -> Vec<u8> {
        let tails = orders.iter().map(encode_order).collect::<Vec<_>>();
        let heads_bytes = tails.len() * 32;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&word(U256::from(tails.len())));
        let mut offset = heads_bytes;
        for tail in &tails {
            encoded.extend_from_slice(&word(U256::from(offset)));
            offset += tail.len();
        }
        for tail in tails {
            encoded.extend_from_slice(&tail);
        }
        encoded
    }

    pub(in crate::chain_log_audit) fn encode_call(
        taker: &FifthMatchOrder,
        makers: &[FifthMatchOrder],
        fills: &[U256],
        fees: &[U256],
        taker_amounts: FifthTakerAmounts,
    ) -> Vec<u8> {
        let taker_tail = encode_order(taker);
        let makers_tail = encode_order_array(makers);
        let fills_tail = encode_u256_array(fills);
        let fees_tail = encode_u256_array(fees);
        let taker_offset = TOP_HEAD_BYTES;
        let makers_offset = taker_offset + taker_tail.len();
        let fills_offset = makers_offset + makers_tail.len();
        let fees_offset = fills_offset + fills_tail.len();
        let mut args = Vec::new();
        for offset in [taker_offset, makers_offset, fills_offset, fees_offset] {
            args.extend_from_slice(&word(U256::from(offset)));
        }
        for value in [
            taker_amounts.taker_fill_amount,
            taker_amounts.taker_receive_amount,
            taker_amounts.taker_fee_amount,
        ] {
            args.extend_from_slice(&word(value));
        }
        args.extend_from_slice(&taker_tail);
        args.extend_from_slice(&makers_tail);
        args.extend_from_slice(&fills_tail);
        args.extend_from_slice(&fees_tail);
        let mut input = FIFTH_MATCH_ORDERS_SELECTOR.to_vec();
        input.extend_from_slice(&args);
        input
    }

    fn sample_order(seed: u8) -> FifthMatchOrder {
        FifthMatchOrder {
            salt: U256::from(seed),
            maker: Address::repeat_byte(seed),
            signer: Address::repeat_byte(seed.wrapping_add(1)),
            token_id: U256::from(0x1234_u64 + u64::from(seed)),
            maker_amount: U256::from(100_u64 + u64::from(seed)),
            taker_amount: U256::from(200_u64 + u64::from(seed)),
            side: if seed % 2 == 0 {
                FifthOrderSide::Buy
            } else {
                FifthOrderSide::Sell
            },
            signature_type: match seed % 4 {
                0 => FifthOrderSignatureType::Eoa,
                1 => FifthOrderSignatureType::PolyProxy,
                2 => FifthOrderSignatureType::PolyGnosisSafe,
                _ => FifthOrderSignatureType::Poly1271,
            },
            timestamp: U256::from(1_700_000_000_u64 + u64::from(seed)),
            metadata: B256::repeat_byte(seed.wrapping_add(2)),
            builder: B256::repeat_byte(seed.wrapping_add(3)),
            signature: vec![seed; usize::from(seed) + 1],
        }
    }

    #[test]
    fn decodes_canonical_multi_maker_call_and_preserves_full_width_words() {
        let mut taker = sample_order(0);
        taker.salt = U256::MAX;
        taker.token_id = U256::from_be_bytes([0x91; 32]);
        let makers = [sample_order(1), sample_order(2)];
        let taker_amounts = FifthTakerAmounts {
            taker_fill_amount: U256::from(41_u64),
            taker_receive_amount: U256::from(37_u64),
            taker_fee_amount: U256::from(2_u64),
        };
        let input = encode_call(
            &taker,
            &makers,
            &[U256::from(11_u64), U256::from(13_u64)],
            &[U256::from(1_u64), U256::from(3_u64)],
            taker_amounts,
        );
        let decoded = decode_fifth_match_orders_calldata(&input).unwrap();
        assert_eq!(decoded.taker_order, taker);
        assert_eq!(decoded.maker_orders, makers);
        assert_eq!(
            decoded.maker_fill_amounts,
            [U256::from(11_u64), U256::from(13_u64)]
        );
        assert_eq!(decoded.maker_fee_amounts, [U256::ONE, U256::from(3_u64)]);
        assert_eq!(decoded.taker_amounts, taker_amounts);
    }

    #[test]
    fn accepts_zero_amounts_and_all_source_enumerants_as_structural_abi() {
        for signature_type in [
            FifthOrderSignatureType::Eoa,
            FifthOrderSignatureType::PolyProxy,
            FifthOrderSignatureType::PolyGnosisSafe,
            FifthOrderSignatureType::Poly1271,
        ] {
            let mut order = sample_order(0);
            order.maker_amount = U256::ZERO;
            order.taker_amount = U256::ZERO;
            order.signature_type = signature_type;
            order.signature.clear();
            for side in [FifthOrderSide::Buy, FifthOrderSide::Sell] {
                order.side = side;
                let amounts = FifthTakerAmounts {
                    taker_fill_amount: U256::ZERO,
                    taker_receive_amount: U256::ZERO,
                    taker_fee_amount: U256::ZERO,
                };
                let input = encode_call(
                    &order,
                    &[order.clone()],
                    &[U256::ZERO],
                    &[U256::ZERO],
                    amounts,
                );
                assert!(decode_fifth_match_orders_calldata(&input).is_some());
            }
        }
    }

    #[test]
    fn refuses_noncanonical_offsets_enums_padding_counts_and_trailing_bytes() {
        let order = sample_order(1);
        let baseline = encode_call(
            &order,
            &[sample_order(2)],
            &[U256::ONE],
            &[U256::ZERO],
            FifthTakerAmounts {
                taker_fill_amount: U256::ONE,
                taker_receive_amount: U256::from(2_u64),
                taker_fee_amount: U256::ZERO,
            },
        );
        assert!(decode_fifth_match_orders_calldata(&baseline).is_some());

        let mut bad_selector = baseline.clone();
        bad_selector[0] ^= 1;
        assert!(decode_fifth_match_orders_calldata(&bad_selector).is_none());
        let mut bad_offset = baseline.clone();
        bad_offset[4 + 31] = 8;
        assert!(decode_fifth_match_orders_calldata(&bad_offset).is_none());
        let mut trailing = baseline.clone();
        trailing.push(0);
        assert!(decode_fifth_match_orders_calldata(&trailing).is_none());
        let mut oversized_calldata = baseline.clone();
        oversized_calldata.resize(FIFTH_MATCH_ORDERS_MAX_CALLDATA_BYTES + 1, 0);
        assert!(decode_fifth_match_orders_calldata(&oversized_calldata).is_none());

        let mut bad_side = baseline.clone();
        bad_side[4 + TOP_HEAD_BYTES + 6 * 32 + 31] = 2;
        assert!(decode_fifth_match_orders_calldata(&bad_side).is_none());
        let mut bad_signature_type = baseline.clone();
        bad_signature_type[4 + TOP_HEAD_BYTES + 7 * 32 + 31] = 4;
        assert!(decode_fifth_match_orders_calldata(&bad_signature_type).is_none());
        let mut bad_address_padding = baseline.clone();
        bad_address_padding[4 + TOP_HEAD_BYTES + 32] = 1;
        assert!(decode_fifth_match_orders_calldata(&bad_address_padding).is_none());

        let signature_length = order.signature.len();
        if signature_length % 32 != 0 {
            let padding_index = 4 + TOP_HEAD_BYTES + ORDER_HEAD_BYTES + 32 + signature_length;
            let mut bad_signature_padding = baseline.clone();
            bad_signature_padding[padding_index] = 1;
            assert!(decode_fifth_match_orders_calldata(&bad_signature_padding).is_none());
        }

        let makers_offset =
            usize::try_from(U256::from_be_slice(&baseline[4 + 32..4 + 64])).unwrap();
        let mut no_makers = baseline.clone();
        no_makers[4 + makers_offset + 31] = 0;
        assert!(decode_fifth_match_orders_calldata(&no_makers).is_none());
        let mut too_many_makers = baseline.clone();
        too_many_makers[4 + makers_offset + 30] = 1;
        too_many_makers[4 + makers_offset + 31] = 129;
        assert!(decode_fifth_match_orders_calldata(&too_many_makers).is_none());

        let mut wrong_fill_count = baseline.clone();
        let fills_offset = usize::try_from(U256::from_be_slice(&baseline[4 + 64..4 + 96])).unwrap();
        wrong_fill_count[4 + fills_offset + 31] = 2;
        assert!(decode_fifth_match_orders_calldata(&wrong_fill_count).is_none());
        let mut wrong_fee_count = baseline.clone();
        let fees_offset = usize::try_from(U256::from_be_slice(&baseline[4 + 96..4 + 128])).unwrap();
        wrong_fee_count[4 + fees_offset + 31] = 2;
        assert!(decode_fifth_match_orders_calldata(&wrong_fee_count).is_none());

        let mut noncanonical_order_array_offset = baseline.clone();
        noncanonical_order_array_offset[4 + makers_offset + 32 + 31] = 1;
        assert!(decode_fifth_match_orders_calldata(&noncanonical_order_array_offset).is_none());

        let mut oversized_signature = sample_order(1);
        oversized_signature.signature = vec![0; FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES + 1];
        let oversized = encode_call(
            &oversized_signature,
            &[sample_order(2)],
            &[U256::ONE],
            &[U256::ZERO],
            FifthTakerAmounts {
                taker_fill_amount: U256::ONE,
                taker_receive_amount: U256::ONE,
                taker_fee_amount: U256::ZERO,
            },
        );
        assert!(decode_fifth_match_orders_calldata(&oversized).is_none());

        let mut maximum_signature = sample_order(1);
        maximum_signature.signature = vec![0x5a; FIFTH_MATCH_ORDERS_MAX_SIGNATURE_BYTES];
        let maximum_signature_call = encode_call(
            &maximum_signature,
            &[sample_order(2)],
            &[U256::ONE],
            &[U256::ZERO],
            FifthTakerAmounts {
                taker_fill_amount: U256::ONE,
                taker_receive_amount: U256::ONE,
                taker_fee_amount: U256::ZERO,
            },
        );
        assert!(decode_fifth_match_orders_calldata(&maximum_signature_call).is_some());

        let maximum_makers = vec![sample_order(1); FIFTH_MATCH_ORDERS_MAX_MAKERS];
        let maximum_maker_call = encode_call(
            &order,
            &maximum_makers,
            &vec![U256::ONE; FIFTH_MATCH_ORDERS_MAX_MAKERS],
            &vec![U256::ZERO; FIFTH_MATCH_ORDERS_MAX_MAKERS],
            FifthTakerAmounts {
                taker_fill_amount: U256::ONE,
                taker_receive_amount: U256::ONE,
                taker_fee_amount: U256::ZERO,
            },
        );
        assert_eq!(
            decode_fifth_match_orders_calldata(&maximum_maker_call)
                .unwrap()
                .maker_orders
                .len(),
            FIFTH_MATCH_ORDERS_MAX_MAKERS
        );
    }

    #[test]
    fn order_digest_uses_source_typehash_polygon_domain_and_exchange_proxy() {
        let order = FifthMatchOrder {
            salt: U256::ONE,
            maker: Address::repeat_byte(0x11),
            signer: Address::repeat_byte(0x22),
            token_id: U256::from(0x123456_u64),
            maker_amount: U256::from(17_u64),
            taker_amount: U256::from(23_u64),
            side: FifthOrderSide::Sell,
            signature_type: FifthOrderSignatureType::Poly1271,
            timestamp: U256::from(0x010203_u64),
            metadata: B256::repeat_byte(0x33),
            builder: B256::repeat_byte(0x44),
            signature: vec![0xaa, 0xbb],
        };
        assert_eq!(
            fifth_order_struct_hash(&order),
            B256::from_slice(
                &hex::decode("ba003bffbe4bf3ea647204f08628f9b60391183ef046f09928a408b8ef19ad2c")
                    .unwrap()
            )
        );
        let proxy = Address::from_slice(&hex::decode(&EXCHANGE_PROXY[2..]).unwrap());
        assert_eq!(
            fifth_order_eip712_hash(&order, proxy),
            B256::from_slice(
                &hex::decode("9abc86ab5279f567cf4d08bdbbe31cdd70ebbc37d3880ad8fc357e4c4c84f494")
                    .unwrap()
            )
        );
        assert_ne!(
            fifth_order_eip712_hash(&order, Address::repeat_byte(0x64)),
            fifth_order_eip712_hash(&order, proxy)
        );
    }

    #[test]
    fn independent_source_vectors_cross_decode_and_match_all_order_hashes() {
        use std::str::FromStr;

        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "artifacts/fifth-match-orders-source-vectors.json"
        ))
        .unwrap();
        let proxy = Address::from_slice(
            &hex::decode(&EXCHANGE_PROXY[2..]).expect("known source proxy address"),
        );
        for vector in vectors["vectors"].as_array().unwrap() {
            let encoded = hex::decode(
                vector["calldata"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            assert_eq!(
                vector["calldata_bytes"].as_u64().unwrap(),
                u64::try_from(encoded.len()).unwrap()
            );
            let call = decode_fifth_match_orders_calldata(&encoded).unwrap();
            assert_eq!(
                call.maker_orders.len(),
                usize::try_from(vector["maker_count"].as_u64().unwrap()).unwrap()
            );
            let decimal_array = |name: &str| {
                vector[name]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| U256::from_str(value.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>()
            };
            assert_eq!(call.maker_fill_amounts, decimal_array("maker_fill_amounts"));
            assert_eq!(call.maker_fee_amounts, decimal_array("maker_fee_amounts"));
            let taker_amounts = decimal_array("taker_amounts");
            assert_eq!(call.taker_amounts.taker_fill_amount, taker_amounts[0]);
            assert_eq!(call.taker_amounts.taker_receive_amount, taker_amounts[1]);
            assert_eq!(call.taker_amounts.taker_fee_amount, taker_amounts[2]);

            let orders = std::iter::once(&call.taker_order).chain(call.maker_orders.iter());
            for (order, expected) in orders.zip(vector["order_hashes"].as_array().unwrap()) {
                let expected_struct_hash = B256::from_slice(
                    &hex::decode(
                        expected["struct_hash"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                    )
                    .unwrap(),
                );
                let expected_digest = B256::from_slice(
                    &hex::decode(
                        expected["digest"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                    )
                    .unwrap(),
                );
                assert_eq!(fifth_order_struct_hash(order), expected_struct_hash);
                assert_eq!(fifth_order_eip712_hash(order, proxy), expected_digest);
            }
        }
    }
}
