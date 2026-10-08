//! Local content binding for Bor/Ethereum-shaped RPC headers. This verifies
//! only that the returned hash matches Bor's RLP codec, not consensus validity.

use serde_json::Value;
use sha3::{Digest, Keccak256};

use super::{
    ChainLogAuditError, MAX_RESPONSE_BYTES, rlp_list, signed_transaction_quantity, validate_hex,
    validate_hex_data_with_limit,
};

const REQUIRED_FIELDS: [&str; 15] = [
    "parentHash",
    "sha3Uncles",
    "miner",
    "stateRoot",
    "transactionsRoot",
    "receiptsRoot",
    "logsBloom",
    "difficulty",
    "number",
    "gasLimit",
    "gasUsed",
    "timestamp",
    "extraData",
    "mixHash",
    "nonce",
];
const OPTIONAL_FIELDS: [&str; 6] = [
    "baseFeePerGas",
    "withdrawalsRoot",
    "blobGasUsed",
    "excessBlobGas",
    "parentBeaconBlockRoot",
    "requestsHash",
];
const ENVELOPE_FIELDS: [&str; 5] = [
    "size",
    "transactions",
    "uncles",
    "withdrawals",
    "totalDifficulty",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckedHeader {
    pub(super) hash: String,
    pub(super) number: u64,
    pub(super) parent_hash: String,
    pub(super) state_root: String,
    pub(super) transactions_root: String,
    pub(super) receipts_root: String,
    pub(super) gas_limit: u64,
    pub(super) gas_used: u64,
    pub(super) base_fee_per_gas: Option<alloy_primitives::U256>,
    pub(super) timestamp: u64,
}

pub(super) fn bind_header(value: &Value) -> Result<CheckedHeader, ChainLogAuditError> {
    let object = value.as_object().ok_or(ChainLogAuditError::Unverified)?;
    for key in object.keys() {
        if key != "hash"
            && !REQUIRED_FIELDS.contains(&key.as_str())
            && !OPTIONAL_FIELDS.contains(&key.as_str())
            && !ENVELOPE_FIELDS.contains(&key.as_str())
        {
            return Err(ChainLogAuditError::Unverified);
        }
    }
    let computed_hash = recompute_header_hash(value)?;
    let hash = validate_hex(text(value, "hash")?, 32)?;
    if hash != computed_hash {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(CheckedHeader {
        hash,
        number: quantity_u64(value, "number")?,
        parent_hash: fixed_hex(value, "parentHash", 32)?,
        state_root: fixed_hex(value, "stateRoot", 32)?,
        transactions_root: fixed_hex(value, "transactionsRoot", 32)?,
        receipts_root: fixed_hex(value, "receiptsRoot", 32)?,
        gas_limit: quantity_u64(value, "gasLimit")?,
        gas_used: quantity_u64(value, "gasUsed")?,
        base_fee_per_gas: value
            .get("baseFeePerGas")
            .filter(|field| !field.is_null())
            .map(signed_transaction_quantity)
            .transpose()?,
        timestamp: quantity_u64(value, "timestamp")?,
    })
}

fn recompute_header_hash(value: &Value) -> Result<String, ChainLogAuditError> {
    let mut fields = Vec::with_capacity(REQUIRED_FIELDS.len() + OPTIONAL_FIELDS.len());
    fields.push(fixed_rlp(value, "parentHash", 32)?);
    fields.push(fixed_rlp(value, "sha3Uncles", 32)?);
    fields.push(fixed_rlp(value, "miner", 20)?);
    fields.push(fixed_rlp(value, "stateRoot", 32)?);
    fields.push(fixed_rlp(value, "transactionsRoot", 32)?);
    fields.push(fixed_rlp(value, "receiptsRoot", 32)?);
    fields.push(fixed_rlp(value, "logsBloom", 256)?);
    fields.push(big_quantity_rlp(value, "difficulty")?);
    fields.push(quantity_rlp(value, "number")?);
    fields.push(quantity_rlp(value, "gasLimit")?);
    fields.push(quantity_rlp(value, "gasUsed")?);
    fields.push(quantity_rlp(value, "timestamp")?);
    fields.push(data_rlp(value, "extraData")?);
    fields.push(fixed_rlp(value, "mixHash", 32)?);
    fields.push(fixed_rlp(value, "nonce", 8)?);

    let optional = OPTIONAL_FIELDS
        .iter()
        .map(|name| optional_rlp(value, name))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(last_present) = optional.iter().rposition(Option::is_some) {
        for field in optional.into_iter().take(last_present + 1) {
            fields.push(field.unwrap_or_else(|| alloy_rlp::encode(&[][..])));
        }
    }

    let encoded = rlp_list(&fields);
    Ok(format!("0x{}", hex::encode(Keccak256::digest(encoded))))
}

fn optional_rlp(value: &Value, name: &str) -> Result<Option<Vec<u8>>, ChainLogAuditError> {
    let Some(value) = value.get(name).filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let encoded = match name {
        "baseFeePerGas" => big_quantity_rlp_value(value)?,
        "blobGasUsed" | "excessBlobGas" => quantity_rlp_value(value)?,
        "withdrawalsRoot" | "parentBeaconBlockRoot" | "requestsHash" => {
            fixed_rlp_value(value, name, 32)?
        }
        _ => return Err(ChainLogAuditError::Unverified),
    };
    Ok(Some(encoded))
}

fn fixed_rlp(value: &Value, name: &str, bytes: usize) -> Result<Vec<u8>, ChainLogAuditError> {
    fixed_rlp_value(
        value.get(name).ok_or(ChainLogAuditError::Unverified)?,
        name,
        bytes,
    )
}

fn fixed_rlp_value(
    value: &Value,
    _name: &str,
    bytes: usize,
) -> Result<Vec<u8>, ChainLogAuditError> {
    let value = value.as_str().ok_or(ChainLogAuditError::Unverified)?;
    let hex = validate_hex(value, bytes)?;
    let decoded = hex::decode(&hex[2..]).map_err(|_| ChainLogAuditError::Unverified)?;
    Ok(alloy_rlp::encode(decoded.as_slice()))
}

fn fixed_hex(value: &Value, name: &str, bytes: usize) -> Result<String, ChainLogAuditError> {
    validate_hex(text(value, name)?, bytes)
}

fn data_rlp(value: &Value, name: &str) -> Result<Vec<u8>, ChainLogAuditError> {
    let value = text(value, name)?;
    let data = validate_hex_data_with_limit(value, MAX_RESPONSE_BYTES)?;
    let decoded = hex::decode(&data[2..]).map_err(|_| ChainLogAuditError::Unverified)?;
    Ok(alloy_rlp::encode(decoded.as_slice()))
}

fn quantity_rlp(value: &Value, name: &str) -> Result<Vec<u8>, ChainLogAuditError> {
    let raw = text(value, name)?;
    Ok(alloy_rlp::encode(parse_canonical_u64(raw)?))
}

fn quantity_rlp_value(value: &Value) -> Result<Vec<u8>, ChainLogAuditError> {
    let raw = value.as_str().ok_or(ChainLogAuditError::Unverified)?;
    Ok(alloy_rlp::encode(parse_canonical_u64(raw)?))
}

fn quantity_u64(value: &Value, name: &str) -> Result<u64, ChainLogAuditError> {
    parse_canonical_u64(text(value, name)?)
}

fn big_quantity_rlp(value: &Value, name: &str) -> Result<Vec<u8>, ChainLogAuditError> {
    let raw = text(value, name)?;
    big_quantity_rlp_text(raw)
}

fn big_quantity_rlp_value(value: &Value) -> Result<Vec<u8>, ChainLogAuditError> {
    let raw = value.as_str().ok_or(ChainLogAuditError::Unverified)?;
    big_quantity_rlp_text(raw)
}

fn big_quantity_rlp_text(value: &str) -> Result<Vec<u8>, ChainLogAuditError> {
    let digits = canonical_quantity_digits(value)?;
    let padded;
    let digits = if digits.len() % 2 == 0 {
        digits
    } else {
        padded = format!("0{digits}");
        &padded
    };
    let decoded = hex::decode(digits).map_err(|_| ChainLogAuditError::Unverified)?;
    let first_nonzero = decoded
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(decoded.len());
    Ok(alloy_rlp::encode(&decoded[first_nonzero..]))
}

fn parse_canonical_u64(value: &str) -> Result<u64, ChainLogAuditError> {
    let digits = canonical_quantity_digits(value)?;
    u64::from_str_radix(digits, 16).map_err(|_| ChainLogAuditError::Unverified)
}

fn canonical_quantity_digits(value: &str) -> Result<&str, ChainLogAuditError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(ChainLogAuditError::Unverified)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ChainLogAuditError::Unverified);
    }
    Ok(digits)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, ChainLogAuditError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ChainLogAuditError::Unverified)
}

#[cfg(test)]
pub(super) fn fixture_hash(value: &Value) -> Result<String, ChainLogAuditError> {
    recompute_header_hash(value)
}

#[cfg(test)]
pub(super) fn fixture_header(
    number: u64,
    parent_hash: &str,
    state_root: &str,
    receipts_root: &str,
    transactions_root: &str,
) -> Value {
    let mut header = serde_json::json!({
        "parentHash": parent_hash,
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": "0x0000000000000000000000000000000000000001",
        "stateRoot": state_root,
        "transactionsRoot": transactions_root,
        "receiptsRoot": receipts_root,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x1",
        "number": format!("{number:#x}"),
        "gasLimit": "0x100000",
        "gasUsed": "0x5208",
        "timestamp": "0x6712ba6e",
        "extraData": "0x",
        "mixHash": format!("0x{}", "00".repeat(32)),
        "nonce": "0x0000000000000000"
    });
    let hash = recompute_header_hash(&header).expect("well-formed fixture header");
    header["hash"] = serde_json::json!(hash);
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use serde_json::{Map, json};

    fn sample_header() -> Value {
        json!({
            "parentHash": format!("0x{}", "11".repeat(32)),
            "sha3Uncles": format!("0x{}", "22".repeat(32)),
            "miner": format!("0x{}", "33".repeat(20)),
            "stateRoot": format!("0x{}", "44".repeat(32)),
            "transactionsRoot": format!("0x{}", "55".repeat(32)),
            "receiptsRoot": format!("0x{}", "66".repeat(32)),
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "difficulty": "0x1",
            "number": "0x64",
            "gasLimit": "0x100000",
            "gasUsed": "0x20000",
            "timestamp": "0x6712ba6e",
            "extraData": format!("0x{}", "ab".repeat(40)),
            "mixHash": format!("0x{}", "77".repeat(32)),
            "nonce": "0x0000000000000000",
        })
    }

    fn seal(mut header: Value) -> Value {
        header["hash"] = json!(fixture_hash(&header).unwrap());
        header
    }

    #[test]
    fn binds_bor_required_fields_and_accepts_long_extra_data_and_rpc_envelope() {
        let mut header = sample_header();
        header["size"] = json!("0x100");
        header["transactions"] = json!([]);
        header["uncles"] = json!([]);
        header["withdrawals"] = json!([]);
        header["totalDifficulty"] = json!("0x1000");
        let header = seal(header);
        assert_eq!(bind_header(&header).unwrap().hash, header["hash"]);
        assert_eq!(header["extraData"].as_str().unwrap().len(), 82);
    }

    #[test]
    fn optional_tail_uses_bor_nil_holes_and_absent_or_null_means_nil() {
        let base = sample_header();
        let mut hole = base.clone();
        hole["blobGasUsed"] = json!("0x1");
        hole["requestsHash"] = json!(format!("0x{}", "99".repeat(32)));
        let hole = seal(hole);
        assert!(bind_header(&hole).is_ok());

        let mut with_null = base;
        with_null["baseFeePerGas"] = Value::Null;
        with_null["requestsHash"] = json!(format!("0x{}", "99".repeat(32)));
        let with_null = seal(with_null);
        assert!(bind_header(&with_null).is_ok());
    }

    #[test]
    fn malformed_required_optional_and_unknown_fields_fail_closed() {
        let baseline = seal(sample_header());
        for (key, value) in [
            ("logsBloom", json!("0x12")),
            ("miner", json!(true)),
            ("number", json!("0x064")),
            ("gasLimit", json!("0x")),
            ("difficulty", json!("0x00")),
            ("blobGasUsed", json!("0x01")),
            ("parentBeaconBlockRoot", json!("0x12")),
            (
                "extraData",
                json!(format!("0x{}", "aa".repeat(MAX_RESPONSE_BYTES + 1))),
            ),
            ("surpriseField", json!("0x1")),
        ] {
            let mut header = baseline.clone();
            header[key] = value;
            assert_eq!(
                bind_header(&header),
                Err(ChainLogAuditError::Unverified),
                "{key}"
            );
        }
    }

    #[test]
    fn uint64_quantities_accept_max_and_reject_overflow_without_u128_fallback() {
        const MAX_U64: &str = "0xffffffffffffffff";
        const OVER_U64: &str = "0x10000000000000000";

        let mut at_limit = sample_header();
        for name in ["number", "gasLimit", "gasUsed", "timestamp"] {
            at_limit[name] = json!(MAX_U64);
        }
        at_limit["blobGasUsed"] = json!(MAX_U64);
        at_limit["excessBlobGas"] = json!(MAX_U64);
        let at_limit = seal(at_limit);
        let checked = bind_header(&at_limit).unwrap();
        assert_eq!(checked.number, u64::MAX);
        assert_eq!(checked.timestamp, u64::MAX);

        for name in [
            "number",
            "gasLimit",
            "gasUsed",
            "timestamp",
            "blobGasUsed",
            "excessBlobGas",
        ] {
            let mut overflow = sample_header();
            overflow[name] = json!(OVER_U64);
            assert_eq!(
                fixture_hash(&overflow),
                Err(ChainLogAuditError::Unverified),
                "{name}"
            );
            assert_eq!(
                bind_header(&overflow),
                Err(ChainLogAuditError::Unverified),
                "{name}"
            );
        }
    }

    #[test]
    fn difficulty_and_base_fee_keep_big_quantity_range() {
        let mut header = sample_header();
        header["difficulty"] = json!("0x10000000000000000");
        header["baseFeePerGas"] = json!("0x10000000000000000");
        let header = seal(header);
        assert!(bind_header(&header).is_ok());
    }

    #[test]
    fn matching_providers_cannot_make_content_mutation_hash_valid() {
        let baseline = seal(sample_header());
        for key in [
            "receiptsRoot",
            "transactionsRoot",
            "timestamp",
            "parentHash",
        ] {
            let mut tampered = baseline.clone();
            if key == "timestamp" {
                tampered[key] = json!("0x6712ba6f");
            } else {
                tampered[key] = json!(format!("0x{}", "fe".repeat(32)));
            }
            // Both providers returning these same altered bytes does not help:
            // the unchanged claimed hash fails local content binding.
            assert_eq!(
                bind_header(&tampered),
                Err(ChainLogAuditError::Unverified),
                "{key}"
            );
        }
    }

    fn header_json_from_rlp(encoded: &[u8], hash: &str) -> Value {
        let fields = alloy_rlp::decode_exact::<Vec<Bytes>>(encoded).unwrap();
        let mut object = Map::new();
        let names = [
            "parentHash",
            "sha3Uncles",
            "miner",
            "stateRoot",
            "transactionsRoot",
            "receiptsRoot",
            "logsBloom",
            "difficulty",
            "number",
            "gasLimit",
            "gasUsed",
            "timestamp",
            "extraData",
            "mixHash",
            "nonce",
        ];
        for (index, name) in names.iter().enumerate() {
            let bytes = fields[index].as_ref();
            let value = match index {
                7..=11 => quantity_json(bytes),
                12 => format!("0x{}", hex::encode(bytes)),
                _ => format!("0x{}", hex::encode(bytes)),
            };
            object.insert((*name).to_owned(), json!(value));
        }
        for (offset, name) in OPTIONAL_FIELDS.iter().enumerate() {
            let Some(bytes) = fields.get(names.len() + offset) else {
                break;
            };
            let bytes = bytes.as_ref();
            let value = if matches!(
                *name,
                "withdrawalsRoot" | "parentBeaconBlockRoot" | "requestsHash"
            ) {
                (bytes.len() == 32).then(|| json!(format!("0x{}", hex::encode(bytes))))
            } else if bytes.is_empty() {
                (names.len() + offset + 1 == fields.len()).then(|| json!("0x0"))
            } else {
                Some(json!(quantity_json(bytes)))
            };
            object.insert((*name).to_owned(), value.unwrap_or(Value::Null));
        }
        object.insert("hash".to_owned(), json!(hash));
        Value::Object(object)
    }

    fn quantity_json(bytes: &[u8]) -> String {
        let digits = hex::encode(bytes);
        let digits = digits.trim_start_matches('0');
        if digits.is_empty() {
            "0x0".to_owned()
        } else {
            format!("0x{digits}")
        }
    }

    #[test]
    fn pinned_bor_validator_block_header_vector_binds_hash() {
        // 0xPolygon/bor 755ae8b81843d00d32fd4ae33329be5eeace8ce6,
        // core/types/block_test.go TestValidatorBytesBlockDecoding blockEnc's first header.
        let encoded = hex::decode(include_str!("header_binding/bor_header.rlp").trim()).unwrap();
        let header = header_json_from_rlp(
            &encoded,
            "0xd41b39190a90b9c047ed091c4c77ba03289fef1ae6e87600ab60f7242d63e4a5",
        );
        assert_eq!(fixture_hash(&header).unwrap(), header["hash"]);
        let checked = bind_header(&header).unwrap();
        assert_eq!(checked.hash, header["hash"]);
        assert_eq!(checked.timestamp, 1_426_516_743);
    }

    #[test]
    fn pinned_alloy_ronin_header_rlp_vector_binds_hash() {
        // alloy-consensus 2.4.2 src/block/header.rs decode_header_rlp, Ronin fixture.
        let encoded =
            hex::decode(include_str!("header_binding/alloy_ronin_header.rlp").trim()).unwrap();
        let header = header_json_from_rlp(
            &encoded,
            "0x4f05e4392969fc82e41f6d6a8cea379323b0b2d3ddf7def1a33eec03883e3a33",
        );
        assert_eq!(bind_header(&header).unwrap().hash, header["hash"]);
    }

    #[test]
    fn pinned_alloy_prague_header_vector_hashes_with_optional_tail() {
        // alloy-consensus 2.4.2 src/block/header.rs serde_tests::serde_rlp_prague.
        let mut header = json!({
            "baseFeePerGas":"0x7","blobGasUsed":"0x20000","difficulty":"0x0","excessBlobGas":"0x40000",
            "extraData":"0xd883010e0c846765746888676f312e32332e32856c696e7578","gasLimit":"0x1c9c380","gasUsed":"0x5208",
            "hash":"0x661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26",
            "logsBloom":format!("0x{}", "00".repeat(256)),
            "miner":"0xf97e180c050e5ab072211ad2c213eb5aee4df134","mixHash":"0xe6d9c084dd36560520d5776a5387a82fb44793c9cd1b69afb61d53af29ee64b0",
            "nonce":"0x0000000000000000","number":"0x315","parentBeaconBlockRoot":"0xd0bdb48ab45028568e66c8ddd600ac4c2a52522714bbfbf00ea6d20ba40f3ae2",
            "parentHash":"0x60f1563d2c572116091a4b91421d8d972118e39604d23455d841f9431cea4b6a","receiptsRoot":"0xeaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab",
            "requestsHash":"0x6036c41849da9c076ed79654d434017387a88fb833c2856b32e18218b3341c5f","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "stateRoot":"0x8101d88f2761eb9849634740f92fe09735551ad5a4d5e9da9bcae1ef4726a475","timestamp":"0x6712ba6e",
            "transactionsRoot":"0xf543eb3d405d2d6320344d348b06703ff1abeef71288181a24061e53f89bb5ef","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        });
        assert_eq!(bind_header(&header).unwrap().hash, header["hash"]);
        header["totalDifficulty"] = json!("0x123");
        assert_eq!(
            bind_header(&header).unwrap().hash,
            "0x661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26"
        );
    }

    #[test]
    fn pinned_alloy_prague_json_fixture_file_binds_claimed_hash() {
        let header: Value =
            serde_json::from_str(include_str!("header_binding/alloy_prague.json")).unwrap();
        assert_eq!(
            bind_header(&header).unwrap().hash,
            "0x661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26"
        );
    }
}
