//! Pure decoder for one bounded provider-reported CTF V1/V2 OrderFilled log.
//!
//! The result is a provider-reported event fact only. It is not receipt
//! inclusion, execution, finality, interval completeness, or cash-flow
//! reconciliation evidence.

use serde_json::Value;
use thiserror::Error;

use super::{
    CanonicalLog, ChainMakerFill, EXCHANGES, RpcLog, V1_ORDER_FILLED, V2_ORDER_FILLED,
    decode_maker_fill, parse_hex_u64, validate_hex, validate_hex_data_with_limit,
};

/// The maximum serialized size accepted for one provider-reported log.
pub const PROVIDER_REPORTED_MAKER_FILL_LOG_MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProviderReportedMakerFillError {
    #[error("provider-reported maker fill log is malformed")]
    MalformedLog,
    #[error("provider-reported maker fill log was removed")]
    RemovedLog,
    #[error("provider-reported maker fill exchange is unsupported")]
    UnsupportedExchange,
}

pub(super) struct ProviderReportedLogEnvelope {
    pub(super) block_number: u64,
    pub(super) transaction_index: u64,
    pub(super) log_index: u64,
    pub(super) address: String,
    block_hash: String,
    transaction_hash: String,
    topics: Vec<String>,
    data: String,
}

pub(super) struct NormalizedProviderReportedLog {
    pub(super) block_number: u64,
    pub(super) block_hash: String,
    pub(super) transaction_hash: String,
    pub(super) transaction_index: u64,
    pub(super) log_index: u64,
    pub(super) address: String,
    pub(super) topics: Vec<String>,
    pub(super) data: String,
}

pub(super) fn parse_provider_reported_log_envelope(
    raw_log: &Value,
) -> Result<ProviderReportedLogEnvelope, ProviderReportedMakerFillError> {
    parse_provider_reported_log_envelope_with_limit(
        raw_log,
        PROVIDER_REPORTED_MAKER_FILL_LOG_MAX_BYTES,
    )
}

pub(super) fn parse_provider_reported_log_envelope_with_limit(
    raw_log: &Value,
    max_bytes: usize,
) -> Result<ProviderReportedLogEnvelope, ProviderReportedMakerFillError> {
    let encoded =
        serde_json::to_vec(raw_log).map_err(|_| ProviderReportedMakerFillError::MalformedLog)?;
    if encoded.len() > max_bytes {
        return Err(ProviderReportedMakerFillError::MalformedLog);
    }
    let row: RpcLog = serde_json::from_value(raw_log.clone())
        .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?;
    if row.removed {
        return Err(ProviderReportedMakerFillError::RemovedLog);
    }
    let transaction_index = raw_log
        .get("transactionIndex")
        .and_then(Value::as_str)
        .ok_or(ProviderReportedMakerFillError::MalformedLog)?;
    Ok(ProviderReportedLogEnvelope {
        block_number: parse_hex_u64(&row.block_number)
            .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?,
        transaction_index: parse_hex_u64(transaction_index)
            .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?,
        log_index: parse_hex_u64(&row.log_index)
            .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?,
        address: validate_hex(&row.address, 20)
            .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?,
        block_hash: row.block_hash,
        transaction_hash: row.transaction_hash,
        topics: row.topics,
        data: row.data,
    })
}

pub(super) fn normalize_provider_reported_log(
    row: ProviderReportedLogEnvelope,
    data_limit_bytes: usize,
) -> Result<NormalizedProviderReportedLog, ProviderReportedMakerFillError> {
    let block_hash = validate_hex(&row.block_hash, 32)
        .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?;
    let transaction_hash = validate_hex(&row.transaction_hash, 32)
        .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?;
    let topics = row
        .topics
        .iter()
        .map(|topic| {
            validate_hex(topic, 32).map_err(|_| ProviderReportedMakerFillError::MalformedLog)
        })
        .collect::<Result<_, _>>()?;
    let data = validate_hex_data_with_limit(&row.data, data_limit_bytes)
        .map_err(|_| ProviderReportedMakerFillError::MalformedLog)?;
    Ok(NormalizedProviderReportedLog {
        block_number: row.block_number,
        block_hash,
        transaction_hash,
        transaction_index: row.transaction_index,
        log_index: row.log_index,
        address: row.address,
        topics,
        data,
    })
}

/// Decode one bounded JSON-RPC log into the existing gross-plus-fee CTF fill
/// shape. Only known first-party CTF V1/V2 exchange address/topic pairs are
/// accepted; the fifth exchange and unknown emitters remain unsupported.
pub fn decode_provider_reported_maker_fill(
    raw_log: &Value,
) -> Result<ChainMakerFill, ProviderReportedMakerFillError> {
    let envelope = parse_provider_reported_log_envelope(raw_log)?;
    let address = envelope.address.clone();
    let is_v1 = EXCHANGES[..2]
        .iter()
        .any(|exchange| exchange.eq_ignore_ascii_case(&address));
    let is_v2 = EXCHANGES[2..4]
        .iter()
        .any(|exchange| exchange.eq_ignore_ascii_case(&address));
    if !is_v1 && !is_v2 {
        return Err(ProviderReportedMakerFillError::UnsupportedExchange);
    }
    let row = normalize_provider_reported_log(envelope, 5 * 32)?;
    let block_number = row.block_number;
    let log_index = row.log_index;
    let block_hash = row.block_hash;
    let transaction_hash = row.transaction_hash;
    let topics = row.topics;
    let data = row.data;
    if topics.len() != 4 || data.len() != 2 + 5 * 64 {
        return Err(ProviderReportedMakerFillError::MalformedLog);
    }

    let expected_topic = if is_v1 {
        V1_ORDER_FILLED
    } else {
        V2_ORDER_FILLED
    };
    if topics[0] != expected_topic {
        return Err(ProviderReportedMakerFillError::MalformedLog);
    }

    let canonical = CanonicalLog {
        address,
        block_number,
        block_hash,
        transaction_hash,
        log_index,
        topics,
        data,
    };
    decode_maker_fill(&canonical).map_err(|_| ProviderReportedMakerFillError::MalformedLog)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ProviderReportedMakerFillError as Error, decode_provider_reported_maker_fill};
    use crate::TradeSide;
    use crate::chain_log_audit::{
        CtfDecoderVersion, EXCHANGES, FeeAsset, V1_ORDER_FILLED, V2_ORDER_FILLED,
    };

    fn word(value: u128) -> String {
        format!("{value:064x}")
    }

    fn address_topic(address: &str) -> String {
        format!("0x{}{}", "00".repeat(12), address[2..].to_ascii_lowercase())
    }

    fn log(exchange: &str, topic: &str) -> Value {
        log_with_data(
            exchange,
            topic,
            [0, 123, 5_000_000, 7_000_000, 9],
            "0x2222222222222222222222222222222222222222",
        )
    }

    fn log_with_data(exchange: &str, topic: &str, words: [u128; 5], counterparty: &str) -> Value {
        let owner = "0x1111111111111111111111111111111111111111";
        let data = words.into_iter().map(word).collect::<String>();
        json!({
            "address": exchange,
            "blockNumber": "0x64",
            "blockHash": format!("0x{}", "aa".repeat(32)),
            "transactionHash": format!("0x{}", "bb".repeat(32)),
            "transactionIndex": "0x1",
            "logIndex": "0x2",
            "topics": [
                topic,
                format!("0x{}", "33".repeat(32)),
                address_topic(owner),
                address_topic(counterparty),
            ],
            "data": format!("0x{data}"),
            "removed": false,
        })
    }

    #[test]
    fn decodes_provider_reported_v1_and_v2_gross_fill_with_separate_fee() {
        let v1 = decode_provider_reported_maker_fill(&log(EXCHANGES[0], V1_ORDER_FILLED))
            .expect("known V1 event");
        assert_eq!(v1.block_number, 100);
        assert_eq!(v1.log_index, 2);
        assert_eq!(v1.block_hash, format!("0x{}", "aa".repeat(32)));
        assert_eq!(v1.transaction_hash, format!("0x{}", "bb".repeat(32)));
        assert_eq!(v1.decoder_version, CtfDecoderVersion::V1);
        assert_eq!(v1.wallet, "0x1111111111111111111111111111111111111111");
        assert_eq!(
            v1.raw_counterparty,
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(v1.token_id, "123");
        assert_eq!(v1.side, TradeSide::Buy);
        assert_eq!(v1.share_base_units, 7_000_000);
        assert_eq!(v1.collateral_base_units, 5_000_000);
        assert_eq!(v1.fee_base_units, 9);
        assert_eq!(v1.fee_asset, FeeAsset::OutcomeToken);

        let v2 = decode_provider_reported_maker_fill(&log(EXCHANGES[2], V2_ORDER_FILLED))
            .expect("known V2 event");
        assert_eq!(v2.decoder_version, CtfDecoderVersion::V2);
        assert_eq!(v2.side, TradeSide::Buy);
        assert_eq!(v2.share_base_units, 7_000_000);
        assert_eq!(v2.collateral_base_units, 5_000_000);
        assert_eq!(v2.fee_base_units, 9);
        assert_eq!(v2.fee_asset, FeeAsset::Collateral);
    }

    #[test]
    fn decodes_v1_and_v2_sell_amount_order_and_collateral_fee() {
        let v1 = decode_provider_reported_maker_fill(&log_with_data(
            EXCHANGES[0],
            V1_ORDER_FILLED,
            [123, 0, 7_000_000, 5_000_000, 9],
            EXCHANGES[0],
        ))
        .expect("known V1 SELL event");
        assert_eq!(v1.side, TradeSide::Sell);
        assert_eq!(v1.share_base_units, 7_000_000);
        assert_eq!(v1.collateral_base_units, 5_000_000);
        assert_eq!(v1.fee_base_units, 9);
        assert_eq!(v1.fee_asset, FeeAsset::Collateral);
        assert!(v1.exchange_counterparty_aggregate_shape);

        let v2 = decode_provider_reported_maker_fill(&log_with_data(
            EXCHANGES[2],
            V2_ORDER_FILLED,
            [1, 123, 7_000_000, 5_000_000, 9],
            "0x2222222222222222222222222222222222222222",
        ))
        .expect("known V2 SELL event");
        assert_eq!(v2.side, TradeSide::Sell);
        assert_eq!(v2.share_base_units, 7_000_000);
        assert_eq!(v2.collateral_base_units, 5_000_000);
        assert_eq!(v2.fee_base_units, 9);
        assert_eq!(v2.fee_asset, FeeAsset::Collateral);
        assert!(!v2.exchange_counterparty_aggregate_shape);
    }

    #[test]
    fn refuses_malformed_locator_topics_dimensions_and_removed_logs() {
        let mut bad_indexed_address = log(EXCHANGES[0], V1_ORDER_FILLED);
        bad_indexed_address["topics"][2] = Value::String(format!("0x{}", "11".repeat(32)));
        assert_eq!(
            decode_provider_reported_maker_fill(&bad_indexed_address),
            Err(Error::MalformedLog)
        );

        let mut missing_dimension = log(EXCHANGES[0], V1_ORDER_FILLED);
        missing_dimension
            .as_object_mut()
            .unwrap()
            .remove("blockHash");
        assert_eq!(
            decode_provider_reported_maker_fill(&missing_dimension),
            Err(Error::MalformedLog)
        );

        let mut missing_transaction_index = log(EXCHANGES[0], V1_ORDER_FILLED);
        missing_transaction_index
            .as_object_mut()
            .unwrap()
            .remove("transactionIndex");
        assert_eq!(
            decode_provider_reported_maker_fill(&missing_transaction_index),
            Err(Error::MalformedLog)
        );

        let mut invalid_log_index = log(EXCHANGES[0], V1_ORDER_FILLED);
        invalid_log_index["logIndex"] = Value::String("0xnope".to_owned());
        assert_eq!(
            decode_provider_reported_maker_fill(&invalid_log_index),
            Err(Error::MalformedLog)
        );

        let mut short_topics = log(EXCHANGES[2], V2_ORDER_FILLED);
        short_topics["topics"] = json!(
            short_topics["topics"]
                .as_array()
                .unwrap()
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decode_provider_reported_maker_fill(&short_topics),
            Err(Error::MalformedLog)
        );

        let mut wrong_topic = log(EXCHANGES[2], V1_ORDER_FILLED);
        assert_eq!(
            decode_provider_reported_maker_fill(&wrong_topic),
            Err(Error::MalformedLog)
        );
        wrong_topic["topics"][0] = Value::String(V2_ORDER_FILLED.to_owned());
        wrong_topic["removed"] = Value::Bool(true);
        assert_eq!(
            decode_provider_reported_maker_fill(&wrong_topic),
            Err(Error::RemovedLog)
        );
    }

    #[test]
    fn fifth_and_unknown_exchanges_are_explicitly_unsupported() {
        assert_eq!(
            decode_provider_reported_maker_fill(&log(EXCHANGES[4], V2_ORDER_FILLED)),
            Err(Error::UnsupportedExchange)
        );
        assert_eq!(
            decode_provider_reported_maker_fill(&log(
                "0x9999999999999999999999999999999999999999",
                V2_ORDER_FILLED
            )),
            Err(Error::UnsupportedExchange)
        );
    }

    #[test]
    fn requires_removed_field_and_enforces_single_log_size_bound() {
        let mut missing_removed = log(EXCHANGES[0], V1_ORDER_FILLED);
        missing_removed.as_object_mut().unwrap().remove("removed");
        assert_eq!(
            decode_provider_reported_maker_fill(&missing_removed),
            Err(Error::MalformedLog)
        );

        let mut oversized = log(EXCHANGES[0], V1_ORDER_FILLED);
        oversized["providerExtra"] = Value::String("x".repeat(16 * 1024));
        assert_eq!(
            decode_provider_reported_maker_fill(&oversized),
            Err(Error::MalformedLog)
        );
    }
}
