//! Bounded provider-reported raw events from the fifth Exchange proxy.
//!
//! These observations are not receipt/root verified, successful-call verified,
//! implementation-bound, or a complete activity/history claim. They expose no
//! cash-flow or P&L semantics.

use alloy_primitives::{B256, U256};
use serde_json::Value;
use thiserror::Error;

use crate::TradeSide;

use super::{CHAIN_ID, fifth_code_context::EXCHANGE_PROXY, v1_event_topic};
use super::{
    fifth_receipt_maker_window::{
        ORDER_FILLED_SIGNATURE, ORDERS_MATCHED_SIGNATURE, decode_fifth_order_filled_fields,
        decode_fifth_orders_matched_fields,
    },
    provider_reported_maker_fill::{
        PROVIDER_REPORTED_MAKER_FILL_LOG_MAX_BYTES, ProviderReportedMakerFillError,
        normalize_provider_reported_log, parse_provider_reported_log_envelope,
    },
};

pub const FIFTH_PROVIDER_REPORTED_EVENT_POLICY_VERSION: &str =
    "fifth-exchange-provider-reported-raw-event/1";
pub const FIFTH_PROVIDER_REPORTED_EVENT_LOG_MAX_BYTES: usize =
    PROVIDER_REPORTED_MAKER_FILL_LOG_MAX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProviderReportedFifthEventError {
    #[error("provider-reported fifth Exchange event log is malformed or unsupported")]
    MalformedLog,
    #[error("provider-reported fifth Exchange event log was removed")]
    RemovedLog,
    #[error("provider-reported fifth Exchange event emitter is unsupported")]
    UnsupportedEmitter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FifthEventObservationSource {
    ProviderReported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FifthEventImplementationVersion {
    Unbound,
}

/// One unverified JSON-RPC fifth Exchange event with source locator metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReportedFifthEvent {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_hash: String,
    pub transaction_index: u64,
    pub log_index: u64,
    pub emitter: String,
    pub source: FifthEventObservationSource,
    pub implementation_version: FifthEventImplementationVersion,
    pub event: ProviderReportedFifthEventKind,
}

impl ProviderReportedFifthEvent {
    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_PROVIDER_REPORTED_EVENT_POLICY_VERSION
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderReportedFifthEventKind {
    OrderFilled(ProviderReportedFifthOrderFilled),
    OrdersMatched(ProviderReportedFifthOrdersMatched),
}

/// Raw ABI values from `OrderFilled`; the fee is separate and has no inferred
/// denomination, transfer, net-cash, or P&L meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReportedFifthOrderFilled {
    pub order_hash: B256,
    pub maker: String,
    pub taker: String,
    pub side: TradeSide,
    pub token_id: U256,
    pub maker_amount_filled: U256,
    pub taker_amount_filled: U256,
    pub fee_amount: U256,
    pub builder: B256,
    pub metadata: B256,
}

/// Raw aggregate `OrdersMatched` fields. It is not paired to an `OrderFilled`
/// row and does not by itself establish an owner fill.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReportedFifthOrdersMatched {
    pub order_hash: B256,
    pub maker: String,
    pub side: TradeSide,
    pub token_id: U256,
    pub maker_amount_filled: U256,
    pub taker_amount_filled: U256,
}

/// Decode one bounded raw JSON-RPC event row from the known fifth Exchange
/// proxy. The result remains provider-reported and implementation-unbound.
pub fn decode_provider_reported_fifth_event(
    raw_log: &Value,
) -> Result<ProviderReportedFifthEvent, ProviderReportedFifthEventError> {
    let envelope = parse_provider_reported_log_envelope(raw_log).map_err(map_log_error)?;
    if !envelope.address.eq_ignore_ascii_case(EXCHANGE_PROXY) {
        return Err(ProviderReportedFifthEventError::UnsupportedEmitter);
    }
    let row =
        normalize_provider_reported_log(envelope, FIFTH_PROVIDER_REPORTED_EVENT_LOG_MAX_BYTES)
            .map_err(map_log_error)?;
    let event_topic = row
        .topics
        .first()
        .ok_or(ProviderReportedFifthEventError::MalformedLog)?;
    let event = if event_topic == &v1_event_topic(ORDER_FILLED_SIGNATURE) {
        let parsed = decode_fifth_order_filled_fields(&row.topics, &row.data)
            .map_err(|_| ProviderReportedFifthEventError::MalformedLog)?;
        ProviderReportedFifthEventKind::OrderFilled(ProviderReportedFifthOrderFilled {
            order_hash: parsed.order_hash,
            maker: parsed.maker,
            taker: parsed.taker,
            side: parsed.side,
            token_id: parsed.token_id,
            maker_amount_filled: parsed.maker_amount_filled,
            taker_amount_filled: parsed.taker_amount_filled,
            fee_amount: parsed.fee_amount,
            builder: parsed.builder,
            metadata: parsed.metadata,
        })
    } else if event_topic == &v1_event_topic(ORDERS_MATCHED_SIGNATURE) {
        let parsed = decode_fifth_orders_matched_fields(&row.topics, &row.data)
            .map_err(|_| ProviderReportedFifthEventError::MalformedLog)?;
        if parsed.maker == format!("0x{}", "00".repeat(20)) {
            return Err(ProviderReportedFifthEventError::MalformedLog);
        }
        ProviderReportedFifthEventKind::OrdersMatched(ProviderReportedFifthOrdersMatched {
            order_hash: parsed.order_hash,
            maker: parsed.maker,
            side: parsed.side,
            token_id: parsed.token_id,
            maker_amount_filled: parsed.maker_amount_filled,
            taker_amount_filled: parsed.taker_amount_filled,
        })
    } else {
        return Err(ProviderReportedFifthEventError::MalformedLog);
    };

    Ok(ProviderReportedFifthEvent {
        chain_id: CHAIN_ID,
        block_number: row.block_number,
        block_hash: row.block_hash,
        transaction_hash: row.transaction_hash,
        transaction_index: row.transaction_index,
        log_index: row.log_index,
        emitter: row.address,
        source: FifthEventObservationSource::ProviderReported,
        implementation_version: FifthEventImplementationVersion::Unbound,
        event,
    })
}

fn map_log_error(error: ProviderReportedMakerFillError) -> ProviderReportedFifthEventError {
    match error {
        ProviderReportedMakerFillError::RemovedLog => ProviderReportedFifthEventError::RemovedLog,
        ProviderReportedMakerFillError::MalformedLog
        | ProviderReportedMakerFillError::UnsupportedExchange => {
            ProviderReportedFifthEventError::MalformedLog
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U256};
    use serde_json::{Value, json};

    use super::{
        FIFTH_PROVIDER_REPORTED_EVENT_LOG_MAX_BYTES, FifthEventImplementationVersion,
        FifthEventObservationSource, ProviderReportedFifthEventError as Error,
        ProviderReportedFifthEventKind, decode_provider_reported_fifth_event,
    };
    use crate::{TradeSide, chain_log_audit};

    fn word(value: U256) -> String {
        hex::encode(value.to_be_bytes::<32>())
    }

    fn address_topic(address: &str) -> String {
        format!("0x{}{}", "00".repeat(12), &address[2..])
    }

    fn event_log(signature: &str, is_matched: bool, amounts: [U256; 7]) -> Value {
        let proxy = chain_log_audit::fifth_code_context::EXCHANGE_PROXY;
        let maker = "0x1111111111111111111111111111111111111111";
        let taker = "0x2222222222222222222222222222222222222222";
        let mut data_words = vec![amounts[0], amounts[1], amounts[2], amounts[3]];
        if !is_matched {
            data_words.extend([amounts[4], amounts[5], amounts[6]]);
        }
        let topics = if is_matched {
            vec![
                chain_log_audit::v1_event_topic(signature),
                format!("0x{}", "33".repeat(32)),
                address_topic(maker),
            ]
        } else {
            vec![
                chain_log_audit::v1_event_topic(signature),
                format!("0x{}", "33".repeat(32)),
                address_topic(maker),
                address_topic(taker),
            ]
        };
        json!({
            "address":proxy,
            "blockNumber":"0x1234",
            "blockHash":format!("0x{}", "aa".repeat(32)),
            "transactionHash":format!("0x{}", "bb".repeat(32)),
            "transactionIndex":"0x2",
            "logIndex":"0x7",
            "topics":topics,
            "data":format!("0x{}", data_words.into_iter().map(word).collect::<String>()),
            "removed":false,
        })
    }

    fn order_filled_log() -> Value {
        event_log(
            "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)",
            false,
            [
                U256::ONE,
                U256::from(1_u8) << 200,
                U256::from(1_u8) << 220,
                U256::MAX,
                U256::from(1_u8) << 180,
                U256::from(0x44_u8),
                U256::from(0x55_u8),
            ],
        )
    }

    #[test]
    fn common_source_event_preserves_full_width_fields_without_version_binding() {
        let raw = order_filled_log();
        let decoded = decode_provider_reported_fifth_event(&raw).unwrap();
        assert_eq!(decoded.chain_id, 137);
        assert_eq!(decoded.block_number, 0x1234);
        assert_eq!(decoded.block_hash, format!("0x{}", "aa".repeat(32)));
        assert_eq!(decoded.transaction_hash, format!("0x{}", "bb".repeat(32)));
        assert_eq!(decoded.transaction_index, 2);
        assert_eq!(decoded.log_index, 7);
        assert_eq!(
            decoded.source,
            FifthEventObservationSource::ProviderReported
        );
        assert_eq!(
            decoded.implementation_version,
            FifthEventImplementationVersion::Unbound
        );
        let ProviderReportedFifthEventKind::OrderFilled(fill) = decoded.event else {
            panic!("OrderFilled event shape expected");
        };
        assert_eq!(fill.order_hash, B256::repeat_byte(0x33));
        assert_eq!(fill.maker, "0x1111111111111111111111111111111111111111");
        assert_eq!(fill.taker, "0x2222222222222222222222222222222222222222");
        assert_eq!(fill.side, TradeSide::Sell);
        assert_eq!(fill.token_id, U256::from(1_u8) << 200);
        assert_eq!(fill.maker_amount_filled, U256::from(1_u8) << 220);
        assert_eq!(fill.taker_amount_filled, U256::MAX);
        assert_eq!(fill.fee_amount, U256::from(1_u8) << 180);
        assert_eq!(
            fill.builder,
            B256::new(U256::from(0x44_u8).to_be_bytes::<32>())
        );
        assert_eq!(
            fill.metadata,
            B256::new(U256::from(0x55_u8).to_be_bytes::<32>())
        );
    }

    #[test]
    fn orders_matched_remains_a_raw_unpaired_aggregate_event() {
        let raw = event_log(
            "OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)",
            true,
            [
                U256::ZERO,
                U256::from(1_u8) << 200,
                U256::MAX,
                U256::from(7_u8),
                U256::ZERO,
                U256::ZERO,
                U256::ZERO,
            ],
        );
        let decoded = decode_provider_reported_fifth_event(&raw).unwrap();
        let ProviderReportedFifthEventKind::OrdersMatched(matched) = decoded.event else {
            panic!("OrdersMatched event shape expected");
        };
        assert_eq!(matched.side, TradeSide::Buy);
        assert_eq!(matched.token_id, U256::from(1_u8) << 200);
        assert_eq!(matched.maker_amount_filled, U256::MAX);
        assert_eq!(matched.taker_amount_filled, U256::from(7_u8));
    }

    #[test]
    fn rejects_removed_wrong_emitter_topic_shape_malformed_words_and_oversize() {
        let mut removed = order_filled_log();
        removed["removed"] = Value::Bool(true);
        assert_eq!(
            decode_provider_reported_fifth_event(&removed),
            Err(Error::RemovedLog)
        );

        let mut wrong_emitter = order_filled_log();
        wrong_emitter["address"] =
            Value::String("0x1111111111111111111111111111111111111111".to_owned());
        assert_eq!(
            decode_provider_reported_fifth_event(&wrong_emitter),
            Err(Error::UnsupportedEmitter)
        );

        let mut wrong_topic = order_filled_log();
        wrong_topic["topics"][0] = Value::String(format!("0x{}", "99".repeat(32)));
        assert_eq!(
            decode_provider_reported_fifth_event(&wrong_topic),
            Err(Error::MalformedLog)
        );

        let mut wrong_indexed_address = order_filled_log();
        wrong_indexed_address["topics"][2] = Value::String(format!("0x{}", "11".repeat(32)));
        assert_eq!(
            decode_provider_reported_fifth_event(&wrong_indexed_address),
            Err(Error::MalformedLog)
        );

        let mut wrong_topic_count = order_filled_log();
        wrong_topic_count["topics"]
            .as_array_mut()
            .unwrap()
            .truncate(3);
        assert_eq!(
            decode_provider_reported_fifth_event(&wrong_topic_count),
            Err(Error::MalformedLog)
        );

        let mut wrong_fee_width = order_filled_log();
        let data = wrong_fee_width["data"].as_str().unwrap().to_owned();
        let fee_start = 2 + 4 * 64;
        let fee_end = fee_start + 64;
        wrong_fee_width["data"] = Value::String(format!(
            "{}{}{}",
            &data[..fee_start],
            &data[fee_start..fee_end - 2],
            &data[fee_end..]
        ));
        assert_eq!(
            decode_provider_reported_fifth_event(&wrong_fee_width),
            Err(Error::MalformedLog)
        );

        let mut missing_locator = order_filled_log();
        missing_locator
            .as_object_mut()
            .unwrap()
            .remove("transactionIndex");
        assert_eq!(
            decode_provider_reported_fifth_event(&missing_locator),
            Err(Error::MalformedLog)
        );

        let mut too_large = order_filled_log();
        too_large["padding"] =
            Value::String("x".repeat(FIFTH_PROVIDER_REPORTED_EVENT_LOG_MAX_BYTES));
        assert_eq!(
            decode_provider_reported_fifth_event(&too_large),
            Err(Error::MalformedLog)
        );
    }
}
