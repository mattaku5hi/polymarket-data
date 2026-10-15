//! Pure composition of current `/v2/value` observations and a same-block cash
//! snapshot. These mixed capture windows are estimates, not an atomic NAV.

use chrono::{DateTime, Utc};
use num_bigint::{BigInt, BigUint};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};

use crate::{
    collateral_cash::{CollateralAsset, CollateralCashBlock, CollateralCashSnapshot},
    economics::{EconomicsSource, PortfolioValue, V2_PORTFOLIO_VALUE_PATH},
    position_history::normalize_address,
};

const MAX_VALUE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_VALUE_NUMBER_BYTES: usize = 128;
const MAX_CANONICAL_DECIMAL_BYTES: usize = 128;

/// Output of provider-reported mark composition. It contains no completeness,
/// historical NAV, or risk-pass assertion.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentPortfolioEstimateSet {
    /// The exact provider-reported cash snapshot used by the estimates.
    pub cash_observation: CollateralCashSnapshot,
    /// The mixed RPC capture interval; it is not a portfolio `as_of` time.
    pub cash_capture_started_at: DateTime<Utc>,
    pub cash_capture_completed_at: DateTime<Utc>,
    /// The provider's same-block anchor for collateral balances only.
    pub cash_block: CollateralCashBlock,
    pub wallets: Vec<CurrentWalletEstimate>,
}

/// A one-wallet estimate retaining the whole validated cash capture. The
/// snapshot is intentionally not reduced to a fabricated wallet sub-artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentWalletEstimateWithCashEvidence {
    pub estimate: CurrentWalletEstimate,
    pub cash_observation: CollateralCashSnapshot,
    pub cash_capture_started_at: DateTime<Utc>,
    pub cash_capture_completed_at: DateTime<Utc>,
    pub cash_block: CollateralCashBlock,
}

/// One wallet's current marked-position-plus-cash estimate and original source
/// responses. The position value's API has no as-of timestamp.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentWalletEstimate {
    pub wallet: String,
    /// `None` means the provider returned explicit JSON null (unknown).
    pub positions_value_usdc: Option<Decimal>,
    pub pusd_cash_usdc: Decimal,
    pub usdce_cash_usdc: Decimal,
    pub collateral_cash_usdc: Decimal,
    /// `None` when positions value is unknown; otherwise a checked Decimal sum.
    pub combined_value_estimate_usdc: Option<Decimal>,
    /// Original raw `/v2/value` body, parameters, and HTTP timing evidence.
    pub value_observation: PortfolioValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarkCompositionError {
    #[error("cash snapshot failed offline validation")]
    InvalidCashEvidence,
    #[error("portfolio value observations do not match the cash wallet set")]
    WalletSetMismatch,
    #[error("portfolio value observation is malformed or unbound to its raw response")]
    InvalidValueEvidence,
    #[error("portfolio value is not an exact nonnegative Decimal")]
    InvalidValueAmount,
    #[error("cash or combined value is outside Decimal's exact range")]
    AmountOutOfRange,
}

/// Compose existing captures without performing requests. Cash evidence is
/// fully revalidated against its raw RPC frames via the artifact validator.
/// `/v2/value` is a separate HTTP observation with no source as-of time, so
/// the result is intentionally an estimate over mixed capture windows.
pub fn compose_current_portfolio_estimates(
    observations: Vec<PortfolioValue>,
    cash_observation: CollateralCashSnapshot,
) -> Result<CurrentPortfolioEstimateSet, MarkCompositionError> {
    let (cash_capture_started_at, cash_capture_completed_at) =
        validate_cash_observation(&cash_observation)?;

    if observations.len() != cash_observation.wallets.len() {
        return Err(MarkCompositionError::WalletSetMismatch);
    }
    let mut by_wallet = std::collections::HashMap::with_capacity(observations.len());
    for observation in observations {
        let wallet = validate_value_observation(&observation)?;
        if by_wallet.insert(wallet, observation).is_some() {
            return Err(MarkCompositionError::WalletSetMismatch);
        }
    }

    let mut wallets = Vec::with_capacity(cash_observation.wallets.len());
    for wallet in &cash_observation.wallets {
        let observation = by_wallet
            .remove(wallet)
            .ok_or(MarkCompositionError::WalletSetMismatch)?;
        wallets.push(build_wallet_estimate(
            observation,
            &cash_observation,
            wallet.clone(),
        )?);
    }
    if !by_wallet.is_empty() {
        return Err(MarkCompositionError::WalletSetMismatch);
    }

    Ok(CurrentPortfolioEstimateSet {
        cash_block: cash_observation.block.clone(),
        cash_capture_started_at,
        cash_capture_completed_at,
        cash_observation,
        wallets,
    })
}

/// Compose one selected wallet without requiring `/v2/value` observations for
/// any of the other wallets in the fully validated cash snapshot.
pub fn compose_current_wallet_estimate(
    observation: PortfolioValue,
    cash_observation: CollateralCashSnapshot,
) -> Result<CurrentWalletEstimateWithCashEvidence, MarkCompositionError> {
    let (cash_capture_started_at, cash_capture_completed_at) =
        validate_cash_observation(&cash_observation)?;
    let wallet = validate_value_observation(&observation)?;
    if !cash_observation.wallets.iter().any(|item| item == &wallet) {
        return Err(MarkCompositionError::WalletSetMismatch);
    }
    let estimate = build_wallet_estimate(observation, &cash_observation, wallet)?;
    Ok(CurrentWalletEstimateWithCashEvidence {
        cash_block: cash_observation.block.clone(),
        cash_capture_started_at,
        cash_capture_completed_at,
        cash_observation,
        estimate,
    })
}

fn validate_cash_observation(
    cash_observation: &CollateralCashSnapshot,
) -> Result<(DateTime<Utc>, DateTime<Utc>), MarkCompositionError> {
    cash_observation
        .to_artifact()
        .map_err(|_| MarkCompositionError::InvalidCashEvidence)?;
    let first = cash_observation
        .requests
        .first()
        .ok_or(MarkCompositionError::InvalidCashEvidence)?;
    let last = cash_observation
        .requests
        .last()
        .ok_or(MarkCompositionError::InvalidCashEvidence)?;
    Ok((*first.started_at(), *last.completed_at()))
}

fn build_wallet_estimate(
    observation: PortfolioValue,
    cash_observation: &CollateralCashSnapshot,
    wallet: String,
) -> Result<CurrentWalletEstimate, MarkCompositionError> {
    let positions_value_usdc = parse_position_value(&observation)?;
    let (pusd_cash_usdc, usdce_cash_usdc) = wallet_cash(cash_observation, &wallet)?;
    let collateral_cash_usdc = checked_exact_add(pusd_cash_usdc, usdce_cash_usdc)
        .ok_or(MarkCompositionError::AmountOutOfRange)?;
    let combined_value_estimate_usdc = positions_value_usdc
        .map(|positions| {
            checked_exact_add(positions, collateral_cash_usdc)
                .ok_or(MarkCompositionError::AmountOutOfRange)
        })
        .transpose()?;
    Ok(CurrentWalletEstimate {
        wallet,
        positions_value_usdc,
        pusd_cash_usdc,
        usdce_cash_usdc,
        collateral_cash_usdc,
        combined_value_estimate_usdc,
        value_observation: observation,
    })
}

fn validate_value_observation(
    observation: &PortfolioValue,
) -> Result<String, MarkCompositionError> {
    let evidence = &observation.evidence;
    if evidence.source != EconomicsSource::VenueReported
        || evidence.route_path != V2_PORTFOLIO_VALUE_PATH
        || evidence.request_started_at > evidence.retrieved_at
        || evidence.raw_body.len() > MAX_VALUE_BODY_BYTES
        || evidence.request_params.len() != 1
        || evidence.request_params[0].0 != "user"
    {
        return Err(MarkCompositionError::InvalidValueEvidence);
    }
    let requested_wallet = normalize_address(&evidence.request_params[0].1)
        .ok_or(MarkCompositionError::InvalidValueEvidence)?;
    let projected_wallet = normalize_address(&observation.proxy_wallet)
        .ok_or(MarkCompositionError::InvalidValueEvidence)?;
    if requested_wallet != projected_wallet {
        return Err(MarkCompositionError::InvalidValueEvidence);
    }

    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        data: &'a RawValue,
    }
    #[derive(Deserialize)]
    struct RawData<'a> {
        proxy_wallet: &'a str,
        #[serde(borrow)]
        value: &'a RawValue,
    }
    let envelope: Envelope<'_> = serde_json::from_slice(&evidence.raw_body)
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    let raw_data: RawData<'_> = serde_json::from_str(envelope.data.get())
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    let raw_wallet = normalize_address(raw_data.proxy_wallet)
        .ok_or(MarkCompositionError::InvalidValueEvidence)?;
    if raw_wallet != requested_wallet {
        return Err(MarkCompositionError::InvalidValueEvidence);
    }
    let projected_data: Value = serde_json::from_str(envelope.data.get())
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    let projected_value: Value = serde_json::from_str(raw_data.value.get())
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    if projected_data != observation.raw_data || projected_value != observation.value {
        return Err(MarkCompositionError::InvalidValueEvidence);
    }
    Ok(requested_wallet)
}

fn parse_position_value(
    observation: &PortfolioValue,
) -> Result<Option<Decimal>, MarkCompositionError> {
    if observation.value.is_null() {
        return Ok(None);
    }
    let envelope: RawEnvelope<'_> = serde_json::from_slice(&observation.evidence.raw_body)
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    let raw_data: RawDataValue<'_> = serde_json::from_str(envelope.data.get())
        .map_err(|_| MarkCompositionError::InvalidValueEvidence)?;
    let lexeme = raw_data.value.get();
    let decimal = exact_json_decimal(lexeme).ok_or(MarkCompositionError::InvalidValueAmount)?;
    if decimal.is_sign_negative() {
        return Err(MarkCompositionError::InvalidValueAmount);
    }
    Ok(Some(decimal))
}

#[derive(Deserialize)]
struct RawEnvelope<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
}

#[derive(Deserialize)]
struct RawDataValue<'a> {
    #[serde(borrow)]
    value: &'a RawValue,
}

fn wallet_cash(
    snapshot: &CollateralCashSnapshot,
    wallet: &str,
) -> Result<(Decimal, Decimal), MarkCompositionError> {
    let mut pusd = None;
    let mut usdce = None;
    for balance in snapshot
        .balances
        .iter()
        .filter(|balance| balance.wallet == wallet)
    {
        if balance.decimals != CollateralAsset::Pusd.decimals() {
            return Err(MarkCompositionError::InvalidCashEvidence);
        }
        let amount = uint256_six_decimals(&balance.balance_word)?;
        let slot = match balance.asset {
            CollateralAsset::Pusd => &mut pusd,
            CollateralAsset::UsdcE => &mut usdce,
        };
        if slot.replace(amount).is_some() {
            return Err(MarkCompositionError::InvalidCashEvidence);
        }
    }
    Ok((
        pusd.ok_or(MarkCompositionError::InvalidCashEvidence)?,
        usdce.ok_or(MarkCompositionError::InvalidCashEvidence)?,
    ))
}

fn checked_exact_add(left: Decimal, right: Decimal) -> Option<Decimal> {
    let result = left.checked_add(right)?;
    let scale = left.scale().max(right.scale()).max(result.scale());
    let exact = decimal_at_scale(left, scale) + decimal_at_scale(right, scale);
    (decimal_at_scale(result, scale) == exact).then_some(result)
}

fn decimal_at_scale(value: Decimal, scale: u32) -> BigInt {
    BigInt::from(value.mantissa()) * BigInt::from(10_u8).pow(scale - value.scale())
}

fn uint256_six_decimals(word: &[u8; 32]) -> Result<Decimal, MarkCompositionError> {
    let digits = BigUint::from_bytes_be(word).to_str_radix(10);
    let mut lexeme = if digits.len() <= 6 {
        format!("0.{:0>6}", digits)
    } else {
        let point = digits.len() - 6;
        format!("{}.{}", &digits[..point], &digits[point..])
    };
    while lexeme.ends_with('0') {
        lexeme.pop();
    }
    if lexeme.ends_with('.') {
        lexeme.pop();
    }
    Decimal::from_str_exact(&lexeme).map_err(|_| MarkCompositionError::AmountOutOfRange)
}

fn exact_json_decimal(raw: &str) -> Option<Decimal> {
    if raw.len() > MAX_VALUE_NUMBER_BYTES {
        return None;
    }
    let (mantissa, exponent) = match raw.bytes().position(|byte| byte == b'e' || byte == b'E') {
        Some(index) => {
            if raw[index + 1..]
                .bytes()
                .any(|byte| byte == b'e' || byte == b'E')
            {
                return None;
            }
            let exponent = raw[index + 1..].parse::<i32>().ok()?;
            (&raw[..index], exponent)
        }
        None => (raw, 0),
    };
    let negative = mantissa.starts_with('-');
    let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let mut split = unsigned.split('.');
    let integer = split.next()?;
    let fraction = split.next().unwrap_or("");
    if split.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = format!("{integer}{fraction}");
    let scale = i32::try_from(fraction.len()).ok()?.checked_sub(exponent)?;
    let mut rendered = if scale <= 0 {
        let zeros = usize::try_from(scale.checked_neg()?).ok()?;
        if digits.len().checked_add(zeros)? > MAX_CANONICAL_DECIMAL_BYTES {
            return None;
        }
        digits.push_str(&"0".repeat(zeros));
        digits
    } else {
        let scale = usize::try_from(scale).ok()?;
        if scale >= digits.len() {
            let zero_count = scale - digits.len();
            if zero_count + 2 + digits.len() > MAX_CANONICAL_DECIMAL_BYTES {
                return None;
            }
            format!("0.{}{digits}", "0".repeat(zero_count))
        } else {
            let point = digits.len() - scale;
            format!("{}.{}", &digits[..point], &digits[point..])
        }
    };
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    if negative
        && rendered
            .bytes()
            .any(|byte| byte.is_ascii_digit() && byte != b'0')
    {
        rendered.insert(0, '-');
    }
    Decimal::from_str_exact(&rendered).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    use crate::{
        collateral_cash::{
            CollateralBalance, CollateralCashBlock, CollateralCashSource, CollateralRpcEvidence,
            POLYGON_CHAIN_ID, PUSD_ADDRESS, USDCE_ADDRESS, encode_rpc_request,
        },
        economics::ResponseEvidence,
    };

    const WALLET: &str = "0x1111111111111111111111111111111111111111";

    fn time(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(second, 0).single().unwrap()
    }

    fn word(value: u64) -> [u8; 32] {
        let mut output = [0; 32];
        output[24..].copy_from_slice(&value.to_be_bytes());
        output
    }

    fn response(id: u64, result: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":id, "result":result})).unwrap()
    }

    fn request(id: u64, method: &str, params: Value, result: Value) -> CollateralRpcEvidence {
        CollateralRpcEvidence {
            method: method.to_owned(),
            request_id: id,
            started_at: time(100 + id as i64),
            completed_at: time(100 + id as i64),
            request_body: encode_rpc_request(id, method, &params).unwrap(),
            response_body: response(id, result),
        }
    }

    fn block_result() -> Value {
        json!({
            "number":"0x14",
            "hash":format!("0x{}", "ab".repeat(32)),
            "timestamp":"0x64"
        })
    }

    fn cash_snapshot(pusd: u64, usdce: u64) -> CollateralCashSnapshot {
        cash_snapshot_for(&[(WALLET, pusd, usdce)])
    }

    fn cash_snapshot_for(entries: &[(&str, u64, u64)]) -> CollateralCashSnapshot {
        let block_tag = "0x14";
        let mut requests = vec![
            request(1, "eth_chainId", json!([]), json!("0x89")),
            request(
                2,
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                block_result(),
            ),
            request(
                3,
                "eth_call",
                json!([{"to":PUSD_ADDRESS,"data":"0x313ce567"},block_tag]),
                json!(format!("0x{}06", "00".repeat(31))),
            ),
            request(
                4,
                "eth_call",
                json!([{"to":USDCE_ADDRESS,"data":"0x313ce567"},block_tag]),
                json!(format!("0x{}06", "00".repeat(31))),
            ),
        ];
        let mut balances = Vec::with_capacity(2 * entries.len());
        for (wallet, pusd, usdce) in entries {
            for (asset, token, amount) in [
                (CollateralAsset::Pusd, PUSD_ADDRESS, *pusd),
                (CollateralAsset::UsdcE, USDCE_ADDRESS, *usdce),
            ] {
                let request_id = requests.len() as u64 + 1;
                requests.push(request(
                    request_id,
                    "eth_call",
                    json!([{
                        "to":token,
                        "data":format!("0x70a08231{}", "0".repeat(24) + &wallet[2..])
                    },block_tag]),
                    json!(format!("0x{}", hex_word(amount))),
                ));
                balances.push(CollateralBalance {
                    wallet: (*wallet).to_owned(),
                    asset,
                    balance_word: word(amount),
                    decimals: 6,
                });
            }
        }
        let final_header_id = requests.len() as u64 + 1;
        requests.push(request(
            final_header_id,
            "eth_getBlockByNumber",
            json!([block_tag, false]),
            block_result(),
        ));
        let final_request = requests.last_mut().unwrap();
        final_request.completed_at = time(101 + final_header_id as i64);
        CollateralCashSnapshot {
            source: CollateralCashSource::ProviderReported,
            block: CollateralCashBlock {
                chain_id: POLYGON_CHAIN_ID,
                number: 20,
                hash: format!("0x{}", "ab".repeat(32)),
                timestamp: 100,
            },
            wallets: entries
                .iter()
                .map(|(wallet, _, _)| (*wallet).to_owned())
                .collect(),
            balances,
            requests,
        }
    }

    fn hex_word(value: u64) -> String {
        format!("{}{:016x}", "0".repeat(48), value)
    }

    fn value_observation(wallet: &str, value_raw: &str) -> PortfolioValue {
        let raw_body = format!(
            r#"{{"data":{{"proxy_wallet":"{wallet}","value":{value_raw},"future_field":"kept"}}}}"#
        )
        .into_bytes();
        let raw_data: Value = serde_json::from_slice::<Value>(&raw_body).unwrap()["data"].clone();
        PortfolioValue {
            evidence: ResponseEvidence {
                source: EconomicsSource::VenueReported,
                route_path: V2_PORTFOLIO_VALUE_PATH.to_owned(),
                request_started_at: time(90),
                retrieved_at: time(95),
                response_age: None,
                response_date: None,
                cache_control: None,
                request_params: vec![("user".to_owned(), wallet.to_owned())],
                raw_body,
            },
            proxy_wallet: wallet.to_owned(),
            value: raw_data["value"].clone(),
            raw_data,
        }
    }

    #[test]
    fn composes_exact_values_and_keeps_mixed_capture_evidence() {
        let cash = cash_snapshot(1_234_567, 2_000_000);
        let original_value = value_observation(WALLET, "123.4500");
        let estimate =
            compose_current_portfolio_estimates(vec![original_value.clone()], cash.clone())
                .unwrap();
        let wallet = &estimate.wallets[0];
        assert_eq!(
            wallet.positions_value_usdc,
            Some(Decimal::from_str_exact("123.45").unwrap())
        );
        assert_eq!(
            wallet.pusd_cash_usdc,
            Decimal::from_str_exact("1.234567").unwrap()
        );
        assert_eq!(wallet.usdce_cash_usdc, Decimal::from(2));
        assert_eq!(
            wallet.combined_value_estimate_usdc,
            Some(Decimal::from_str_exact("126.684567").unwrap())
        );
        assert_eq!(wallet.value_observation, original_value);
        assert_eq!(estimate.cash_block, cash.block);
        assert_eq!(estimate.cash_capture_started_at, time(101));
        assert_eq!(estimate.cash_capture_completed_at, time(108));
        assert_eq!(
            estimate.wallets[0].value_observation.evidence.raw_body,
            original_value.evidence.raw_body
        );
    }

    #[test]
    fn single_wallet_composition_retains_whole_validated_cash_capture() {
        let cash = cash_snapshot(1_000_000, 2_000_000);
        let result =
            compose_current_wallet_estimate(value_observation(WALLET, "8.5"), cash.clone())
                .unwrap();
        assert_eq!(result.estimate.wallet, WALLET);
        assert_eq!(
            result.estimate.combined_value_estimate_usdc,
            Some(Decimal::from_str_exact("11.5").unwrap())
        );
        assert_eq!(result.cash_observation, cash);
        assert_eq!(result.cash_observation.requests.len(), 7);
        assert_eq!(result.cash_capture_started_at, time(101));
        assert_eq!(result.cash_capture_completed_at, time(108));
        assert_eq!(result.cash_block.number, 20);
    }

    #[test]
    fn single_wallet_path_does_not_require_other_value_rows() {
        let other_wallet = "0x2222222222222222222222222222222222222222";
        let cash = cash_snapshot_for(&[(WALLET, 1_000_000, 0), (other_wallet, 0, 2_000_000)]);
        let result = compose_current_wallet_estimate(value_observation(WALLET, "5"), cash).unwrap();
        assert_eq!(result.estimate.wallet, WALLET);
        assert_eq!(
            result.estimate.combined_value_estimate_usdc,
            Some(Decimal::from(6))
        );
        assert_eq!(result.cash_observation.wallets.len(), 2);
        assert_eq!(result.cash_observation.requests.len(), 9);
    }

    #[test]
    fn explicit_null_keeps_combined_estimate_unknown_but_retains_cash() {
        let estimate = compose_current_portfolio_estimates(
            vec![value_observation(WALLET, "null")],
            cash_snapshot(1_000_000, 2_000_000),
        )
        .unwrap();
        assert_eq!(estimate.wallets[0].positions_value_usdc, None);
        assert_eq!(estimate.wallets[0].combined_value_estimate_usdc, None);
        assert_eq!(estimate.wallets[0].collateral_cash_usdc, Decimal::from(3));
    }

    #[test]
    fn rejects_identity_projection_and_unrepresentable_amount_mismatches() {
        let cash = cash_snapshot(0, 0);
        let mut wrong_identity = value_observation(WALLET, "1");
        wrong_identity.proxy_wallet = "0x2222222222222222222222222222222222222222".to_owned();
        assert_eq!(
            compose_current_portfolio_estimates(vec![wrong_identity], cash.clone()).unwrap_err(),
            MarkCompositionError::InvalidValueEvidence
        );
        let mut wrong_projection = value_observation(WALLET, "1");
        wrong_projection.raw_data["future_field"] = json!("changed");
        assert_eq!(
            compose_current_portfolio_estimates(vec![wrong_projection], cash.clone()).unwrap_err(),
            MarkCompositionError::InvalidValueEvidence
        );
        assert_eq!(
            compose_current_portfolio_estimates(vec![value_observation(WALLET, "1e100")], cash)
                .unwrap_err(),
            MarkCompositionError::InvalidValueAmount
        );
    }

    #[test]
    fn rejects_missing_value_and_raw_response_wallet_mismatch() {
        let other_wallet = "0x2222222222222222222222222222222222222222";
        let mut missing_value = value_observation(WALLET, "1");
        missing_value.evidence.raw_body =
            format!(r#"{{"data":{{"proxy_wallet":"{WALLET}","future_field":"kept"}}}}"#)
                .into_bytes();
        assert_eq!(
            compose_current_wallet_estimate(missing_value, cash_snapshot(0, 0)).unwrap_err(),
            MarkCompositionError::InvalidValueEvidence
        );

        let mut raw_identity_mismatch = value_observation(WALLET, "1");
        raw_identity_mismatch.evidence.raw_body = format!(
            r#"{{"data":{{"proxy_wallet":"{other_wallet}","value":1,"future_field":"kept"}}}}"#
        )
        .into_bytes();
        assert_eq!(
            compose_current_wallet_estimate(raw_identity_mismatch, cash_snapshot(0, 0))
                .unwrap_err(),
            MarkCompositionError::InvalidValueEvidence
        );
    }

    #[test]
    fn rejects_wrong_wallet_set_and_unrepresentable_uint256_cash() {
        let wrong_wallet = "0x2222222222222222222222222222222222222222";
        assert_eq!(
            compose_current_portfolio_estimates(
                vec![value_observation(wrong_wallet, "1")],
                cash_snapshot(0, 0)
            )
            .unwrap_err(),
            MarkCompositionError::WalletSetMismatch
        );
        assert_eq!(
            uint256_six_decimals(&[0xff; 32]),
            Err(MarkCompositionError::AmountOutOfRange)
        );
        let mut large_trailing_zero_word = [0; 32];
        let raw_units = BigUint::from(10_u8).pow(30).to_bytes_be();
        large_trailing_zero_word[32 - raw_units.len()..].copy_from_slice(&raw_units);
        assert_eq!(
            uint256_six_decimals(&large_trailing_zero_word),
            Ok(Decimal::from_str_exact("1000000000000000000000000").unwrap())
        );
        assert_eq!(
            checked_exact_add(
                Decimal::from_str_exact("10000000000000000000000000000").unwrap(),
                Decimal::new(1, 6),
            ),
            None
        );
        assert_eq!(
            checked_exact_add(
                Decimal::from_str_exact("1000000000000000000000000").unwrap(),
                Decimal::from(1),
            ),
            Some(Decimal::from_str_exact("1000000000000000000000001").unwrap())
        );
        let duplicate = value_observation(WALLET, "1");
        assert_eq!(
            compose_current_portfolio_estimates(
                vec![duplicate.clone(), duplicate],
                cash_snapshot(0, 0),
            )
            .unwrap_err(),
            MarkCompositionError::WalletSetMismatch
        );
    }

    #[test]
    fn decimal_lexeme_conversion_is_exact_and_bounded() {
        assert_eq!(exact_json_decimal("1.2300e2"), Some(Decimal::from(123)));
        assert_eq!(exact_json_decimal("1e-6"), Some(Decimal::new(1, 6)));
        assert_eq!(exact_json_decimal("1e100"), None);
        assert_eq!(exact_json_decimal(&format!("1e{}", "9".repeat(120))), None);
    }
}
