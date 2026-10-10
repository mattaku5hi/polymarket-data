//! Read-only, full-depth pre-trade estimates from a sealed execution context.
//!
//! Positive fees use the supported market API fee-curve shape at each merged displayed
//! price level and round upward to five decimal places with integer-rational
//! arithmetic. The result is a modeled estimate, not the exchange's ex-post
//! match fee or a settlement guarantee.

use std::collections::BTreeMap;
use std::time::Duration;

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{BookLevel, execution_context::ExecutionContextObservation};

const FEE_DECIMAL_PLACES: u32 = 5;
const MAX_SUPPORTED_EXPONENT: u32 = 8;
const BUY_SHARE_DECIMAL_PLACES: u32 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteSide {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteAmountKind {
    BuyGrossNotional,
    BuyAllInCash,
    SellShares,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteRole {
    Taker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteBuilderPolicy {
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteFeeKind {
    /// The explicit market fee-disabled profile was verified.
    ExactZero,
    /// A fee curve was evaluated under the documented local estimate policy.
    ModeledEstimate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionQuoteFeeCurrency {
    /// CLOB cash notation, without a collateral token or address binding.
    ClobUsdNotional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionQuoteError {
    #[error("execution quote input is invalid")]
    InvalidInput,
    #[error("execution context is expired under the requested local age")]
    Expired,
    #[error("market fee metadata is missing, contradictory, or unsupported")]
    UnsupportedFeeMetadata,
    #[error("requested size exceeds displayed book depth")]
    InsufficientDepth,
    #[error("quote arithmetic overflowed supported decimal precision")]
    ArithmeticOverflow,
    #[error("BUY budget is below the supported share quantity precision")]
    BuyQuantityPrecision,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionQuote {
    side: ExecutionQuoteSide,
    amount_kind: ExecutionQuoteAmountKind,
    requested_amount: Decimal,
    gross_shares: Decimal,
    gross_notional: Decimal,
    unspent_buy_budget: Option<Decimal>,
    vwap: Decimal,
    estimated_platform_fee: Decimal,
    fee_rate: Decimal,
    fee_exponent: u32,
    fee_kind: ExecutionQuoteFeeKind,
    fee_currency: ExecutionQuoteFeeCurrency,
    total_buy_cash: Option<Decimal>,
    net_sell_proceeds: Option<Decimal>,
    api_condition_id: String,
    selected_asset_id: String,
    selected_outcome_index: usize,
    protocol_version: super::execution_context::ObservedMarketVersion,
    book_hash: String,
    vendor_timestamp: String,
    observed_at: chrono::DateTime<chrono::Utc>,
    available_at: chrono::DateTime<chrono::Utc>,
    valid_until: tokio::time::Instant,
    request_count: usize,
}

impl ExecutionQuote {
    #[must_use]
    pub const fn side(&self) -> ExecutionQuoteSide {
        self.side
    }
    #[must_use]
    pub const fn amount_kind(&self) -> ExecutionQuoteAmountKind {
        self.amount_kind
    }
    #[must_use]
    pub const fn requested_amount(&self) -> Decimal {
        self.requested_amount
    }
    #[must_use]
    pub const fn gross_shares(&self) -> Decimal {
        self.gross_shares
    }
    #[must_use]
    pub const fn gross_notional(&self) -> Decimal {
        self.gross_notional
    }
    #[must_use]
    pub const fn unspent_buy_budget(&self) -> Option<Decimal> {
        self.unspent_buy_budget
    }
    #[must_use]
    pub const fn vwap(&self) -> Decimal {
        self.vwap
    }
    #[must_use]
    pub const fn estimated_platform_fee(&self) -> Decimal {
        self.estimated_platform_fee
    }
    #[must_use]
    pub const fn fee_rate(&self) -> Decimal {
        self.fee_rate
    }
    #[must_use]
    pub const fn fee_exponent(&self) -> u32 {
        self.fee_exponent
    }
    #[must_use]
    pub const fn fee_kind(&self) -> ExecutionQuoteFeeKind {
        self.fee_kind
    }
    #[must_use]
    pub const fn fee_currency(&self) -> ExecutionQuoteFeeCurrency {
        self.fee_currency
    }
    #[must_use]
    pub const fn total_buy_cash(&self) -> Option<Decimal> {
        self.total_buy_cash
    }
    #[must_use]
    pub const fn net_sell_proceeds(&self) -> Option<Decimal> {
        self.net_sell_proceeds
    }
    #[must_use]
    pub fn api_condition_id(&self) -> &str {
        &self.api_condition_id
    }
    #[must_use]
    pub fn selected_asset_id(&self) -> &str {
        &self.selected_asset_id
    }
    #[must_use]
    pub const fn selected_outcome_index(&self) -> usize {
        self.selected_outcome_index
    }
    #[must_use]
    pub const fn protocol_version(&self) -> super::execution_context::ObservedMarketVersion {
        self.protocol_version
    }
    #[must_use]
    pub fn book_hash(&self) -> &str {
        &self.book_hash
    }
    #[must_use]
    pub fn vendor_timestamp(&self) -> &str {
        &self.vendor_timestamp
    }
    #[must_use]
    pub const fn observed_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.observed_at
    }
    #[must_use]
    pub const fn available_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.available_at
    }
    #[must_use]
    pub const fn valid_until(&self) -> tokio::time::Instant {
        self.valid_until
    }
    pub fn check_validity(&self) -> Result<(), ExecutionQuoteError> {
        if tokio::time::Instant::now() >= self.valid_until {
            return Err(ExecutionQuoteError::Expired);
        }
        Ok(())
    }
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.request_count
    }
    /// This API always models the explicitly selected taker role.
    #[must_use]
    pub const fn role(&self) -> ExecutionQuoteRole {
        ExecutionQuoteRole::Taker
    }
    /// Builder fees are excluded by this supported estimate model.
    #[must_use]
    pub const fn builder_policy(&self) -> ExecutionQuoteBuilderPolicy {
        ExecutionQuoteBuilderPolicy::Disabled
    }
    #[must_use]
    pub const fn fee_model_version(&self) -> &'static str {
        "clob-api-fee-curve-price-level-ceil-5dp-estimate/1"
    }
    #[must_use]
    pub const fn fee_rounding_policy(&self) -> &'static str {
        "ceil-per-consumed-price-level-to-5-decimals"
    }
    #[must_use]
    pub const fn fee_aggregation_policy(&self) -> &'static str {
        "sum-rounded-displayed-price-level-estimates"
    }
}

/// Calculate a full-depth BUY by gross notional or SELL by share quantity.
///
/// `max_age` is local acquisition age only and is anchored to the sealed
/// context's original start. BUY amount is the requested gross book notional;
/// SELL amount is requested shares, which must be fully covered. BUY share
/// quantity is floored to 18 decimal places to cap gross spend; book depth must
/// cover the budget except for the explicitly returned quantity-rounding dust.
///
/// # Errors
/// Returns an error for expired contexts, unsupported fee metadata, incomplete
/// depth, nonpositive sizes, or checked arithmetic failure.
pub fn estimate_execution_quote(
    context: &ExecutionContextObservation,
    side: ExecutionQuoteSide,
    amount: Decimal,
    max_age: Duration,
) -> Result<ExecutionQuote, ExecutionQuoteError> {
    if amount <= Decimal::ZERO {
        return Err(ExecutionQuoteError::InvalidInput);
    }
    let valid_until = context
        .local_valid_until(max_age)
        .map_err(|error| match error {
            super::execution_context::ExecutionContextValidityError::Expired => {
                ExecutionQuoteError::Expired
            }
            super::execution_context::ExecutionContextValidityError::InvalidMaxAge => {
                ExecutionQuoteError::InvalidInput
            }
        })?;
    let fee_profile = fee_profile(context)?;
    let levels = match side {
        ExecutionQuoteSide::Buy => &context.book().asks,
        ExecutionQuoteSide::Sell => &context.book().bids,
    };
    let (gross_shares, gross_notional, estimated_platform_fee, unspent_buy_budget) =
        walk(levels, side, amount, fee_profile)?;
    if estimated_platform_fee > gross_notional {
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    }
    let vwap = gross_notional
        .checked_div(gross_shares)
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    let total_buy_cash = if side == ExecutionQuoteSide::Buy {
        Some(checked_add_exact(gross_notional, estimated_platform_fee)?)
    } else {
        None
    };
    let net_sell_proceeds = if side == ExecutionQuoteSide::Sell {
        Some(checked_sub_exact(gross_notional, estimated_platform_fee)?)
    } else {
        None
    };
    context
        .local_valid_until(max_age)
        .map_err(|error| match error {
            super::execution_context::ExecutionContextValidityError::Expired => {
                ExecutionQuoteError::Expired
            }
            super::execution_context::ExecutionContextValidityError::InvalidMaxAge => {
                ExecutionQuoteError::InvalidInput
            }
        })?;
    Ok(ExecutionQuote {
        side,
        amount_kind: match side {
            ExecutionQuoteSide::Buy => ExecutionQuoteAmountKind::BuyGrossNotional,
            ExecutionQuoteSide::Sell => ExecutionQuoteAmountKind::SellShares,
        },
        requested_amount: amount,
        gross_shares,
        gross_notional,
        unspent_buy_budget,
        vwap,
        estimated_platform_fee,
        fee_rate: fee_profile.rate,
        fee_exponent: fee_profile.exponent,
        fee_kind: if fee_profile.rate.is_zero() {
            ExecutionQuoteFeeKind::ExactZero
        } else {
            ExecutionQuoteFeeKind::ModeledEstimate
        },
        fee_currency: ExecutionQuoteFeeCurrency::ClobUsdNotional,
        total_buy_cash,
        net_sell_proceeds,
        api_condition_id: context.api_condition_id().to_owned(),
        selected_asset_id: context.selected_asset_id().to_owned(),
        selected_outcome_index: context.selected_outcome_index(),
        protocol_version: context.protocol_version(),
        book_hash: context.book().hash.clone(),
        vendor_timestamp: context.book().timestamp.clone(),
        observed_at: context.started_at(),
        available_at: context.completed_at(),
        valid_until,
        request_count: context.request_count(),
    })
}

/// Calculate the maximum BUY shares supported by a total cash budget.
///
/// This is a modeled estimate over the displayed asks. Fees use the same
/// ceil-to-five-decimal-per-merged-price-level policy as
/// [`estimate_execution_quote`]. The budget includes modeled fees, and any
/// remaining amount is returned as unspent precision dust. This does not bind
/// settlement collateral or guarantee execution or settlement.
///
/// # Errors
/// Returns an error for expired contexts, unsupported fee metadata, incomplete
/// displayed depth, nonpositive budgets, budgets below share precision, or
/// checked arithmetic failure.
pub fn estimate_all_in_buy_execution_quote(
    context: &ExecutionContextObservation,
    max_cash_budget: Decimal,
    max_age: Duration,
) -> Result<ExecutionQuote, ExecutionQuoteError> {
    if max_cash_budget <= Decimal::ZERO {
        return Err(ExecutionQuoteError::InvalidInput);
    }
    let valid_until = context
        .local_valid_until(max_age)
        .map_err(|error| match error {
            super::execution_context::ExecutionContextValidityError::Expired => {
                ExecutionQuoteError::Expired
            }
            super::execution_context::ExecutionContextValidityError::InvalidMaxAge => {
                ExecutionQuoteError::InvalidInput
            }
        })?;
    let fee_profile = fee_profile(context)?;
    let (gross_shares, gross_notional, estimated_platform_fee, unspent_buy_budget) =
        walk_all_in_buy(&context.book().asks, max_cash_budget, fee_profile)?;
    let total_buy_cash = checked_add_exact(gross_notional, estimated_platform_fee)?;
    if total_buy_cash > max_cash_budget {
        return Err(ExecutionQuoteError::ArithmeticOverflow);
    }
    let vwap = gross_notional
        .checked_div(gross_shares)
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    context
        .local_valid_until(max_age)
        .map_err(|error| match error {
            super::execution_context::ExecutionContextValidityError::Expired => {
                ExecutionQuoteError::Expired
            }
            super::execution_context::ExecutionContextValidityError::InvalidMaxAge => {
                ExecutionQuoteError::InvalidInput
            }
        })?;
    Ok(ExecutionQuote {
        side: ExecutionQuoteSide::Buy,
        amount_kind: ExecutionQuoteAmountKind::BuyAllInCash,
        requested_amount: max_cash_budget,
        gross_shares,
        gross_notional,
        unspent_buy_budget: Some(unspent_buy_budget),
        vwap,
        estimated_platform_fee,
        fee_rate: fee_profile.rate,
        fee_exponent: fee_profile.exponent,
        fee_kind: if fee_profile.rate.is_zero() {
            ExecutionQuoteFeeKind::ExactZero
        } else {
            ExecutionQuoteFeeKind::ModeledEstimate
        },
        fee_currency: ExecutionQuoteFeeCurrency::ClobUsdNotional,
        total_buy_cash: Some(total_buy_cash),
        net_sell_proceeds: None,
        api_condition_id: context.api_condition_id().to_owned(),
        selected_asset_id: context.selected_asset_id().to_owned(),
        selected_outcome_index: context.selected_outcome_index(),
        protocol_version: context.protocol_version(),
        book_hash: context.book().hash.clone(),
        vendor_timestamp: context.book().timestamp.clone(),
        observed_at: context.started_at(),
        available_at: context.completed_at(),
        valid_until,
        request_count: context.request_count(),
    })
}

#[derive(Clone, Copy)]
struct FeeProfile {
    rate: Decimal,
    exponent: u32,
}

fn fee_profile(context: &ExecutionContextObservation) -> Result<FeeProfile, ExecutionQuoteError> {
    let gamma: Vec<GammaFeeMarket<'_>> = serde_json::from_str(context.gamma_raw_body())
        .map_err(|_| ExecutionQuoteError::UnsupportedFeeMetadata)?;
    let [gamma] = gamma.as_slice() else {
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    };
    let enabled = gamma
        .fees_enabled
        .ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)?;
    let schedule = parse_gamma_fee_fields(gamma.fee_schedule)?;
    let clob: ClobFeeMarket<'_> = serde_json::from_str(context.clob_market_raw_body())
        .map_err(|_| ExecutionQuoteError::UnsupportedFeeMetadata)?;
    let fd = parse_clob_fee_fields(clob.fd)?;
    if !enabled {
        let gamma_zero = schedule.is_none_or(GammaFeeFields::is_explicit_zero);
        let clob_zero = fd.is_none_or(ClobFeeFields::is_explicit_zero);
        let gamma_taker = schedule
            .and_then(|fields| fields.taker_only)
            .and_then(raw_bool);
        let clob_taker = fd.and_then(|fields| fields.taker_only).and_then(raw_bool);
        let taker_consistent = gamma_taker.zip(clob_taker).is_none_or(|(g, c)| g == c);
        if gamma_zero && clob_zero && taker_consistent {
            return Ok(FeeProfile {
                rate: Decimal::ZERO,
                exponent: 0,
            });
        }
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    }
    let gamma = schedule.ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)?;
    let clob = fd.ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)?;
    let gamma_rate = decimal_value(gamma.rate)?;
    let gamma_exp = exponent_value(gamma.exponent)?;
    let gamma_taker = bool_value(gamma.taker_only)?;
    let clob_rate = decimal_value(clob.rate)?;
    let clob_exp = exponent_value(clob.exponent)?;
    let clob_taker = bool_value(clob.taker_only)?;
    if gamma_rate <= Decimal::ZERO
        || gamma_rate > Decimal::ONE
        || gamma_exp > MAX_SUPPORTED_EXPONENT
        || gamma_rate != clob_rate
        || gamma_exp != clob_exp
        || gamma_taker != clob_taker
    {
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    }
    Ok(FeeProfile {
        rate: gamma_rate,
        exponent: gamma_exp,
    })
}

#[derive(Clone, Copy, Deserialize)]
struct GammaFeeMarket<'a> {
    #[serde(rename = "feesEnabled")]
    fees_enabled: Option<bool>,
    #[serde(borrow, rename = "feeSchedule")]
    fee_schedule: Option<&'a RawValue>,
}

#[derive(Clone, Copy, Deserialize)]
struct ClobFeeMarket<'a> {
    #[serde(borrow)]
    fd: Option<&'a RawValue>,
}

#[derive(Clone, Copy, Deserialize)]
struct GammaFeeFields<'a> {
    #[serde(borrow)]
    rate: Option<&'a RawValue>,
    #[serde(borrow)]
    exponent: Option<&'a RawValue>,
    #[serde(borrow, rename = "takerOnly")]
    taker_only: Option<&'a RawValue>,
}

impl GammaFeeFields<'_> {
    fn is_explicit_zero(self) -> bool {
        zero_rate(self.rate)
            && self.exponent.is_some_and(valid_exponent)
            && self.taker_only.is_none_or(valid_bool)
    }
}

#[derive(Clone, Copy, Deserialize)]
struct ClobFeeFields<'a> {
    #[serde(borrow, rename = "r")]
    rate: Option<&'a RawValue>,
    #[serde(borrow, rename = "e")]
    exponent: Option<&'a RawValue>,
    #[serde(borrow, rename = "to")]
    taker_only: Option<&'a RawValue>,
}

impl ClobFeeFields<'_> {
    fn is_explicit_zero(self) -> bool {
        zero_rate(self.rate)
            && self.exponent.is_some_and(valid_exponent)
            && self.taker_only.is_none_or(valid_bool)
    }
}

fn parse_gamma_fee_fields<'a>(
    raw: Option<&'a RawValue>,
) -> Result<Option<GammaFeeFields<'a>>, ExecutionQuoteError> {
    raw.filter(|value| value.get() != "null")
        .map(|value| {
            serde_json::from_str(value.get())
                .map_err(|_| ExecutionQuoteError::UnsupportedFeeMetadata)
        })
        .transpose()
}

fn parse_clob_fee_fields<'a>(
    raw: Option<&'a RawValue>,
) -> Result<Option<ClobFeeFields<'a>>, ExecutionQuoteError> {
    raw.filter(|value| value.get() != "null")
        .map(|value| {
            serde_json::from_str(value.get())
                .map_err(|_| ExecutionQuoteError::UnsupportedFeeMetadata)
        })
        .transpose()
}

fn zero_rate(value: Option<&RawValue>) -> bool {
    value.is_some_and(|raw| {
        Decimal::from_str_exact(raw.get()).is_ok_and(|decimal| decimal.is_zero())
    })
}
fn valid_exponent(value: &RawValue) -> bool {
    value.get().parse::<u64>().is_ok()
}
fn valid_bool(value: &RawValue) -> bool {
    raw_bool(value).is_some()
}
fn raw_bool(value: &RawValue) -> Option<bool> {
    value.get().parse::<bool>().ok()
}
fn decimal_value(value: Option<&RawValue>) -> Result<Decimal, ExecutionQuoteError> {
    value
        .and_then(|raw| Decimal::from_str_exact(raw.get()).ok())
        .ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)
}
fn exponent_value(value: Option<&RawValue>) -> Result<u32, ExecutionQuoteError> {
    value
        .and_then(|raw| raw.get().parse::<u32>().ok())
        .ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)
}
fn bool_value(value: Option<&RawValue>) -> Result<bool, ExecutionQuoteError> {
    value
        .and_then(raw_bool)
        .ok_or(ExecutionQuoteError::UnsupportedFeeMetadata)
}

fn walk(
    levels: &[BookLevel],
    side: ExecutionQuoteSide,
    amount: Decimal,
    fee: FeeProfile,
) -> Result<(Decimal, Decimal, Decimal, Option<Decimal>), ExecutionQuoteError> {
    let mut remaining = amount;
    let mut shares = Decimal::ZERO;
    let mut notional = Decimal::ZERO;
    let mut fee_total = Decimal::ZERO;
    let mut buy_budget_limited = false;
    let mut merged = BTreeMap::<Decimal, Decimal>::new();
    for level in levels {
        let price =
            Decimal::from_str_exact(&level.price).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        let size =
            Decimal::from_str_exact(&level.size).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        let prior = merged.get(&price).copied().unwrap_or(Decimal::ZERO);
        merged.insert(price, checked_add_exact(prior, size)?);
    }
    let ordered: Vec<_> = match side {
        ExecutionQuoteSide::Buy => merged.into_iter().collect(),
        ExecutionQuoteSide::Sell => merged.into_iter().rev().collect(),
    };
    for (price, available) in ordered {
        let (take, budget_limited) = match side {
            ExecutionQuoteSide::Buy => {
                let (affordable, budget_limited) =
                    affordable_buy_shares(remaining, price, available)?;
                if affordable.is_zero() {
                    if shares.is_zero() {
                        return Err(ExecutionQuoteError::BuyQuantityPrecision);
                    }
                    buy_budget_limited = true;
                    break;
                }
                (available.min(affordable), budget_limited)
            }
            ExecutionQuoteSide::Sell => (available.min(remaining), false),
        };
        if take <= Decimal::ZERO {
            continue;
        }
        let level_notional = checked_mul_exact(take, price)?;
        let level_fee = fee_for_level(take, price, fee)?;
        shares = checked_add_exact(shares, take)?;
        notional = checked_add_exact(notional, level_notional)?;
        fee_total = checked_add_exact(fee_total, level_fee)?;
        remaining = match side {
            ExecutionQuoteSide::Buy => checked_sub_exact(remaining, level_notional)?,
            ExecutionQuoteSide::Sell => checked_sub_exact(remaining, take)?,
        };
        if side == ExecutionQuoteSide::Buy && budget_limited {
            buy_budget_limited = true;
            break;
        }
        if remaining.is_zero() {
            break;
        }
    }
    if !remaining.is_zero() && !buy_budget_limited {
        return Err(ExecutionQuoteError::InsufficientDepth);
    }
    if shares.is_zero() {
        return Err(ExecutionQuoteError::BuyQuantityPrecision);
    }
    let unspent = (side == ExecutionQuoteSide::Buy).then_some(checked_sub_exact(amount, notional)?);
    Ok((shares, notional, fee_total, unspent))
}

fn walk_all_in_buy(
    levels: &[BookLevel],
    budget: Decimal,
    fee: FeeProfile,
) -> Result<(Decimal, Decimal, Decimal, Decimal), ExecutionQuoteError> {
    let mut merged = BTreeMap::<Decimal, Decimal>::new();
    for level in levels {
        let price =
            Decimal::from_str_exact(&level.price).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        let size =
            Decimal::from_str_exact(&level.size).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        let prior = merged.get(&price).copied().unwrap_or(Decimal::ZERO);
        merged.insert(price, checked_add_exact(prior, size)?);
    }

    let mut remaining = budget;
    let mut shares = Decimal::ZERO;
    let mut notional = Decimal::ZERO;
    let mut fee_total = Decimal::ZERO;
    let mut last_level: Option<(Decimal, BigUint, BigUint)> = None;
    for (price, available) in merged {
        let (available_num, available_den) = decimal_ratio(available)?;
        let scale = BigUint::from(10u8).pow(BUY_SHARE_DECIMAL_PLACES);
        let max_units = (&available_num * &scale) / &available_den;
        let take_units = if all_in_cost_within_budget(&max_units, price, remaining, fee)? {
            max_units.clone()
        } else {
            affordable_all_in_shares(remaining, price, &max_units, fee)?
        };
        if take_units.is_zero() {
            continue;
        }
        let take = shares_from_units(&take_units)?;
        let level_notional = checked_mul_exact(take, price)?;
        let level_fee = fee_for_level(take, price, fee)?;
        let level_cash = checked_add_exact(level_notional, level_fee)?;
        shares = checked_add_exact(shares, take)?;
        notional = checked_add_exact(notional, level_notional)?;
        fee_total = checked_add_exact(fee_total, level_fee)?;
        remaining = checked_sub_exact(remaining, level_cash)?;
        let reached_level_end = take_units == max_units;
        last_level = Some((price, take_units, max_units));
        if !reached_level_end {
            break;
        }
    }

    if shares.is_zero() {
        return Err(ExecutionQuoteError::BuyQuantityPrecision);
    }
    if fee_total > notional {
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    }
    if !remaining.is_zero() {
        if let Some((price, take_units, available_units)) = last_level {
            if take_units == available_units
                && incremental_level_cost_within_budget(&take_units, price, &remaining, fee)?
            {
                return Err(ExecutionQuoteError::InsufficientDepth);
            }
        }
    }
    let unspent = checked_sub_exact(budget, checked_add_exact(notional, fee_total)?)?;
    Ok((shares, notional, fee_total, unspent))
}

fn affordable_all_in_shares(
    budget: Decimal,
    price: Decimal,
    max_units: &BigUint,
    fee: FeeProfile,
) -> Result<BigUint, ExecutionQuoteError> {
    let mut low = BigUint::zero();
    let mut high = max_units.clone();
    while low < high {
        let mid = (&low + &high + BigUint::from(1u8)) / BigUint::from(2u8);
        if all_in_cost_within_budget(&mid, price, budget, fee)? {
            low = mid;
        } else {
            high = mid - BigUint::from(1u8);
        }
    }
    Ok(low)
}

fn shares_from_units(units: &BigUint) -> Result<Decimal, ExecutionQuoteError> {
    decimal_from_coefficient(units.clone(), BUY_SHARE_DECIMAL_PLACES)
}

fn all_in_cost_within_budget(
    share_units: &BigUint,
    price: Decimal,
    budget: Decimal,
    fee: FeeProfile,
) -> Result<bool, ExecutionQuoteError> {
    let (price_num, price_den) = decimal_ratio(price)?;
    let (budget_num, budget_den) = decimal_ratio(budget)?;
    let share_scale = BigUint::from(10u8).pow(BUY_SHARE_DECIMAL_PLACES);
    let fee_scale = BigUint::from(10u8).pow(FEE_DECIMAL_PLACES);
    let fee_units = fee_units_for_share_units(share_units, price, fee)?;
    let gross_and_fee =
        share_units * &price_num * &fee_scale + fee_units * &share_scale * &price_den;
    let denominator = share_scale * price_den * fee_scale;
    Ok(gross_and_fee * budget_den <= budget_num * denominator)
}

fn incremental_level_cost_within_budget(
    share_units: &BigUint,
    price: Decimal,
    budget: &Decimal,
    fee: FeeProfile,
) -> Result<bool, ExecutionQuoteError> {
    let (price_num, price_den) = decimal_ratio(price)?;
    let (budget_num, budget_den) = decimal_ratio(*budget)?;
    let share_scale = BigUint::from(10u8).pow(BUY_SHARE_DECIMAL_PLACES);
    let fee_scale = BigUint::from(10u8).pow(FEE_DECIMAL_PLACES);
    let current_fee = fee_units_for_share_units(share_units, price, fee)?;
    let next_fee = fee_units_for_share_units(&(share_units + BigUint::from(1u8)), price, fee)?;
    if next_fee < current_fee {
        return Err(ExecutionQuoteError::ArithmeticOverflow);
    }
    let fee_delta = next_fee - current_fee;
    let gross_and_fee = &price_num * &fee_scale + fee_delta * &share_scale * &price_den;
    let denominator = share_scale * price_den * fee_scale;
    Ok(gross_and_fee * budget_den <= budget_num * denominator)
}

fn affordable_buy_shares(
    budget: Decimal,
    price: Decimal,
    available: Decimal,
) -> Result<(Decimal, bool), ExecutionQuoteError> {
    let (budget_num, budget_den) = decimal_ratio(budget)?;
    let (price_num, price_den) = decimal_ratio(price)?;
    let (available_num, available_den) = decimal_ratio(available)?;
    let scale = BigUint::from(10u8).pow(BUY_SHARE_DECIMAL_PLACES);
    let budget_scaled = &budget_num * &price_den * &scale;
    let units = &budget_scaled / (&budget_den * &price_num);
    let units_at_available_scale = &units * available_den;
    let available_at_scale = available_num * &scale;
    if units_at_available_scale > available_at_scale {
        return Ok((available, false));
    }
    if units_at_available_scale == available_at_scale {
        let next_unit_cost = (&units + BigUint::from(1u8)) * &price_num * &budget_den;
        return Ok((available, budget_scaled < next_unit_cost));
    }
    let units = units
        .to_u128()
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    let units = i128::try_from(units).map_err(|_| ExecutionQuoteError::ArithmeticOverflow)?;
    Ok((
        Decimal::try_from_i128_with_scale(units, BUY_SHARE_DECIMAL_PLACES)
            .map_err(|_| ExecutionQuoteError::ArithmeticOverflow)?,
        true,
    ))
}

fn checked_mul_exact(left: Decimal, right: Decimal) -> Result<Decimal, ExecutionQuoteError> {
    let scale = left.scale().saturating_add(right.scale());
    let coefficient = decimal_coefficient(left) * decimal_coefficient(right);
    decimal_from_coefficient(coefficient, scale)
}

fn checked_add_exact(left: Decimal, right: Decimal) -> Result<Decimal, ExecutionQuoteError> {
    let scale = left.scale().max(right.scale());
    let left_coeff = decimal_coefficient(left) * BigUint::from(10u8).pow(scale - left.scale());
    let right_coeff = decimal_coefficient(right) * BigUint::from(10u8).pow(scale - right.scale());
    decimal_from_coefficient(left_coeff + right_coeff, scale)
}

fn checked_sub_exact(left: Decimal, right: Decimal) -> Result<Decimal, ExecutionQuoteError> {
    let scale = left.scale().max(right.scale());
    let left_coeff = decimal_coefficient(left) * BigUint::from(10u8).pow(scale - left.scale());
    let right_coeff = decimal_coefficient(right) * BigUint::from(10u8).pow(scale - right.scale());
    if right_coeff > left_coeff {
        return Err(ExecutionQuoteError::ArithmeticOverflow);
    }
    decimal_from_coefficient(left_coeff - right_coeff, scale)
}

fn decimal_coefficient(value: Decimal) -> BigUint {
    BigUint::from(value.mantissa().unsigned_abs())
}

fn decimal_from_coefficient(
    mut coefficient: BigUint,
    mut scale: u32,
) -> Result<Decimal, ExecutionQuoteError> {
    let max = BigUint::from(Decimal::MAX.mantissa().unsigned_abs());
    while (scale > Decimal::MAX_SCALE || coefficient > max)
        && scale > 0
        && (&coefficient % BigUint::from(10u8)).is_zero()
    {
        coefficient /= BigUint::from(10u8);
        scale -= 1;
    }
    if scale > Decimal::MAX_SCALE || coefficient > max {
        return Err(ExecutionQuoteError::ArithmeticOverflow);
    }
    let mantissa = coefficient
        .to_u128()
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    let mantissa = i128::try_from(mantissa).map_err(|_| ExecutionQuoteError::ArithmeticOverflow)?;
    Decimal::try_from_i128_with_scale(mantissa, scale)
        .map_err(|_| ExecutionQuoteError::ArithmeticOverflow)
}

fn fee_for_level(
    shares: Decimal,
    price: Decimal,
    fee: FeeProfile,
) -> Result<Decimal, ExecutionQuoteError> {
    if fee.rate.is_zero() {
        return Ok(Decimal::ZERO);
    }
    let (shares_num, shares_den) = decimal_ratio(shares)?;
    decimal_from_coefficient(
        fee_units_for_ratio(&shares_num, &shares_den, price, fee)?,
        FEE_DECIMAL_PLACES,
    )
}

fn fee_units_for_share_units(
    share_units: &BigUint,
    price: Decimal,
    fee: FeeProfile,
) -> Result<BigUint, ExecutionQuoteError> {
    let shares_den = BigUint::from(10u8).pow(BUY_SHARE_DECIMAL_PLACES);
    fee_units_for_ratio(share_units, &shares_den, price, fee)
}

fn fee_units_for_ratio(
    shares_num: &BigUint,
    shares_den: &BigUint,
    price: Decimal,
    fee: FeeProfile,
) -> Result<BigUint, ExecutionQuoteError> {
    if fee.rate.is_zero() {
        return Ok(BigUint::zero());
    }
    let one_minus_price = checked_sub_exact(Decimal::ONE, price)?;
    let (rate_num, rate_den) = decimal_ratio(fee.rate)?;
    let (price_num, price_den) = decimal_ratio(price)?;
    let (complement_num, complement_den) = decimal_ratio(one_minus_price)?;
    let curve_num = price_num * complement_num;
    let curve_den = price_den * complement_den;
    let numerator = shares_num * rate_num * curve_num.pow(fee.exponent);
    let denominator = shares_den * rate_den * curve_den.pow(fee.exponent);
    let scaled = numerator * BigUint::from(10u8).pow(FEE_DECIMAL_PLACES);
    let quotient = &scaled / &denominator;
    let remainder = &scaled % &denominator;
    Ok(if remainder == BigUint::default() {
        quotient
    } else {
        quotient + BigUint::from(1u8)
    })
}

fn decimal_ratio(value: Decimal) -> Result<(BigUint, BigUint), ExecutionQuoteError> {
    let mantissa =
        u128::try_from(value.mantissa()).map_err(|_| ExecutionQuoteError::ArithmeticOverflow)?;
    let numerator = BigUint::from(mantissa);
    let denominator = BigUint::from(10u8).pow(value.scale());
    Ok((numerator, denominator))
}

#[cfg(test)]
mod tests {
    use super::{FeeProfile, GammaFeeFields, GammaFeeMarket, decimal_value, fee_for_level};
    use rust_decimal::Decimal;

    #[test]
    fn gamma_fee_rate_lexeme_is_not_rounded_through_binary_float() {
        let raw = r#"[{"feesEnabled":true,"feeSchedule":{"rate":0.0200000000000000000000000001,"exponent":8,"takerOnly":true}}]"#;
        let rows: Vec<GammaFeeMarket<'_>> = serde_json::from_str(raw).unwrap();
        let fee = rows[0].fee_schedule.unwrap();
        let fields: GammaFeeFields<'_> = serde_json::from_str(fee.get()).unwrap();
        assert_eq!(
            decimal_value(fields.rate).unwrap(),
            Decimal::from_str_exact("0.0200000000000000000000000001").unwrap()
        );
    }

    #[test]
    fn positive_fee_below_decimal_precision_still_rounds_up_conservatively() {
        let rate = Decimal::from_str_exact("0.0000000000000000000000000001").unwrap();
        let fee = fee_for_level(
            Decimal::ONE,
            Decimal::new(5, 1),
            FeeProfile { rate, exponent: 8 },
        )
        .unwrap();
        assert_eq!(fee, Decimal::new(1, 5));
    }
}
