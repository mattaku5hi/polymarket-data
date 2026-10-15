use std::{collections::BTreeMap, time::Duration};

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use rust_decimal::Decimal;

use super::{
    ExecutionQuote, ExecutionQuoteAmountKind, ExecutionQuoteError, ExecutionQuoteFeeCurrency,
    ExecutionQuoteFeeKind, ExecutionQuoteSide, FeeProfile, MarketBuyBudget, cents_coefficient,
    checked_add_exact, checked_mul_exact, checked_sub_exact, decimal_from_coefficient,
    decimal_ratio, fee_for_level, fee_profile, floor_to_cents,
};
use crate::clob::execution_context::ExecutionContextObservation;

const ORDER_AMOUNT_DECIMALS: u32 = 6;
const ORDER_AMOUNT_POLICY_VERSION: &str = "polymarket-protected-buy-tick-share-six-decimal-guard/1";
const ORDER_AMOUNT_SOURCE_COMMIT: &str = "24e346374acef3e3a3da4e3c08a8981e0122ea81";
const ORDER_AMOUNT_SOURCE_SHA256: &str =
    "1e373ee5207426201cff4687c7dbaf4b2094483c4fda094da4c20065b0cd9fe0";

/// Immutable estimate of protected market BUY amount legs and capped displayed depth.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtectedMarketBuyQuote {
    quote: ExecutionQuote,
    normalized_maker_notional: Decimal,
    maker_cash_base_units: u128,
    taker_share_base_units: u128,
    max_price: Decimal,
    reserved_buy_cash: Decimal,
}

impl ProtectedMarketBuyQuote {
    #[must_use]
    pub const fn quote(&self) -> &ExecutionQuote {
        &self.quote
    }
    #[must_use]
    pub const fn normalized_maker_notional(&self) -> Decimal {
        self.normalized_maker_notional
    }
    #[must_use]
    pub const fn required_maker_minimum(&self) -> Decimal {
        Decimal::ONE
    }
    /// Unsigned amount encoding; this is not a signed or submitted payload.
    #[must_use]
    pub const fn maker_cash_base_units(&self) -> u128 {
        self.maker_cash_base_units
    }
    /// Unsigned amount encoding; this is not a signed or submitted payload.
    #[must_use]
    pub const fn taker_share_base_units(&self) -> u128 {
        self.taker_share_base_units
    }
    #[must_use]
    pub const fn max_price(&self) -> Decimal {
        self.max_price
    }
    #[must_use]
    pub const fn reserved_buy_cash(&self) -> Decimal {
        self.reserved_buy_cash
    }
    #[must_use]
    pub const fn order_amount_decimals(&self) -> u32 {
        ORDER_AMOUNT_DECIMALS
    }
    #[must_use]
    pub const fn order_amount_policy_version(&self) -> &'static str {
        ORDER_AMOUNT_POLICY_VERSION
    }
    #[must_use]
    pub const fn order_amount_source_commit(&self) -> &'static str {
        ORDER_AMOUNT_SOURCE_COMMIT
    }
    /// SHA-256 of the pinned `market.py` amount construction source.
    #[must_use]
    pub const fn order_amount_source_sha256(&self) -> &'static str {
        ORDER_AMOUNT_SOURCE_SHA256
    }
}

/// Estimate a protected market BUY from gross maker cash and an unchanged max-price cap.
///
/// The result contains source-shaped six-decimal amount legs, but it does not sign or
/// submit an order. Displayed asks above `max_price` are excluded and better prices do
/// not increase the target share amount. The fee and fill values remain estimates.
pub fn estimate_protected_market_buy_quote(
    context: &ExecutionContextObservation,
    budget: MarketBuyBudget,
    max_price: Decimal,
    max_age: Duration,
) -> Result<ProtectedMarketBuyQuote, ExecutionQuoteError> {
    let requested_budget = match budget {
        MarketBuyBudget::GrossNotional(amount) | MarketBuyBudget::AllInCash(amount) => amount,
    };
    if requested_budget <= Decimal::ZERO {
        return Err(ExecutionQuoteError::InvalidInput);
    }
    let valid_until = context
        .local_valid_until(max_age)
        .map_err(map_context_validity)?;
    let (tick_size, amount_decimals) = observed_tick_amount_precision(context)?;
    validate_max_price(max_price, tick_size)?;
    let fee = fee_profile(context)?;
    let config = ProtectedQuoteConfig {
        max_price,
        amount_decimals,
        fee,
        valid_until,
    };
    check_deadline(valid_until)?;
    match budget {
        MarketBuyBudget::GrossNotional(maker_budget) => {
            let maker = floor_to_cents(maker_budget)?;
            if maker < Decimal::ONE {
                return Err(ExecutionQuoteError::BelowMarketBuyCashMinimum);
            }
            let mut candidate = evaluate_protected_candidate(context, maker, config)?;
            if !candidate.guard_safe {
                return Err(ExecutionQuoteError::ProtectedPricePrecision);
            }
            candidate.protected.quote.requested_amount = maker_budget;
            candidate.protected.quote.unspent_buy_budget = Some(checked_sub_exact(
                maker_budget,
                candidate.protected.quote.gross_notional,
            )?);
            Ok(candidate.protected)
        }
        MarketBuyBudget::AllInCash(cash_cap) => {
            let max_cents = cents_coefficient(cash_cap)?;
            let selected_cents =
                select_all_in_maker_cents(context, cash_cap, max_cents, config, tick_size)?;
            let maker = decimal_from_coefficient(selected_cents, 2)?;
            let mut candidate = evaluate_protected_candidate(context, maker, config)?;
            if !candidate.guard_safe || candidate.protected.reserved_buy_cash > cash_cap {
                return Err(ExecutionQuoteError::ArithmeticOverflow);
            }
            let quote = &mut candidate.protected.quote;
            quote.amount_kind = ExecutionQuoteAmountKind::BuyAllInCash;
            quote.requested_amount = cash_cap;
            let actual_total = quote
                .total_buy_cash
                .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
            quote.unspent_buy_budget = Some(checked_sub_exact(cash_cap, actual_total)?);
            Ok(candidate.protected)
        }
    }
}

#[derive(Clone, Copy)]
struct ProtectedQuoteConfig {
    max_price: Decimal,
    amount_decimals: u32,
    fee: FeeProfile,
    valid_until: tokio::time::Instant,
}

struct CandidateQuote {
    protected: ProtectedMarketBuyQuote,
    guard_safe: bool,
}

fn evaluate_protected_candidate(
    context: &ExecutionContextObservation,
    maker: Decimal,
    config: ProtectedQuoteConfig,
) -> Result<CandidateQuote, ExecutionQuoteError> {
    check_deadline(config.valid_until)?;
    let normalized_maker_notional = floor_to_cents(maker)?;
    if normalized_maker_notional < Decimal::ONE {
        return Err(ExecutionQuoteError::BelowMarketBuyCashMinimum);
    }
    let (target_shares, maker_cash_base_units, taker_share_base_units) = amount_legs(
        normalized_maker_notional,
        config.max_price,
        config.amount_decimals,
    )?;
    let guard_safe = amount_guard_is_safe(
        maker_cash_base_units,
        taker_share_base_units,
        config.max_price,
    )?;
    let (gross_notional, estimated_platform_fee) = walk_protected_asks(
        &context.book().asks,
        target_shares,
        config.max_price,
        config.fee,
    )?;
    if estimated_platform_fee > gross_notional {
        return Err(ExecutionQuoteError::UnsupportedFeeMetadata);
    }
    let vwap = gross_notional
        .checked_div(target_shares)
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    let total_buy_cash = checked_add_exact(gross_notional, estimated_platform_fee)?;
    let reserved_buy_cash = checked_add_exact(normalized_maker_notional, estimated_platform_fee)?;
    check_deadline(config.valid_until)?;
    Ok(CandidateQuote {
        protected: ProtectedMarketBuyQuote {
            quote: ExecutionQuote {
                side: ExecutionQuoteSide::Buy,
                amount_kind: ExecutionQuoteAmountKind::BuyGrossNotional,
                requested_amount: maker,
                gross_shares: target_shares,
                gross_notional,
                unspent_buy_budget: Some(checked_sub_exact(maker, gross_notional)?),
                vwap,
                estimated_platform_fee,
                fee_rate: config.fee.rate,
                fee_exponent: config.fee.exponent,
                fee_kind: if config.fee.rate.is_zero() {
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
                valid_until: config.valid_until,
                request_count: context.request_count(),
            },
            normalized_maker_notional,
            maker_cash_base_units,
            taker_share_base_units,
            max_price: config.max_price,
            reserved_buy_cash,
        },
        guard_safe,
    })
}

fn select_all_in_maker_cents(
    context: &ExecutionContextObservation,
    cash_cap: Decimal,
    max_cents: BigUint,
    config: ProtectedQuoteConfig,
    tick_size: Decimal,
) -> Result<BigUint, ExecutionQuoteError> {
    let minimum = BigUint::from(100u8);
    if max_cents < minimum {
        return Err(ExecutionQuoteError::BelowMarketBuyCashMinimum);
    }
    let mut low = BigUint::from(99u8);
    let mut high = &max_cents + BigUint::from(1u8);
    while high > &low + BigUint::from(1u8) {
        let middle = (&low + &high) / BigUint::from(2u8);
        let maker = decimal_from_coefficient(middle.clone(), 2)?;
        match evaluate_protected_candidate(context, maker, config) {
            Ok(candidate) if candidate.protected.reserved_buy_cash <= cash_cap => low = middle,
            Ok(_) | Err(ExecutionQuoteError::InsufficientDepth) => high = middle,
            Err(error) => return Err(error),
        }
    }
    if low < minimum {
        match evaluate_protected_candidate(context, Decimal::ONE, config) {
            Err(ExecutionQuoteError::InsufficientDepth) => {
                return Err(ExecutionQuoteError::InsufficientDepth);
            }
            Err(error) => return Err(error),
            Ok(candidate) if candidate.protected.reserved_buy_cash > cash_cap => {
                return Err(ExecutionQuoteError::BelowMarketBuyCashMinimum);
            }
            Ok(_) => return Err(ExecutionQuoteError::ArithmeticOverflow),
        }
    }
    select_guard_safe_cents(low, config, tick_size)
}

fn select_guard_safe_cents(
    max_feasible_cents: BigUint,
    config: ProtectedQuoteConfig,
    tick_size: Decimal,
) -> Result<BigUint, ExecutionQuoteError> {
    if tick_size != Decimal::new(1, 1) {
        let maker = decimal_from_coefficient(max_feasible_cents.clone(), 2)?;
        let (_, maker_units, taker_units) =
            amount_legs(maker, config.max_price, config.amount_decimals)?;
        return if amount_guard_is_safe(maker_units, taker_units, config.max_price)? {
            Ok(max_feasible_cents)
        } else {
            Err(ExecutionQuoteError::ProtectedPricePrecision)
        };
    }

    let (price_num, price_den) = decimal_ratio(config.max_price)?;
    let numerator = &price_num * BigUint::from(10u8);
    if &numerator % &price_den != BigUint::default() {
        return Err(ExecutionQuoteError::InvalidProtectedMarketBuyPrice);
    }
    let n = (&numerator / &price_den)
        .to_u32()
        .filter(|value| (1..=9).contains(value))
        .ok_or(ExecutionQuoteError::InvalidProtectedMarketBuyPrice)?;
    let period = n / gcd(100, n);
    let mut candidate = max_feasible_cents;
    for _ in 0..period {
        if candidate < BigUint::from(100u8) {
            break;
        }
        let maker = decimal_from_coefficient(candidate.clone(), 2)?;
        let (_, maker_units, taker_units) =
            amount_legs(maker, config.max_price, config.amount_decimals)?;
        if amount_guard_is_safe(maker_units, taker_units, config.max_price)? {
            return Ok(candidate);
        }
        candidate -= BigUint::from(1u8);
    }
    Err(ExecutionQuoteError::ProtectedPricePrecision)
}

fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn check_deadline(deadline: tokio::time::Instant) -> Result<(), ExecutionQuoteError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(ExecutionQuoteError::Expired);
    }
    Ok(())
}

fn map_context_validity(
    error: super::super::execution_context::ExecutionContextValidityError,
) -> ExecutionQuoteError {
    match error {
        super::super::execution_context::ExecutionContextValidityError::Expired => {
            ExecutionQuoteError::Expired
        }
        super::super::execution_context::ExecutionContextValidityError::InvalidMaxAge => {
            ExecutionQuoteError::InvalidInput
        }
    }
}

fn observed_tick_amount_precision(
    context: &ExecutionContextObservation,
) -> Result<(Decimal, u32), ExecutionQuoteError> {
    let tick = Decimal::from_str_exact(context.min_tick_size())
        .map_err(|_| ExecutionQuoteError::UnsupportedProtectedMarketBuyTick)?;
    let amount_decimals = match tick {
        value if value == Decimal::new(1, 1) => 3,
        value if value == Decimal::new(1, 2) => 4,
        value if value == Decimal::new(5, 3) => 5,
        value if value == Decimal::new(25, 4) => 6,
        value if value == Decimal::new(1, 3) => 5,
        value if value == Decimal::new(1, 4) => 6,
        _ => return Err(ExecutionQuoteError::UnsupportedProtectedMarketBuyTick),
    };
    Ok((tick, amount_decimals))
}

fn validate_max_price(max_price: Decimal, tick_size: Decimal) -> Result<(), ExecutionQuoteError> {
    if max_price < tick_size || max_price > checked_sub_exact(Decimal::ONE, tick_size)? {
        return Err(ExecutionQuoteError::InvalidProtectedMarketBuyPrice);
    }
    if normalized_decimal_places(max_price) > normalized_decimal_places(tick_size) {
        return Err(ExecutionQuoteError::InvalidProtectedMarketBuyPrice);
    }
    let (price_num, price_den) = decimal_ratio(max_price)?;
    let (tick_num, tick_den) = decimal_ratio(tick_size)?;
    if (&price_num * tick_den) % (&price_den * tick_num) != BigUint::default() {
        return Err(ExecutionQuoteError::InvalidProtectedMarketBuyPrice);
    }
    Ok(())
}

fn normalized_decimal_places(value: Decimal) -> u32 {
    let mut places = value.scale();
    let mut mantissa = value.mantissa();
    while places > 0 && mantissa % 10 == 0 {
        mantissa /= 10;
        places -= 1;
    }
    places
}

fn amount_legs(
    maker: Decimal,
    max_price: Decimal,
    amount_decimals: u32,
) -> Result<(Decimal, u128, u128), ExecutionQuoteError> {
    let (maker_num, maker_den) = decimal_ratio(maker)?;
    let (price_num, price_den) = decimal_ratio(max_price)?;
    let target_units = (maker_num * price_den * BigUint::from(10u8).pow(amount_decimals))
        / (maker_den * price_num);
    if target_units.is_zero() {
        return Err(ExecutionQuoteError::InvalidInput);
    }
    let target_shares = decimal_from_coefficient(target_units.clone(), amount_decimals)?;
    let taker_base_units = target_units
        .to_u128()
        .and_then(|units| units.checked_mul(10u128.pow(ORDER_AMOUNT_DECIMALS - amount_decimals)))
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)?;
    Ok((target_shares, decimal_base_units(maker)?, taker_base_units))
}

fn decimal_base_units(value: Decimal) -> Result<u128, ExecutionQuoteError> {
    let (numerator, denominator) = decimal_ratio(value)?;
    let scaled = numerator * BigUint::from(10u8).pow(ORDER_AMOUNT_DECIMALS);
    if &scaled % &denominator != BigUint::default() {
        return Err(ExecutionQuoteError::ArithmeticOverflow);
    }
    (scaled / denominator)
        .to_u128()
        .ok_or(ExecutionQuoteError::ArithmeticOverflow)
}

fn amount_guard_is_safe(
    maker_units: u128,
    taker_units: u128,
    max_price: Decimal,
) -> Result<bool, ExecutionQuoteError> {
    if maker_units == 0 || taker_units == 0 {
        return Ok(false);
    }
    let maker = BigUint::from(maker_units);
    let taker = BigUint::from(taker_units);
    let (price_num, price_den) = decimal_ratio(max_price)?;
    if &maker * &price_den < &taker * &price_num {
        return Ok(false);
    }
    let upper_price =
        checked_add_exact(max_price, decimal_from_coefficient(BigUint::from(1u8), 4)?)?;
    let (upper_num, upper_den) = decimal_ratio(upper_price)?;
    if &maker * upper_den >= &taker * upper_num {
        return Ok(false);
    }
    Ok(true)
}

fn walk_protected_asks(
    levels: &[crate::clob::BookLevel],
    target_shares: Decimal,
    max_price: Decimal,
    fee: FeeProfile,
) -> Result<(Decimal, Decimal), ExecutionQuoteError> {
    let mut merged = BTreeMap::<Decimal, Decimal>::new();
    for level in levels {
        let price =
            Decimal::from_str_exact(&level.price).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        if price > max_price {
            continue;
        }
        let size =
            Decimal::from_str_exact(&level.size).map_err(|_| ExecutionQuoteError::InvalidInput)?;
        let prior = merged.get(&price).copied().unwrap_or(Decimal::ZERO);
        merged.insert(price, checked_add_exact(prior, size)?);
    }
    let mut remaining = target_shares;
    let mut gross_notional = Decimal::ZERO;
    let mut estimated_platform_fee = Decimal::ZERO;
    for (price, available) in merged {
        if available <= Decimal::ZERO {
            continue;
        }
        let take = available.min(remaining);
        if take <= Decimal::ZERO {
            continue;
        }
        gross_notional = checked_add_exact(gross_notional, checked_mul_exact(take, price)?)?;
        estimated_platform_fee =
            checked_add_exact(estimated_platform_fee, fee_for_level(take, price, fee)?)?;
        remaining = checked_sub_exact(remaining, take)?;
        if remaining.is_zero() {
            break;
        }
    }
    if !remaining.is_zero() {
        return Err(ExecutionQuoteError::InsufficientDepth);
    }
    Ok((gross_notional, estimated_platform_fee))
}
