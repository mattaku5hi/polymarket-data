//! Source-bound native cash annotation for a modeled CLOB execution quote.
//!
//! The annotation identifies quote cash as pUSD under the rooted native
//! profile. It does not convert CLOB USD notation, model supplied native fees,
//! or guarantee execution or settlement.

use alloy_primitives::B256;
use thiserror::Error;

use crate::clob::{
    execution_context::ExecutionContextObservation,
    execution_quote::{ExecutionQuote, ExecutionQuoteError},
};

use super::{
    fifth_code_context::FifthExchangeImplementationVersion,
    fifth_execution_context::FifthNativeExecutionAssetBinding,
    fifth_native_binary::FifthNativeBinaryObservation,
};

pub const FIFTH_NATIVE_EXECUTION_QUOTE_BINDING_POLICY_VERSION: &str =
    "fifth-native-v2-rooted-pusd-modeled-quote-binding/1";
const FIFTH_NATIVE_SHARE_UNIT_POLICY_VERSION: &str =
    "fifth-native-v2-position-share-six-decimal-scale/1";

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FifthNativeExecutionQuoteBindingError {
    #[error("execution quote does not match the sealed V2 native asset context")]
    ContextMismatch,
    #[error("execution quote expired at its original local deadline")]
    QuoteExpired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifthNativeQuoteCashUnit {
    Pusd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FifthNativeQuoteShareUnit {
    NormalizedNativePositionShares,
}

/// A borrowed native pUSD annotation for one quote from the bound context.
///
/// The quote's fee kind and amounts remain those of its original modeled API
/// estimate. Native collateral identity and the Exchange fee cap are separate
/// rooted source facts, not expected or settled quote fees.
#[derive(Debug)]
pub struct FifthNativeExecutionQuoteBinding<'a> {
    native_context: &'a FifthNativeBinaryObservation,
    execution_context: &'a ExecutionContextObservation,
    quote: &'a ExecutionQuote,
    selected_native_outcome_index: usize,
    selected_native_position_id: B256,
}

impl FifthNativeExecutionQuoteBinding<'_> {
    #[must_use]
    pub const fn quote(&self) -> &ExecutionQuote {
        self.quote
    }

    #[must_use]
    pub const fn native_context(&self) -> &FifthNativeBinaryObservation {
        self.native_context
    }

    #[must_use]
    pub const fn execution_context(&self) -> &ExecutionContextObservation {
        self.execution_context
    }

    #[must_use]
    pub const fn selected_native_outcome_index(&self) -> usize {
        self.selected_native_outcome_index
    }

    #[must_use]
    pub const fn selected_native_position_id(&self) -> B256 {
        self.selected_native_position_id
    }

    /// The modeled quote cash fields are annotated with this native unit.
    /// This does not assert parity with CLOB USD notation or USDC.
    #[must_use]
    pub const fn quote_cash_unit(&self) -> FifthNativeQuoteCashUnit {
        FifthNativeQuoteCashUnit::Pusd
    }

    #[must_use]
    pub const fn quote_cash_decimals(&self) -> u8 {
        self.native_context.selected_balances().pusd_decimals()
    }

    /// Position amounts use the normalized native six-decimal share scale.
    /// PositionManager itself stores raw ERC-1155 integers without declaring
    /// token decimals; the scale follows native split/merge parity with pUSD
    /// base units and the official native order encoder's six-decimal scale.
    #[must_use]
    pub const fn quote_share_unit(&self) -> FifthNativeQuoteShareUnit {
        FifthNativeQuoteShareUnit::NormalizedNativePositionShares
    }

    #[must_use]
    pub const fn quote_share_decimals(&self) -> u8 {
        6
    }

    #[must_use]
    pub const fn share_unit_policy_version(&self) -> &'static str {
        FIFTH_NATIVE_SHARE_UNIT_POLICY_VERSION
    }

    /// Modeled BUY share quantity received at full displayed-depth completion.
    /// Native fees are cash-side, so the quote fee is not subtracted from this
    /// estimate. This does not guarantee a fill, settlement, or redeemability
    /// before a full winning outcome.
    #[must_use]
    pub const fn estimated_buy_received_shares(&self) -> Option<rust_decimal::Decimal> {
        match self.quote.side() {
            crate::clob::execution_quote::ExecutionQuoteSide::Buy => {
                Some(self.quote.gross_shares())
            }
            crate::clob::execution_quote::ExecutionQuoteSide::Sell => None,
        }
    }

    /// Return the modeled gross quantity in six-decimal native base units only
    /// when it is exactly representable. The quote may retain an 18-decimal
    /// share grid; this conversion does not assert tick-dependent order
    /// precision or signed-order encodability, and it never rounds the quote.
    #[must_use]
    pub fn exact_modeled_share_base_units(&self) -> Option<alloy_primitives::U256> {
        exact_decimal_base_units(self.quote.gross_shares(), self.quote_share_decimals())
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.native_context.selected_balances().chain_id()
    }

    #[must_use]
    pub const fn root_block_number(&self) -> u64 {
        self.native_context.selected_balances().block_number()
    }

    #[must_use]
    pub fn root_block_hash(&self) -> &str {
        self.native_context.selected_balances().block_hash()
    }

    #[must_use]
    pub fn root_state_root(&self) -> &str {
        self.native_context.selected_balances().state_root()
    }

    #[must_use]
    pub fn native_balance_source_policy_version(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .source_policy_version()
    }

    #[must_use]
    pub const fn native_binary_source_policy_version(&self) -> &'static str {
        self.native_context.source_policy_version()
    }

    #[must_use]
    pub fn code_context_source_policy_version(&self) -> &'static str {
        self.code_context().code_context_policy_version()
    }

    #[must_use]
    pub fn asset_binding_source_policy_version(&self) -> &'static str {
        super::fifth_execution_context::FIFTH_NATIVE_EXECUTION_ASSET_BINDING_POLICY_VERSION
    }

    #[must_use]
    pub const fn quote_binding_policy_version(&self) -> &'static str {
        FIFTH_NATIVE_EXECUTION_QUOTE_BINDING_POLICY_VERSION
    }

    #[must_use]
    pub fn collateral_proxy(&self) -> &'static str {
        self.native_context.selected_balances().pusd_proxy()
    }

    #[must_use]
    pub const fn collateral_symbol(&self) -> &'static str {
        "pUSD"
    }

    #[must_use]
    pub fn collateral_proxy_code_hash(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .pusd_proxy_code_hash()
    }

    #[must_use]
    pub fn collateral_implementation(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .pusd_implementation()
    }

    #[must_use]
    pub fn collateral_implementation_code_hash(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .pusd_implementation_code_hash()
    }

    #[must_use]
    pub fn position_manager_proxy(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .position_manager_proxy()
    }

    #[must_use]
    pub fn position_manager_proxy_code_hash(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .position_manager_proxy_code_hash()
    }

    #[must_use]
    pub fn position_manager_implementation(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .position_manager_implementation()
    }

    #[must_use]
    pub fn position_manager_implementation_code_hash(&self) -> &'static str {
        self.native_context
            .selected_balances()
            .position_manager_implementation_code_hash()
    }

    #[must_use]
    pub fn exchange_proxy(&self) -> &'static str {
        self.code_context().exchange_proxy()
    }

    #[must_use]
    pub fn exchange_proxy_code_hash(&self) -> &'static str {
        self.code_context().exchange_proxy_code_hash()
    }

    #[must_use]
    pub fn exchange_implementation(&self) -> &'static str {
        self.code_context().exchange_implementation()
    }

    #[must_use]
    pub fn exchange_implementation_code_hash(&self) -> &'static str {
        self.code_context().exchange_implementation_code_hash()
    }

    #[must_use]
    pub const fn exchange_implementation_version(&self) -> FifthExchangeImplementationVersion {
        self.code_context().exchange_implementation_version()
    }

    /// Source-bound per-order ceiling, distinct from the quote's modeled fee.
    #[must_use]
    pub const fn exchange_fee_cap_bps(&self) -> u16 {
        self.code_context().exchange_max_fee_rate_bps()
    }

    #[must_use]
    pub const fn exchange_fee_cap_policy_version(&self) -> &'static str {
        self.code_context()
            .exchange_fee_cap_binding_policy_version()
    }

    #[must_use]
    pub const fn exchange_fee_cap_source_provenance(&self) -> &'static str {
        self.code_context().exchange_fee_cap_source_provenance()
    }

    #[must_use]
    pub const fn valid_until(&self) -> tokio::time::Instant {
        self.quote.valid_until()
    }

    const fn code_context(&self) -> &super::fifth_code_context::FifthCodeContextObservation {
        self.native_context.selected_balances().code_context()
    }
}

fn exact_decimal_base_units(
    amount: rust_decimal::Decimal,
    decimals: u8,
) -> Option<alloy_primitives::U256> {
    let mantissa = u128::try_from(amount.mantissa()).ok()?;
    let scale = amount.scale();
    let base_scale = u32::from(decimals);
    let raw_units = if scale <= base_scale {
        let factor = 10_u128.checked_pow(base_scale - scale)?;
        mantissa.checked_mul(factor)?
    } else {
        let factor = 10_u128.checked_pow(scale - base_scale)?;
        if mantissa % factor != 0 {
            return None;
        }
        mantissa / factor
    };
    Some(alloy_primitives::U256::from(raw_units))
}

/// Bind a modeled quote to the already sealed native V2 pair and source profile.
///
/// Every HTTP identity, selected asset, book provenance, and acquisition timing
/// field must match the context used by the quote. The quote's original deadline
/// is checked and retained; this function does not renew it or perform I/O.
pub fn bind_fifth_native_execution_quote<'a>(
    asset_binding: &'a FifthNativeExecutionAssetBinding<'_>,
    quote: &'a ExecutionQuote,
) -> Result<FifthNativeExecutionQuoteBinding<'a>, FifthNativeExecutionQuoteBindingError> {
    let context = asset_binding.execution_context();
    if quote.api_condition_id() != context.api_condition_id()
        || quote.protocol_version() != context.protocol_version()
        || quote.selected_asset_id() != context.selected_asset_id()
        || quote.selected_outcome_index() != context.selected_outcome_index()
        || quote.book_hash() != context.book().hash
        || quote.vendor_timestamp() != context.book().timestamp
        || quote.observed_at() != context.started_at()
        || quote.available_at() != context.completed_at()
        || quote.request_count() != context.request_count()
    {
        return Err(FifthNativeExecutionQuoteBindingError::ContextMismatch);
    }
    quote.check_validity().map_err(|error| match error {
        ExecutionQuoteError::Expired => FifthNativeExecutionQuoteBindingError::QuoteExpired,
        _ => FifthNativeExecutionQuoteBindingError::ContextMismatch,
    })?;
    Ok(FifthNativeExecutionQuoteBinding {
        native_context: asset_binding.native_context(),
        execution_context: context,
        quote,
        selected_native_outcome_index: asset_binding.selected_native_outcome_index(),
        selected_native_position_id: asset_binding.selected_native_position_id(),
    })
}
