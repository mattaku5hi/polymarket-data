//! Exact asset-pair agreement between rooted native evidence and HTTP context.
//!
//! This binds only the two observed token identifiers. It does not establish
//! semantic labels, condition identity across providers, fees, currency, or
//! execution readiness.

use alloy_primitives::{B256, U256};
use thiserror::Error;

use crate::clob::execution_context::{ExecutionContextObservation, ObservedMarketVersion};

use super::fifth_native_binary::FifthNativeBinaryObservation;

pub const FIFTH_NATIVE_EXECUTION_ASSET_BINDING_POLICY_VERSION: &str =
    "fifth-native-binary-v2-provider-asset-pair-root-equality/1";

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FifthNativeExecutionAssetBindingError {
    #[error("execution context must explicitly identify protocol V2")]
    UnsupportedProtocol,
    #[error("execution context asset ID is not canonical uint256 decimal text")]
    InvalidAssetId,
    #[error("execution context and rooted native asset pairs do not match exactly")]
    AssetMismatch,
}

/// A borrowed proof that the HTTP V2 pair equals the rooted native pair.
///
/// The private fields prevent callers from constructing a binding from an
/// arbitrary tuple or serializing one as independently supplied evidence.
#[derive(Debug)]
pub struct FifthNativeExecutionAssetBinding<'a> {
    native_context: &'a FifthNativeBinaryObservation,
    execution_context: &'a ExecutionContextObservation,
    selected_native_outcome_index: usize,
    selected_native_position_id: B256,
}

impl<'a> FifthNativeExecutionAssetBinding<'a> {
    #[must_use]
    pub const fn native_context(&self) -> &'a FifthNativeBinaryObservation {
        self.native_context
    }

    #[must_use]
    pub const fn execution_context(&self) -> &'a ExecutionContextObservation {
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

    #[must_use]
    pub const fn source_policy_version(&self) -> &'static str {
        FIFTH_NATIVE_EXECUTION_ASSET_BINDING_POLICY_VERSION
    }
}

/// Binds the explicitly selected V2 provider pair to one rooted native pair.
///
/// The provider condition selector is intentionally kept separate from the
/// native condition identifier. Only the ordered full-width asset IDs are
/// compared.
pub fn bind_fifth_native_execution_assets<'a>(
    native: &'a FifthNativeBinaryObservation,
    context: &'a ExecutionContextObservation,
) -> Result<FifthNativeExecutionAssetBinding<'a>, FifthNativeExecutionAssetBindingError> {
    if context.protocol_version() != ObservedMarketVersion::V2 {
        return Err(FifthNativeExecutionAssetBindingError::UnsupportedProtocol);
    }

    let context_outcomes = context.outcomes();
    let context_ids = [
        parse_canonical_uint256_decimal(context_outcomes[0].asset_id())
            .ok_or(FifthNativeExecutionAssetBindingError::InvalidAssetId)?,
        parse_canonical_uint256_decimal(context_outcomes[1].asset_id())
            .ok_or(FifthNativeExecutionAssetBindingError::InvalidAssetId)?,
    ];
    let position_ids = native.position_ids();
    let native_ids = [
        U256::from_be_slice(position_ids[0].as_slice()),
        U256::from_be_slice(position_ids[1].as_slice()),
    ];
    if context_ids != native_ids {
        return Err(FifthNativeExecutionAssetBindingError::AssetMismatch);
    }

    let selected_native_outcome_index = context.selected_outcome_index();
    let selected_native_position_id = native.position_ids()[selected_native_outcome_index];
    Ok(FifthNativeExecutionAssetBinding {
        native_context: native,
        execution_context: context,
        selected_native_outcome_index,
        selected_native_position_id,
    })
}

fn parse_canonical_uint256_decimal(value: &str) -> Option<U256> {
    if value.is_empty()
        || value.len() > 78
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let parsed = U256::from_str_radix(value, 10).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}
