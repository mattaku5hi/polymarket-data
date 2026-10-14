//! Bounded single-block capture and offline replay for CTF V2 owner fills.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use super::v2_owner_fill_signals::{
    CTF_V2_OWNER_FILL_SIGNAL_POLICY_VERSION, V2OwnerFillSignal, V2OwnerFillSignalProvenance,
    extract_ctf_v2_owner_fill_signals_with_provenance,
};
use super::{
    ChainLogAuditError, ChainLogVerifier, ChainReceiptIntervalEvidence,
    MAX_RECORDED_RECEIPT_REQUEST_BYTES, MAX_RECORDED_RECEIPT_REQUESTS,
    MAX_RECORDED_RECEIPT_RESPONSE_BYTES, MAX_RECORDED_RECEIPT_TIMEOUT,
    RecordedChainTransactionReceiptRpcTranscript, RpcCaptureState, RpcExecution, RpcReplayState,
    TransactionRequestBudget, recorded_full_block_hash_lookup, validate_hex,
};

pub const RECORDED_V2_OWNER_FILL_PACKET_SCHEMA_VERSION: &str =
    "recorded-ctf-v2-owner-fill-packet/1";
pub const V2_OWNER_FILL_CAPTURE_POLICY_VERSION: &str =
    "ctf-v2-complete-rooted-single-block-owner-fill-capture/1";
pub const V2_OWNER_FILL_RECORDED_REVERIFICATION_POLICY_VERSION: &str =
    "ctf-v2-recorded-rooted-single-block-owner-fill-reverification/1";

/// Untrusted serialized inputs. The transcript becomes useful only after its
/// exact request sequence is replayed through the receipt-root verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedV2OwnerFillSignalsPacket {
    packet_schema_version: String,
    capture_policy_version: String,
    signal_policy_version: String,
    block_number: u64,
    expected_parent_hash: String,
    expected_end_hash: String,
    transcript: RecordedChainTransactionReceiptRpcTranscript,
}

impl RecordedV2OwnerFillSignalsPacket {
    #[must_use]
    pub fn packet_schema_version(&self) -> &str {
        &self.packet_schema_version
    }

    #[must_use]
    pub fn capture_policy_version(&self) -> &str {
        &self.capture_policy_version
    }

    #[must_use]
    pub fn signal_policy_version(&self) -> &str {
        &self.signal_policy_version
    }

    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn expected_parent_hash(&self) -> &str {
        &self.expected_parent_hash
    }

    #[must_use]
    pub fn expected_end_hash(&self) -> &str {
        &self.expected_end_hash
    }

    #[must_use]
    pub const fn transcript(&self) -> &RecordedChainTransactionReceiptRpcTranscript {
        &self.transcript
    }

    #[must_use]
    pub fn request_count(&self) -> usize {
        self.transcript.request_count()
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.transcript.response_bytes()
    }
}

/// Online interval verification paired with its owner signals and exact RPC
/// transcript. This interval retains the live providers' reported-finality
/// attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedV2OwnerFillSignals {
    interval: ChainReceiptIntervalEvidence,
    signals: Vec<V2OwnerFillSignal>,
    packet: RecordedV2OwnerFillSignalsPacket,
}

impl CapturedV2OwnerFillSignals {
    #[must_use]
    pub const fn interval(&self) -> &ChainReceiptIntervalEvidence {
        &self.interval
    }

    #[must_use]
    pub fn signals(&self) -> &[V2OwnerFillSignal] {
        &self.signals
    }

    #[must_use]
    pub const fn packet(&self) -> &RecordedV2OwnerFillSignalsPacket {
        &self.packet
    }
}

/// One primary-provider header observation for an explicit Polygon block.
/// This does not establish finality or agreement; use the existing anchored
/// two-provider capture before treating it as verified evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedChainBlockAnchor {
    block_number: u64,
    block_hash: String,
    parent_hash: String,
    response_bytes: usize,
}

impl ObservedChainBlockAnchor {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    #[must_use]
    pub fn parent_hash(&self) -> &str {
        &self.parent_hash
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

/// Offline-reverified owner signals. It intentionally exposes only the
/// checked single-block anchors, never a live-finality interval object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedV2OwnerFillSignals {
    block_number: u64,
    expected_parent_hash: String,
    expected_end_hash: String,
    signals: Vec<V2OwnerFillSignal>,
}

impl RecordedV2OwnerFillSignals {
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    #[must_use]
    pub fn expected_parent_hash(&self) -> &str {
        &self.expected_parent_hash
    }

    #[must_use]
    pub fn expected_end_hash(&self) -> &str {
        &self.expected_end_hash
    }

    #[must_use]
    pub fn signals(&self) -> &[V2OwnerFillSignal] {
        &self.signals
    }

    #[must_use]
    pub const fn policy_version(&self) -> &'static str {
        V2_OWNER_FILL_RECORDED_REVERIFICATION_POLICY_VERSION
    }
}

/// Caller limits or recorded transcript could not be verified.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BoundedRecordedOwnerFillSignalsError {
    #[error("owner-fill capture/replay request budget exhausted")]
    RequestBudgetExceeded,
    #[error("owner-fill capture/replay exceeded its total deadline")]
    Timeout,
    #[error(transparent)]
    Verification(ChainLogAuditError),
}

impl ChainLogVerifier {
    /// Observe a content-bound block header from the primary provider under
    /// one actual-send budget, response-byte cap, and total deadline. The
    /// returned anchor is only an observation; the subsequent sealed capture
    /// independently checks both providers, finality, receipts, and logs.
    pub async fn observe_block_anchor_bounded(
        &self,
        block_number: u64,
        budget: &TransactionRequestBudget,
        max_total_response_bytes: usize,
        total_timeout: Duration,
    ) -> Result<ObservedChainBlockAnchor, BoundedRecordedOwnerFillSignalsError> {
        validate_limits(max_total_response_bytes, total_timeout)?;
        if block_number == 0 {
            return Err(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::InvalidInput,
            ));
        }
        let deadline_at = tokio::time::Instant::now()
            .checked_add(total_timeout)
            .ok_or(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::InvalidInput,
            ))?;
        let capture = Arc::new(Mutex::new(RpcCaptureState {
            max_response_bytes: max_total_response_bytes,
            response_bytes: 0,
            pages: Vec::new(),
        }));
        let mut scoped = self.with_request_budget(budget.inner());
        scoped.rpc_execution = RpcExecution::Capture(Arc::clone(&capture));
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let request = scoped.rpc(
            &scoped.primary,
            "eth_getBlockByNumber",
            json!([format!("{block_number:#x}"), false]),
        );
        tokio::pin!(request);
        let header = tokio::select! {
            biased;
            _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                return Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded);
            }
            () = tokio::time::sleep_until(deadline_at) => {
                return if budget.is_exhausted() {
                    Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded)
                } else {
                    Err(BoundedRecordedOwnerFillSignalsError::Timeout)
                };
            }
            result = &mut request => {
                if budget.is_exhausted() {
                    return Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded);
                }
                result.map_err(BoundedRecordedOwnerFillSignalsError::Verification)?
            }
        };
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
        }
        let header = super::bind_header(&header)
            .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
        }
        let response_bytes = capture.lock().await.response_bytes;
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
        }
        if header.number != block_number {
            return Err(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::Unverified,
            ));
        }
        Ok(ObservedChainBlockAnchor {
            block_number: header.number,
            block_hash: header.hash,
            parent_hash: header.parent_hash,
            response_bytes,
        })
    }

    /// Capture one anchored receipt block and CTF V2 owner signals. It does not
    /// scan arbitrary ranges or assert continuity with another block.
    pub async fn capture_v2_owner_fill_signals_bounded(
        &self,
        block_number: u64,
        expected_parent_hash: &str,
        expected_end_hash: &str,
        budget: &TransactionRequestBudget,
        max_total_response_bytes: usize,
        total_timeout: Duration,
    ) -> Result<CapturedV2OwnerFillSignals, BoundedRecordedOwnerFillSignalsError> {
        validate_limits(max_total_response_bytes, total_timeout)?;
        let expected_parent_hash = validate_block_anchor(block_number, expected_parent_hash)?;
        let expected_end_hash = validate_hex(expected_end_hash, 32)
            .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;

        let deadline_at = tokio::time::Instant::now() + total_timeout;
        let capture = Arc::new(Mutex::new(RpcCaptureState {
            max_response_bytes: max_total_response_bytes,
            response_bytes: 0,
            pages: Vec::new(),
        }));
        let mut scoped = self.with_request_budget(budget.inner());
        scoped.rpc_execution = RpcExecution::Capture(Arc::clone(&capture));
        let mut exhaustion = budget.0.exhaustion.subscribe();
        let interval = {
            let verification = scoped.verify_receipt_interval_inner(
                block_number,
                block_number,
                &expected_parent_hash,
                &expected_end_hash,
            );
            tokio::pin!(verification);
            let deadline = tokio::time::sleep_until(deadline_at);
            tokio::pin!(deadline);
            tokio::select! {
                biased;
                _ = exhaustion.wait_for(|is_exhausted| *is_exhausted) => {
                    return Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded);
                }
                () = &mut deadline => {
                    return if budget.is_exhausted() {
                        Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded)
                    } else {
                        Err(BoundedRecordedOwnerFillSignalsError::Timeout)
                    };
                }
                result = &mut verification => {
                    if budget.is_exhausted() {
                        return Err(BoundedRecordedOwnerFillSignalsError::RequestBudgetExceeded);
                    }
                    result.map_err(BoundedRecordedOwnerFillSignalsError::Verification)?
                }
            }
        };
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
        }
        let pages = {
            let mut state = capture.lock().await;
            std::mem::take(&mut state.pages)
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(BoundedRecordedOwnerFillSignalsError::Verification(
                    ChainLogAuditError::Unverified,
                ))?
        };
        let signals = extract_ctf_v2_owner_fill_signals_with_provenance(
            &interval,
            V2OwnerFillSignalProvenance::OnlineProvidersReportFinalized,
        )
        .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;
        let captured = CapturedV2OwnerFillSignals {
            interval,
            signals,
            packet: RecordedV2OwnerFillSignalsPacket {
                packet_schema_version: RECORDED_V2_OWNER_FILL_PACKET_SCHEMA_VERSION.to_owned(),
                capture_policy_version: V2_OWNER_FILL_CAPTURE_POLICY_VERSION.to_owned(),
                signal_policy_version: CTF_V2_OWNER_FILL_SIGNAL_POLICY_VERSION.to_owned(),
                block_number,
                expected_parent_hash,
                expected_end_hash,
                transcript: RecordedChainTransactionReceiptRpcTranscript { pages },
            },
        };
        if tokio::time::Instant::now() >= deadline_at {
            return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
        }
        Ok(captured)
    }
}

/// Reverify a saved one-block transcript without constructing an RPC client or
/// selecting an endpoint. Every saved request must be consumed exactly.
pub async fn reverify_recorded_v2_owner_fill_signals_bounded(
    packet: &RecordedV2OwnerFillSignalsPacket,
    max_total_response_bytes: usize,
    total_timeout: Duration,
) -> Result<RecordedV2OwnerFillSignals, BoundedRecordedOwnerFillSignalsError> {
    validate_limits(max_total_response_bytes, total_timeout)?;
    let deadline_at = tokio::time::Instant::now() + total_timeout;
    if packet.packet_schema_version != RECORDED_V2_OWNER_FILL_PACKET_SCHEMA_VERSION
        || packet.capture_policy_version != V2_OWNER_FILL_CAPTURE_POLICY_VERSION
        || packet.signal_policy_version != CTF_V2_OWNER_FILL_SIGNAL_POLICY_VERSION
    {
        return Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified,
        ));
    }
    let expected_parent_hash =
        validate_block_anchor(packet.block_number, &packet.expected_parent_hash)?;
    let expected_end_hash = validate_hex(&packet.expected_end_hash, 32)
        .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;

    let transcript = &packet.transcript;
    if transcript.pages.is_empty() || transcript.pages.len() > MAX_RECORDED_RECEIPT_REQUESTS {
        return Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified,
        ));
    }
    let mut response_bytes = 0_usize;
    let mut primary_pages = Vec::new();
    let mut secondary_pages = Vec::new();
    for page in &transcript.pages {
        if page.request_json.len() > MAX_RECORDED_RECEIPT_REQUEST_BYTES
            || page.response_json.len() > super::MAX_RESPONSE_BYTES
        {
            return Err(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::Unverified,
            ));
        }
        response_bytes = response_bytes.checked_add(page.response_json.len()).ok_or(
            BoundedRecordedOwnerFillSignalsError::Verification(ChainLogAuditError::Unverified),
        )?;
        if response_bytes > max_total_response_bytes {
            return Err(BoundedRecordedOwnerFillSignalsError::Verification(
                ChainLogAuditError::Unverified,
            ));
        }
        match page.source {
            super::ChainRpcSourceRole::Primary => primary_pages.push(page.clone()),
            super::ChainRpcSourceRole::Secondary => secondary_pages.push(page.clone()),
        }
    }
    let full_block_hash_lookup = recorded_full_block_hash_lookup(&transcript.pages)
        .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;
    if tokio::time::Instant::now() >= deadline_at {
        return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
    }
    let replay = Arc::new(Mutex::new(RpcReplayState {
        primary_pages,
        secondary_pages,
        primary_cursor: 0,
        secondary_cursor: 0,
        max_response_bytes: max_total_response_bytes,
        response_bytes: 0,
    }));
    let verifier = ChainLogVerifier {
        client: None,
        primary: "recorded-owner-fill-primary".to_owned(),
        secondary: "recorded-owner-fill-secondary".to_owned(),
        primary_rpc_headers: reqwest::header::HeaderMap::new(),
        secondary_rpc_headers: reqwest::header::HeaderMap::new(),
        request_budget: None,
        scoped_call_targets: None,
        rpc_execution: RpcExecution::Recorded(Arc::clone(&replay)),
        full_block_hash_lookup,
    };
    let verification = verifier.verify_receipt_interval_inner(
        packet.block_number,
        packet.block_number,
        &expected_parent_hash,
        &expected_end_hash,
    );
    tokio::pin!(verification);
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);
    let interval = tokio::select! {
        biased;
        () = &mut deadline => return Err(BoundedRecordedOwnerFillSignalsError::Timeout),
        result = &mut verification => {
            result.map_err(BoundedRecordedOwnerFillSignalsError::Verification)?
        }
    };
    if !replay.lock().await.is_complete() {
        return Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::Unverified,
        ));
    }
    if tokio::time::Instant::now() >= deadline_at {
        return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
    }
    let signals = extract_ctf_v2_owner_fill_signals_with_provenance(
        &interval,
        V2OwnerFillSignalProvenance::RecordedProvidersReportedFinalized,
    )
    .map_err(BoundedRecordedOwnerFillSignalsError::Verification)?;
    let recorded = RecordedV2OwnerFillSignals {
        block_number: interval.from_block(),
        expected_parent_hash: interval.expected_parent_hash().to_owned(),
        expected_end_hash: interval.expected_end_hash().to_owned(),
        signals,
    };
    if tokio::time::Instant::now() >= deadline_at {
        return Err(BoundedRecordedOwnerFillSignalsError::Timeout);
    }
    Ok(recorded)
}

fn validate_limits(
    max_total_response_bytes: usize,
    total_timeout: Duration,
) -> Result<(), BoundedRecordedOwnerFillSignalsError> {
    if max_total_response_bytes == 0
        || max_total_response_bytes > MAX_RECORDED_RECEIPT_RESPONSE_BYTES
        || total_timeout.is_zero()
        || total_timeout > MAX_RECORDED_RECEIPT_TIMEOUT
    {
        return Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::InvalidInput,
        ));
    }
    Ok(())
}

fn validate_block_anchor(
    block_number: u64,
    expected_parent_hash: &str,
) -> Result<String, BoundedRecordedOwnerFillSignalsError> {
    if block_number == 0 {
        return Err(BoundedRecordedOwnerFillSignalsError::Verification(
            ChainLogAuditError::InvalidInput,
        ));
    }
    validate_hex(expected_parent_hash, 32)
        .map_err(BoundedRecordedOwnerFillSignalsError::Verification)
}
