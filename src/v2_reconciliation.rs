//! Bounded candidate overlap, NOT canonical execution identity or coverage.
//! Mutable enrichment is deliberately excluded; raw evidence remains separate.

use std::collections::HashMap;

use rust_decimal::Decimal;
use serde_json::Value;

/// In-memory safety cap, not a selected production capacity or recovery horizon.
pub const MAX_CANDIDATE_ROWS: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid v2 candidate at row {row_index}, field {field}")]
pub struct CandidateError {
    pub row_index: usize,
    pub field: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateOverlap {
    pub matched_occurrences: usize,
    pub missing_previous_occurrences: usize,
    pub repeated_previous_occurrences: usize,
    pub repeated_refreshed_occurrences: usize,
    pub unmatched_newer_occurrences: usize,
    pub unmatched_at_or_before_previous_head: usize,
    pub extended_below_previous_oldest: bool,
}

/// A polling decision, deliberately without a `Ready`/`Complete` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadAssessment {
    Unverifiable,
    Stale,
    NoAdvance,
    Regressed,
    /// Still requires durable admission, overlap and independent verification.
    AdvancedCandidate,
}

/// Assess only observed head/cache age against a caller-selected local budget.
/// Missing cache evidence and future timestamps stay unverifiable. Neither an
/// advancing timestamp nor a cache miss proves provider publication/completeness.
/// This never grants a launch epoch, clears a gap or refreshes coverage health.
#[must_use]
pub fn assess_head(
    previous_newest: chrono::DateTime<chrono::Utc>,
    current_newest: Option<chrono::DateTime<chrono::Utc>>,
    received_at: chrono::DateTime<chrono::Utc>,
    cache_age_seconds: Option<u64>,
    max_age_seconds: u64,
) -> HeadAssessment {
    let Some(current) = current_newest else {
        return HeadAssessment::Unverifiable;
    };
    if max_age_seconds == 0 || received_at < current || received_at < previous_newest {
        return HeadAssessment::Unverifiable;
    }
    let trade_age = received_at.signed_duration_since(current).num_seconds() as u64;
    if trade_age >= max_age_seconds || cache_age_seconds.is_some_and(|age| age >= max_age_seconds) {
        return HeadAssessment::Stale;
    }
    if current < previous_newest {
        return HeadAssessment::Regressed;
    }
    if current == previous_newest {
        return HeadAssessment::NoAdvance;
    }
    if cache_age_seconds.is_none() {
        return HeadAssessment::Unverifiable;
    }
    HeadAssessment::AdvancedCandidate
}

// Never log candidate keys or turn them into purported fill IDs.
#[derive(PartialEq, Eq, Hash)]
struct Candidate {
    wallet: String,
    transaction: String,
    token: String,
    side: String,
    timestamp: i64,
    price: Decimal,
    size: Decimal,
}

fn candidate(row: &Value, row_index: usize) -> Result<Candidate, CandidateError> {
    let error = |field| CandidateError { row_index, field };
    let object = row.as_object().ok_or_else(|| error("object"))?;
    let text = |field| {
        super::require_string(object, field)
            .map(str::trim)
            .map_err(|_| error(field))
    };
    let decimal = |field| {
        let raw = super::require_number_string(object, field).map_err(|_| error(field))?;
        Decimal::from_str_exact(&raw).map_err(|_| error(field))
    };
    let timestamp = object.get("timestamp").ok_or_else(|| error("timestamp"))?;
    let timestamp = match timestamp {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
    .filter(|value| *value > 0 && *value < super::MILLISECOND_THRESHOLD)
    .filter(|value| chrono::DateTime::from_timestamp(*value, 0).is_some())
    .ok_or_else(|| error("timestamp"))?;
    let side = text("side")?.to_ascii_uppercase();
    if side != "BUY" && side != "SELL" {
        return Err(error("side"));
    }
    let price = decimal("price")?;
    let size = decimal("size")?;
    if price <= Decimal::ZERO || price > Decimal::ONE {
        return Err(error("price"));
    }
    if size <= Decimal::ZERO {
        return Err(error("size"));
    }
    let hex = |field, digits: usize| {
        let value = text(field)?.to_ascii_lowercase();
        if value.len() != digits + 2
            || !value.starts_with("0x")
            || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(error(field));
        }
        Ok(value)
    };
    let token = text("token_id")?;
    if token.len() > 78 || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error("token_id"));
    }
    Ok(Candidate {
        wallet: hex("proxy_wallet", 40)?,
        transaction: hex("transaction_hash", 64)?,
        token: token.to_owned(),
        side,
        timestamp,
        price,
        size,
    })
}

/// Compare candidate occurrences, excluding condition/profile/market metadata.
/// Even complete overlap is NOT a fill-identity or completeness proof. This
/// function never discards rows, creates events, approves readiness or clears
/// gaps; the caller must retain the raw pages and resolve execution ambiguity.
///
/// # Errors
/// Rejects an empty baseline, oversized/unordered input or an invalid candidate;
/// errors contain no raw IDs. Timestamps must be epoch seconds, not truncated
/// milliseconds; decimals must fit exactly without rounding.
pub fn compare_candidates(
    previous: &[Value],
    refreshed: &[Value],
) -> Result<CandidateOverlap, CandidateError> {
    if previous.len() > MAX_CANDIDATE_ROWS || refreshed.len() > MAX_CANDIDATE_ROWS {
        return Err(CandidateError {
            row_index: 0,
            field: "row_limit",
        });
    }
    let previous = previous
        .iter()
        .enumerate()
        .map(|(index, row)| candidate(row, index))
        .collect::<Result<Vec<_>, _>>()?;
    let refreshed = refreshed
        .iter()
        .enumerate()
        .map(|(index, row)| candidate(row, index))
        .collect::<Result<Vec<_>, _>>()?;
    for rows in [&previous, &refreshed] {
        if let Some(index) = rows
            .windows(2)
            .position(|pair| pair[0].timestamp < pair[1].timestamp)
        {
            return Err(CandidateError {
                row_index: index + 1,
                field: "ordering",
            });
        }
    }
    let head = previous
        .iter()
        .map(|row| row.timestamp)
        .max()
        .ok_or(CandidateError {
            row_index: 0,
            field: "baseline",
        })?;
    let oldest = previous.iter().map(|row| row.timestamp).min().unwrap();
    let mut remaining = HashMap::<&Candidate, usize>::new();
    for row in &previous {
        *remaining.entry(row).or_default() += 1;
    }
    let mut refreshed_counts = HashMap::<&Candidate, usize>::new();
    for row in &refreshed {
        *refreshed_counts.entry(row).or_default() += 1;
    }
    let mut result = CandidateOverlap {
        matched_occurrences: 0,
        missing_previous_occurrences: previous.len(),
        repeated_previous_occurrences: previous.len() - remaining.len(),
        repeated_refreshed_occurrences: refreshed.len() - refreshed_counts.len(),
        unmatched_newer_occurrences: 0,
        unmatched_at_or_before_previous_head: 0,
        extended_below_previous_oldest: refreshed.iter().any(|row| row.timestamp < oldest),
    };
    for row in &refreshed {
        if let Some(count) = remaining.get_mut(row).filter(|count| **count > 0) {
            *count -= 1;
            result.matched_occurrences += 1;
            result.missing_previous_occurrences -= 1;
        } else if row.timestamp > head {
            result.unmatched_newer_occurrences += 1;
        } else {
            result.unmatched_at_or_before_previous_head += 1;
        }
    }
    Ok(result)
}
