//! Deterministic gross depth calculations over one validated CLOB book.
//!
//! Quotes retain the selected book identity and raw millisecond timestamp. They
//! contain no fee, currency conversion, freshness or execution inference.

use rust_decimal::Decimal;

use super::{BookLevel, BookObservation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuyDepthQuote {
    pub requested_notional: Decimal,
    pub filled_notional: Decimal,
    pub filled_quantity: Decimal,
    pub vwap_price: Decimal,
    pub asset_id: String,
    pub book_hash: String,
    pub book_timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellDepthQuote {
    pub requested_quantity: Decimal,
    pub filled_quantity: Decimal,
    pub gross_proceeds: Decimal,
    pub vwap_price: Decimal,
    pub asset_id: String,
    pub book_hash: String,
    pub book_timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DepthQuoteError {
    #[error("depth request must be positive")]
    InvalidRequest,
    #[error("book depth is empty")]
    EmptyDepth,
    #[error("book level is malformed")]
    MalformedBook,
    #[error("book depth arithmetic is not representable")]
    Arithmetic,
}

/// Return the highest validated bid from this book.
///
/// # Errors
/// Returns an error if any bid is invalid or if the bid side is empty.
pub fn best_bid(book: &BookObservation) -> Result<Decimal, DepthQuoteError> {
    validated_levels(&book.bids)?
        .into_iter()
        .map(|(price, _)| price)
        .max()
        .ok_or(DepthQuoteError::EmptyDepth)
}

/// Walk asks in ascending price order for a gross quote at the requested notional.
/// Partial depth is returned when the book cannot fill the requested amount.
///
/// # Errors
/// Rejects non-positive requests, malformed relevant levels, empty asks and
/// arithmetic that cannot be represented by `Decimal`.
pub fn quote_buy(
    book: &BookObservation,
    requested_notional: Decimal,
) -> Result<BuyDepthQuote, DepthQuoteError> {
    if requested_notional <= Decimal::ZERO {
        return Err(DepthQuoteError::InvalidRequest);
    }
    let mut levels = validated_levels(&book.asks)?;
    if levels.is_empty() {
        return Err(DepthQuoteError::EmptyDepth);
    }
    levels.sort_unstable_by_key(|(price, _)| *price);

    let mut remaining = requested_notional;
    let mut filled_notional = Decimal::ZERO;
    let mut filled_quantity = Decimal::ZERO;
    for (price, size) in levels {
        let level_notional = price.checked_mul(size).ok_or(DepthQuoteError::Arithmetic)?;
        let consumed_notional = remaining.min(level_notional);
        let consumed_quantity = consumed_notional
            .checked_div(price)
            .ok_or(DepthQuoteError::Arithmetic)?;
        filled_notional = filled_notional
            .checked_add(consumed_notional)
            .ok_or(DepthQuoteError::Arithmetic)?;
        filled_quantity = filled_quantity
            .checked_add(consumed_quantity)
            .ok_or(DepthQuoteError::Arithmetic)?;
        remaining = remaining
            .checked_sub(consumed_notional)
            .ok_or(DepthQuoteError::Arithmetic)?;
        if remaining.is_zero() {
            break;
        }
    }
    if filled_quantity.is_zero() {
        return Err(DepthQuoteError::EmptyDepth);
    }
    let vwap_price = filled_notional
        .checked_div(filled_quantity)
        .ok_or(DepthQuoteError::Arithmetic)?;
    Ok(BuyDepthQuote {
        requested_notional,
        filled_notional,
        filled_quantity,
        vwap_price,
        asset_id: book.asset_id.clone(),
        book_hash: book.hash.clone(),
        book_timestamp: book.timestamp.clone(),
    })
}

/// Walk bids in descending price order for a gross quote at the requested quantity.
/// Partial depth is returned; a host that requires a full sell must enforce it.
///
/// # Errors
/// Rejects non-positive requests, malformed relevant levels, empty bids and
/// arithmetic that cannot be represented by `Decimal`.
pub fn quote_sell(
    book: &BookObservation,
    requested_quantity: Decimal,
) -> Result<SellDepthQuote, DepthQuoteError> {
    if requested_quantity <= Decimal::ZERO {
        return Err(DepthQuoteError::InvalidRequest);
    }
    let mut levels = validated_levels(&book.bids)?;
    if levels.is_empty() {
        return Err(DepthQuoteError::EmptyDepth);
    }
    levels.sort_unstable_by(|(left, _), (right, _)| right.cmp(left));

    let mut remaining = requested_quantity;
    let mut gross_proceeds = Decimal::ZERO;
    let mut filled_quantity = Decimal::ZERO;
    for (price, size) in levels {
        let consumed = remaining.min(size);
        let proceeds = price
            .checked_mul(consumed)
            .ok_or(DepthQuoteError::Arithmetic)?;
        gross_proceeds = gross_proceeds
            .checked_add(proceeds)
            .ok_or(DepthQuoteError::Arithmetic)?;
        filled_quantity = filled_quantity
            .checked_add(consumed)
            .ok_or(DepthQuoteError::Arithmetic)?;
        remaining = remaining
            .checked_sub(consumed)
            .ok_or(DepthQuoteError::Arithmetic)?;
        if remaining.is_zero() {
            break;
        }
    }
    if filled_quantity.is_zero() {
        return Err(DepthQuoteError::EmptyDepth);
    }
    let vwap_price = gross_proceeds
        .checked_div(filled_quantity)
        .ok_or(DepthQuoteError::Arithmetic)?;
    Ok(SellDepthQuote {
        requested_quantity,
        filled_quantity,
        gross_proceeds,
        vwap_price,
        asset_id: book.asset_id.clone(),
        book_hash: book.hash.clone(),
        book_timestamp: book.timestamp.clone(),
    })
}

fn validated_levels(levels: &[BookLevel]) -> Result<Vec<(Decimal, Decimal)>, DepthQuoteError> {
    levels
        .iter()
        .map(|level| {
            let price = Decimal::from_str_exact(&level.price)
                .map_err(|_| DepthQuoteError::MalformedBook)?;
            let size =
                Decimal::from_str_exact(&level.size).map_err(|_| DepthQuoteError::MalformedBook)?;
            if price <= Decimal::ZERO || price > Decimal::ONE || size <= Decimal::ZERO {
                return Err(DepthQuoteError::MalformedBook);
            }
            Ok((price, size))
        })
        .collect()
}
