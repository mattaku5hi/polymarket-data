//! Read-only quote smoke: CONDITION_ID ASSET_ID MODE AMOUNT [MAX_PRICE].
//! BUY is gross notional; BUY-all-in caps gross plus modeled fees.

use std::{error::Error, time::Duration};

use polymarket_data::clob::{
    execution_context::{ClobExecutionContextReader, ExecutionContextRequest},
    execution_quote::{
        ExecutionQuoteSide, MarketBuyBudget, estimate_all_in_buy_execution_quote,
        estimate_execution_quote, estimate_normalized_market_buy_quote,
        estimate_protected_market_buy_quote,
    },
};
use rust_decimal::Decimal;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !matches!(args.len(), 4 | 5) {
        return Err(
            "usage: execution_quote CONDITION_ID ASSET_ID buy|buy-all-in|buy-normalized|buy-all-in-normalized|buy-protected|buy-all-in-protected|sell AMOUNT [MAX_PRICE]".into(),
        );
    }
    let side = match args[2].as_str() {
        "buy"
        | "buy-all-in"
        | "buy-normalized"
        | "buy-all-in-normalized"
        | "buy-protected"
        | "buy-all-in-protected" => ExecutionQuoteSide::Buy,
        "sell" => ExecutionQuoteSide::Sell,
        _ => return Err("unsupported quote mode".into()),
    };
    let amount = Decimal::from_str_exact(&args[3])?;
    let protected_mode = matches!(args[2].as_str(), "buy-protected" | "buy-all-in-protected");
    let max_price = match (protected_mode, args.get(4)) {
        (true, Some(value)) => Some(Decimal::from_str_exact(value)?),
        (true, None) => return Err("protected BUY requires MAX_PRICE".into()),
        (false, Some(_)) => return Err("MAX_PRICE is only valid for protected BUY".into()),
        (false, None) => None,
    };
    let reader = ClobExecutionContextReader::with_client_builder(
        reqwest::Client::builder().user_agent("polymarket-data-readonly-quote-example/1"),
        "https://clob.polymarket.com",
        "https://gamma-api.polymarket.com",
    )?;
    let context = reader
        .read_context(&ExecutionContextRequest {
            api_condition_id: args[0].clone(),
            selected_asset_id: args[1].clone(),
            max_requests: 3,
            total_timeout: Duration::from_secs(5),
        })
        .await?;
    let max_age = Duration::from_secs(10);
    let normalized = match args[2].as_str() {
        "buy-normalized" => Some(estimate_normalized_market_buy_quote(
            &context,
            MarketBuyBudget::GrossNotional(amount),
            max_age,
        )?),
        "buy-all-in-normalized" => Some(estimate_normalized_market_buy_quote(
            &context,
            MarketBuyBudget::AllInCash(amount),
            max_age,
        )?),
        _ => None,
    };
    let protected = if let Some(max_price) = max_price {
        let budget = if args[2] == "buy-all-in-protected" {
            MarketBuyBudget::AllInCash(amount)
        } else {
            MarketBuyBudget::GrossNotional(amount)
        };
        Some(estimate_protected_market_buy_quote(
            &context, budget, max_price, max_age,
        )?)
    } else {
        None
    };
    let quote = if let Some(protected) = &protected {
        protected.quote().clone()
    } else if let Some(normalized) = &normalized {
        normalized.quote().clone()
    } else if args[2] == "buy-all-in" {
        estimate_all_in_buy_execution_quote(&context, amount, Duration::from_secs(10))?
    } else {
        estimate_execution_quote(&context, side, amount, Duration::from_secs(10))?
    };
    quote.check_validity()?;
    if let Some(normalized) = &normalized {
        println!(
            "normalized_maker_notional={} reserved_buy_cash={} maker_policy={}",
            normalized.normalized_maker_notional(),
            normalized.reserved_buy_cash(),
            normalized.maker_amount_policy_version(),
        );
    }
    if let Some(protected) = &protected {
        println!(
            "normalized_maker_notional={} maker_cash_base_units={} taker_share_base_units={} max_price={} reserved_buy_cash={} amount_policy={}",
            protected.normalized_maker_notional(),
            protected.maker_cash_base_units(),
            protected.taker_share_base_units(),
            protected.max_price(),
            protected.reserved_buy_cash(),
            protected.order_amount_policy_version(),
        );
    }
    println!(
        "protocol={:?} side={:?} amount_kind={:?} shares={} gross={} estimated_fee={} buy_total={:?} sell_net={:?} unspent_buy_budget={:?} cash_unit={:?} fee_model={} client_minimum={:?} minimum_basis={:?} minimum_check_amount={} venue_minimum={:?} local_ttl_ms={}",
        quote.protocol_version(),
        quote.side(),
        quote.amount_kind(),
        quote.gross_shares(),
        quote.gross_notional(),
        quote.estimated_platform_fee(),
        quote.total_buy_cash(),
        quote.net_sell_proceeds(),
        quote.unspent_buy_budget(),
        quote.fee_currency(),
        quote.fee_model_version(),
        quote.market_minimum_status(),
        quote.market_minimum_basis(),
        quote.market_minimum_check_amount(),
        quote.venue_minimum_status(),
        quote
            .valid_until()
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis(),
    );
    Ok(())
}
