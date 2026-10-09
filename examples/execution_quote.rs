//! Read-only quote smoke: CONDITION_ID ASSET_ID buy|sell AMOUNT.
//! BUY amount is gross notional; fees are additional modeled cash.

use std::{error::Error, time::Duration};

use polymarket_data::clob::{
    execution_context::{ClobExecutionContextReader, ExecutionContextRequest},
    execution_quote::{ExecutionQuoteSide, estimate_execution_quote},
};
use rust_decimal::Decimal;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: execution_quote CONDITION_ID ASSET_ID buy|sell AMOUNT".into());
    }
    let side = match args[2].as_str() {
        "buy" => ExecutionQuoteSide::Buy,
        "sell" => ExecutionQuoteSide::Sell,
        _ => return Err("side must be buy or sell".into()),
    };
    let amount = Decimal::from_str_exact(&args[3])?;
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
    let quote = estimate_execution_quote(&context, side, amount, Duration::from_secs(10))?;
    quote.check_validity()?;
    println!(
        "protocol={:?} side={:?} shares={} gross={} estimated_fee={} buy_total={:?} sell_net={:?} unspent_buy_budget={:?} cash_unit={:?} fee_model={} local_ttl_ms={}",
        quote.protocol_version(),
        quote.side(),
        quote.gross_shares(),
        quote.gross_notional(),
        quote.estimated_platform_fee(),
        quote.total_buy_cash(),
        quote.net_sell_proceeds(),
        quote.unspent_buy_budget(),
        quote.fee_currency(),
        quote.fee_model_version(),
        quote
            .valid_until()
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis(),
    );
    Ok(())
}
