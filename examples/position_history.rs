//! Read-only RPC capture; configure POLYGON_HISTORY_RPC_URL without printing it.
//! Arguments: HOLDER FROM_BLOCK THROUGH_BLOCK EXPECTED_BLOCK_HASH [MAX_BLOCKS_PER_LOG_QUERY].
//! Pagination is one bounded invocation and does not guarantee full-genesis coverage.

use std::{error::Error, time::Duration};

use polymarket_data::{
    position_history::PositionLedger,
    rpc_position_history::{RpcPositionHistoryReader, RpcPositionHistoryRequest},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(4..=5).contains(&args.len()) {
        return Err("usage: position_history HOLDER FROM_BLOCK THROUGH_BLOCK EXPECTED_BLOCK_HASH [MAX_BLOCKS_PER_LOG_QUERY]".into());
    }
    let endpoint = std::env::var("POLYGON_HISTORY_RPC_URL")
        .map_err(|_| "POLYGON_HISTORY_RPC_URL must be configured")?;
    let reader = RpcPositionHistoryReader::new(
        reqwest::Client::builder().user_agent("polymarket-data-readonly-position-history/1"),
        &endpoint,
    )?;
    let request = RpcPositionHistoryRequest {
        holder_address: args[0].clone(),
        from_block: args[1].parse()?,
        through_block: args[2].parse()?,
        expected_through_hash: args[3].clone(),
        max_requests: if args.len() == 5 { 512 } else { 6 },
        max_total_response_bytes: 32 * 1024 * 1024,
        total_timeout: Duration::from_secs(30),
    };
    let history = if let Some(width) = args.get(4) {
        reader
            .read_history_paginated(&request, width.parse()?)
            .await?
    } else {
        reader.read_history(&request).await?
    };
    let ctf = history
        .logs()
        .iter()
        .filter(|log| log.ledger() == PositionLedger::Ctf)
        .count();
    println!(
        "source_only=true logs={} ctf_logs={} native_pm_logs={} requests={} bytes={} elapsed_ms={}",
        history.logs().len(),
        ctf,
        history.logs().len() - ctf,
        history.request_count(),
        history.response_bytes(),
        history.elapsed().as_millis(),
    );
    Ok(())
}
