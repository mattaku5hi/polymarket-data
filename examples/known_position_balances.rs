//! Read-only proof batch. Arguments: PRIVATE_INPUT_JSON PRIVATE_OUTPUT_JSON.
//! Configure POLYGON_BALANCE_RPC_PRIMARY and POLYGON_BALANCE_RPC_SECONDARY.
//! Input: {owner, block_number, block_hash, ids:[{namespace:"ctf"|"position_manager",id:"0x…"}]}.
//! Output contains private holder/ID data; stdout contains counts only.

#[cfg(not(feature = "chain-audit"))]
fn main() {
    eprintln!("known_position_balances requires --features chain-audit");
    std::process::exit(1);
}

#[cfg(feature = "chain-audit")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use alloy_primitives::B256;
    use polymarket_data::chain_log_audit::{
        ChainLogVerifier, KnownPositionBalanceId, KnownPositionBalanceNamespace,
    };
    use serde::Deserialize;
    use serde_json::json;
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        time::Duration,
    };

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        owner: String,
        block_number: u64,
        block_hash: String,
        ids: Vec<Asset>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Asset {
        namespace: String,
        id: String,
    }

    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: known_position_balances PRIVATE_INPUT_JSON PRIVATE_OUTPUT_JSON".into());
    }
    let mut raw = Vec::new();
    std::fs::File::open(&args[0])
        .map_err(|_| "cannot read input manifest")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read input manifest")?;
    if raw.len() > 1024 * 1024 {
        return Err("input manifest exceeds 1 MiB".into());
    }
    let input: Input = serde_json::from_slice(&raw).map_err(|_| "invalid input manifest")?;
    let ids: Vec<_> = input
        .ids
        .iter()
        .map(|asset| {
            let namespace = match asset.namespace.as_str() {
                "ctf" => KnownPositionBalanceNamespace::Ctf,
                "position_manager" => KnownPositionBalanceNamespace::PositionManager,
                _ => return Err("invalid namespace"),
            };
            Ok(KnownPositionBalanceId {
                namespace,
                id: asset.id.parse::<B256>().map_err(|_| "invalid ID word")?,
            })
        })
        .collect::<Result<_, &str>>()?;
    let primary = std::env::var("POLYGON_BALANCE_RPC_PRIMARY")
        .map_err(|_| "POLYGON_BALANCE_RPC_PRIMARY must be configured")?;
    let secondary = std::env::var("POLYGON_BALANCE_RPC_SECONDARY")
        .map_err(|_| "POLYGON_BALANCE_RPC_SECONDARY must be configured")?;
    let observation = ChainLogVerifier::new(&primary, &secondary)?
        .verify_known_position_balances_bounded(
            &input.owner,
            &ids,
            input.block_number,
            &input.block_hash,
            80,
            Duration::from_secs(60),
        )
        .await?;
    let rows: Vec<_> = observation
        .rows()
        .iter()
        .map(|row| {
            json!({
                "namespace": match row.namespace() {
                    KnownPositionBalanceNamespace::Ctf => "ctf",
                    KnownPositionBalanceNamespace::PositionManager => "position_manager",
                },
                "id": format!("{:#x}", row.id()),
                "balance": row.balance().to_string(),
            })
        })
        .collect();
    let output = serde_json::to_vec(&json!({
        "owner": observation.owner(), "block_number": observation.block_number(),
        "block_hash": observation.block_hash(), "state_root": observation.state_root(),
        "policy": observation.source_policy_version(), "rows": rows,
        "requests": observation.request_count(), "history_complete": false,
        "qualified": false,
    }))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&args[1])
        .map_err(|_| "cannot create private output")?;
    file.write_all(&output)?;
    file.sync_all()?;
    println!(
        "point_balances_only=true ids={} requests={} history_complete=false qualified=false",
        observation.rows().len(),
        observation.request_count(),
    );
    Ok(())
}
