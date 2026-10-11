#![cfg(feature = "chain-audit")]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use alloy_primitives::U256;
use alloy_rlp::Header as RlpHeader;
use alloy_trie::root::ordered_trie_root_encoded;
use axum::{Json, Router, extract::State};
use polymarket_data::{
    chain_log_audit::{ChainLogVerifier, ChainTransactionReceiptEvidence},
    position_history::{
        CTF_EMITTER, POSITION_MANAGER_EMITTER, PositionLedger, TRANSFER_BATCH_TOPIC,
        TRANSFER_SINGLE_TOPIC,
    },
    position_history_receipts::{
        PositionHistoryReceiptJoinError, PositionHistoryReceiptSourceKind,
        bind_position_history_receipts, bind_recorded_position_history_receipts,
        validate_position_history_source_agreement,
    },
    rpc_position_history::{
        RecordedRpcPositionHistoryPage, RpcPositionHistoryReader, RpcPositionHistoryRequest,
        reverify_recorded_rpc_position_history_segment,
    },
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const FIXTURE: &str =
    include_str!("fixtures/fifth-native-binary-activity-partial-redemption-rpc.json");
const OWNER: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
const OTHER_HOLDER: &str = "0x4646464646464646464646464646464646464646";

#[derive(Clone)]
struct ReplayState {
    fixture: Arc<Value>,
}

#[derive(Clone, Copy)]
enum SourceVariant {
    Exact,
    ChangedData,
    ChangedLocator,
    ChangedTransactionIndex,
    OmitOneMatchingLog,
}

#[derive(Clone)]
struct SourceState {
    transfers: Arc<Vec<Value>>,
    headers: Arc<BTreeMap<u64, Value>>,
    finalized: Value,
    variant: SourceVariant,
}

async fn replay_rpc(State(state): State<ReplayState>, Json(request): Json<Value>) -> Json<Value> {
    let method = request["method"].as_str().unwrap_or_default();
    let params = &request["params"];
    let result = if method == "eth_getTransactionReceipt" {
        let hash = params[0].as_str().unwrap_or_default();
        state
            .fixture
            .get("rpc_responses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|row| row["method"] == "eth_getBlockReceipts")
            .filter_map(|row| row["result"].as_array())
            .flatten()
            .find(|receipt| receipt["transactionHash"] == hash)
            .cloned()
    } else {
        state
            .fixture
            .get("rpc_responses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|row| row["method"] == method && row["params"] == *params)
            .and_then(|row| row.get("result"))
            .cloned()
    };
    match result {
        Some(result) => Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result})),
        None => Json(
            json!({"jsonrpc":"2.0", "id":request["id"], "error":{"code":-32601,"message":"unmatched replay request"}}),
        ),
    }
}

async fn source_rpc(State(state): State<SourceState>, Json(request): Json<Value>) -> Json<Value> {
    let method = request["method"].as_str().unwrap_or_default();
    let params = &request["params"];
    let result = match method {
        "eth_chainId" => json!("0x89"),
        "eth_getBlockByNumber" if params[0] == "finalized" => state.finalized.clone(),
        "eth_getBlockByNumber" => params[0]
            .as_str()
            .and_then(parse_quantity)
            .and_then(|number| state.headers.get(&number).cloned())
            .unwrap_or(Value::Null),
        "eth_getLogs" => {
            let filter = &params[0];
            let from = filter["fromBlock"]
                .as_str()
                .and_then(parse_quantity)
                .unwrap();
            let through = filter["toBlock"].as_str().and_then(parse_quantity).unwrap();
            let topics = filter["topics"].as_array().unwrap();
            let matches_holder = |log: &Value| {
                topics
                    .get(2)
                    .and_then(Value::as_str)
                    .is_none_or(|topic| log["topics"][2] == topic)
                    && topics
                        .get(3)
                        .and_then(Value::as_str)
                        .is_none_or(|topic| log["topics"][3] == topic)
            };
            let mut logs = state
                .transfers
                .iter()
                .filter(|log| {
                    log["blockNumber"]
                        .as_str()
                        .and_then(parse_quantity)
                        .is_some_and(|number| (from..=through).contains(&number))
                        && matches_holder(log)
                })
                .cloned()
                .collect::<Vec<_>>();
            match state.variant {
                SourceVariant::Exact => {}
                SourceVariant::ChangedData => {
                    for log in &mut logs {
                        let mut data = log["data"].as_str().unwrap().to_owned();
                        let replacement = if &data[2..3] == "0" { "1" } else { "0" };
                        data.replace_range(2..3, replacement);
                        log["data"] = json!(data);
                    }
                }
                SourceVariant::ChangedLocator => {
                    for log in &mut logs {
                        let index = log["logIndex"].as_str().and_then(parse_quantity).unwrap();
                        log["logIndex"] = json!(format!("0x{:x}", index + 1000));
                    }
                }
                SourceVariant::ChangedTransactionIndex => {
                    for log in &mut logs {
                        let index = log["transactionIndex"]
                            .as_str()
                            .and_then(parse_quantity)
                            .unwrap();
                        log["transactionIndex"] = json!(format!("0x{:x}", index + 1));
                    }
                }
                SourceVariant::OmitOneMatchingLog => {
                    logs.pop();
                }
            }
            json!(logs)
        }
        _ => Value::Null,
    };
    Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
}

async fn serve<T>(
    state: T,
    route: axum::routing::MethodRouter<T>,
) -> (String, tokio::task::JoinHandle<()>)
where
    T: Clone + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/", route).with_state(state))
            .await
            .unwrap();
    });
    (format!("http://{address}/"), task)
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

// This packet changes two receipt logs and recomputes the ordered receipt root and block hash.
// The verifier seals the evidence through its public loopback API; the packet proves trie/root
// binding only, not EVM execution or bloom correctness as an execution claim.
fn synthetic_ctf_batch_fixture(malformed_batch: bool, native_batch: bool) -> Value {
    let mut fixture = fixture();
    let original_header = fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["method"] == "eth_getBlockByNumber"
                && row["params"][0] == "0x64"
                && row["params"][1] == false
        })
        .unwrap();
    assert_eq!(
        header_hash(&original_header["result"]),
        original_header["result"]["hash"]
    );
    let receipts_row = fixture["rpc_responses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["method"] == "eth_getBlockReceipts")
        .unwrap();
    let receipts = receipts_row["result"].as_array_mut().unwrap();
    let receipt = receipts
        .iter_mut()
        .find(|receipt| {
            receipt["logs"].as_array().is_some_and(|logs| {
                logs.iter().any(|log| {
                    log["topics"][0] == TRANSFER_SINGLE_TOPIC
                        && log["topics"][3] == format!("0x{:0>64}", &OWNER[2..])
                })
            })
        })
        .unwrap();
    let mut owner_logs = receipt["logs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|log| {
            log["topics"][0] == TRANSFER_SINGLE_TOPIC
                && log["topics"][3] == format!("0x{:0>64}", &OWNER[2..])
        })
        .collect::<Vec<_>>();
    assert_eq!(owner_logs.len(), 2);
    owner_logs[0]["address"] = json!(CTF_EMITTER);
    owner_logs[0]["data"] = json!(single_data(111, 5));
    owner_logs[1]["address"] = json!(if native_batch {
        POSITION_MANAGER_EMITTER
    } else {
        CTF_EMITTER
    });
    owner_logs[1]["topics"][0] = json!(TRANSFER_BATCH_TOPIC);
    owner_logs[1]["data"] = json!(if malformed_batch {
        "0x00".to_owned()
    } else {
        batch_data(&[if native_batch { 111 } else { 201 }, 202], &[7, 9])
    });

    let mut block_bloom = [0_u8; 256];
    for receipt in receipts.iter_mut() {
        let bloom = receipt_logs_bloom(&receipt["logs"]);
        receipt["logsBloom"] = json!(format!("0x{}", hex::encode(bloom)));
        for (to, from) in block_bloom.iter_mut().zip(bloom) {
            *to |= from;
        }
    }
    let encoded_receipts = receipts.iter().map(encode_receipt).collect::<Vec<_>>();
    let receipts_root = format!("{:#x}", ordered_trie_root_encoded(&encoded_receipts));

    let response_rows = fixture["rpc_responses"].as_array_mut().unwrap();
    for row in response_rows.iter_mut() {
        if row["method"] == "eth_getBlockByNumber" && row["params"][0] == "0x64" {
            row["result"]["receiptsRoot"] = json!(receipts_root);
            row["result"]["logsBloom"] = json!(format!("0x{}", hex::encode(block_bloom)));
        }
    }
    let new_hash = fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["method"] == "eth_getBlockByNumber"
                && row["params"][0] == "0x64"
                && row["params"][1] == false
        })
        .map(|row| header_hash(&row["result"]))
        .unwrap();
    let response_rows = fixture["rpc_responses"].as_array_mut().unwrap();
    for row in response_rows.iter_mut() {
        if row["method"] == "eth_getBlockByNumber" && row["params"][0] == "0x64" {
            row["result"]["hash"] = json!(new_hash);
            if let Some(transactions) = row["result"]["transactions"].as_array_mut() {
                for transaction in transactions {
                    if transaction.is_object() {
                        transaction["blockHash"] = json!(new_hash);
                    }
                }
            }
        }
        if row["method"] == "eth_getLogs" {
            if let Some(logs) = row["result"].as_array_mut() {
                for log in logs {
                    if log["blockNumber"] == "0x64" {
                        log["blockHash"] = json!(new_hash);
                    }
                }
            }
        }
    }
    for receipt in fixture["rpc_responses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|row| row["method"] == "eth_getBlockReceipts")
        .flat_map(|row| row["result"].as_array_mut().unwrap())
    {
        receipt["blockHash"] = json!(new_hash);
        for log in receipt["logs"].as_array_mut().unwrap() {
            log["blockHash"] = json!(new_hash);
        }
    }
    assert_eq!(
        header_hash(
            &fixture["rpc_responses"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| {
                    row["method"] == "eth_getBlockByNumber"
                        && row["params"][0] == "0x64"
                        && row["params"][1] == false
                })
                .unwrap()["result"]
        ),
        new_hash
    );
    fixture
}

fn single_data(id: u64, amount: u64) -> String {
    format!("0x{id:064x}{amount:064x}")
}

fn batch_data(ids: &[u64], amounts: &[u64]) -> String {
    assert_eq!(ids.len(), amounts.len());
    let amount_offset = 64 + 32 + 32 * ids.len();
    let mut data = format!("0x{:064x}{:064x}{:064x}", 64, amount_offset, ids.len());
    for id in ids {
        data.push_str(&format!("{id:064x}"));
    }
    data.push_str(&format!("{:064x}", amounts.len()));
    for amount in amounts {
        data.push_str(&format!("{amount:064x}"));
    }
    data
}

fn encode_receipt(receipt: &Value) -> Vec<u8> {
    let encoded_logs = receipt["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| {
            let topics = log["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|topic| {
                    alloy_rlp::encode(
                        hex::decode(topic.as_str().unwrap().trim_start_matches("0x"))
                            .unwrap()
                            .as_slice(),
                    )
                })
                .collect::<Vec<_>>();
            rlp_list(&[
                alloy_rlp::encode(
                    hex::decode(log["address"].as_str().unwrap().trim_start_matches("0x"))
                        .unwrap()
                        .as_slice(),
                ),
                rlp_list(&topics),
                alloy_rlp::encode(
                    hex::decode(log["data"].as_str().unwrap().trim_start_matches("0x"))
                        .unwrap()
                        .as_slice(),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let body = rlp_list(&[
        alloy_rlp::encode(parse_quantity(receipt["status"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(parse_quantity(receipt["cumulativeGasUsed"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(
            hex::decode(
                receipt["logsBloom"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap()
            .as_slice(),
        ),
        rlp_list(&encoded_logs),
    ]);
    let kind = parse_quantity(receipt["type"].as_str().unwrap()).unwrap();
    if kind == 0 {
        body
    } else {
        let mut typed = vec![u8::try_from(kind).unwrap()];
        typed.extend_from_slice(&body);
        typed
    }
}

fn receipt_logs_bloom(logs: &Value) -> [u8; 256] {
    let mut bloom = [0_u8; 256];
    for log in logs.as_array().unwrap() {
        bloom_add(
            &mut bloom,
            hex::decode(log["address"].as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .as_slice(),
        );
        for topic in log["topics"].as_array().unwrap() {
            bloom_add(
                &mut bloom,
                hex::decode(topic.as_str().unwrap().trim_start_matches("0x"))
                    .unwrap()
                    .as_slice(),
            );
        }
    }
    bloom
}

fn bloom_add(bloom: &mut [u8; 256], value: &[u8]) {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(value);
    for offset in [0, 2, 4] {
        let bit = (usize::from(hash[offset]) << 8 | usize::from(hash[offset + 1])) & 2047;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

fn header_hash(header: &Value) -> String {
    use sha3::{Digest, Keccak256};
    let mut fields = vec![
        fixed_rlp(header, "parentHash"),
        fixed_rlp(header, "sha3Uncles"),
        fixed_rlp(header, "miner"),
        fixed_rlp(header, "stateRoot"),
        fixed_rlp(header, "transactionsRoot"),
        fixed_rlp(header, "receiptsRoot"),
        fixed_rlp(header, "logsBloom"),
        big_quantity_rlp(header["difficulty"].as_str().unwrap()),
        alloy_rlp::encode(parse_quantity(header["number"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(parse_quantity(header["gasLimit"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(parse_quantity(header["gasUsed"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(parse_quantity(header["timestamp"].as_str().unwrap()).unwrap()),
        alloy_rlp::encode(
            hex::decode(
                header["extraData"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap()
            .as_slice(),
        ),
        fixed_rlp(header, "mixHash"),
        fixed_rlp(header, "nonce"),
    ];
    let optional = [
        header.get("baseFeePerGas"),
        header.get("withdrawalsRoot"),
        header.get("blobGasUsed"),
        header.get("excessBlobGas"),
        header.get("parentBeaconBlockRoot"),
        header.get("requestsHash"),
    ];
    if let Some(last) = optional
        .iter()
        .rposition(|field| field.is_some_and(|v| !v.is_null()))
    {
        for field in optional.into_iter().take(last + 1) {
            fields.push(match field.filter(|field| !field.is_null()) {
                Some(value)
                    if value
                        .as_str()
                        .is_some_and(|s| s.starts_with("0x") && s.len() == 66) =>
                {
                    alloy_rlp::encode(
                        hex::decode(value.as_str().unwrap().trim_start_matches("0x"))
                            .unwrap()
                            .as_slice(),
                    )
                }
                Some(value) => big_quantity_rlp(value.as_str().unwrap()),
                None => alloy_rlp::encode(&[][..]),
            });
        }
    }
    format!("0x{}", hex::encode(Keccak256::digest(rlp_list(&fields))))
}

fn fixed_rlp(header: &Value, field: &str) -> Vec<u8> {
    alloy_rlp::encode(
        hex::decode(header[field].as_str().unwrap().trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
}

fn big_quantity_rlp(quantity: &str) -> Vec<u8> {
    let digits = quantity.trim_start_matches("0x");
    let padded;
    let digits = if digits.len() % 2 == 0 {
        digits
    } else {
        padded = format!("0{digits}");
        &padded
    };
    let bytes = hex::decode(digits).unwrap();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    alloy_rlp::encode(&bytes[first_nonzero..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut result = Vec::new();
    RlpHeader {
        list: true,
        payload_length: items.iter().map(Vec::len).sum(),
    }
    .encode(&mut result);
    for item in items {
        result.extend_from_slice(item);
    }
    result
}

fn fixture_header(fixture: &Value, number: u64) -> Value {
    fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["method"] == "eth_getBlockByNumber"
                && row["params"][0] == format!("0x{number:x}")
                && row["params"][1] == false
        })
        .unwrap()["result"]
        .clone()
}

fn fixture_finalized(fixture: &Value) -> Value {
    fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["method"] == "eth_getBlockByNumber" && row["params"][0] == "finalized")
        .unwrap()["result"]
        .clone()
}

fn transfer_logs(receipt: &Value) -> Vec<Value> {
    receipt["logs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|log| {
            matches!(
                log["topics"][0].as_str(),
                Some("0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62")
                    | Some("0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb")
            )
        })
        .cloned()
        .collect()
}

fn fixture_receipt_and_hash(fixture: &Value) -> (Value, String) {
    let receipt = fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["method"] == "eth_getBlockReceipts")
        .flat_map(|row| row["result"].as_array().unwrap())
        .find(|receipt| {
            receipt["logs"].as_array().is_some_and(|logs| {
                logs.iter().any(|log| {
                    log["topics"][0]
                        == "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
                        && log["topics"][3] == format!("0x{:0>64}", &OWNER[2..])
                })
            })
        })
        .unwrap()
        .clone();
    (
        receipt.clone(),
        receipt["transactionHash"].as_str().unwrap().to_owned(),
    )
}

async fn start_replay(fixture: Value) -> (String, tokio::task::JoinHandle<()>) {
    serve(
        ReplayState {
            fixture: Arc::new(fixture),
        },
        axum::routing::post(replay_rpc),
    )
    .await
}

async fn rooted_receipt(fixture: &Value, tx_hash: &str) -> ChainTransactionReceiptEvidence {
    let (primary, primary_task) = start_replay(fixture.clone()).await;
    let (secondary, secondary_task) = start_replay(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let evidence = verifier
        .verify_transaction_receipt_observation_bounded(tx_hash, 128, Duration::from_secs(10))
        .await
        .unwrap();
    primary_task.abort();
    secondary_task.abort();
    evidence
}

fn unrelated_transaction_hash(fixture: &Value, selected_hash: &str) -> String {
    fixture["rpc_responses"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["method"] == "eth_getBlockReceipts")
        .flat_map(|row| row["result"].as_array().unwrap())
        .map(|receipt| receipt["transactionHash"].as_str().unwrap())
        .find(|hash| *hash != selected_hash)
        .unwrap()
        .to_owned()
}

fn source_state(fixture: &Value, variant: SourceVariant) -> SourceState {
    let (receipt, _) = fixture_receipt_and_hash(fixture);
    let headers = [99, 100]
        .into_iter()
        .map(|number| (number, fixture_header(fixture, number)))
        .collect();
    SourceState {
        transfers: Arc::new(transfer_logs(&receipt)),
        headers: Arc::new(headers),
        finalized: fixture_finalized(fixture),
        variant,
    }
}

async fn history_observation(
    fixture: &Value,
    variant: SourceVariant,
    width: u64,
    holder: &str,
    from_block: u64,
    through_block: u64,
) -> polymarket_data::rpc_position_history::RpcPositionHistoryObservation {
    let state = source_state(fixture, variant);
    let (endpoint, task) = serve(state, axum::routing::post(source_rpc)).await;
    let reader = RpcPositionHistoryReader::new(reqwest::Client::builder(), &endpoint).unwrap();
    let header = fixture_header(fixture, through_block);
    let request = RpcPositionHistoryRequest {
        holder_address: holder.to_owned(),
        from_block,
        through_block,
        expected_through_hash: header["hash"].as_str().unwrap().to_owned(),
        max_requests: 16,
        max_total_response_bytes: 32 * 1024 * 1024,
        total_timeout: Duration::from_secs(5),
    };
    let observation = reader
        .read_history_paginated(&request, width)
        .await
        .unwrap();
    task.abort();
    observation
}

struct HistorySegmentCapture {
    online: polymarket_data::rpc_position_history::RpcPositionHistorySegmentObservation,
    recorded: polymarket_data::rpc_position_history::RecordedRpcPositionHistorySegmentObservation,
    pages: Vec<RecordedRpcPositionHistoryPage>,
    request: RpcPositionHistoryRequest,
}

async fn history_segment_and_recorded(
    fixture: &Value,
    variant: SourceVariant,
    width: u64,
    holder: &str,
    from_block: u64,
    through_block: u64,
) -> HistorySegmentCapture {
    let state = source_state(fixture, variant);
    let (endpoint, task) = serve(state, axum::routing::post(source_rpc)).await;
    let reader = RpcPositionHistoryReader::new(reqwest::Client::builder(), &endpoint).unwrap();
    let header = fixture_header(fixture, through_block);
    let request = RpcPositionHistoryRequest {
        holder_address: holder.to_owned(),
        from_block,
        through_block,
        expected_through_hash: header["hash"].as_str().unwrap().to_owned(),
        max_requests: 16,
        max_total_response_bytes: 32 * 1024 * 1024,
        total_timeout: Duration::from_secs(5),
    };
    let online = reader
        .read_history_segment_paginated(&request, width)
        .await
        .unwrap();
    task.abort();
    let pages = online
        .history()
        .pages()
        .iter()
        .map(|page| RecordedRpcPositionHistoryPage {
            request_json: page.request_json().to_owned(),
            response_json: page.response_json().to_owned(),
        })
        .collect::<Vec<_>>();
    let recorded = reverify_recorded_rpc_position_history_segment(&request, width, &pages)
        .await
        .unwrap();
    HistorySegmentCapture {
        online,
        recorded,
        pages,
        request,
    }
}

fn parse_quantity(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}

#[tokio::test]
async fn joins_two_public_history_observations_to_a_rooted_single_receipt() {
    let fixture = fixture();
    let (root_receipt, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    assert_eq!(receipt.transaction_hash(), tx_hash);
    assert_eq!(receipt.chain_id(), 137);
    assert_eq!(receipt.receipt_status(), 1);
    assert!(
        receipt
            .receipt_logs()
            .iter()
            .any(|log| { log.transaction_hash() == tx_hash && log.block_log_index() == 1 })
    );

    let first = history_observation(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let second = history_observation(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    assert_eq!(
        validate_position_history_source_agreement(&first, &second),
        Ok(())
    );
    let different_holder =
        history_observation(&fixture, SourceVariant::Exact, 2, OTHER_HOLDER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(&first, &different_holder, &[]).unwrap_err(),
        PositionHistoryReceiptJoinError::InvalidInput
    );
    let joined = bind_position_history_receipts(&first, &second, &[receipt]).unwrap();

    assert_eq!(joined.source_event_count(), 2);
    assert_eq!(joined.unique_transaction_count(), 1);
    assert_eq!(joined.receipt_count(), 1);
    assert_eq!(joined.candidate_ids().len(), 2);
    assert!(joined.candidate_ids().iter().all(|candidate| {
        candidate.ledger() == PositionLedger::PositionManager && candidate.locators().len() == 1
    }));
    assert_eq!(joined.history_coverage(), "partial_interval_only");
    assert_eq!(joined.opening_inventory(), "unknown");
    assert!(!joined.complete_wallet_history());
    assert!(!joined.qualification());
    assert!(!joined.candidate_ids()[0].id_hex().is_empty());
    assert_eq!(first.pages().len(), 8);
    assert_eq!(second.pages().len(), 6);
    assert_ne!(
        first.pages()[6].request_json(),
        second.pages()[4].request_json()
    );
    assert_eq!(root_receipt["transactionHash"], tx_hash);
}

#[tokio::test]
async fn joins_synthetic_trie_rooted_ctf_single_and_batch_logs() {
    let fixture = synthetic_ctf_batch_fixture(false, false);
    let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    assert!(receipt.movement_observations().iter().any(|movement| {
        movement.log_index() == 2
            && matches!(
                movement.status(),
                polymarket_data::chain_log_audit::MovementObservationStatus::Decoded(
                    polymarket_data::chain_log_audit::ObservedAssetMovement::Erc1155TransferBatch { .. }
                )
            )
    }));
    let first = history_observation(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let second = history_observation(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    let joined = bind_position_history_receipts(&first, &second, &[receipt]).unwrap();

    assert_eq!(joined.source_event_count(), 2);
    assert_eq!(joined.candidate_ids().len(), 3);
    assert!(joined.candidate_ids().iter().all(|candidate| {
        candidate.ledger() == PositionLedger::Ctf && candidate.locators().len() == 1
    }));
    assert_eq!(
        joined
            .candidate_ids()
            .iter()
            .map(|candidate| candidate.id())
            .collect::<Vec<_>>(),
        vec![U256::from(111), U256::from(201), U256::from(202)]
    );

    let malformed_fixture = synthetic_ctf_batch_fixture(true, false);
    let (_, malformed_tx_hash) = fixture_receipt_and_hash(&malformed_fixture);
    let malformed_receipt = rooted_receipt(&malformed_fixture, &malformed_tx_hash).await;
    let malformed_a =
        history_observation(&malformed_fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let malformed_b =
        history_observation(&malformed_fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(&malformed_a, &malformed_b, &[malformed_receipt])
            .unwrap_err(),
        PositionHistoryReceiptJoinError::UnsupportedMovement
    );
}

#[tokio::test]
async fn refuses_receipt_cardinality_source_disagreement_and_root_log_mismatch() {
    let fixture = fixture();
    let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    let exact_a = history_observation(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let exact_b = history_observation(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(&exact_a, &exact_b, &[]).unwrap_err(),
        PositionHistoryReceiptJoinError::ReceiptSetMismatch
    );
    let extra = rooted_receipt(&fixture, &unrelated_transaction_hash(&fixture, &tx_hash)).await;
    assert_eq!(
        bind_position_history_receipts(&exact_a, &exact_b, &[receipt.clone(), extra]).unwrap_err(),
        PositionHistoryReceiptJoinError::ReceiptSetMismatch
    );
    assert_eq!(
        bind_position_history_receipts(&exact_a, &exact_b, &[receipt.clone(), receipt.clone()])
            .unwrap_err(),
        PositionHistoryReceiptJoinError::DuplicateReceipt
    );

    let changed_source =
        history_observation(&fixture, SourceVariant::ChangedData, 2, OWNER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(&exact_a, &changed_source, std::slice::from_ref(&receipt))
            .unwrap_err(),
        PositionHistoryReceiptJoinError::SourceMismatch
    );
    assert_eq!(
        validate_position_history_source_agreement(&exact_a, &changed_source),
        Err(PositionHistoryReceiptJoinError::SourceMismatch)
    );
    let changed_root_log =
        history_observation(&fixture, SourceVariant::ChangedData, 1, OWNER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(
            &changed_root_log,
            &changed_root_log,
            std::slice::from_ref(&receipt)
        )
        .unwrap_err(),
        PositionHistoryReceiptJoinError::RootLogMismatch
    );
    let changed_locator =
        history_observation(&fixture, SourceVariant::ChangedLocator, 1, OWNER, 99, 100).await;
    assert_eq!(
        bind_position_history_receipts(
            &changed_locator,
            &changed_locator,
            std::slice::from_ref(&receipt)
        )
        .unwrap_err(),
        PositionHistoryReceiptJoinError::MissingRootedLog
    );
    let changed_index = history_observation(
        &fixture,
        SourceVariant::ChangedTransactionIndex,
        1,
        OWNER,
        99,
        100,
    )
    .await;
    assert_eq!(
        bind_position_history_receipts(&changed_index, &changed_index, &[receipt]).unwrap_err(),
        PositionHistoryReceiptJoinError::ReceiptLocatorMismatch
    );
}

#[tokio::test]
async fn equal_raw_ids_in_two_ledgers_remain_separate_candidates() {
    let fixture = synthetic_ctf_batch_fixture(false, true);
    let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    let first = history_observation(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let second = history_observation(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    let joined = bind_position_history_receipts(&first, &second, &[receipt]).unwrap();
    assert_eq!(
        joined
            .candidate_ids()
            .iter()
            .map(|id| (id.ledger(), id.id()))
            .collect::<Vec<_>>(),
        vec![
            (PositionLedger::Ctf, U256::from(111)),
            (PositionLedger::PositionManager, U256::from(111)),
            (PositionLedger::PositionManager, U256::from(202)),
        ]
    );
}

#[tokio::test]
async fn empty_interval_returns_empty_candidates_and_other_holder_is_rechecked_from_receipt() {
    let fixture = fixture();
    let empty_a = history_observation(&fixture, SourceVariant::Exact, 1, OWNER, 99, 99).await;
    let empty_b = history_observation(&fixture, SourceVariant::Exact, 3, OWNER, 99, 99).await;
    let empty = bind_position_history_receipts(&empty_a, &empty_b, &[]).unwrap();
    assert!(empty.candidate_ids().is_empty());
    assert_eq!(empty.history_coverage(), "partial_interval_only");
    assert_eq!(empty.opening_inventory(), "unknown");

    let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    let omitted_a = history_observation(
        &fixture,
        SourceVariant::OmitOneMatchingLog,
        1,
        OWNER,
        99,
        100,
    )
    .await;
    let omitted_b = history_observation(
        &fixture,
        SourceVariant::OmitOneMatchingLog,
        2,
        OWNER,
        99,
        100,
    )
    .await;
    assert_eq!(omitted_a.logs().len(), 1);
    assert_eq!(omitted_b.logs().len(), 1);
    assert_eq!(
        bind_position_history_receipts(&omitted_a, &omitted_b, &[receipt]).unwrap_err(),
        PositionHistoryReceiptJoinError::MissingRootedLog
    );
}

#[tokio::test]
async fn recorded_receipt_join_matches_live_ids_and_locators_with_recorded_provenance() {
    for fixture in [
        fixture(),
        synthetic_ctf_batch_fixture(false, false),
        synthetic_ctf_batch_fixture(false, true),
    ] {
        let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
        let receipt = rooted_receipt(&fixture, &tx_hash).await;
        let capture_a =
            history_segment_and_recorded(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
        let capture_b =
            history_segment_and_recorded(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;

        let live = bind_position_history_receipts(
            capture_a.online.history(),
            capture_b.online.history(),
            std::slice::from_ref(&receipt),
        )
        .unwrap();
        let recorded = bind_recorded_position_history_receipts(
            &capture_a.recorded,
            &capture_b.recorded,
            std::slice::from_ref(&receipt),
        )
        .unwrap();

        assert_eq!(live.candidate_ids(), recorded.candidate_ids());
        assert_eq!(live.source_event_count(), recorded.source_event_count());
        assert_eq!(
            live.unique_transaction_count(),
            recorded.unique_transaction_count()
        );
        assert_eq!(live.receipt_count(), recorded.receipt_count());
        assert_eq!(
            live.source_kind(),
            PositionHistoryReceiptSourceKind::NetworkObservation
        );
        assert_eq!(
            recorded.source_kind(),
            PositionHistoryReceiptSourceKind::RecordedTranscript
        );
    }
}

#[tokio::test]
async fn recorded_receipt_join_refuses_missing_duplicate_and_incomplete_receipts() {
    let fixture = fixture();
    let (_, tx_hash) = fixture_receipt_and_hash(&fixture);
    let receipt = rooted_receipt(&fixture, &tx_hash).await;
    let exact_a =
        history_segment_and_recorded(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    let exact_b =
        history_segment_and_recorded(&fixture, SourceVariant::Exact, 2, OWNER, 99, 100).await;
    assert_eq!(
        bind_recorded_position_history_receipts(&exact_a.recorded, &exact_b.recorded, &[])
            .unwrap_err(),
        PositionHistoryReceiptJoinError::ReceiptSetMismatch
    );
    assert_eq!(
        bind_recorded_position_history_receipts(
            &exact_a.recorded,
            &exact_b.recorded,
            &[receipt.clone(), receipt.clone()]
        )
        .unwrap_err(),
        PositionHistoryReceiptJoinError::DuplicateReceipt
    );

    let omitted_a = history_segment_and_recorded(
        &fixture,
        SourceVariant::OmitOneMatchingLog,
        1,
        OWNER,
        99,
        100,
    )
    .await;
    let omitted_b = history_segment_and_recorded(
        &fixture,
        SourceVariant::OmitOneMatchingLog,
        2,
        OWNER,
        99,
        100,
    )
    .await;
    assert_eq!(
        bind_recorded_position_history_receipts(
            &omitted_a.recorded,
            &omitted_b.recorded,
            std::slice::from_ref(&receipt)
        )
        .unwrap_err(),
        PositionHistoryReceiptJoinError::MissingRootedLog
    );
}

#[tokio::test]
async fn recorded_receipt_join_preserves_empty_scope_and_refuses_start_header_disagreement() {
    let fixture = fixture();
    let capture_a =
        history_segment_and_recorded(&fixture, SourceVariant::Exact, 1, OWNER, 99, 99).await;
    let capture_b =
        history_segment_and_recorded(&fixture, SourceVariant::Exact, 3, OWNER, 99, 99).await;
    let live =
        bind_position_history_receipts(capture_a.online.history(), capture_b.online.history(), &[])
            .unwrap();
    let recorded =
        bind_recorded_position_history_receipts(&capture_a.recorded, &capture_b.recorded, &[])
            .unwrap();
    assert!(recorded.candidate_ids().is_empty());
    assert_eq!(live.candidate_ids(), recorded.candidate_ids());
    assert_eq!(
        recorded.source_kind(),
        PositionHistoryReceiptSourceKind::RecordedTranscript
    );
    assert_eq!(recorded.opening_inventory(), "unknown");
    assert!(!recorded.complete_wallet_history());
    assert!(!recorded.qualification());

    let mut start_capture =
        history_segment_and_recorded(&fixture, SourceVariant::Exact, 1, OWNER, 99, 100).await;
    assert_eq!(start_capture.recorded.start_block_number(), 99);
    let start_page = start_capture
        .pages
        .iter_mut()
        .find(|page| {
            let request: Value = serde_json::from_str(&page.request_json).unwrap();
            request["method"] == "eth_getBlockByNumber" && request["params"][0] == "0x63"
        })
        .unwrap();
    let mut response: Value = serde_json::from_str(&start_page.response_json).unwrap();
    response["result"]["parentHash"] = json!(format!("0x{:064x}", 123_456));
    start_page.response_json = response.to_string();
    let changed_start = reverify_recorded_rpc_position_history_segment(
        &start_capture.request,
        1,
        &start_capture.pages,
    )
    .await
    .unwrap();
    assert_eq!(
        bind_recorded_position_history_receipts(&start_capture.recorded, &changed_start, &[])
            .unwrap_err(),
        PositionHistoryReceiptJoinError::SourceMismatch
    );
}
