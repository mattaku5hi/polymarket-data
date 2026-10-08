use super::*;
use std::str::FromStr;

const MODULE: &str = "0x3333333333333333333333333333333333333333";
const FEE_RECEIVER: &str = "0x115f48dc2a731aa16251c6d6e1befc42f92accc9";
const TRADE_OPERATOR_SEED: u8 = 0x43;

fn log_value(log: &ChainReceiptLog) -> Value {
    json!({
        "address":log.address(),
        "topics":log.topics(),
        "data":log.data(),
    })
}

fn exchange_control_words(
    submitter: Address,
    makers: &[Address],
    user_pause_block_interval: U256,
) -> Vec<(B256, U256)> {
    const ROLE_SEED: [u8; 4] = [0x8b, 0x78, 0xc6, 0xd8];
    let mut words = vec![
        (B256::ZERO, U256::ZERO),
        (B256::with_last_byte(1), user_pause_block_interval),
    ];
    let mut role_preimage = [0_u8; 32];
    role_preimage[..20].copy_from_slice(submitter.as_slice());
    role_preimage[28..].copy_from_slice(&ROLE_SEED);
    words.push((
        B256::from_slice(&Keccak256::digest(role_preimage)),
        U256::from(2_u64),
    ));
    for maker in makers {
        let mut pause_preimage = [0_u8; 64];
        pause_preimage[12..32].copy_from_slice(maker.as_slice());
        pause_preimage[63] = 3;
        words.push((
            B256::from_slice(&Keccak256::digest(pause_preimage)),
            U256::ZERO,
        ));
    }
    words
}

fn mixed_activity_fixture() -> (CtfInventoryFixture, Address, [B256; 2], String) {
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let module = vectors["module"].as_str().unwrap();
    let condition_id = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let position_ids = [
        parse_fixed_b256(vectors["position_ids"][0].as_str().unwrap()).unwrap(),
        parse_fixed_b256(vectors["position_ids"][1].as_str().unwrap()).unwrap(),
    ];
    let owner = Address::from_str(&owner_text).unwrap();
    let operator = Address::from_str(
        &signed_polygon_transaction_with_key(
            super::fifth_code_context::EXCHANGE_PROXY,
            &[],
            TRADE_OPERATOR_SEED,
        )
        .1,
    )
    .unwrap();

    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let maker = Address::repeat_byte(0x44);
    let taker_order = fifth_source_order(
        61,
        owner,
        U256::from_be_bytes(position_ids[0].0),
        60,
        100,
        FifthOrderSide::Buy,
        0x66,
    );
    let maker_order = fifth_source_order(
        62,
        maker,
        U256::from_be_bytes(position_ids[0].0),
        100,
        50,
        FifthOrderSide::Sell,
        0x67,
    );
    let taker_hash = fifth_order_eip712_hash(&taker_order, exchange);
    let maker_hash = fifth_order_eip712_hash(&maker_order, exchange);
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        std::slice::from_ref(&maker_order),
        &[U256::from(100_u64)],
        &[U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(60_u64),
            taker_receive_amount: U256::from(100_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let (trade_transaction, recovered_operator) = signed_polygon_transaction_with_key(
        super::fifth_code_context::EXCHANGE_PROXY,
        &input,
        TRADE_OPERATOR_SEED,
    );
    assert_eq!(recovered_operator, format!("{operator:#x}"));
    let encoded_trade =
        encode_signed_transaction_with_sender_recovery(&trade_transaction, true).unwrap();
    assert_eq!(encoded_trade.eip155_chain_id, Some(U256::from(137_u64)));
    let mut trade_logs = vec![
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker:#x}"),
            &owner_text,
            U256::from_be_bytes(position_ids[0].0),
            100,
            0,
        ),
        fifth_source_pusd(&owner_text, &format!("{maker:#x}"), 49, 1),
        fifth_source_order_filled(&maker_order, maker_hash, owner, 100, 50, 1, 2),
        fifth_source_fee(1, 3),
        fifth_source_fee(1, 4),
        fifth_source_pusd(&owner_text, FEE_RECEIVER, 2, 5),
    ];
    trade_logs.extend(fifth_source_taker_events(
        &taker_order,
        taker_hash,
        50,
        100,
        1,
        6,
    ));

    let calls = vectors["calls"].as_array().unwrap();
    let call = |name: &str| calls.iter().find(|row| row["name"] == name).unwrap();
    let funding = call("pusd-fund-split10");
    let funding_input = hex::decode(
        funding["calldata"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (funding_transaction, recovered_owner) =
        signed_polygon_owner_call(funding["to"].as_str().unwrap(), &funding_input, 0);
    assert_eq!(recovered_owner, owner_text);

    let split = call("split-owner10");
    let split_input =
        hex::decode(split["calldata"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let (split_transaction, split_owner) =
        signed_polygon_owner_call(split["to"].as_str().unwrap(), &split_input, 1);
    assert_eq!(split_owner, owner_text);

    let split_logs = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "split")
        .unwrap()["source_receipt_logs"][1]
        .as_array()
        .unwrap()
        .clone();
    let funding_log = log_value(&fifth_source_pusd(&owner_text, module, 10, 0));
    let trade_receipt_logs = trade_logs.iter().map(log_value).collect::<Vec<_>>();

    let (open_root, open_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            [U256::ZERO; 2],
            U256::from(1_000_u64),
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &exchange_control_words(operator, &[owner, maker], U256::from(7_u64)),
        );
    let (middle_root, middle_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            [U256::from(100_u64), U256::ZERO],
            U256::from(939_u64),
            [U256::ZERO; 2],
            U256::from(10_u64),
            U256::ONE,
            [U256::ZERO; 3],
            &exchange_control_words(operator, &[owner, maker], U256::from(7_u64)),
        );
    let (end_root, end_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            [U256::from(110_u64), U256::from(10_u64)],
            U256::from(939_u64),
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &exchange_control_words(operator, &[owner, maker], U256::from(7_u64)),
        );

    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = open_root;
    fixture.post_state = Some((middle_root, Value::Null));
    fixture.extra_post_state = Some((end_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, open_proofs),
        (100, middle_proofs),
        (101, end_proofs),
    ]));
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![funding_transaction, trade_transaction.clone()],
        receipt_logs: vec![vec![funding_log.clone()], trade_receipt_logs.clone()],
        receipt_statuses: vec![1, 1],
        cumulative_gas_used: vec![21_000, 42_000],
        receipt_types: vec![0, 0],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    fixture.inventory_logs = Some(
        vec![funding_log]
            .into_iter()
            .chain(trade_receipt_logs)
            .collect(),
    );
    fixture.direct_call_transaction = Some(trade_transaction.clone());
    fixture.extra_direct_call_transaction = Some(split_transaction);
    fixture.extra_inventory_logs = Some(split_logs);
    (fixture, owner, position_ids, owner_text)
}

#[allow(clippy::too_many_arguments)]
fn replace_native_activity_point(
    fixture: &mut CtfInventoryFixture,
    block_number: u64,
    owner: Address,
    condition_id: B256,
    owner_positions: [U256; 2],
    owner_cash: U256,
    module_positions: [U256; 2],
    module_cash: U256,
    user_pause_block_interval: U256,
) {
    let operator = Address::from_str(
        &signed_polygon_transaction_with_key(
            super::fifth_code_context::EXCHANGE_PROXY,
            &[],
            TRADE_OPERATOR_SEED,
        )
        .1,
    )
    .unwrap();
    let maker = Address::repeat_byte(0x44);
    let (state_root, proofs) =
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &format!("{owner:#x}"),
            condition_id,
            owner_positions,
            owner_cash,
            module_positions,
            module_cash,
            U256::ONE,
            [U256::ZERO; 3],
            &exchange_control_words(operator, &[owner, maker], user_pause_block_interval),
        );
    match block_number {
        99 => fixture.state_root = state_root,
        100 => fixture.post_state = Some((state_root, Value::Null)),
        101 => fixture.extra_post_state = Some((state_root, Value::Null)),
        _ => panic!("native activity fixture supports only blocks 99 through 101"),
    }
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(block_number, proofs);
}

fn set_quiet_block_101(fixture: &mut CtfInventoryFixture) {
    let (quiet, _) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 1);
    fixture.extra_direct_call_transaction = Some(quiet);
    fixture.extra_inventory_logs = Some(Vec::new());
}

async fn verify_activity(
    fixture: &CtfInventoryFixture,
    owner: &str,
    condition_id: B256,
    max_requests: usize,
    total_timeout: Duration,
) -> Result<FifthNativeBinaryActivityObservation, BoundedFifthNativeBinaryActivityError> {
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            owner,
            &format!("{condition_id:#x}"),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            max_requests,
            total_timeout,
        )
        .await
}

fn capture_mixed_activity(
    fixture: &CtfInventoryFixture,
    report: &FifthNativeBinaryActivityObservation,
    owner: &str,
    condition_id: B256,
    parent_hash: &Value,
    end_hash: &Value,
) {
    let Ok(directory) = std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_ACTIVITY_DIRECTORY") else {
        return;
    };
    let mut unique = BTreeMap::new();
    for row in fixture.rpc_capture.lock().unwrap().iter() {
        let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
        if let Some(previous) = unique.insert(key, row.clone()) {
            assert_eq!(previous["result"], row["result"]);
        }
    }
    let boundary = |point: &FifthNativeBinaryModuleOperationBoundary| {
        let balances = point.native_context().selected_balances();
        json!({
            "block_number":balances.block_number(),
            "block_hash":balances.block_hash(),
            "state_root":balances.state_root(),
            "owner_position_balances":[format!("{:#x}",balances.position_balance_a()),format!("{:#x}",balances.position_balance_b())],
            "owner_pusd_balance":format!("{:#x}",balances.pusd_balance()),
            "module_position_balances":point.module_position_balances().map(|value|format!("{value:#x}")),
            "module_pusd_balance":format!("{:#x}",point.module_pusd_balance()),
            "module_role_bitmap":format!("{:#x}",point.module_role_bitmap()),
        })
    };
    let trade_facts = report.transactions().iter().map(|fact| json!({
        "block_number":fact.block_number(),
        "block_hash":fact.block_hash(),
        "transaction_hash":fact.transaction_hash(),
        "transaction_index":fact.transaction_index(),
        "branch":format!("{:?}",fact.branch()),
        "owner_position_inflows":fact.owner_position_inflows().map(|value|format!("{value:#x}")),
        "owner_position_outflows":fact.owner_position_outflows().map(|value|format!("{value:#x}")),
        "owner_pusd_inflow":format!("{:#x}",fact.owner_pusd_inflow()),
        "owner_pusd_outflow":format!("{:#x}",fact.owner_pusd_outflow()),
        "owner_fee_amount":format!("{:#x}",fact.owner_fee_amount()),
        "order_fills":fact.order_fills().iter().map(|fill|json!({
            "order_hash":format!("{:#x}",fill.order_hash()),
            "token_id":format!("{:#x}",fill.token_id()),
            "maker":format!("{:#x}",fill.maker()),
            "signer":format!("{:#x}",fill.signer()),
            "side":format!("{:?}",fill.side()),
            "owner_role":format!("{:?}",fill.owner_role()),
            "maker_amount_filled":format!("{:#x}",fill.maker_amount_filled()),
            "taker_amount_filled":format!("{:#x}",fill.taker_amount_filled()),
            "fee_amount":format!("{:#x}",fill.fee_amount()),
        })).collect::<Vec<_>>(),
    })).collect::<Vec<_>>();
    let locator =
        |value: &super::fifth_direct_module_operations::FifthDirectModuleTransactionLocator| {
            json!({
                "block_number":value.block_number(),
                "block_hash":value.block_hash(),
                "transaction_hash":value.transaction_hash(),
                "transaction_index":value.transaction_index(),
            })
        };
    let module_facts = report.module_operations().iter().map(|fact| json!({
        "kind":format!("{:?}",fact.kind()),
        "condition_id":format!("{:#x}",fact.condition_id()),
        "position_id":fact.position_id().map(|value|format!("{value:#x}")),
        "amount":format!("{:#x}",fact.amount()),
        "payout":fact.payout().map(|value|format!("{value:#x}")),
        "owner_position_inflows":fact.owner_position_inflows().map(|value|format!("{value:#x}")),
        "owner_position_outflows":fact.owner_position_outflows().map(|value|format!("{value:#x}")),
        "owner_pusd_inflow":format!("{:#x}",fact.owner_pusd_inflow()),
        "owner_pusd_outflow":format!("{:#x}",fact.owner_pusd_outflow()),
        "funding_transactions":fact.funding_transactions().iter().map(|funding|json!({
            "transaction":locator(funding.transaction()),
            "asset":format!("{:?}",funding.asset()),
            "position_id":funding.position_id().map(|value|format!("{value:#x}")),
            "amount":format!("{:#x}",funding.amount()),
        })).collect::<Vec<_>>(),
        "operation_transaction":locator(fact.operation_transaction()),
    })).collect::<Vec<_>>();
    let controls = report.controls().iter().map(|control| json!({
        "block_number":control.code_context().block_number(),
        "submitter":format!("{:#x}",control.submitter()),
        "maker":format!("{:#x}",control.maker()),
        "global_pause_word":format!("{:#x}",control.global_pause_word()),
        "global_paused":control.global_paused(),
        "submitter_role_bitmap":format!("{:#x}",control.submitter_role_bitmap()),
        "submitter_has_operator_role":control.submitter_has_operator_role(),
        "maker_pause_activation_block":format!("{:#x}",control.maker_pause_activation_block()),
        "maker_pause_active":control.maker_pause_active(),
    })).collect::<Vec<_>>();
    let envelope = json!({
        "provenance":"Synthetic signed Polygon module funding, Exchange trade, and native split with root-bound owner/module proofs; no external chain observation.",
        "case":"fund-trade-split",
        "owner":owner,
        "condition_id":format!("{condition_id:#x}"),
        "from_block":100,
        "through_block":101,
        "parent_hash":parent_hash,
        "end_hash":end_hash,
        "status":format!("{:?}",report.status()),
        "source_policy_version":report.source_policy_version(),
        "opening":boundary(report.opening()),
        "block_observations":report.block_observations().iter().map(boundary).collect::<Vec<_>>(),
        "trades":trade_facts,
        "module_operations":module_facts,
        "controls":controls,
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    let path = std::path::Path::new(&directory)
        .join("fifth-native-binary-activity-fund-trade-split-rpc.json");
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
}

#[tokio::test]
async fn native_binary_activity_replays_funding_trade_and_cross_block_consumption() {
    let (fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[0]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            130,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

    assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
    assert_eq!(report.transactions().len(), 1);
    assert_eq!(report.module_operations().len(), 1);
    let trade = &report.transactions()[0];
    assert_eq!(trade.branch(), FifthTradeBranch::Normal);
    assert_eq!(
        trade.owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(trade.owner_pusd_outflow(), U256::from(51_u64));
    let split = &report.module_operations()[0];
    assert_eq!(split.kind(), FifthDirectModuleOperationKind::Split);
    assert_eq!(split.amount(), U256::from(10_u64));
    assert_eq!(split.owner_pusd_outflow(), U256::from(10_u64));
    assert_eq!(split.owner_position_inflows(), [U256::from(10_u64); 2]);
    assert_eq!(split.funding_transactions().len(), 1);
    assert_eq!(
        split.funding_transactions()[0].transaction().block_number(),
        100
    );
    assert_eq!(split.operation_transaction().block_number(), 101);
    assert_eq!(
        report
            .opening()
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(1_000_u64)
    );
    assert_eq!(
        report.block_observations()[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(100_u64)
    );
    assert_eq!(
        report.block_observations()[0].module_pusd_balance(),
        U256::from(10_u64)
    );
    let closing = report.block_observations().last().unwrap();
    assert_eq!(
        closing
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(110_u64)
    );
    assert_eq!(
        closing
            .native_context()
            .selected_balances()
            .position_balance_b(),
        U256::from(10_u64)
    );
    assert_eq!(
        closing.native_context().selected_balances().pusd_balance(),
        U256::from(939_u64)
    );
    assert_eq!(closing.module_position_balances(), [U256::ZERO; 2]);
    assert_eq!(closing.module_pusd_balance(), U256::ZERO);
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 130);
    capture_mixed_activity(
        &fixture,
        &report,
        &owner_text,
        position_ids[0],
        &opening["hash"],
        &ending["hash"],
    );
}

#[tokio::test]
async fn native_binary_activity_one_short_request_budget_returns_no_report() {
    let (fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[0]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            129,
            Duration::from_secs(20),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded
    );
    let sends = fixture.requests.load(Ordering::Relaxed);
    assert!(sends > 0);
    assert!(sends <= 129);
}

#[tokio::test]
async fn native_binary_activity_rejects_unconsumed_funding_without_balance_mismatch() {
    use super::fifth_direct_module_operations::FifthLegacyBinaryModuleOperationsUnavailableReason;
    use super::fifth_native_activity::FifthNativeBinaryActivityUnavailableReason;

    let (mut fixture, owner, position_ids, owner_text) = mixed_activity_fixture();
    replace_native_activity_point(
        &mut fixture,
        101,
        owner,
        position_ids[0],
        [U256::from(100_u64), U256::ZERO],
        U256::from(939_u64),
        [U256::ZERO; 2],
        U256::from(10_u64),
        U256::from(7_u64),
    );
    set_quiet_block_101(&mut fixture);

    let report = verify_activity(
        &fixture,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert!(matches!(
        report.status(),
        FifthNativeBinaryActivityStatus::Unavailable {
            block_number: Some(101),
            reason: FifthNativeBinaryActivityUnavailableReason::Module(
                FifthLegacyBinaryModuleOperationsUnavailableReason::SourceSettlementMismatch
            ),
            ..
        }
    ));
    assert!(report.transactions().is_empty());
    assert!(report.module_operations().is_empty());
    assert_eq!(
        report
            .block_observations()
            .last()
            .unwrap()
            .module_pusd_balance(),
        U256::from(10_u64)
    );
}

#[tokio::test]
async fn native_binary_activity_clears_prefix_on_middle_module_balance_mismatch() {
    use super::fifth_direct_module_operations::{
        FifthDirectModuleOperationsAsset, FifthDirectModuleOperationsHolder,
    };

    let (mut fixture, owner, position_ids, owner_text) = mixed_activity_fixture();
    replace_native_activity_point(
        &mut fixture,
        100,
        owner,
        position_ids[0],
        [U256::from(100_u64), U256::ZERO],
        U256::from(939_u64),
        [U256::ZERO; 2],
        U256::from(9_u64),
        U256::from(7_u64),
    );

    let report = verify_activity(
        &fixture,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert!(report.transactions().is_empty());
    assert!(report.module_operations().is_empty());
    assert!(matches!(
        report.status(),
        FifthNativeBinaryActivityStatus::Mismatch {
            block_number: 100,
            holder: FifthDirectModuleOperationsHolder::Module,
            asset: FifthDirectModuleOperationsAsset::Pusd,
            authenticated_balance,
            reconstructed_balance,
        } if *authenticated_balance == U256::from(9_u64)
            && *reconstructed_balance == U256::from(10_u64)
    ));
}

#[tokio::test]
async fn native_binary_activity_clears_prefix_on_late_unsupported_module_call() {
    use super::fifth_native_activity::FifthNativeBinaryActivityUnavailableReason;

    let (mut fixture, owner, position_ids, owner_text) = mixed_activity_fixture();
    replace_native_activity_point(
        &mut fixture,
        101,
        owner,
        position_ids[0],
        [U256::from(100_u64), U256::ZERO],
        U256::from(939_u64),
        [U256::ZERO; 2],
        U256::from(10_u64),
        U256::from(7_u64),
    );
    let (unsupported, from) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 1);
    assert_eq!(from, owner_text);
    fixture.extra_direct_call_transaction = Some(unsupported);
    fixture.extra_inventory_logs = Some(Vec::new());

    let report = verify_activity(
        &fixture,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert!(report.transactions().is_empty());
    assert!(report.module_operations().is_empty());
    assert!(matches!(
        report.status(),
        FifthNativeBinaryActivityStatus::Unavailable {
            block_number: Some(101),
            reason: FifthNativeBinaryActivityUnavailableReason::Module(_),
            ..
        }
    ));
}

#[tokio::test]
async fn native_binary_activity_refuses_exchange_control_change() {
    use super::fifth_native_activity::FifthNativeBinaryActivityUnavailableReason;
    use super::fifth_native_binary_trades::FifthNativeBinaryTradeUnavailableReason;

    let (mut fixture, owner, position_ids, owner_text) = mixed_activity_fixture();
    replace_native_activity_point(
        &mut fixture,
        100,
        owner,
        position_ids[0],
        [U256::from(100_u64), U256::ZERO],
        U256::from(939_u64),
        [U256::ZERO; 2],
        U256::from(10_u64),
        U256::from(8_u64),
    );

    let report = verify_activity(
        &fixture,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert!(report.transactions().is_empty());
    assert!(report.module_operations().is_empty());
    assert!(matches!(
        report.status(),
        FifthNativeBinaryActivityStatus::Unavailable {
            reason: FifthNativeBinaryActivityUnavailableReason::Trade(
                FifthNativeBinaryTradeUnavailableReason::ExchangeControlTransition
            ),
            ..
        }
    ));
}

#[tokio::test]
async fn native_binary_activity_refuses_pause_unpause_round_trip_logs() {
    let (mut fixture, owner, position_ids, owner_text) = mixed_activity_fixture();
    let logs = &mut fixture.rooted_gas_block.as_mut().unwrap().receipt_logs[1];
    let pauser_topic = format!("0x{}{}", "00".repeat(12), hex::encode(owner.as_slice()));
    for signature in ["TradingPaused(address)", "TradingUnpaused(address)"] {
        logs.push(json!({
            "address":super::fifth_code_context::EXCHANGE_PROXY,
            "topics":[
                format!("0x{}",hex::encode(Keccak256::digest(signature.as_bytes()))),
                pauser_topic,
            ],
            "data":"0x",
        }));
    }

    let report = verify_activity(
        &fixture,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert_ne!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
    assert!(report.transactions().is_empty());
    assert!(report.module_operations().is_empty());
}

#[tokio::test]
async fn native_binary_activity_rejects_noncanonical_condition_before_rpc() {
    let (fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[1]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            1,
            Duration::from_secs(20),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        BoundedFifthNativeBinaryActivityError::Verification(ChainLogAuditError::InvalidInput)
    );
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_binary_activity_rejects_wrong_end_hash_without_report() {
    let (fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let (opening, _, _, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[0]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            &format!("{:#x}", B256::ZERO),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        BoundedFifthNativeBinaryActivityError::Verification(ChainLogAuditError::Unverified)
    );
}

#[tokio::test]
async fn prior_trade_only_and_module_only_apis_refuse_mixed_activity() {
    use super::fifth_native_binary_trades::FifthNativeBinaryTradeStatus;
    use super::fifth_native_module_operations::FifthNativeBinaryModuleOperationsStatus;

    let (fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let trade = verifier
        .verify_fifth_native_binary_trade_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[0]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap();
    let module = verifier
        .verify_fifth_native_binary_module_operations_interval_bounded(
            &owner_text,
            &format!("{:#x}", position_ids[0]),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

    assert_ne!(trade.status(), &FifthNativeBinaryTradeStatus::Matched);
    assert!(trade.transactions().is_empty());
    assert_ne!(
        module.status(),
        &FifthNativeBinaryModuleOperationsStatus::Matched
    );
    assert!(module.operations().is_empty());
}

#[tokio::test]
async fn native_binary_activity_honors_deadline_and_stops_sends_after_abort() {
    let (mut delayed, _owner, position_ids, owner_text) = mixed_activity_fixture();
    delayed.delay_ms = 10;
    let error = verify_activity(
        &delayed,
        &owner_text,
        position_ids[0],
        2_000,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert_eq!(error, BoundedFifthNativeBinaryActivityError::Timeout);

    let (mut fixture, _owner, position_ids, owner_text) = mixed_activity_fixture();
    let gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(gate.clone());
    let send_counter = fixture.requests.clone();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture).await;
    let condition_id = format!("{:#x}", position_ids[0]);
    let task = tokio::spawn(async move {
        ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_activity_interval_bounded(
                &owner_text,
                &condition_id,
                100,
                101,
                opening["hash"].as_str().unwrap(),
                ending["hash"].as_str().unwrap(),
                2_000,
                Duration::from_secs(20),
            )
            .await
    });
    tokio::select! {
        _ = gate.started.notified() => {}
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("native activity receipt gate was not reached"),
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    gate.release.send_replace(true);
    tokio::time::sleep(Duration::from_millis(25)).await;
    let settled = send_counter.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(send_counter.load(Ordering::Relaxed), settled);
}
