use super::*;
use std::str::FromStr;

const QUIET_KEY: u8 = 0x43;
const FEE_RECEIVER: &str = "0x115f48dc2a731aa16251c6d6e1befc42f92accc9";
const MODULE: &str = "0x3333333333333333333333333333333333333333";
const PUSD: &str = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";

fn native_accounting_log_json(log: &ChainReceiptLog) -> Value {
    json!({
        "address":log.address(),
        "topics":log.topics(),
        "data":log.data(),
    })
}

fn native_accounting_control_words(operator: Address, makers: &[Address]) -> Vec<(B256, U256)> {
    const ROLE_SEED: [u8; 4] = [0x8b, 0x78, 0xc6, 0xd8];
    let mut words = vec![
        (B256::ZERO, U256::ZERO),
        (B256::with_last_byte(1), U256::from(7_u64)),
    ];
    let mut role_preimage = [0_u8; 32];
    role_preimage[..20].copy_from_slice(operator.as_slice());
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

fn native_accounting_fund_split_buy_sell_fixture() -> (CtfInventoryFixture, B256, String) {
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let owner = Address::from_str(&owner_text).unwrap();
    let condition_id = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let position_ids = [
        parse_fixed_b256(vectors["position_ids"][0].as_str().unwrap()).unwrap(),
        parse_fixed_b256(vectors["position_ids"][1].as_str().unwrap()).unwrap(),
    ];
    let module = vectors["module"].as_str().unwrap();
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let maker_buy = Address::repeat_byte(0x44);
    let maker_sell = Address::repeat_byte(0x45);

    let calls = vectors["calls"].as_array().unwrap();
    let call = |name: &str| calls.iter().find(|row| row["name"] == name).unwrap();
    let calldata = |name: &str| {
        hex::decode(
            call(name)["calldata"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
    };
    let (fund_transaction, recovered_owner) =
        signed_polygon_owner_call(PUSD, &calldata("pusd-fund-split10"), 0);
    assert_eq!(recovered_owner, owner_text);
    let (split_transaction, split_owner) =
        signed_polygon_owner_call(module, &calldata("split-owner10"), 1);
    assert_eq!(split_owner, owner_text);

    let buy_taker = fifth_source_order(
        81,
        owner,
        U256::from_be_bytes(position_ids[0].0),
        60,
        100,
        FifthOrderSide::Buy,
        0x81,
    );
    let buy_maker = fifth_source_order(
        82,
        maker_buy,
        U256::from_be_bytes(position_ids[0].0),
        100,
        50,
        FifthOrderSide::Sell,
        0x82,
    );
    let buy_taker_hash = fifth_order_eip712_hash(&buy_taker, exchange);
    let buy_maker_hash = fifth_order_eip712_hash(&buy_maker, exchange);
    let buy_input = super::fifth_match_orders_call::tests::encode_call(
        &buy_taker,
        std::slice::from_ref(&buy_maker),
        &[U256::from(100_u64)],
        &[U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(60_u64),
            taker_receive_amount: U256::from(100_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let (buy_transaction, recovered_buy_operator) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &buy_input, 2);
    assert_eq!(recovered_buy_operator, owner_text);

    let sell_taker = fifth_source_order(
        83,
        owner,
        U256::from_be_bytes(position_ids[0].0),
        50,
        20,
        FifthOrderSide::Sell,
        0x83,
    );
    let sell_maker = fifth_source_order(
        84,
        maker_sell,
        U256::from_be_bytes(position_ids[0].0),
        25,
        50,
        FifthOrderSide::Buy,
        0x84,
    );
    let sell_taker_hash = fifth_order_eip712_hash(&sell_taker, exchange);
    let sell_maker_hash = fifth_order_eip712_hash(&sell_maker, exchange);
    let sell_input = super::fifth_match_orders_call::tests::encode_call(
        &sell_taker,
        std::slice::from_ref(&sell_maker),
        &[U256::from(25_u64)],
        &[U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(50_u64),
            taker_receive_amount: U256::from(25_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let (sell_transaction, recovered_sell_operator) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &sell_input, 3);
    assert_eq!(recovered_sell_operator, owner_text);

    // These ordered logs are independently specified settlement evidence. They intentionally do
    // not come from a settlement builder or from the expected trade facts under test.
    let split_logs = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "split")
        .unwrap()["source_receipt_logs"][1]
        .as_array()
        .unwrap()
        .clone();
    let buy_logs = [
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker_buy:#x}"),
            &owner_text,
            U256::from_be_bytes(position_ids[0].0),
            100,
            0,
        ),
        fifth_source_pusd(&owner_text, &format!("{maker_buy:#x}"), 49, 1),
        fifth_source_order_filled(&buy_maker, buy_maker_hash, owner, 100, 50, 1, 2),
        fifth_source_fee(1, 3),
        fifth_source_fee(1, 4),
        fifth_source_pusd(&owner_text, FEE_RECEIVER, 2, 5),
        fifth_source_taker_events(&buy_taker, buy_taker_hash, 50, 100, 1, 6)[0].clone(),
        fifth_source_taker_events(&buy_taker, buy_taker_hash, 50, 100, 1, 6)[1].clone(),
    ];
    let sell_logs = vec![
        fifth_source_order_filled(&sell_maker, sell_maker_hash, owner, 25, 50, 1, 0),
        fifth_source_pusd(
            &format!("{maker_sell:#x}"),
            super::fifth_code_context::EXCHANGE_PROXY,
            26,
            1,
        ),
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            &format!("{maker_sell:#x}"),
            U256::from_be_bytes(position_ids[0].0),
            50,
            0,
        ),
        fifth_source_fee(1, 3),
        fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            24,
            4,
        ),
        fifth_source_fee(1, 5),
        fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            FEE_RECEIVER,
            2,
            6,
        ),
        fifth_source_taker_events(&sell_taker, sell_taker_hash, 50, 25, 1, 7)[0].clone(),
        fifth_source_taker_events(&sell_taker, sell_taker_hash, 50, 25, 1, 7)[1].clone(),
    ];

    let operator = owner;
    let controls = native_accounting_control_words(operator, &[owner, maker_buy, maker_sell]);
    let point = |positions: [U256; 2], cash: U256| {
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            positions,
            cash,
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &controls,
        )
    };
    let (open_root, open_proofs) = point([U256::ZERO; 2], U256::from(1_000_u64));
    let (block100_root, block100_proofs) = point(
        [U256::from(60_u64), U256::from(10_u64)],
        U256::from(963_u64),
    );
    let (block101_root, block101_proofs) = point(
        [U256::from(60_u64), U256::from(10_u64)],
        U256::from(963_u64),
    );

    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = open_root;
    fixture.post_state = Some((block100_root, Value::Null));
    fixture.extra_post_state = Some((block101_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, open_proofs),
        (100, block100_proofs),
        (101, block101_proofs),
    ]));

    let quiet_to = "0x3535353535353535353535353535353535353535";
    let (quiet_transaction, _) = signed_polygon_transaction_with_key(quiet_to, &[], QUIET_KEY);
    fixture.extra_direct_call_transaction = Some(quiet_transaction);
    fixture.extra_inventory_logs = Some(Vec::new());
    fixture.direct_call_transaction = Some(buy_transaction.clone());
    fixture.inventory_logs = Some(
        buy_logs
            .iter()
            .chain(sell_logs.iter())
            .map(native_accounting_log_json)
            .collect(),
    );
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![
            fund_transaction,
            split_transaction,
            buy_transaction,
            sell_transaction,
        ],
        receipt_logs: vec![
            vec![native_accounting_log_json(&fifth_source_pusd(
                &owner_text,
                module,
                10,
                0,
            ))],
            split_logs,
            buy_logs.iter().map(native_accounting_log_json).collect(),
            sell_logs.iter().map(native_accounting_log_json).collect(),
        ],
        receipt_statuses: vec![1; 4],
        cumulative_gas_used: vec![21_000, 42_000, 63_000, 84_000],
        receipt_types: vec![0; 4],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    (fixture, condition_id, owner_text)
}

fn native_contiguous_fund_quiet_sell_fixture() -> (CtfInventoryFixture, B256, String) {
    let (mut fixture, condition_id, owner_text) = native_accounting_fund_split_buy_sell_fixture();
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    let sell_transaction = rooted.transactions.pop().unwrap();
    let sell_logs = rooted.receipt_logs.pop().unwrap();
    rooted.transactions.truncate(3);
    rooted.receipt_logs.truncate(3);
    rooted.receipt_statuses.truncate(3);
    rooted.cumulative_gas_used.truncate(3);
    rooted.receipt_types.truncate(3);

    fixture.third_direct_call_transaction = Some(sell_transaction);
    fixture.third_inventory_logs = Some(sell_logs);
    fixture.extra_inventory_logs = Some(Vec::new());

    let owner = Address::from_str(&owner_text).unwrap();
    let condition = condition_id;
    let maker_buy = Address::repeat_byte(0x44);
    let maker_sell = Address::repeat_byte(0x45);
    let controls = native_accounting_control_words(owner, &[owner, maker_buy, maker_sell]);
    let point = |positions: [U256; 2], cash: U256| {
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition,
            positions,
            cash,
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &controls,
        )
    };
    let (opening_root, opening_proofs) = point([U256::ZERO; 2], U256::from(1_000_u64));
    let (acquisition_root, acquisition_proofs) = point(
        [U256::from(110_u64), U256::from(10_u64)],
        U256::from(939_u64),
    );
    let (closing_root, closing_proofs) = point(
        [U256::from(60_u64), U256::from(10_u64)],
        U256::from(963_u64),
    );
    fixture.state_root = opening_root;
    fixture.post_state = Some((acquisition_root.clone(), Value::Null));
    fixture.extra_post_state = Some((acquisition_root, Value::Null));
    fixture.third_post_state = Some((closing_root, Value::Null));
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, opening_proofs),
        (100, acquisition_proofs.clone()),
        (101, acquisition_proofs),
        (102, closing_proofs),
    ]));
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    (fixture, condition_id, owner_text)
}

fn native_contiguous_late_unsupported_fixture() -> (CtfInventoryFixture, B256, String) {
    let (mut fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    let (transaction, recovered_owner) =
        signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 3);
    assert_eq!(recovered_owner, owner_text);
    fixture.third_direct_call_transaction = Some(transaction);
    fixture.third_inventory_logs = Some(Vec::new());

    let owner = Address::from_str(&owner_text).unwrap();
    let maker_buy = Address::repeat_byte(0x44);
    let maker_sell = Address::repeat_byte(0x45);
    let controls = native_accounting_control_words(owner, &[owner, maker_buy, maker_sell]);
    let (closing_root, closing_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            [U256::from(110_u64), U256::from(10_u64)],
            U256::from(939_u64),
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &controls,
        );
    fixture.third_post_state = Some((closing_root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(102, closing_proofs);
    (fixture, condition_id, owner_text)
}

fn native_contiguous_anchors(
    fixture: &CtfInventoryFixture,
) -> Vec<super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor> {
    let (opening, block100, block101, block102) = ctf_inventory_headers_with_102(fixture);
    vec![
        super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor::new(
            100,
            100,
            opening["hash"].as_str().unwrap(),
            block100["hash"].as_str().unwrap(),
        ),
        super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor::new(
            101,
            101,
            block100["hash"].as_str().unwrap(),
            block101["hash"].as_str().unwrap(),
        ),
        super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor::new(
            102,
            102,
            block101["hash"].as_str().unwrap(),
            block102["hash"].as_str().unwrap(),
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn capture_native_accounting_activity(
    fixture: &CtfInventoryFixture,
    report: &FifthNativeBinaryActivityObservation,
    owner: &str,
    condition_id: B256,
    parent_hash: &Value,
    end_hash: &Value,
    case: &str,
    capture_filename: &str,
) {
    let Ok(directory) = std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_ACCOUNTING_DIRECTORY") else {
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
            "native_result_length":format!("{:#x}",point.native_context().result_length()),
            "native_normalized_numerators":point.native_context().normalized_numerators().map(|values|values.map(|value|format!("{value:#x}"))),
        })
    };
    let locator =
        |value: &super::fifth_direct_module_operations::FifthDirectModuleTransactionLocator| {
            json!({
                "block_number":value.block_number(),
                "block_hash":value.block_hash(),
                "transaction_hash":value.transaction_hash(),
                "transaction_index":value.transaction_index(),
                "log_index":value.log_index(),
            })
        };
    let envelope = json!({
        "provenance":"Synthetic signed Polygon native Binary activity with root-bound owner/module proofs; no external chain observation.",
        "case":case,
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
        "trades":report.transactions().iter().map(|fact|json!({
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
            "owner_refund_amount":format!("{:#x}",fact.owner_refund_amount()),
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
            "log_index":fill.log_index(),
        })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "module_operations":report.module_operations().iter().map(|fact|json!({
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
        })).collect::<Vec<_>>(),
        "controls":report.controls().iter().map(|control|json!({
            "block_number":control.code_context().block_number(),
            "submitter":format!("{:#x}",control.submitter()),
            "maker":format!("{:#x}",control.maker()),
            "global_pause_word":format!("{:#x}",control.global_pause_word()),
            "global_paused":control.global_paused(),
            "submitter_role_bitmap":format!("{:#x}",control.submitter_role_bitmap()),
            "submitter_has_operator_role":control.submitter_has_operator_role(),
            "maker_pause_activation_block":format!("{:#x}",control.maker_pause_activation_block()),
            "maker_pause_active":control.maker_pause_active(),
        })).collect::<Vec<_>>(),
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    let path = std::path::Path::new(&directory).join(capture_filename);
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
}

fn capture_native_contiguous_activity(
    fixture: &CtfInventoryFixture,
    reports: &[FifthNativeBinaryActivityObservation],
    intervals: &[super::fifth_native_activity::FifthNativeBinaryActivityIntervalAnchor],
    owner: &str,
    condition_id: B256,
) {
    let Ok(directory) = std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_CONTIGUOUS_DIRECTORY") else {
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
            "native_condition_id":format!("{:#x}",point.native_context().condition_id()),
            "native_position_ids":point.native_context().position_ids().map(|value|format!("{value:#x}")),
            "native_legacy_mapping_value":format!("{:#x}",point.native_context().legacy_mapping_value()),
            "native_result_length":format!("{:#x}",point.native_context().result_length()),
            "native_normalized_numerators":point.native_context().normalized_numerators().map(|values|values.map(|value|format!("{value:#x}"))),
        })
    };
    let locator =
        |value: &super::fifth_direct_module_operations::FifthDirectModuleTransactionLocator| {
            json!({
                "block_number":value.block_number(),
                "block_hash":value.block_hash(),
                "transaction_hash":value.transaction_hash(),
                "transaction_index":value.transaction_index(),
                "log_index":value.log_index(),
            })
        };
    let segments = reports
        .iter()
        .zip(intervals)
        .map(|(report, interval)| {
            json!({
                "from_block":interval.from_block,
                "through_block":interval.through_block,
                "parent_hash":interval.expected_parent_hash,
                "end_hash":interval.expected_end_hash,
                "status":format!("{:?}",report.status()),
                "source_policy_version":report.source_policy_version(),
                "opening":boundary(report.opening()),
                "block_observations":report.block_observations().iter().map(boundary).collect::<Vec<_>>(),
                "trades":report.transactions().iter().map(|fact|json!({
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
                        "log_index":fill.log_index(),
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "module_operations":report.module_operations().iter().map(|fact|json!({
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
                })).collect::<Vec<_>>(),
                "controls":report.controls().iter().map(|control|json!({
                    "block_number":control.code_context().block_number(),
                    "submitter":format!("{:#x}",control.submitter()),
                    "maker":format!("{:#x}",control.maker()),
                    "global_pause_word":format!("{:#x}",control.global_pause_word()),
                    "global_paused":control.global_paused(),
                    "submitter_role_bitmap":format!("{:#x}",control.submitter_role_bitmap()),
                    "submitter_has_operator_role":control.submitter_has_operator_role(),
                    "maker_pause_activation_block":format!("{:#x}",control.maker_pause_activation_block()),
                    "maker_pause_active":control.maker_pause_active(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let envelope = json!({
        "provenance":"Synthetic signed Polygon native Binary activity with root-bound owner/module proofs; no external chain observation.",
        "case":"fund-split-buy-quiet-sell-contiguous",
        "owner":owner,
        "condition_id":format!("{condition_id:#x}"),
        "segments":segments,
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    let path = std::path::Path::new(&directory)
        .join("fifth-native-binary-activity-fund-quiet-sell-rpc.json");
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
}

fn capture_native_failed_type2_gas(
    fixture: &CtfInventoryFixture,
    report: &FifthNativeBinaryActivityObservation,
    gas: &super::NativeGasOwnerIntervalObservation,
    owner: &str,
    condition_id: B256,
) {
    let Ok(directory) = std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_GAS_DIRECTORY") else {
        return;
    };
    let envelope = json!({
        "provenance":"Synthetic signed Polygon native Binary activity with root-bound owner/module proofs; no external chain observation.",
        "case":"fund-split-buy-sell-failed-type2-gas",
        "owner":owner,
        "condition_id":format!("{condition_id:#x}"),
        "activity_status":format!("{:?}",report.status()),
        "gas_observation":{
            "owner":gas.owner(),
            "from_block":gas.from_block(),
            "through_block":gas.through_block(),
            "parent_hash":gas.parent_hash(),
            "end_hash":gas.end_hash(),
            "segment_count":gas.segment_count(),
            "total_owner_paid_base_units":format!("{:#x}",gas.total_owner_paid_base_units()),
            "transactions":gas.transactions().iter().map(|transaction|json!({
                "block_number":transaction.block_number(),
                "block_hash":transaction.block_hash(),
                "transaction_hash":transaction.transaction_hash(),
                "transaction_index":transaction.transaction_index(),
                "receipt_status":transaction.receipt_status(),
                "recovered_sender":transaction.recovered_sender(),
                "gas_used":format!("{:#x}",transaction.gas_used()),
                "effective_gas_price":format!("{:#x}",transaction.effective_gas_price()),
                "charge_base_units":format!("{:#x}",transaction.charge_base_units()),
                "owner_paid":transaction.owner_paid(),
            })).collect::<Vec<_>>(),
        },
        "rpc_responses":fixture.rpc_capture.lock().unwrap().clone(),
    });
    let path = std::path::Path::new(&directory)
        .join("fifth-native-binary-activity-failed-type2-gas-rpc.json");
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
async fn native_binary_activity_accounts_for_fund_split_buy_and_sell() {
    use super::fifth_native_activity::FifthNativeBinaryActivityStatus;

    let (fixture, condition_id, owner_text) = native_accounting_fund_split_buy_sell_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

    assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
    assert_eq!(report.transactions().len(), 2);
    assert_eq!(report.module_operations().len(), 1);
    assert!(
        report
            .transactions()
            .iter()
            .all(|fact| fact.branch() == FifthTradeBranch::Normal)
    );
    let buy = &report.transactions()[0];
    assert_eq!(
        buy.owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(buy.owner_position_outflows(), [U256::ZERO; 2]);
    assert_eq!(buy.owner_pusd_outflow(), U256::from(51_u64));
    assert_eq!(buy.order_fills().len(), 1);
    assert_eq!(buy.order_fills()[0].log_index(), 11);
    let sell = &report.transactions()[1];
    assert_eq!(sell.owner_position_inflows(), [U256::ZERO; 2]);
    assert_eq!(
        sell.owner_position_outflows(),
        [U256::from(50_u64), U256::ZERO]
    );
    assert_eq!(sell.owner_pusd_inflow(), U256::from(24_u64));
    assert_eq!(sell.order_fills().len(), 1);
    assert_eq!(sell.order_fills()[0].log_index(), 20);
    let split = &report.module_operations()[0];
    assert_eq!(split.kind(), FifthDirectModuleOperationKind::Split);
    assert_eq!(split.amount(), U256::from(10_u64));
    assert_eq!(split.funding_transactions().len(), 1);
    assert_eq!(split.funding_transactions()[0].transaction().log_index(), 0);
    assert_eq!(split.operation_transaction().log_index(), 4);
    assert_eq!(split.owner_position_inflows(), [U256::from(10_u64); 2]);
    assert_eq!(split.owner_pusd_outflow(), U256::from(10_u64));
    let opening_balances = report.opening().native_context().selected_balances();
    assert_eq!(opening_balances.position_balance_a(), U256::ZERO);
    assert_eq!(opening_balances.position_balance_b(), U256::ZERO);
    assert_eq!(opening_balances.pusd_balance(), U256::from(1_000_u64));
    let closing = report.block_observations().last().unwrap();
    let closing_balances = closing.native_context().selected_balances();
    assert_eq!(closing_balances.position_balance_a(), U256::from(60_u64));
    assert_eq!(closing_balances.position_balance_b(), U256::from(10_u64));
    assert_eq!(closing_balances.pusd_balance(), U256::from(963_u64));
    assert_eq!(closing.module_position_balances(), [U256::ZERO; 2]);
    assert_eq!(closing.module_pusd_balance(), U256::ZERO);
    let native_gas = super::observe_native_binary_gas_for_owner(
        &[&report],
        &owner_text,
        &format!("{condition_id:#x}"),
    )
    .unwrap();
    assert_eq!(
        native_gas.total_owner_paid_base_units(),
        U256::from(84_000_u64)
    );
    assert_eq!(native_gas.transactions().len(), 5);
    assert_eq!(
        native_gas
            .transactions()
            .iter()
            .filter(|transaction| transaction.owner_paid())
            .count(),
        4
    );
    assert!(!native_gas.transactions()[4].owner_paid());
    assert_eq!(
        native_gas.transactions()[4].gas_used(),
        U256::from(21_000_u64)
    );
    assert!(report.controls().iter().all(|control| {
        !control.global_paused()
            && control.submitter_has_operator_role()
            && !control.maker_pause_active()
    }));
    assert!(fixture.requests.load(Ordering::Relaxed) > 0);
    capture_native_accounting_activity(
        &fixture,
        &report,
        &owner_text,
        condition_id,
        &opening["hash"],
        &ending["hash"],
        "fund-split-buy-sell",
        "fifth-native-binary-activity-fund-split-buy-sell-rpc.json",
    );
}

#[tokio::test]
async fn native_binary_activity_batches_fund_quiet_and_sell_segments_contiguously() {
    use super::fifth_native_activity::{
        BoundedFifthNativeBinaryActivityError, FifthNativeBinaryActivityIntervalAnchor,
        FifthNativeBinaryActivityStatus,
    };

    let (fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    let (opening, block100, block101, block102) = ctf_inventory_headers_with_102(&fixture);
    assert_eq!(block101["transactions"].as_array().unwrap().len(), 1);
    assert!(fixture.extra_inventory_logs.as_ref().unwrap().is_empty());
    let intervals = vec![
        FifthNativeBinaryActivityIntervalAnchor::new(
            100,
            100,
            opening["hash"].as_str().unwrap(),
            block100["hash"].as_str().unwrap(),
        ),
        FifthNativeBinaryActivityIntervalAnchor::new(
            101,
            101,
            block100["hash"].as_str().unwrap(),
            block101["hash"].as_str().unwrap(),
        ),
        FifthNativeBinaryActivityIntervalAnchor::new(
            102,
            102,
            block101["hash"].as_str().unwrap(),
            block102["hash"].as_str().unwrap(),
        ),
    ];
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let reports = verifier
        .verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            2_000,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    assert_eq!(reports.len(), 3);
    assert!(
        reports
            .iter()
            .all(|report| report.status() == &FifthNativeBinaryActivityStatus::Matched)
    );
    assert_eq!(reports[0].transactions().len(), 1);
    assert_eq!(reports[0].module_operations().len(), 1);
    assert_eq!(
        reports[0].transactions()[0].owner_pusd_outflow(),
        U256::from(51_u64)
    );
    assert_eq!(
        reports[0].module_operations()[0].amount(),
        U256::from(10_u64)
    );
    assert!(reports[1].transactions().is_empty());
    assert!(reports[1].module_operations().is_empty());
    assert_eq!(reports[2].transactions().len(), 1);
    assert_eq!(
        reports[2].transactions()[0].owner_pusd_inflow(),
        U256::from(24_u64)
    );

    let acquisition_close = reports[0].block_observations().last().unwrap();
    let quiet_open = reports[1].opening();
    let quiet_close = reports[1].block_observations().last().unwrap();
    let sale_open = reports[2].opening();
    assert_eq!(acquisition_close, quiet_open);
    assert_eq!(quiet_close, sale_open);
    let acquisition_balances = acquisition_close.native_context().selected_balances();
    assert_eq!(
        acquisition_balances.position_balance_a(),
        U256::from(110_u64)
    );
    assert_eq!(
        acquisition_balances.position_balance_b(),
        U256::from(10_u64)
    );
    assert_eq!(acquisition_balances.pusd_balance(), U256::from(939_u64));
    let closing = reports[2].block_observations().last().unwrap();
    let closing_balances = closing.native_context().selected_balances();
    assert_eq!(closing_balances.position_balance_a(), U256::from(60_u64));
    assert_eq!(closing_balances.position_balance_b(), U256::from(10_u64));
    assert_eq!(closing_balances.pusd_balance(), U256::from(963_u64));
    let report_refs = reports.iter().collect::<Vec<_>>();
    let native_gas = super::observe_native_binary_gas_for_owner(
        &report_refs,
        &owner_text,
        &format!("{condition_id:#x}"),
    )
    .unwrap();
    assert_eq!(
        native_gas.total_owner_paid_base_units(),
        U256::from(84_000_u64)
    );
    assert_eq!(native_gas.segment_count(), 3);
    assert_eq!(native_gas.transactions().len(), 5);
    assert_eq!(
        native_gas
            .transactions()
            .iter()
            .filter(|transaction| transaction.owner_paid())
            .count(),
        4
    );

    let mut wrong_condition = condition_id.0;
    wrong_condition[1] ^= 1;
    let wrong_condition = format!("{:#x}", B256::from(wrong_condition));
    assert_eq!(
        super::observe_native_binary_gas_for_owner(&report_refs, &owner_text, &wrong_condition)
            .unwrap_err(),
        "native_gas_identity_or_anchor_mismatch"
    );
    assert_eq!(
        super::observe_native_binary_gas_for_owner(
            &report_refs,
            &format!("0x{}", "22".repeat(20)),
            &format!("{condition_id:#x}")
        )
        .unwrap_err(),
        "native_gas_identity_or_anchor_mismatch"
    );
    assert_eq!(
        super::observe_native_binary_gas_for_owner(
            &[&reports[0], &reports[2]],
            &owner_text,
            &format!("{condition_id:#x}")
        )
        .unwrap_err(),
        "native_gas_interval_discontinuity"
    );
    assert_eq!(
        super::observe_native_binary_gas_for_owner(
            &[&reports[0], &reports[0]],
            &owner_text,
            &format!("{condition_id:#x}")
        )
        .unwrap_err(),
        "native_gas_interval_discontinuity"
    );
    assert_eq!(
        super::observe_native_binary_gas_for_owner(
            &[&reports[2], &reports[1]],
            &owner_text,
            &format!("{condition_id:#x}")
        )
        .unwrap_err(),
        "native_gas_interval_discontinuity"
    );
    assert_eq!(
        reports[0].module_operations()[0].funding_transactions()[0]
            .transaction()
            .block_number(),
        100
    );
    assert_eq!(
        reports[0].module_operations()[0]
            .operation_transaction()
            .block_number(),
        100
    );
    assert_eq!(reports[2].transactions()[0].block_number(), 102);
    capture_native_contiguous_activity(&fixture, &reports, &intervals, &owner_text, condition_id);

    let exact_request_count = fixture.requests.load(Ordering::Relaxed);
    assert!(exact_request_count > 0);
    let (exact_fixture, _, _) = native_contiguous_fund_quiet_sell_fixture();
    let exact_primary = ctf_inventory_provider(exact_fixture.clone()).await;
    let exact_secondary = ctf_inventory_provider(exact_fixture.clone()).await;
    let exact_report = ChainLogVerifier::new(&exact_primary, &exact_secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            exact_request_count,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(exact_report.len(), 3);

    let (short_fixture, _, _) = native_contiguous_fund_quiet_sell_fixture();
    let short_primary = ctf_inventory_provider(short_fixture.clone()).await;
    let short_secondary = ctf_inventory_provider(short_fixture.clone()).await;
    let short_result = ChainLogVerifier::new(&short_primary, &short_secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            exact_request_count - 1,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        short_result,
        Err(BoundedFifthNativeBinaryActivityError::RequestBudgetExceeded)
    );
}

fn rpc_requested_block_102(row: &Value) -> bool {
    row["method"] == "eth_getBlockByNumber" && row["params"][0] == "0x66"
        || row["method"] == "eth_getBlockReceipts" && row["params"][0] == "0x66"
        || row["method"] == "eth_getProof" && row["params"][2] == "0x66"
        || row["method"] == "eth_getLogs" && row["params"][0]["fromBlock"] == "0x66"
}

#[tokio::test]
async fn native_binary_activity_batch_uses_one_absolute_deadline_across_segments() {
    use super::fifth_native_activity::BoundedFifthNativeBinaryActivityError;

    let (mut fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    fixture.initial_clock_advance_ms = Some(500);
    let gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(gate.clone());
    let capture = fixture.rpc_capture.clone();
    let intervals = native_contiguous_anchors(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();

    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                2_000,
                Duration::from_secs(1),
            )
            .await
    });
    tokio::select! {
        _ = gate.started.notified() => {}
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("batch did not reach block101 receipt gate"),
    }
    assert_eq!(
        tokio::time::Instant::now().duration_since(start),
        Duration::from_millis(500)
    );
    assert!(
        capture
            .lock()
            .unwrap()
            .iter()
            .any(|row| { row["method"] == "eth_getBlockReceipts" && row["params"][0] == "0x64" })
    );

    tokio::time::advance(Duration::from_millis(600)).await;
    let joined = tokio::select! {
        output = &mut task => output,
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("batch deadline did not settle"),
    }
    .unwrap();
    assert_eq!(joined, Err(BoundedFifthNativeBinaryActivityError::Timeout));
    gate.release.send_replace(true);
    tokio::task::yield_now().await;
    assert!(!capture.lock().unwrap().iter().any(rpc_requested_block_102));
    tokio::time::resume();
}

#[tokio::test]
async fn native_binary_activity_batch_cancellation_stops_after_block101_gate() {
    let (mut fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    let gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(gate.clone());
    let capture = fixture.rpc_capture.clone();
    let send_counter = fixture.requests.clone();
    let intervals = native_contiguous_anchors(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                2_000,
                Duration::from_secs(20),
            )
            .await
    });
    tokio::select! {
        _ = gate.started.notified() => {}
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("batch did not reach block101 receipt gate"),
    }
    assert!(
        capture
            .lock()
            .unwrap()
            .iter()
            .any(|row| { row["method"] == "eth_getBlockReceipts" && row["params"][0] == "0x64" })
    );

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    gate.release.send_replace(true);
    test_wall_timeout(Duration::from_millis(50)).await;
    let settled = send_counter.load(Ordering::Relaxed);
    test_wall_timeout(Duration::from_millis(50)).await;
    assert_eq!(send_counter.load(Ordering::Relaxed), settled);
    assert!(!capture.lock().unwrap().iter().any(rpc_requested_block_102));
}

#[tokio::test]
async fn native_binary_activity_batch_discards_prefix_on_late_unsupported_call() {
    use super::fifth_native_activity::BoundedFifthNativeBinaryActivityError;

    let (fixture, condition_id, owner_text) = native_contiguous_late_unsupported_fixture();
    let intervals = native_contiguous_anchors(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            2_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(BoundedFifthNativeBinaryActivityError::SegmentUnavailable { segment_index: 2 })
    );
}

#[tokio::test]
async fn native_binary_activity_gas_counts_failed_owner_type_two_receipt() {
    let (mut fixture, condition_id, owner_text) = native_accounting_fund_split_buy_sell_fixture();
    let (failed_transaction, failed_owner) = super::signed_polygon_native_gas_transaction(
        2,
        0x42,
        4,
        100_000,
        U256::ZERO,
        U256::from(25_u64),
        U256::from(25_u64),
    );
    assert_eq!(failed_owner, owner_text);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(failed_transaction);
    rooted.receipt_logs.push(Vec::new());
    rooted.receipt_statuses.push(0);
    rooted.cumulative_gas_used.push(114_000);
    rooted.receipt_types.push(2);
    assert_eq!(rooted.base_fee_per_gas, U256::ZERO);

    let (opening, _, block101, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            block101["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let gas = super::observe_native_binary_gas_for_owner(
        &[&report],
        &owner_text,
        &format!("{condition_id:#x}"),
    )
    .unwrap();
    assert_eq!(gas.total_owner_paid_base_units(), U256::from(834_000_u64));
    assert_eq!(gas.transactions().len(), 6);
    assert!(gas.transactions()[..4].iter().all(|transaction| {
        transaction.block_number() == 100
            && transaction.owner_paid()
            && transaction.gas_used() == U256::from(21_000_u64)
            && transaction.effective_gas_price() == U256::ONE
            && transaction.charge_base_units() == U256::from(21_000_u64)
    }));
    let failed = gas
        .transactions()
        .iter()
        .find(|transaction| {
            transaction.block_number() == 100 && transaction.transaction_index() == 4
        })
        .unwrap();
    assert_eq!(failed.receipt_status(), 0);
    assert!(failed.owner_paid());
    assert_eq!(failed.gas_used(), U256::from(30_000_u64));
    assert_eq!(failed.effective_gas_price(), U256::from(25_u64));
    assert_eq!(failed.charge_base_units(), U256::from(750_000_u64));
    assert!(!gas.transactions()[5].owner_paid());
    assert_eq!(gas.transactions()[5].block_number(), 101);
    assert_eq!(
        gas.transactions()[5].charge_base_units(),
        U256::from(21_000_u64)
    );
    capture_native_failed_type2_gas(&fixture, &report, &gas, &owner_text, condition_id);
}

#[tokio::test]
async fn native_binary_activity_gas_remains_available_when_source_attribution_is_unavailable() {
    let (fixture, condition_id, owner_text) = native_contiguous_late_unsupported_fixture();
    let (_, _, block101, block102) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            102,
            102,
            block101["hash"].as_str().unwrap(),
            block102["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_ne!(
        report.status(),
        &super::FifthNativeBinaryActivityStatus::Matched
    );
    let gas = super::observe_native_binary_gas_for_owner(
        &[&report],
        &owner_text,
        &format!("{condition_id:#x}"),
    )
    .unwrap();
    assert_eq!(gas.total_owner_paid_base_units(), U256::from(21_000_u64));
    assert_eq!(gas.transactions().len(), 1);
    assert!(gas.transactions()[0].owner_paid());
}

#[tokio::test]
async fn native_binary_activity_gas_refusal_keeps_activity_evidence_matched() {
    let (mut fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    fixture
        .rooted_gas_block
        .as_mut()
        .unwrap()
        .cumulative_gas_used[1] = 20_000;
    let intervals = native_contiguous_anchors(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let reports = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            2_000,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert!(
        reports
            .iter()
            .all(|report| { report.status() == &super::FifthNativeBinaryActivityStatus::Matched })
    );
    let report_refs = reports.iter().collect::<Vec<_>>();
    assert_eq!(
        super::observe_native_binary_gas_for_owner(
            &report_refs,
            &owner_text,
            &format!("{condition_id:#x}")
        )
        .unwrap_err(),
        "native_gas_evidence_unavailable"
    );
}

#[tokio::test]
async fn native_binary_activity_batch_rejects_discontinuous_anchors_before_rpc() {
    use super::fifth_native_activity::{
        BoundedFifthNativeBinaryActivityError, FifthNativeBinaryActivityIntervalAnchor,
    };

    let (fixture, condition_id, owner_text) = native_contiguous_fund_quiet_sell_fixture();
    let (_, block100, block101, block102) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    for intervals in [
        vec![
            FifthNativeBinaryActivityIntervalAnchor::new(
                100,
                100,
                format!("0x{}", "88".repeat(32)),
                block100["hash"].as_str().unwrap(),
            ),
            FifthNativeBinaryActivityIntervalAnchor::new(
                102,
                102,
                block101["hash"].as_str().unwrap(),
                block102["hash"].as_str().unwrap(),
            ),
        ],
        vec![
            FifthNativeBinaryActivityIntervalAnchor::new(
                101,
                101,
                block100["hash"].as_str().unwrap(),
                block101["hash"].as_str().unwrap(),
            ),
            FifthNativeBinaryActivityIntervalAnchor::new(
                100,
                100,
                format!("0x{}", "88".repeat(32)),
                block100["hash"].as_str().unwrap(),
            ),
        ],
        vec![
            FifthNativeBinaryActivityIntervalAnchor::new(
                100,
                100,
                format!("0x{}", "88".repeat(32)),
                block100["hash"].as_str().unwrap(),
            ),
            FifthNativeBinaryActivityIntervalAnchor::new(
                101,
                101,
                format!("0x{}", "77".repeat(32)),
                block101["hash"].as_str().unwrap(),
            ),
        ],
    ] {
        let result = verifier
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                2_000,
                Duration::from_secs(30),
            )
            .await;
        assert_eq!(
            result,
            Err(BoundedFifthNativeBinaryActivityError::Verification(
                ChainLogAuditError::InvalidInput
            ))
        );
    }
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);
}

fn native_accounting_vector_calldata(vectors: &Value, name: &str) -> (String, Vec<u8>) {
    let row = vectors["calls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap();
    (
        row["to"].as_str().unwrap().to_owned(),
        hex::decode(row["calldata"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
    )
}

fn native_accounting_set_abi_word(calldata: &mut [u8], argument_index: usize, value: U256) {
    let start = 4 + argument_index * 32;
    calldata[start..start + 32].copy_from_slice(&value.to_be_bytes::<32>());
}

fn native_accounting_partial_redemption_fixture() -> (CtfInventoryFixture, B256, String) {
    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let owner = Address::from_str(&owner_text).unwrap();
    let module_text = vectors["module"].as_str().unwrap();
    let condition_id = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let position_a = parse_fixed_b256(vectors["position_ids"][0].as_str().unwrap()).unwrap();
    let position_b = parse_fixed_b256(vectors["position_ids"][1].as_str().unwrap()).unwrap();

    let (fund_target, mut fund_input) =
        native_accounting_vector_calldata(&vectors, "pusd-fund-split10");
    native_accounting_set_abi_word(&mut fund_input, 1, U256::from(101_u64));
    let (fund_transaction, recovered_funder) =
        signed_polygon_owner_call(&fund_target, &fund_input, 0);
    assert_eq!(recovered_funder, owner_text);

    let (split_target, mut split_input) =
        native_accounting_vector_calldata(&vectors, "split-owner10");
    native_accounting_set_abi_word(&mut split_input, 2, U256::from(101_u64));
    let (split_transaction, recovered_splitter) =
        signed_polygon_owner_call(&split_target, &split_input, 1);
    assert_eq!(recovered_splitter, owner_text);

    let (position_funding_target, mut position_funding_input) =
        native_accounting_vector_calldata(&vectors, "pm-fund-a3");
    native_accounting_set_abi_word(&mut position_funding_input, 3, U256::from(50_u64));
    let (position_funding_transaction, recovered_position_funder) =
        signed_polygon_owner_call(&position_funding_target, &position_funding_input, 2);
    assert_eq!(recovered_position_funder, owner_text);

    let (redeem_target, mut redeem_input) =
        native_accounting_vector_calldata(&vectors, "redeem-owner-a3");
    native_accounting_set_abi_word(&mut redeem_input, 2, U256::from(50_u64));
    let (redeem_transaction, recovered_redeemer) =
        signed_polygon_owner_call(&redeem_target, &redeem_input, 3);
    assert_eq!(recovered_redeemer, owner_text);

    let zero = "0x0000000000000000000000000000000000000000";
    let split_logs = [
        fifth_source_position(
            module_text,
            zero,
            &owner_text,
            U256::from_be_bytes(position_a.0),
            101,
            0,
        ),
        fifth_source_position(
            module_text,
            zero,
            &owner_text,
            U256::from_be_bytes(position_b.0),
            101,
            1,
        ),
        fifth_source_pusd(module_text, zero, 101, 2),
        test_indexed_event_log(
            module_text,
            &movement_topic("PositionsSplit(address,bytes31,address,address,uint256)"),
            &[
                test_address_topic(&owner_text),
                format!("{condition_id:#x}"),
                test_address_topic(&owner_text),
            ],
            [
                address_word_bytes(&owner_text),
                movement_word(U256::from(101_u64)),
            ]
            .concat(),
            3,
        ),
    ];
    let position_funding_logs = [fifth_source_position(
        &owner_text,
        &owner_text,
        module_text,
        U256::from_be_bytes(position_a.0),
        50,
        0,
    )];
    let mut redemption_event_data = movement_word(U256::from(50_u64));
    redemption_event_data.extend(movement_word(U256::from(16_u64)));
    let redemption_logs = [
        fifth_source_pusd(zero, &owner_text, 16, 0),
        fifth_source_position(
            module_text,
            module_text,
            zero,
            U256::from_be_bytes(position_a.0),
            50,
            1,
        ),
        test_indexed_event_log(
            module_text,
            &movement_topic("PositionRedeemed(address,uint256,address,uint256,uint256)"),
            &[
                test_address_topic(&owner_text),
                format!("{position_a:#x}"),
                test_address_topic(&owner_text),
            ],
            redemption_event_data,
            2,
        ),
    ];

    let controls = native_accounting_control_words(owner, &[owner]);
    let result = [
        U256::from(2_u64),
        U256::from(333_333_u64),
        U256::from(666_667_u64),
    ];
    let point = |positions: [U256; 2], cash: U256, module_positions: [U256; 2]| {
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            positions,
            cash,
            module_positions,
            U256::ZERO,
            U256::ONE,
            result,
            &controls,
        )
    };
    let (open_root, open_proofs) = point([U256::ZERO; 2], U256::from(1_000_u64), [U256::ZERO; 2]);
    let (block100_root, block100_proofs) = point(
        [U256::from(51_u64), U256::from(101_u64)],
        U256::from(915_u64),
        [U256::ZERO; 2],
    );
    let (block101_root, block101_proofs) = point(
        [U256::from(51_u64), U256::from(101_u64)],
        U256::from(915_u64),
        [U256::ZERO; 2],
    );

    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = open_root;
    fixture.post_state = Some((block100_root, Value::Null));
    fixture.extra_post_state = Some((block101_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, open_proofs),
        (100, block100_proofs),
        (101, block101_proofs),
    ]));
    fixture.direct_call_transaction = Some(redeem_transaction.clone());
    let (quiet_transaction, _) = signed_polygon_transaction_with_key(
        "0x3535353535353535353535353535353535353535",
        &[],
        QUIET_KEY,
    );
    fixture.extra_direct_call_transaction = Some(quiet_transaction);
    fixture.extra_inventory_logs = Some(Vec::new());
    fixture.inventory_logs = Some(
        split_logs
            .iter()
            .chain(position_funding_logs.iter())
            .chain(redemption_logs.iter())
            .map(native_accounting_log_json)
            .collect(),
    );
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![
            fund_transaction,
            split_transaction,
            position_funding_transaction,
            redeem_transaction,
        ],
        receipt_logs: vec![
            vec![native_accounting_log_json(&fifth_source_pusd(
                &owner_text,
                module_text,
                101,
                0,
            ))],
            split_logs.iter().map(native_accounting_log_json).collect(),
            position_funding_logs
                .iter()
                .map(native_accounting_log_json)
                .collect(),
            redemption_logs
                .iter()
                .map(native_accounting_log_json)
                .collect(),
        ],
        receipt_statuses: vec![1; 4],
        cumulative_gas_used: vec![21_000, 42_000, 63_000, 84_000],
        receipt_types: vec![0; 4],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    (fixture, condition_id, owner_text)
}

#[tokio::test]
async fn native_binary_activity_accounts_for_partial_redemption_at_resolved_payout() {
    use super::fifth_native_activity::FifthNativeBinaryActivityStatus;

    let (fixture, condition_id, owner_text) = native_accounting_partial_redemption_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

    assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
    assert!(report.transactions().is_empty());
    assert_eq!(report.module_operations().len(), 2);
    assert_eq!(
        report.opening().native_context().normalized_numerators(),
        Some([U256::from(333_333_u64), U256::from(666_667_u64),])
    );
    let split = &report.module_operations()[0];
    assert_eq!(split.kind(), FifthDirectModuleOperationKind::Split);
    assert_eq!(split.amount(), U256::from(101_u64));
    assert_eq!(split.owner_position_inflows(), [U256::from(101_u64); 2]);
    assert_eq!(split.owner_pusd_outflow(), U256::from(101_u64));
    let redeem = &report.module_operations()[1];
    assert_eq!(redeem.kind(), FifthDirectModuleOperationKind::Redeem);
    assert_eq!(redeem.amount(), U256::from(50_u64));
    assert_eq!(redeem.payout(), Some(U256::from(16_u64)));
    assert_eq!(
        redeem.owner_position_outflows(),
        [U256::from(50_u64), U256::ZERO]
    );
    assert_eq!(redeem.owner_pusd_inflow(), U256::from(16_u64));
    assert_eq!(redeem.funding_transactions().len(), 1);
    let closing = report.block_observations().last().unwrap();
    let balances = closing.native_context().selected_balances();
    assert_eq!(balances.position_balance_a(), U256::from(51_u64));
    assert_eq!(balances.position_balance_b(), U256::from(101_u64));
    assert_eq!(balances.pusd_balance(), U256::from(915_u64));
    assert_eq!(closing.module_position_balances(), [U256::ZERO; 2]);
    assert_eq!(closing.module_pusd_balance(), U256::ZERO);
    capture_native_accounting_activity(
        &fixture,
        &report,
        &owner_text,
        condition_id,
        &opening["hash"],
        &ending["hash"],
        "partial-redemption",
        "fifth-native-binary-activity-partial-redemption-rpc.json",
    );
}

fn native_accounting_multi_maker_refund_fixture() -> (CtfInventoryFixture, B256, String) {
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let owner = Address::from_str(&owner_text).unwrap();
    let condition_id = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let position_ids = [
        parse_fixed_b256(vectors["position_ids"][0].as_str().unwrap()).unwrap(),
        parse_fixed_b256(vectors["position_ids"][1].as_str().unwrap()).unwrap(),
    ];
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let maker_a = Address::repeat_byte(0x48);
    let maker_b = Address::repeat_byte(0x49);
    let taker_order = fifth_source_order(
        91,
        owner,
        U256::from_be_bytes(position_ids[0].0),
        50,
        100,
        FifthOrderSide::Buy,
        0x91,
    );
    let maker_orders = [
        fifth_source_order(
            92,
            maker_a,
            U256::from_be_bytes(position_ids[1].0),
            30,
            50,
            FifthOrderSide::Buy,
            0x92,
        ),
        fifth_source_order(
            93,
            maker_b,
            U256::from_be_bytes(position_ids[1].0),
            30,
            50,
            FifthOrderSide::Buy,
            0x93,
        ),
    ];
    let taker_hash = fifth_order_eip712_hash(&taker_order, exchange);
    let maker_hashes = maker_orders
        .iter()
        .map(|order| fifth_order_eip712_hash(order, exchange))
        .collect::<Vec<_>>();
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        &maker_orders,
        &[U256::from(30_u64), U256::from(30_u64)],
        &[U256::ONE, U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(50_u64),
            taker_receive_amount: U256::from(100_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let (trade_transaction, recovered_operator) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &input, 0);
    assert_eq!(recovered_operator, owner_text);

    // Independently ordered source logs: 113 PUSD collateral enters the Exchange, 100 is
    // consumed to mint the pair, three fees are charged, and the taker receives refund 10.
    let log_rows = vec![
        fifth_source_pusd(
            &owner_text,
            super::fifth_code_context::EXCHANGE_PROXY,
            51,
            0,
        ),
        fifth_source_pusd(
            &format!("{maker_a:#x}"),
            super::fifth_code_context::EXCHANGE_PROXY,
            31,
            1,
        ),
        fifth_source_order_filled(&maker_orders[0], maker_hashes[0], owner, 30, 50, 1, 2),
        fifth_source_pusd(
            &format!("{maker_b:#x}"),
            super::fifth_code_context::EXCHANGE_PROXY,
            31,
            3,
        ),
        fifth_source_order_filled(&maker_orders[1], maker_hashes[1], owner, 30, 50, 1, 4),
        fifth_source_pusd(super::fifth_code_context::EXCHANGE_PROXY, MODULE, 100, 5),
        fifth_source_position(
            MODULE,
            "0x0000000000000000000000000000000000000000",
            super::fifth_code_context::EXCHANGE_PROXY,
            U256::from_be_bytes(position_ids[0].0),
            100,
            6,
        ),
        fifth_source_position(
            MODULE,
            "0x0000000000000000000000000000000000000000",
            super::fifth_code_context::EXCHANGE_PROXY,
            U256::from_be_bytes(position_ids[1].0),
            100,
            7,
        ),
        fifth_source_pusd(MODULE, "0x0000000000000000000000000000000000000000", 100, 8),
        fifth_source_module_event(true, position_ids[0], 100, 9),
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker_a:#x}"),
            U256::from_be_bytes(position_ids[1].0),
            50,
            10,
        ),
        fifth_source_fee(1, 11),
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker_b:#x}"),
            U256::from_be_bytes(position_ids[1].0),
            50,
            12,
        ),
        fifth_source_fee(1, 13),
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            U256::from_be_bytes(position_ids[0].0),
            100,
            14,
        ),
        fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            FEE_RECEIVER,
            3,
            15,
        ),
        fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            10,
            16,
        ),
        fifth_source_fee(1, 17),
    ];
    let mut logs = log_rows;
    logs.extend(fifth_source_taker_events(
        &taker_order,
        taker_hash,
        40,
        100,
        1,
        18,
    ));

    let controls = native_accounting_control_words(owner, &[owner, maker_a, maker_b]);
    let point = |positions: [U256; 2], cash: U256| {
        fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text,
            condition_id,
            positions,
            cash,
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &controls,
        )
    };
    let (open_root, open_proofs) = point([U256::ZERO; 2], U256::from(1_000_u64));
    let (block100_root, block100_proofs) =
        point([U256::from(100_u64), U256::ZERO], U256::from(959_u64));
    let (block101_root, block101_proofs) =
        point([U256::from(100_u64), U256::ZERO], U256::from(959_u64));

    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = open_root;
    fixture.post_state = Some((block100_root, Value::Null));
    fixture.extra_post_state = Some((block101_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, open_proofs),
        (100, block100_proofs),
        (101, block101_proofs),
    ]));
    fixture.direct_call_transaction = Some(trade_transaction.clone());
    let (quiet_transaction, _) = signed_polygon_transaction_with_key(
        "0x3535353535353535353535353535353535353535",
        &[],
        QUIET_KEY,
    );
    fixture.extra_direct_call_transaction = Some(quiet_transaction);
    fixture.extra_inventory_logs = Some(Vec::new());
    fixture.inventory_logs = Some(logs.iter().map(native_accounting_log_json).collect());
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![trade_transaction],
        receipt_logs: vec![logs.iter().map(native_accounting_log_json).collect()],
        receipt_statuses: vec![1],
        cumulative_gas_used: vec![100_000],
        receipt_types: vec![0],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    (fixture, condition_id, owner_text)
}

#[tokio::test]
async fn native_binary_activity_mint_accounts_for_multi_maker_owner_refund_once() {
    use super::fifth_native_activity::FifthNativeBinaryActivityStatus;

    let (fixture, condition_id, owner_text) = native_accounting_multi_maker_refund_fixture();
    let (opening, _, ending, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_activity_interval_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            100,
            101,
            opening["hash"].as_str().unwrap(),
            ending["hash"].as_str().unwrap(),
            2_000,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

    assert_eq!(report.status(), &FifthNativeBinaryActivityStatus::Matched);
    assert_eq!(report.module_operations().len(), 0);
    assert_eq!(report.transactions().len(), 1);
    let trade = &report.transactions()[0];
    assert_eq!(trade.branch(), FifthTradeBranch::Mint);
    assert_eq!(
        trade.owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(trade.owner_pusd_outflow(), U256::from(51_u64));
    assert_eq!(trade.owner_pusd_inflow(), U256::from(10_u64));
    assert_eq!(trade.owner_fee_amount(), U256::ONE);
    assert_eq!(trade.owner_refund_amount(), U256::from(10_u64));
    assert_eq!(trade.order_fills().len(), 1);
    assert_eq!(trade.order_fills()[0].log_index(), 18);
    let opening_balances = report.opening().native_context().selected_balances();
    assert_eq!(opening_balances.position_balance_a(), U256::ZERO);
    assert_eq!(opening_balances.position_balance_b(), U256::ZERO);
    assert_eq!(opening_balances.pusd_balance(), U256::from(1_000_u64));
    let closing = report.block_observations().last().unwrap();
    let balances = closing.native_context().selected_balances();
    assert_eq!(balances.position_balance_a(), U256::from(100_u64));
    assert_eq!(balances.position_balance_b(), U256::ZERO);
    assert_eq!(balances.pusd_balance(), U256::from(959_u64));
    assert_eq!(closing.module_position_balances(), [U256::ZERO; 2]);
    assert_eq!(closing.module_pusd_balance(), U256::ZERO);
    capture_native_accounting_activity(
        &fixture,
        &report,
        &owner_text,
        condition_id,
        &opening["hash"],
        &ending["hash"],
        "mint-multi-refund",
        "fifth-native-binary-activity-mint-multi-refund-rpc.json",
    );
}

#[test]
fn native_trade_classifier_consumes_duplicate_owner_order_hash_occurrences() {
    use super::fifth_binary_trades::TransactionClassification;
    use super::fifth_code_context::FifthExchangeImplementationVersion;
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let (mut transaction, owner, position_ids) =
        super::fifth_binary_trades::tests::native_pair_source_trade();
    let taker = Address::repeat_byte(0x44);
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let token_a = U256::from_be_bytes(position_ids[0].0);
    let taker_order = fifth_source_order(101, taker, token_a, 60, 100, FifthOrderSide::Buy, 0xa1);
    let owner_maker_order =
        fifth_source_order(102, owner, token_a, 100, 50, FifthOrderSide::Sell, 0xa2);
    let duplicated_maker_hash = fifth_order_eip712_hash(&owner_maker_order, exchange);
    let taker_hash = fifth_order_eip712_hash(&taker_order, exchange);
    let call = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        &[owner_maker_order.clone(), owner_maker_order.clone()],
        &[U256::from(50_u64), U256::from(50_u64)],
        &[U256::ONE, U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(60_u64),
            taker_receive_amount: U256::from(100_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let taker_text = format!("{taker:#x}");
    let owner_text = format!("{owner:#x}");
    let mut logs = vec![
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            &taker_text,
            token_a,
            50,
            0,
        ),
        fifth_source_pusd(&taker_text, &owner_text, 24, 1),
        fifth_source_order_filled(
            &owner_maker_order,
            duplicated_maker_hash,
            taker,
            50,
            25,
            1,
            2,
        ),
        fifth_source_fee(1, 3),
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            &taker_text,
            token_a,
            50,
            4,
        ),
        fifth_source_pusd(&taker_text, &owner_text, 24, 5),
        fifth_source_order_filled(
            &owner_maker_order,
            duplicated_maker_hash,
            taker,
            50,
            25,
            1,
            6,
        ),
        fifth_source_fee(1, 7),
        fifth_source_fee(1, 8),
        fifth_source_pusd(&taker_text, FEE_RECEIVER, 3, 9),
    ];
    logs.extend(fifth_source_taker_events(
        &taker_order,
        taker_hash,
        50,
        100,
        1,
        10,
    ));

    let (signed_transaction, recovered_sender) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &call, 0);
    let encoded =
        encode_signed_transaction_with_sender_recovery(&signed_transaction, true).unwrap();
    let transaction_hash = format!("{:#x}", encoded.hash);
    let block_hash = transaction.logs[0].block_hash.clone();
    for (index, log) in logs.iter_mut().enumerate() {
        log.transaction_hash.clone_from(&transaction_hash);
        log.transaction_index = 0;
        log.block_number = 100;
        log.block_hash.clone_from(&block_hash);
        log.block_log_index = index as u64;
    }
    transaction.transaction_hash = transaction_hash;
    transaction.transaction_index = 0;
    transaction.status = 1;
    transaction.receipt_type = 0;
    transaction.to = signed_transaction["to"].as_str().map(str::to_owned);
    transaction.input = Some(call);
    transaction.recovered_from = Some(recovered_sender);
    transaction.value = U256::ZERO;
    transaction.replay_protected_sender = true;
    transaction.native_gas = None;
    transaction.logs = logs;
    transaction.movement_observations.clear();

    let TransactionClassification::Fact(fact) = super::fifth_binary_trades::classify_transaction(
        &transaction,
        100,
        &block_hash,
        owner,
        position_ids,
        Address::repeat_byte(0x33),
        FifthExchangeImplementationVersion::Current641b,
    ) else {
        panic!("two source occurrences with one owner order hash must both classify");
    };
    assert_eq!(
        fact.owner_position_outflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(fact.owner_pusd_inflow(), U256::from(48_u64));
    assert_eq!(fact.owner_pusd_outflow(), U256::ZERO);
    assert_eq!(fact.owner_fee_amount(), U256::from(2_u64));
    assert_eq!(fact.order_fills().len(), 2);
    assert_eq!(fact.order_fills()[0].order_hash(), duplicated_maker_hash);
    assert_eq!(fact.order_fills()[1].order_hash(), duplicated_maker_hash);
    assert_eq!(fact.order_fills()[0].log_index(), 2);
    assert_eq!(fact.order_fills()[1].log_index(), 6);
    assert_ne!(
        fact.order_fills()[0].log_index(),
        fact.order_fills()[1].log_index()
    );
}
