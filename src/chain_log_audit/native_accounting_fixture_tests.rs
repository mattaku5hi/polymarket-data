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

fn native_two_condition_trade_fixture() -> (CtfInventoryFixture, [B256; 2], String) {
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let owner = Address::from_str(&owner_text).unwrap();
    let condition_a = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let mut condition_b_bytes = [0_u8; 32];
    condition_b_bytes[0] = 1;
    condition_b_bytes[1] = 0xb2;
    condition_b_bytes[16] = 0x31;
    let condition_b = B256::from(condition_b_bytes);
    assert!(super::fifth_native_binary::is_canonical_native_binary_condition(condition_b));
    let conditions = [condition_a, condition_b];
    let positions = conditions.map(|condition| {
        let mut opposite = condition.0;
        opposite[31] = 1;
        [condition, B256::from(opposite)]
    });
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let maker_a = Address::repeat_byte(0x54);
    let maker_b = Address::repeat_byte(0x55);
    let maker_sell = Address::repeat_byte(0x56);

    let buy_a_taker = fifth_source_order(
        201,
        owner,
        U256::from_be_bytes(positions[0][0].0),
        3,
        6,
        FifthOrderSide::Buy,
        0xa1,
    );
    let buy_a_maker = fifth_source_order(
        202,
        maker_a,
        U256::from_be_bytes(positions[0][0].0),
        6,
        3,
        FifthOrderSide::Sell,
        0xa2,
    );
    let buy_a_taker_hash = fifth_order_eip712_hash(&buy_a_taker, exchange);
    let buy_a_maker_hash = fifth_order_eip712_hash(&buy_a_maker, exchange);
    let buy_a_input = super::fifth_match_orders_call::tests::encode_call(
        &buy_a_taker,
        std::slice::from_ref(&buy_a_maker),
        &[U256::from(6_u64)],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(3_u64),
            taker_receive_amount: U256::from(6_u64),
            taker_fee_amount: U256::ZERO,
        },
    );
    let (buy_a_transaction, recovered) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &buy_a_input, 0);
    assert_eq!(recovered, owner_text);
    let buy_a_logs = vec![
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker_a:#x}"),
            &owner_text,
            U256::from_be_bytes(positions[0][0].0),
            6,
            0,
        ),
        fifth_source_pusd(&owner_text, &format!("{maker_a:#x}"), 3, 1),
        fifth_source_order_filled(&buy_a_maker, buy_a_maker_hash, owner, 6, 3, 0, 2),
    ]
    .into_iter()
    .chain(fifth_source_taker_events(
        &buy_a_taker,
        buy_a_taker_hash,
        3,
        6,
        0,
        3,
    ))
    .collect::<Vec<_>>();

    let buy_b_taker = fifth_source_order(
        203,
        owner,
        U256::from_be_bytes(positions[1][0].0),
        2,
        4,
        FifthOrderSide::Buy,
        0xb1,
    );
    let buy_b_maker = fifth_source_order(
        204,
        maker_b,
        U256::from_be_bytes(positions[1][0].0),
        4,
        2,
        FifthOrderSide::Sell,
        0xb2,
    );
    let buy_b_taker_hash = fifth_order_eip712_hash(&buy_b_taker, exchange);
    let buy_b_maker_hash = fifth_order_eip712_hash(&buy_b_maker, exchange);
    let buy_b_input = super::fifth_match_orders_call::tests::encode_call(
        &buy_b_taker,
        std::slice::from_ref(&buy_b_maker),
        &[U256::from(4_u64)],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(2_u64),
            taker_receive_amount: U256::from(4_u64),
            taker_fee_amount: U256::ZERO,
        },
    );
    let (buy_b_transaction, recovered) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &buy_b_input, 1);
    assert_eq!(recovered, owner_text);
    let buy_b_logs = vec![
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &format!("{maker_b:#x}"),
            &owner_text,
            U256::from_be_bytes(positions[1][0].0),
            4,
            0,
        ),
        fifth_source_pusd(&owner_text, &format!("{maker_b:#x}"), 2, 1),
        fifth_source_order_filled(&buy_b_maker, buy_b_maker_hash, owner, 4, 2, 0, 2),
    ]
    .into_iter()
    .chain(fifth_source_taker_events(
        &buy_b_taker,
        buy_b_taker_hash,
        2,
        4,
        0,
        3,
    ))
    .collect::<Vec<_>>();

    let sell_taker = fifth_source_order(
        205,
        owner,
        U256::from_be_bytes(positions[0][0].0),
        6,
        2,
        FifthOrderSide::Sell,
        0xc1,
    );
    let sell_maker = fifth_source_order(
        206,
        maker_sell,
        U256::from_be_bytes(positions[0][0].0),
        2,
        6,
        FifthOrderSide::Buy,
        0xc2,
    );
    let sell_taker_hash = fifth_order_eip712_hash(&sell_taker, exchange);
    let sell_maker_hash = fifth_order_eip712_hash(&sell_maker, exchange);
    let sell_input = super::fifth_match_orders_call::tests::encode_call(
        &sell_taker,
        std::slice::from_ref(&sell_maker),
        &[U256::from(2_u64)],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(6_u64),
            taker_receive_amount: U256::from(2_u64),
            taker_fee_amount: U256::ZERO,
        },
    );
    let (sell_transaction, recovered) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &sell_input, 2);
    assert_eq!(recovered, owner_text);
    let sell_logs = vec![
        fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            &format!("{maker_sell:#x}"),
            U256::from_be_bytes(positions[0][0].0),
            6,
            0,
        ),
        fifth_source_pusd(&format!("{maker_sell:#x}"), &owner_text, 2, 1),
        fifth_source_order_filled(&sell_maker, sell_maker_hash, owner, 2, 6, 0, 2),
    ]
    .into_iter()
    .chain(fifth_source_taker_events(
        &sell_taker,
        sell_taker_hash,
        6,
        2,
        0,
        3,
    ))
    .collect::<Vec<_>>();

    let controls = native_accounting_control_words(owner, &[owner, maker_a, maker_b, maker_sell]);
    let point = |owner_positions: [[U256; 2]; 2], cash: u64| {
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner_text,
            condition_a,
            owner_positions[0],
            condition_b,
            owner_positions[1],
            U256::from(cash),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            &controls,
        )
    };
    let (opening_root, opening_proofs) = point([[U256::ZERO; 2], [U256::ZERO; 2]], 1_000);
    let (acquisition_root, acquisition_proofs) = point(
        [
            [U256::from(6_u64), U256::ZERO],
            [U256::from(4_u64), U256::ZERO],
        ],
        995,
    );
    let (closing_root, closing_proofs) =
        point([[U256::ZERO; 2], [U256::from(4_u64), U256::ZERO]], 997);

    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = opening_root;
    fixture.post_state = Some((acquisition_root, Value::Null));
    fixture.extra_post_state = Some((closing_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, opening_proofs),
        (100, acquisition_proofs),
        (101, closing_proofs),
    ]));
    fixture.extra_direct_call_transaction = Some(sell_transaction);
    fixture.extra_inventory_logs = Some(sell_logs.iter().map(native_accounting_log_json).collect());
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![buy_a_transaction, buy_b_transaction],
        receipt_logs: vec![
            buy_a_logs.iter().map(native_accounting_log_json).collect(),
            buy_b_logs.iter().map(native_accounting_log_json).collect(),
        ],
        receipt_statuses: vec![1, 1],
        cumulative_gas_used: vec![21_000, 42_000],
        receipt_types: vec![0, 0],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    (fixture, conditions, owner_text)
}

fn native_two_condition_split_fixture(
    reverse_order: bool,
) -> (CtfInventoryFixture, [B256; 2], String) {
    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let owner_text = vectors["owner"].as_str().unwrap().to_owned();
    let owner = Address::from_str(&owner_text).unwrap();
    let condition_a = parse_fixed_b256(vectors["condition_id"].as_str().unwrap()).unwrap();
    let mut condition_b_bytes = [0_u8; 32];
    condition_b_bytes[0] = 1;
    condition_b_bytes[1] = 0xb2;
    condition_b_bytes[16] = 0x31;
    let conditions = [condition_a, B256::from(condition_b_bytes)];
    let positions = conditions.map(|condition| {
        let mut opposite = condition.0;
        opposite[31] = 1;
        [condition, B256::from(opposite)]
    });
    let (fund_target, fund_input) =
        native_accounting_vector_calldata(&vectors, "pusd-fund-split10");
    let (fund_transaction, recovered_funder) =
        signed_polygon_owner_call(&fund_target, &fund_input, 0);
    assert_eq!(recovered_funder, owner_text);

    let make_split = |condition_index: usize, amount: u64, nonce: u64| {
        let (target, mut input) = native_accounting_vector_calldata(&vectors, "split-owner10");
        native_accounting_set_abi_word(
            &mut input,
            1,
            U256::from_be_bytes(conditions[condition_index].0),
        );
        native_accounting_set_abi_word(&mut input, 2, U256::from(amount));
        let (transaction, recovered) = signed_polygon_owner_call(&target, &input, nonce);
        assert_eq!(recovered, owner_text);
        let zero = "0x0000000000000000000000000000000000000000";
        let logs = vec![
            fifth_source_position(
                MODULE,
                zero,
                &owner_text,
                U256::from_be_bytes(positions[condition_index][0].0),
                amount,
                0,
            ),
            fifth_source_position(
                MODULE,
                zero,
                &owner_text,
                U256::from_be_bytes(positions[condition_index][1].0),
                amount,
                1,
            ),
            fifth_source_pusd(MODULE, zero, amount, 2),
            test_indexed_event_log(
                MODULE,
                &movement_topic("PositionsSplit(address,bytes31,address,address,uint256)"),
                &[
                    test_address_topic(&owner_text),
                    format!("{:#x}", conditions[condition_index]),
                    test_address_topic(&owner_text),
                ],
                [
                    address_word_bytes(&owner_text),
                    movement_word(U256::from(amount)),
                ]
                .concat(),
                3,
            ),
        ];
        (transaction, logs)
    };
    let (split_a, logs_a) = make_split(0, 4, if reverse_order { 2 } else { 1 });
    let (split_b, logs_b) = make_split(1, 6, if reverse_order { 1 } else { 2 });
    let (first_split, first_logs, second_split, second_logs) = if reverse_order {
        (split_b, logs_b, split_a, logs_a)
    } else {
        (split_a, logs_a, split_b, logs_b)
    };

    let controls = native_accounting_control_words(owner, &[owner]);
    let point = |owner_a: [U256; 2], owner_b: [U256; 2], cash: u64, module_cash: u64| {
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner_text,
            conditions[0],
            owner_a,
            conditions[1],
            owner_b,
            U256::from(cash),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::from(module_cash),
            U256::ONE,
            &controls,
        )
    };
    let (opening_root, opening_proofs) = point([U256::ZERO; 2], [U256::ZERO; 2], 1_000, 0);
    let (block100_root, block100_proofs) = if reverse_order {
        point([U256::ZERO; 2], [U256::from(6_u64); 2], 990, 4)
    } else {
        point([U256::from(4_u64); 2], [U256::ZERO; 2], 990, 6)
    };
    let (block101_root, block101_proofs) =
        point([U256::from(4_u64); 2], [U256::from(6_u64); 2], 990, 0);
    let mut fixture = ctf_inventory_fixture(U256::ZERO, 0);
    fixture.state_root = opening_root;
    fixture.post_state = Some((block100_root, Value::Null));
    fixture.extra_post_state = Some((block101_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, opening_proofs),
        (100, block100_proofs),
        (101, block101_proofs),
    ]));
    fixture.rooted_gas_block = Some(RootedGasBlockFixture {
        transactions: vec![fund_transaction, first_split],
        receipt_logs: vec![
            vec![native_accounting_log_json(&fifth_source_pusd(
                &owner_text,
                MODULE,
                10,
                0,
            ))],
            first_logs.iter().map(native_accounting_log_json).collect(),
        ],
        receipt_statuses: vec![1, 1],
        cumulative_gas_used: vec![21_000, 42_000],
        receipt_types: vec![0, 0],
        gas_limit: 1_000_000,
        base_fee_per_gas: U256::ZERO,
        header_gas_used_override: None,
        tamper_header_gas_used: false,
        tamper_cumulative_index: None,
    });
    fixture.extra_direct_call_transaction = Some(second_split);
    fixture.extra_inventory_logs =
        Some(second_logs.iter().map(native_accounting_log_json).collect());
    (fixture, conditions, owner_text)
}

fn native_two_condition_activity_fixture() -> (CtfInventoryFixture, [B256; 2], String) {
    use super::fifth_match_orders_call::{
        FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash,
    };

    let (mut fixture, conditions, owner_text) = native_two_condition_split_fixture(false);
    let owner = Address::from_str(&owner_text).unwrap();
    let maker = Address::repeat_byte(0x56);
    let position_a = U256::from_be_bytes(conditions[0].0);
    let exchange = super::fifth_code_context::EXCHANGE_PROXY;
    let taker_order = fifth_source_order(205, owner, position_a, 4, 3, FifthOrderSide::Sell, 0xc1);
    let maker_order = fifth_source_order(206, maker, position_a, 3, 4, FifthOrderSide::Buy, 0xc2);
    let taker_hash = fifth_order_eip712_hash(&taker_order, Address::from_str(exchange).unwrap());
    let maker_hash = fifth_order_eip712_hash(&maker_order, Address::from_str(exchange).unwrap());
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        std::slice::from_ref(&maker_order),
        &[U256::from(3_u64)],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(4_u64),
            taker_receive_amount: U256::from(3_u64),
            taker_fee_amount: U256::ZERO,
        },
    );
    let (sell_transaction, recovered) = signed_polygon_owner_call(exchange, &input, 2);
    assert_eq!(recovered, owner_text);
    let sell_logs = vec![
        fifth_source_position(
            exchange,
            &owner_text,
            &format!("{maker:#x}"),
            position_a,
            4,
            0,
        ),
        fifth_source_pusd(&format!("{maker:#x}"), &owner_text, 3, 1),
        fifth_source_order_filled(&maker_order, maker_hash, owner, 3, 4, 0, 2),
    ]
    .into_iter()
    .chain(fifth_source_taker_events(
        &taker_order,
        taker_hash,
        4,
        3,
        0,
        3,
    ))
    .collect::<Vec<_>>();

    let second_split_input = hex::decode(
        fixture.extra_direct_call_transaction.as_ref().unwrap()["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (second_split, recovered) = signed_polygon_owner_call(MODULE, &second_split_input, 3);
    assert_eq!(recovered, owner_text);
    fixture.extra_direct_call_transaction = Some(second_split);

    let controls = native_accounting_control_words(owner, &[owner, maker]);
    let point = |owner_a, owner_b, cash, module_cash| {
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner_text,
            conditions[0],
            owner_a,
            conditions[1],
            owner_b,
            U256::from(cash),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::from(module_cash),
            U256::ONE,
            &controls,
        )
    };
    let (opening_root, opening_proofs) = point([U256::ZERO; 2], [U256::ZERO; 2], 1_000_u64, 0_u64);
    let (block100_root, block100_proofs) = point(
        [U256::ZERO, U256::from(4_u64)],
        [U256::ZERO; 2],
        993_u64,
        6_u64,
    );
    let (block101_root, block101_proofs) = point(
        [U256::ZERO, U256::from(4_u64)],
        [U256::from(6_u64); 2],
        993_u64,
        0_u64,
    );
    fixture.state_root = opening_root;
    fixture.post_state = Some((block100_root, Value::Null));
    fixture.extra_post_state = Some((block101_root, Value::Null));
    fixture.finalized_block = 102;
    fixture.filter_fifth_code_proofs_by_requested_keys = true;
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, opening_proofs),
        (100, block100_proofs),
        (101, block101_proofs),
    ]));
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(sell_transaction);
    rooted
        .receipt_logs
        .push(sell_logs.iter().map(native_accounting_log_json).collect());
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    (fixture, conditions, owner_text)
}

fn activity_rooted_point(
    owner: &str,
    conditions: [B256; 2],
    owner_a: [U256; 2],
    owner_b: [U256; 2],
    owner_cash: u64,
    module_cash: u64,
    module_roles: U256,
) -> (String, BTreeMap<String, Value>) {
    let owner_address = Address::from_str(owner).unwrap();
    let maker = Address::repeat_byte(0x56);
    let controls = native_accounting_control_words(owner_address, &[owner_address, maker]);
    fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
        owner,
        conditions[0],
        owner_a,
        conditions[1],
        owner_b,
        U256::from(owner_cash),
        [U256::ZERO; 2],
        [U256::ZERO; 2],
        U256::from(module_cash),
        module_roles,
        &controls,
    )
}

fn move_activity_second_split_into_block100(
    fixture: &mut CtfInventoryFixture,
    owner: &str,
    conditions: [B256; 2],
) {
    let split = fixture.extra_direct_call_transaction.take().unwrap();
    let logs = fixture.extra_inventory_logs.take().unwrap();
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(split);
    rooted.receipt_logs.push(logs);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);

    let (root, proofs) = activity_rooted_point(
        owner,
        conditions,
        [U256::ZERO, U256::from(4_u64)],
        [U256::from(6_u64); 2],
        993,
        0,
        U256::ONE,
    );
    fixture.post_state = Some((root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, proofs);
}

fn capture_native_two_condition_splits(
    fixture: &CtfInventoryFixture,
    report: &super::FifthNativeBinaryTwoConditionSplitObservation,
    conditions: [B256; 2],
    owner: &str,
    parent_hash: &str,
    end_hash: &str,
) {
    let Ok(directory) =
        std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_TWO_CONDITION_SPLITS_DIRECTORY")
    else {
        return;
    };
    let mut unique = BTreeMap::new();
    for row in fixture.rpc_capture.lock().unwrap().iter() {
        let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
        if let Some(previous) = unique.insert(key, row.clone()) {
            assert_eq!(previous["result"], row["result"]);
        }
    }
    let boundary = |pair: &[FifthNativeBinaryModuleOperationBoundary; 2]| {
        pair.iter()
            .map(|point| {
                let selected = point.native_context().selected_balances();
                json!({
                    "block_number":selected.block_number(),
                    "block_hash":selected.block_hash(),
                    "state_root":selected.state_root(),
                    "condition_id":format!("{:#x}",point.native_context().condition_id()),
                    "position_ids":point.native_context().position_ids().map(|id|format!("{id:#x}")),
                    "owner_positions":[format!("{:#x}",selected.position_balance_a()),format!("{:#x}",selected.position_balance_b())],
                    "owner_cash":format!("{:#x}",selected.pusd_balance()),
                    "module_positions":point.module_position_balances().map(|value|format!("{value:#x}")),
                    "module_cash":format!("{:#x}",point.module_pusd_balance()),
                    "module_role":format!("{:#x}",point.module_role_bitmap()),
                    "legacy_mapping":format!("{:#x}",point.native_context().legacy_mapping_value()),
                })
            })
            .collect::<Vec<_>>()
    };
    let locator = |value: &FifthDirectModuleTransactionLocator| {
        json!({
            "block_number":value.block_number(),
            "block_hash":value.block_hash(),
            "transaction_hash":value.transaction_hash(),
            "transaction_index":value.transaction_index(),
            "log_index":value.log_index(),
        })
    };
    let envelope = json!({
        "provenance":"Synthetic signed Polygon native Binary split evidence with root-bound owner/module proofs; no external chain observation.",
        "case":"two-condition-owner-funded-splits",
        "owner":owner,
        "conditions":conditions.map(|condition|format!("{condition:#x}")),
        "from_block":100,
        "through_block":101,
        "parent_hash":parent_hash,
        "end_hash":end_hash,
        "source_policy_version":report.source_policy_version(),
        "opening":boundary(report.opening()),
        "block_observations":report.block_observations().iter().map(boundary).collect::<Vec<_>>(),
        "funding":{
            "transaction":locator(report.funding().transaction()),
            "asset":format!("{:?}",report.funding().asset()),
            "amount":format!("{:#x}",report.funding().amount()),
        },
        "splits":report.splits().iter().map(|fact|json!({
            "condition_index":fact.condition_index(),
            "condition_id":format!("{:#x}",fact.condition_id()),
            "amount":format!("{:#x}",fact.amount()),
            "operation_transaction":locator(fact.operation_transaction()),
        })).collect::<Vec<_>>(),
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    let path = std::path::Path::new(&directory).join("fifth-native-two-condition-splits-rpc.json");
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
}

fn capture_native_two_condition_activity(
    fixture: &CtfInventoryFixture,
    report: &super::FifthNativeBinaryTwoConditionActivityObservation,
    conditions: [B256; 2],
    owner: &str,
    parent_hash: &str,
    end_hash: &str,
) {
    let Ok(directory) =
        std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_TWO_CONDITION_ACTIVITY_DIRECTORY")
    else {
        return;
    };
    let mut unique = BTreeMap::new();
    for row in fixture.rpc_capture.lock().unwrap().iter() {
        let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
        if let Some(previous) = unique.insert(key, row.clone()) {
            assert_eq!(previous["result"], row["result"]);
        }
    }
    let boundary = |pair: &[FifthNativeBinaryModuleOperationBoundary; 2]| {
        pair.iter()
            .map(|point| {
                let selected = point.native_context().selected_balances();
                json!({
                    "block_number":selected.block_number(),
                    "block_hash":selected.block_hash(),
                    "state_root":selected.state_root(),
                    "condition_id":format!("{:#x}",point.native_context().condition_id()),
                    "position_ids":point.native_context().position_ids().map(|id|format!("{id:#x}")),
                    "owner_positions":[format!("{:#x}",selected.position_balance_a()),format!("{:#x}",selected.position_balance_b())],
                    "owner_cash":format!("{:#x}",selected.pusd_balance()),
                    "module_positions":point.module_position_balances().map(|value|format!("{value:#x}")),
                    "module_cash":format!("{:#x}",point.module_pusd_balance()),
                    "module_role":format!("{:#x}",point.module_role_bitmap()),
                    "legacy_mapping":format!("{:#x}",point.native_context().legacy_mapping_value()),
                })
            })
            .collect::<Vec<_>>()
    };
    let locator = |value: &FifthDirectModuleTransactionLocator| {
        json!({
            "block_number":value.block_number(),
            "block_hash":value.block_hash(),
            "transaction_hash":value.transaction_hash(),
            "transaction_index":value.transaction_index(),
            "log_index":value.log_index(),
        })
    };
    let trade_locator = |fact: &super::fifth_binary_trades::FifthTradeTransactionFact| {
        json!({
            "block_number":fact.block_number(),
            "block_hash":fact.block_hash(),
            "transaction_hash":fact.transaction_hash(),
            "transaction_index":fact.transaction_index(),
            "owner_position_inflows":fact.owner_position_inflows().map(|value|format!("{value:#x}")),
            "owner_position_outflows":fact.owner_position_outflows().map(|value|format!("{value:#x}")),
            "owner_pusd_inflow":format!("{:#x}",fact.owner_pusd_inflow()),
            "owner_pusd_outflow":format!("{:#x}",fact.owner_pusd_outflow()),
            "owner_fee_amount":format!("{:#x}",fact.owner_fee_amount()),
        })
    };
    let envelope = json!({
        "provenance":"Synthetic signed Polygon owner funding, native splits and Exchange source trade with root-bound owner/module proofs; no external chain observation.",
        "case":"two-condition-funded-split-and-trade-activity",
        "owner":owner,
        "conditions":conditions.map(|condition|format!("{condition:#x}")),
        "from_block":100,
        "through_block":101,
        "parent_hash":parent_hash,
        "end_hash":end_hash,
        "source_policy_version":report.source_policy_version(),
        "opening":boundary(report.opening()),
        "block_observations":report.block_observations().iter().map(boundary).collect::<Vec<_>>(),
        "funding":{
            "transaction":locator(report.funding().transaction()),
            "asset":format!("{:?}",report.funding().asset()),
            "amount":format!("{:#x}",report.funding().amount()),
        },
        "splits":report.splits().iter().map(|fact|json!({
            "condition_index":fact.condition_index(),
            "condition_id":format!("{:#x}",fact.condition_id()),
            "amount":format!("{:#x}",fact.amount()),
            "operation_transaction":locator(fact.operation_transaction()),
        })).collect::<Vec<_>>(),
        "trades":report.trades().iter().map(|fact|json!({
            "condition_index":fact.condition_index(),
            "transaction":trade_locator(fact.transaction()),
        })).collect::<Vec<_>>(),
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    let path =
        std::path::Path::new(&directory).join("fifth-native-two-condition-activity-rpc.json");
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
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

fn capture_native_two_condition_trade(
    fixture: &CtfInventoryFixture,
    report: &super::FifthNativeBinaryTwoConditionTradeObservation,
    conditions: [B256; 2],
    owner: &str,
    parent_hash: &str,
    end_hash: &str,
) {
    let Ok(directory) =
        std::env::var("POLYMARKET_DATA_CAPTURE_NATIVE_TWO_CONDITION_TRADE_DIRECTORY")
    else {
        return;
    };
    let mut unique = BTreeMap::new();
    for row in fixture.rpc_capture.lock().unwrap().iter() {
        let key = serde_json::to_string(&json!([row["method"], row["params"]])).unwrap();
        if let Some(previous) = unique.insert(key, row.clone()) {
            assert_eq!(previous["result"], row["result"]);
        }
    }
    let boundary = |pair: &[FifthNativeBinaryModuleOperationBoundary; 2]| {
        pair.iter().map(|point| {
            let balances = point.native_context().selected_balances();
            json!({
                "condition_id":format!("{:#x}",point.native_context().condition_id()),
                "block_number":balances.block_number(),
                "block_hash":balances.block_hash(),
                "state_root":balances.state_root(),
                "owner_positions":[format!("{:#x}",balances.position_balance_a()),format!("{:#x}",balances.position_balance_b())],
                "owner_pusd":format!("{:#x}",balances.pusd_balance()),
                "module_positions":point.module_position_balances().map(|value|format!("{value:#x}")),
                "module_pusd":format!("{:#x}",point.module_pusd_balance()),
                "module_roles":format!("{:#x}",point.module_role_bitmap()),
                "module_implementation":format!("{:#x}",point.native_context().module_implementation()),
                "module_code_hash":format!("{:#x}",point.native_context().module_implementation_code_hash()),
                "legacy_mapping":format!("{:#x}",point.native_context().legacy_mapping_value()),
                "result_length":format!("{:#x}",point.native_context().result_length()),
            })
        }).collect::<Vec<_>>()
    };
    let envelope = json!({
        "provenance":"Synthetic signed Polygon two-condition native trade evidence assembled from one same-root trie at each boundary; no external chain observation.",
        "case":"two-condition-cross-pair-trades-shared-pusd",
        "owner":owner,
        "condition_ids":conditions.map(|value|format!("{value:#x}")),
        "from_block":report.evidence().from_block(),
        "through_block":report.evidence().through_block(),
        "parent_hash":parent_hash,
        "end_hash":end_hash,
        "source_policy_version":report.source_policy_version(),
        "opening":boundary(report.opening()),
        "block_observations":report.block_observations().iter().map(boundary).collect::<Vec<_>>(),
        "transactions":report.transactions().iter().map(|tagged| {
            let fact = tagged.transaction();
            json!({
                "condition_index":tagged.condition_index(),
                "block_number":fact.block_number(),
                "block_hash":fact.block_hash(),
                "transaction_hash":fact.transaction_hash(),
                "transaction_index":fact.transaction_index(),
                "branch":format!("{:?}",fact.branch()),
                "owner_position_inflows":fact.owner_position_inflows().map(|value|format!("{value:#x}")),
                "owner_position_outflows":fact.owner_position_outflows().map(|value|format!("{value:#x}")),
                "owner_pusd_inflow":format!("{:#x}",fact.owner_pusd_inflow()),
                "owner_pusd_outflow":format!("{:#x}",fact.owner_pusd_outflow()),
                "owner_fee":format!("{:#x}",fact.owner_fee_amount()),
                "fills":fact.order_fills().iter().map(|fill|json!({
                    "order_hash":format!("{:#x}",fill.order_hash()),
                    "token_id":format!("{:#x}",fill.token_id()),
                    "maker":format!("{:#x}",fill.maker()),
                    "side":format!("{:?}",fill.side()),
                    "owner_role":format!("{:?}",fill.owner_role()),
                    "maker_amount_filled":format!("{:#x}",fill.maker_amount_filled()),
                    "taker_amount_filled":format!("{:#x}",fill.taker_amount_filled()),
                    "fee":format!("{:#x}",fill.fee_amount()),
                    "log_index":fill.log_index(),
                })).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "controls":report.controls().iter().map(|control|json!({
            "block_number":control.code_context().block_number(),
            "submitter":format!("{:#x}",control.submitter()),
            "maker":format!("{:#x}",control.maker()),
            "global_pause_word":format!("{:#x}",control.global_pause_word()),
            "submitter_role_bitmap":format!("{:#x}",control.submitter_role_bitmap()),
            "maker_pause_activation_block":format!("{:#x}",control.maker_pause_activation_block()),
        })).collect::<Vec<_>>(),
        "actual_request_count":fixture.requests.load(Ordering::Relaxed),
        "deduplicated_request_count":unique.len(),
        "rpc_responses":unique.into_values().collect::<Vec<_>>(),
    });
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(std::path::Path::new(&directory).join("fifth-native-two-condition-trade-rpc.json"))
        .unwrap()
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
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
    let reports = super::await_loopback_without_virtual_time_advance(
        verifier.verify_fifth_native_binary_activity_intervals_bounded(
            &owner_text,
            &format!("{condition_id:#x}"),
            &intervals,
            2_000,
            Duration::from_secs(30),
        ),
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
    let exact_report = super::await_loopback_without_virtual_time_advance(
        ChainLogVerifier::new(&exact_primary, &exact_secondary)
            .unwrap()
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                exact_request_count,
                Duration::from_secs(30),
            ),
    )
    .await
    .unwrap();
    assert_eq!(exact_report.len(), 3);

    let (short_fixture, _, _) = native_contiguous_fund_quiet_sell_fixture();
    let short_primary = ctf_inventory_provider(short_fixture.clone()).await;
    let short_secondary = ctf_inventory_provider(short_fixture.clone()).await;
    let short_result = super::await_loopback_without_virtual_time_advance(
        ChainLogVerifier::new(&short_primary, &short_secondary)
            .unwrap()
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                exact_request_count - 1,
                Duration::from_secs(30),
            ),
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
    let result = super::await_loopback_without_virtual_time_advance(
        ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_activity_intervals_bounded(
                &owner_text,
                &format!("{condition_id:#x}"),
                &intervals,
                2_000,
                Duration::from_secs(30),
            ),
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

#[tokio::test]
async fn native_two_condition_trades_share_one_rooted_cash_stream_and_receipt_interval() {
    let (fixture, conditions, owner) = native_two_condition_trade_fixture();
    let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            parent["hash"].as_str().unwrap(),
            end["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();

    assert_eq!(
        report.source_policy_version(),
        super::FIFTH_NATIVE_TWO_CONDITION_TRADE_POLICY_VERSION
    );
    assert_eq!(report.evidence().blocks().len(), 2);
    assert_eq!(report.transactions().len(), 3);
    assert_eq!(
        report
            .transactions()
            .iter()
            .map(|fact| fact.condition_index())
            .collect::<Vec<_>>(),
        vec![0, 1, 0]
    );
    assert!(report.transactions()[0].transaction().block_number() == 100);
    assert!(report.transactions()[1].transaction().block_number() == 100);
    assert!(report.transactions()[2].transaction().block_number() == 101);
    assert_eq!(
        report.transactions()[0]
            .transaction()
            .owner_position_inflows(),
        [U256::from(6_u64), U256::ZERO]
    );
    assert_eq!(
        report.transactions()[0].transaction().owner_pusd_outflow(),
        U256::from(3_u64)
    );
    assert_eq!(
        report.transactions()[1]
            .transaction()
            .owner_position_inflows(),
        [U256::from(4_u64), U256::ZERO]
    );
    assert_eq!(
        report.transactions()[1].transaction().owner_pusd_outflow(),
        U256::from(2_u64)
    );
    assert_eq!(
        report.transactions()[2]
            .transaction()
            .owner_position_outflows(),
        [U256::from(6_u64), U256::ZERO]
    );
    assert_eq!(
        report.transactions()[2].transaction().owner_pusd_inflow(),
        U256::from(2_u64)
    );
    assert!(
        report
            .transactions()
            .iter()
            .all(|fact| fact.transaction().owner_fee_amount().is_zero())
    );

    let opening_cash = report.opening()[0]
        .native_context()
        .selected_balances()
        .pusd_balance();
    assert_eq!(opening_cash, U256::from(1_000_u64));
    let acquired = &report.block_observations()[0];
    assert_eq!(
        acquired[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(6_u64)
    );
    assert_eq!(
        acquired[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(4_u64)
    );
    assert_eq!(
        acquired[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(995_u64)
    );
    let closed = &report.block_observations()[1];
    assert_eq!(
        closed[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::ZERO
    );
    assert_eq!(
        closed[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(4_u64)
    );
    assert_eq!(
        closed[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(997_u64)
    );
    assert_eq!(
        closed[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        closed[1]
            .native_context()
            .selected_balances()
            .pusd_balance()
    );
    assert!(fixture.requests.load(Ordering::Relaxed) > 0);
    assert_eq!(fixture.receipt_requests.load(Ordering::Relaxed), 4);
    capture_native_two_condition_trade(
        &fixture,
        &report,
        conditions,
        &owner,
        parent["hash"].as_str().unwrap(),
        end["hash"].as_str().unwrap(),
    );
}

#[tokio::test]
async fn native_two_condition_splits_replay_one_funding_and_shared_module_cash() {
    let (fixture, conditions, owner) = native_two_condition_split_fixture(false);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();

    assert_eq!(
        report.source_policy_version(),
        super::FIFTH_NATIVE_TWO_CONDITION_SPLIT_POLICY_VERSION
    );
    assert_eq!(report.evidence().blocks().len(), 2);
    assert_eq!(
        report.funding().asset(),
        FifthDirectModuleFundingAsset::Pusd
    );
    assert_eq!(report.funding().amount(), U256::from(10_u64));
    assert_eq!(report.funding().transaction().block_number(), 100);
    assert_eq!(report.funding().transaction().log_index(), 0);
    assert_eq!(report.splits().len(), 2);
    assert_eq!(report.splits()[0].condition_index(), 0);
    assert_eq!(report.splits()[0].amount(), U256::from(4_u64));
    assert_eq!(
        report.splits()[0].operation_transaction().block_number(),
        100
    );
    assert_eq!(report.splits()[1].condition_index(), 1);
    assert_eq!(report.splits()[1].amount(), U256::from(6_u64));
    assert_eq!(
        report.splits()[1].operation_transaction().block_number(),
        101
    );
    let middle = &report.block_observations()[0];
    assert_eq!(
        middle[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(990_u64)
    );
    assert_eq!(
        middle[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(4_u64)
    );
    assert_eq!(
        middle[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::ZERO
    );
    assert_eq!(middle[0].module_pusd_balance(), U256::from(6_u64));
    assert_eq!(middle[1].module_pusd_balance(), U256::from(6_u64));
    let end = &report.block_observations()[1];
    assert_eq!(
        end[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(4_u64)
    );
    assert_eq!(
        end[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(6_u64)
    );
    assert_eq!(end[0].module_pusd_balance(), U256::ZERO);
    assert_eq!(end[1].module_pusd_balance(), U256::ZERO);
    assert!(
        end.iter()
            .all(|point| point.module_position_balances() == [U256::ZERO; 2])
    );
    assert!(fixture.requests.load(Ordering::Relaxed) > 0);
    capture_native_two_condition_splits(
        &fixture,
        &report,
        conditions,
        &owner,
        opening["hash"].as_str().unwrap(),
        closing["hash"].as_str().unwrap(),
    );
}

#[tokio::test]
async fn native_two_condition_activity_replays_funding_split_trade_and_shared_cash_once() {
    let (fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();

    assert_eq!(
        report.source_policy_version(),
        super::FIFTH_NATIVE_TWO_CONDITION_ACTIVITY_POLICY_VERSION
    );
    assert_eq!(report.evidence().blocks().len(), 2);
    assert_eq!(report.funding().amount(), U256::from(10_u64));
    assert_eq!(report.funding().transaction().block_number(), 100);
    assert_eq!(report.splits().len(), 2);
    assert_eq!(
        report
            .splits()
            .iter()
            .map(|fact| (fact.condition_index(), fact.amount()))
            .collect::<Vec<_>>(),
        vec![(0, U256::from(4_u64)), (1, U256::from(6_u64)),]
    );
    assert_eq!(
        report.splits()[0].operation_transaction().block_number(),
        100
    );
    assert_eq!(
        report.splits()[1].operation_transaction().block_number(),
        101
    );
    assert_eq!(report.trades().len(), 1);
    assert_eq!(report.trades()[0].condition_index(), 0);
    assert_eq!(
        report.trades()[0].transaction().owner_position_outflows(),
        [U256::from(4_u64), U256::ZERO]
    );
    assert_eq!(
        report.trades()[0].transaction().owner_pusd_inflow(),
        U256::from(3_u64)
    );
    assert_eq!(
        report.trades()[0].transaction().owner_fee_amount(),
        U256::ZERO
    );
    assert!(!report.controls().is_empty());

    let after_block100 = &report.block_observations()[0];
    assert_eq!(
        after_block100[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(993_u64)
    );
    assert_eq!(
        after_block100[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::ZERO
    );
    assert_eq!(
        after_block100[0]
            .native_context()
            .selected_balances()
            .position_balance_b(),
        U256::from(4_u64)
    );
    assert_eq!(after_block100[0].module_pusd_balance(), U256::from(6_u64));
    assert_eq!(after_block100[1].module_pusd_balance(), U256::from(6_u64));
    let closing_pair = &report.block_observations()[1];
    assert_eq!(
        closing_pair[0]
            .native_context()
            .selected_balances()
            .pusd_balance(),
        U256::from(993_u64)
    );
    assert_eq!(
        closing_pair[0]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::ZERO
    );
    assert_eq!(
        closing_pair[0]
            .native_context()
            .selected_balances()
            .position_balance_b(),
        U256::from(4_u64)
    );
    assert_eq!(
        closing_pair[1]
            .native_context()
            .selected_balances()
            .position_balance_a(),
        U256::from(6_u64)
    );
    assert_eq!(
        closing_pair[1]
            .native_context()
            .selected_balances()
            .position_balance_b(),
        U256::from(6_u64)
    );
    assert_eq!(closing_pair[0].module_pusd_balance(), U256::ZERO);
    assert_eq!(closing_pair[1].module_pusd_balance(), U256::ZERO);
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 220);
    assert_eq!(fixture.receipt_requests.load(Ordering::Relaxed), 4);
    capture_native_two_condition_activity(
        &fixture,
        &report,
        conditions,
        &owner,
        opening["hash"].as_str().unwrap(),
        closing["hash"].as_str().unwrap(),
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_preflight_and_one_short_budget() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let parent_hash = opening["hash"].as_str().unwrap();
    let end_hash = closing["hash"].as_str().unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));

    let invalid = verifier
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[0].as_str()],
            100,
            101,
            parent_hash,
            end_hash,
            220,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        invalid,
        Err(Error::Verification(ChainLogAuditError::InvalidInput))
    );
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);

    let underfunded = verifier
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            parent_hash,
            end_hash,
            219,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(underfunded, Err(Error::RequestBudgetExceeded));
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 218);
}

#[tokio::test]
async fn native_two_condition_activity_ignores_failed_empty_log_calls() {
    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (failed_quiet_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 4);
    assert_eq!(recovered, owner);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(failed_quiet_call);
    rooted.receipt_logs.push(Vec::new());
    rooted.receipt_statuses.push(0);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(report.funding().amount(), U256::from(10_u64));
    assert_eq!(report.splits().len(), 2);
    assert_eq!(report.trades().len(), 1);
}

#[tokio::test]
async fn native_two_condition_activity_refuses_reordered_exchange_source_logs() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.receipt_logs[2].swap(0, 1);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_wrong_middle_cash_even_when_close_matches() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (root, proofs) = activity_rooted_point(
        &owner,
        conditions,
        [U256::ZERO, U256::from(4_u64)],
        [U256::ZERO; 2],
        994,
        5,
        U256::ONE,
    );
    fixture.post_state = Some((root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, proofs);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_role_change_restored_at_close() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (root, proofs) = activity_rooted_point(
        &owner,
        conditions,
        [U256::ZERO, U256::from(4_u64)],
        [U256::ZERO; 2],
        993,
        6,
        U256::from(3_u64),
    );
    fixture.post_state = Some((root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, proofs);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_late_unknown_call_after_all_sources() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    move_activity_second_split_into_block100(&mut fixture, &owner, conditions);
    let (unknown, recovered) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 4);
    assert_eq!(recovered, owner);
    fixture.extra_direct_call_transaction = Some(unknown);
    fixture.extra_inventory_logs = Some(Vec::new());

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_extra_funding_after_both_splits() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    move_activity_second_split_into_block100(&mut fixture, &owner, conditions);
    let fund_input = hex::decode(
        fixture.rooted_gas_block.as_ref().unwrap().transactions[0]["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (deposit, recovered) = signed_polygon_owner_call(PUSD, &fund_input, 4);
    assert_eq!(recovered, owner);
    fixture.extra_direct_call_transaction = Some(deposit);
    fixture.extra_inventory_logs = Some(vec![native_accounting_log_json(&fifth_source_pusd(
        &owner, MODULE, 10, 0,
    ))]);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_same_value_role_update_in_valid_prefix() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let (quiet_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 3);
    assert_eq!(recovered, owner);
    let role_update = json!({
        "address":PUSD,
        "topics":[
            format!("0x{}", hex::encode(Keccak256::digest(b"RolesUpdated(address,uint256)"))),
            test_address_topic(MODULE),
        ],
        "data":format!("0x{}", hex::encode(movement_word(U256::ONE))),
    });
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(quiet_call);
    rooted.receipt_logs.push(vec![role_update]);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);
    let split_input = hex::decode(
        fixture.extra_direct_call_transaction.as_ref().unwrap()["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (split, recovered) = signed_polygon_owner_call(MODULE, &split_input, 4);
    assert_eq!(recovered, owner);
    fixture.extra_direct_call_transaction = Some(split);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_one_exchange_call_mixing_both_pairs() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;
    use super::fifth_match_orders_call::{FifthOrderSide, FifthTakerAmounts, tests::encode_call};

    let (mut fixture, conditions, owner_text) = native_two_condition_activity_fixture();
    let owner = Address::from_str(&owner_text).unwrap();
    let maker = Address::repeat_byte(0x57);
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let taker_order = fifth_source_order(
        207,
        owner,
        U256::from_be_bytes(conditions[0].0),
        1,
        1,
        FifthOrderSide::Sell,
        0xd1,
    );
    let maker_order = fifth_source_order(
        208,
        maker,
        U256::from_be_bytes(conditions[1].0),
        1,
        1,
        FifthOrderSide::Buy,
        0xd2,
    );
    let input = encode_call(
        &taker_order,
        std::slice::from_ref(&maker_order),
        &[U256::ONE],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::ONE,
            taker_receive_amount: U256::ONE,
            taker_fee_amount: U256::ZERO,
        },
    );
    let exchange_target = format!("{exchange:#x}");
    let (mixed_call, recovered) = signed_polygon_owner_call(&exchange_target, &input, 3);
    assert_eq!(recovered, owner_text);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(mixed_call);
    rooted.receipt_logs.push(Vec::new());
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);
    let split_input = hex::decode(
        fixture.extra_direct_call_transaction.as_ref().unwrap()["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (split, recovered) = signed_polygon_owner_call(MODULE, &split_input, 4);
    assert_eq!(recovered, owner_text);
    fixture.extra_direct_call_transaction = Some(split);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner_text,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
}

#[tokio::test]
async fn native_two_condition_activity_refuses_owner_movement_for_unselected_position() {
    use super::BoundedFifthNativeBinaryTwoConditionActivityError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let owner_address = Address::from_str(&owner).unwrap();
    let recipient = Address::repeat_byte(0x58);
    let mut unselected_condition = [0_u8; 32];
    unselected_condition[0] = 1;
    unselected_condition[1] = 0xc3;
    unselected_condition[16] = 0x42;
    let movement = fifth_source_position(
        super::fifth_code_context::POSITION_MANAGER_PROXY,
        &owner,
        &format!("{recipient:#x}"),
        U256::from_be_bytes(unselected_condition),
        1,
        0,
    );
    let (quiet_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 3);
    assert_eq!(recovered, owner);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(quiet_call);
    rooted
        .receipt_logs
        .push(vec![native_accounting_log_json(&movement)]);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);
    let split_input = hex::decode(
        fixture.extra_direct_call_transaction.as_ref().unwrap()["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (split, recovered) = signed_polygon_owner_call(MODULE, &split_input, 4);
    assert_eq!(recovered, owner);
    fixture.extra_direct_call_transaction = Some(split);

    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_activity_bounded(
            &owner,
            [condition_text[0].as_str(), condition_text[1].as_str()],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::Unverified))
    );
    assert_ne!(owner_address, recipient);
}

#[tokio::test]
async fn native_two_condition_activity_deadline_and_cancellation_cover_shared_interval() {
    use super::{
        BoundedFifthNativeBinaryTwoConditionActivityError as Error, CtfInventoryDeadlineGate,
    };

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    fixture.initial_clock_advance_ms = Some(500);
    let gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(gate.clone());
    tokio::time::pause();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let owner_for_task = owner.clone();
    let parent_hash = opening["hash"].as_str().unwrap().to_owned();
    let end_hash = closing["hash"].as_str().unwrap().to_owned();
    let started = tokio::time::Instant::now();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_activity_bounded(
                &owner_for_task,
                [condition_text[0].as_str(), condition_text[1].as_str()],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(1),
            )
            .await
    });
    tokio::select! {
        _ = gate.started.notified() => {}
        result = &mut task => panic!("activity deadline gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("activity deadline gate was not reached"),
    }
    assert_eq!(
        tokio::time::Instant::now().duration_since(started),
        Duration::from_millis(500)
    );
    tokio::time::advance(Duration::from_millis(600)).await;
    let result = tokio::select! {
        result = &mut task => result.unwrap(),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("activity deadline did not settle"),
    };
    gate.release.send_replace(true);
    assert_eq!(result, Err(Error::Timeout));
    tokio::time::resume();

    let (mut fixture, conditions, owner) = native_two_condition_activity_fixture();
    let cancel_gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(cancel_gate.clone());
    let before_abort = fixture.requests.clone();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let parent_hash = opening["hash"].as_str().unwrap().to_owned();
    let end_hash = closing["hash"].as_str().unwrap().to_owned();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_activity_bounded(
                &owner,
                [condition_text[0].as_str(), condition_text[1].as_str()],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(10),
            )
            .await
    });
    tokio::select! {
        _ = cancel_gate.started.notified() => {}
        result = &mut task => panic!("activity cancellation gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("activity cancellation gate was not reached"),
    }
    let sent = before_abort.load(Ordering::Relaxed);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    cancel_gate.release.send_replace(true);
    test_wall_timeout(Duration::from_millis(50)).await;
    assert_eq!(before_abort.load(Ordering::Relaxed), sent);
}

#[tokio::test]
async fn native_two_condition_splits_accept_reverse_source_order() {
    let (fixture, conditions, owner) = native_two_condition_split_fixture(true);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();
    assert_eq!(
        report
            .splits()
            .iter()
            .map(|split| split.condition_index())
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
    assert_eq!(report.splits()[0].amount(), U256::from(6_u64));
    assert_eq!(report.splits()[1].amount(), U256::from(4_u64));
}

#[tokio::test]
async fn native_two_condition_split_refuses_bad_ordered_logs_and_foreign_position_movement() {
    use super::BoundedFifthNativeBinaryTwoConditionSplitError as Error;

    let (mut bad_logs, conditions, owner) = native_two_condition_split_fixture(false);
    bad_logs.rooted_gas_block.as_mut().unwrap().receipt_logs[1][3]["topics"][2] =
        json!(format!("{:#x}", conditions[1]));
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&bad_logs);
    let primary = ctf_inventory_provider(bad_logs.clone()).await;
    let secondary = ctf_inventory_provider(bad_logs).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut reordered_logs, conditions, owner) = native_two_condition_split_fixture(false);
    reordered_logs
        .rooted_gas_block
        .as_mut()
        .unwrap()
        .receipt_logs[1]
        .reverse();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&reordered_logs);
    let primary = ctf_inventory_provider(reordered_logs.clone()).await;
    let secondary = ctf_inventory_provider(reordered_logs.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut extra_log, conditions, owner) = native_two_condition_split_fixture(false);
    let duplicate = extra_log.rooted_gas_block.as_ref().unwrap().receipt_logs[1][0].clone();
    extra_log.rooted_gas_block.as_mut().unwrap().receipt_logs[1].push(duplicate);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&extra_log);
    let primary = ctf_inventory_provider(extra_log.clone()).await;
    let secondary = ctf_inventory_provider(extra_log.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut wrong_caller, conditions, owner) = native_two_condition_split_fixture(false);
    let fund_input = hex::decode(
        wrong_caller.rooted_gas_block.as_ref().unwrap().transactions[0]["input"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let (foreign_funder, foreign_owner) =
        signed_polygon_call_with_seed(PUSD, &fund_input, 0, [0x41; 32]);
    assert_ne!(foreign_owner, owner);
    wrong_caller.rooted_gas_block.as_mut().unwrap().transactions[0] = foreign_funder;
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&wrong_caller);
    let primary = ctf_inventory_provider(wrong_caller.clone()).await;
    let secondary = ctf_inventory_provider(wrong_caller.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut foreign_movement, conditions, owner) = native_two_condition_split_fixture(false);
    let mut third_condition = [0_u8; 32];
    third_condition[0] = 1;
    third_condition[1] = 0xc3;
    third_condition[16] = 0x42;
    let from = Address::repeat_byte(0x58);
    let movement = fifth_source_position(
        MODULE,
        &format!("{from:#x}"),
        &owner,
        U256::from_be_bytes(third_condition),
        1,
        0,
    );
    let (unknown_owner_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 3);
    assert_eq!(recovered, owner);
    let rooted = foreign_movement.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(unknown_owner_call);
    rooted
        .receipt_logs
        .push(vec![native_accounting_log_json(&movement)]);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&foreign_movement);
    let primary = ctf_inventory_provider(foreign_movement.clone()).await;
    let secondary = ctf_inventory_provider(foreign_movement.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));
}

#[tokio::test]
async fn native_two_condition_split_refuses_middle_root_mismatch_even_if_close_would_match() {
    let (mut fixture, conditions, owner_text) = native_two_condition_split_fixture(false);
    let owner = Address::from_str(&owner_text).unwrap();
    let controls = native_accounting_control_words(owner, &[owner]);
    let (wrong_middle_root, wrong_middle_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner_text,
            conditions[0],
            [U256::from(4_u64); 2],
            conditions[1],
            [U256::ZERO; 2],
            U256::from(990_u64),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::from(5_u64),
            U256::ONE,
            &controls,
        );
    fixture.post_state = Some((wrong_middle_root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, wrong_middle_proofs);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner_text,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn native_two_condition_split_refuses_role_change_that_is_restored_at_close() {
    let (mut fixture, conditions, owner_text) = native_two_condition_split_fixture(false);
    let owner = Address::from_str(&owner_text).unwrap();
    let controls = native_accounting_control_words(owner, &[owner]);
    let (changed_role_root, changed_role_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner_text,
            conditions[0],
            [U256::from(4_u64); 2],
            conditions[1],
            [U256::ZERO; 2],
            U256::from(990_u64),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::from(6_u64),
            U256::from(3_u64),
            &controls,
        );
    fixture.post_state = Some((changed_role_root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, changed_role_proofs);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner_text,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn native_two_condition_split_refuses_same_value_role_update_event() {
    use super::BoundedFifthNativeBinaryTwoConditionSplitError as Error;

    let (mut fixture, conditions, owner) = native_two_condition_split_fixture(false);
    let second_split = fixture.extra_direct_call_transaction.take().unwrap();
    let second_split_logs = fixture.extra_inventory_logs.take().unwrap();
    let (router_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 3);
    assert_eq!(recovered, owner);
    let role_topic = format!(
        "0x{}",
        hex::encode(Keccak256::digest(b"RolesUpdated(address,uint256)"))
    );
    let role_update = json!({
        "address":PUSD,
        "topics":[role_topic,test_address_topic(MODULE)],
        "data":format!("0x{}",hex::encode(movement_word(U256::ONE))),
    });
    assert_eq!(role_update["topics"][0].as_str().unwrap().len(), 66);
    assert_eq!(role_update["topics"][1].as_str().unwrap().len(), 66);
    assert_eq!(role_update["data"].as_str().unwrap().len(), 66);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(second_split);
    rooted.receipt_logs.push(second_split_logs);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    rooted.transactions.push(router_call);
    rooted.receipt_logs.push(vec![role_update]);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(84_000);
    rooted.receipt_types.push(0);

    let owner_address = Address::from_str(&owner).unwrap();
    let controls = native_accounting_control_words(owner_address, &[owner_address]);
    let (final_root, final_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner,
            conditions[0],
            [U256::from(4_u64); 2],
            conditions[1],
            [U256::from(6_u64); 2],
            U256::from(990_u64),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            &controls,
        );
    fixture.post_state = Some((final_root, Value::Null));
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, final_proofs);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));
}

#[tokio::test]
async fn native_two_condition_split_budget_is_shared_and_invalid_input_is_pre_io() {
    use super::BoundedFifthNativeBinaryTwoConditionSplitError as Error;

    let (fixture, conditions, owner) = native_two_condition_split_fixture(false);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let result = verifier
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [&condition_text[0], &condition_text[0]],
            100,
            101,
            &format!("0x{}", "11".repeat(32)),
            &format!("0x{}", "22".repeat(32)),
            208,
            Duration::from_secs(10),
        )
        .await;
    assert_eq!(
        result,
        Err(Error::Verification(ChainLogAuditError::InvalidInput))
    );
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);

    let (fixture, conditions, owner) = native_two_condition_split_fixture(false);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            207,
            Duration::from_secs(45),
        )
        .await;
    assert_eq!(result, Err(Error::RequestBudgetExceeded));
    assert!(fixture.requests.load(Ordering::Relaxed) > 0);
    assert!(fixture.requests.load(Ordering::Relaxed) < 208);
}

#[tokio::test]
async fn native_two_condition_split_refuses_unknown_module_call_and_extra_deposit() {
    use super::BoundedFifthNativeBinaryTwoConditionSplitError as Error;

    let (mut unknown_module, conditions, owner) = native_two_condition_split_fixture(false);
    let (unknown, recovered) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 3);
    assert_eq!(recovered, owner);
    let rooted = unknown_module.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(unknown);
    rooted.receipt_logs.push(Vec::new());
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&unknown_module);
    let primary = ctf_inventory_provider(unknown_module.clone()).await;
    let secondary = ctf_inventory_provider(unknown_module.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut late_unknown_module, conditions, owner) = native_two_condition_split_fixture(false);
    let second_split = late_unknown_module
        .extra_direct_call_transaction
        .take()
        .unwrap();
    let second_split_logs = late_unknown_module.extra_inventory_logs.take().unwrap();
    let rooted = late_unknown_module.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(second_split);
    rooted.receipt_logs.push(second_split_logs);
    rooted.receipt_statuses.push(1);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    let owner_address = Address::from_str(&owner).unwrap();
    let controls = native_accounting_control_words(owner_address, &[owner_address]);
    let (final_root, final_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner,
            conditions[0],
            [U256::from(4_u64); 2],
            conditions[1],
            [U256::from(6_u64); 2],
            U256::from(990_u64),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            &controls,
        );
    late_unknown_module.post_state = Some((final_root, Value::Null));
    late_unknown_module
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(100, final_proofs);
    let (unknown, recovered) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 3);
    assert_eq!(recovered, owner);
    late_unknown_module.extra_direct_call_transaction = Some(unknown);
    late_unknown_module.extra_inventory_logs = Some(Vec::new());
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&late_unknown_module);
    let primary = ctf_inventory_provider(late_unknown_module.clone()).await;
    let secondary = ctf_inventory_provider(late_unknown_module.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));

    let (mut extra_deposit, conditions, owner) = native_two_condition_split_fixture(false);
    let vectors: Value = serde_json::from_str(include_str!(
        "artifacts/fifth-native-module-source-vectors.json"
    ))
    .unwrap();
    let (target, mut input) = native_accounting_vector_calldata(&vectors, "pusd-fund-split10");
    native_accounting_set_abi_word(&mut input, 1, U256::ONE);
    let (deposit, recovered) = signed_polygon_owner_call(&target, &input, 3);
    assert_eq!(recovered, owner);
    extra_deposit.extra_direct_call_transaction = Some(deposit);
    extra_deposit.extra_inventory_logs = Some(vec![native_accounting_log_json(
        &fifth_source_pusd(&owner, MODULE, 1, 0),
    )]);
    let owner_address = Address::from_str(&owner).unwrap();
    let controls = native_accounting_control_words(owner_address, &[owner_address]);
    let (closing_root, closing_proofs) =
        fifth_legacy_binary_balances::test_rooted_native_two_condition_point_packet(
            &owner,
            conditions[0],
            [U256::from(4_u64); 2],
            conditions[1],
            [U256::ZERO; 2],
            U256::from(989_u64),
            [U256::ZERO; 2],
            [U256::ZERO; 2],
            U256::from(7_u64),
            U256::ONE,
            &controls,
        );
    extra_deposit.extra_post_state = Some((closing_root, Value::Null));
    extra_deposit
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(101, closing_proofs);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&extra_deposit);
    let primary = ctf_inventory_provider(extra_deposit.clone()).await;
    let secondary = ctf_inventory_provider(extra_deposit.clone()).await;
    let result = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await;
    assert!(matches!(result, Err(Error::Verification(_))));
}

#[tokio::test]
async fn native_two_condition_split_keeps_failed_empty_logs_quiet() {
    let (mut quiet_failure, conditions, owner) = native_two_condition_split_fixture(false);
    let (failed, recovered) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 3);
    assert_eq!(recovered, owner);
    let rooted = quiet_failure.rooted_gas_block.as_mut().unwrap();
    rooted.transactions.push(failed.clone());
    rooted.receipt_logs.push(Vec::new());
    rooted.receipt_statuses.push(0);
    rooted.cumulative_gas_used.push(63_000);
    rooted.receipt_types.push(0);
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&quiet_failure);
    let primary = ctf_inventory_provider(quiet_failure.clone()).await;
    let secondary = ctf_inventory_provider(quiet_failure.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_splits_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            opening["hash"].as_str().unwrap(),
            closing["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();
    assert_eq!(report.splits().len(), 2);
}

#[tokio::test]
async fn native_two_condition_split_deadline_and_cancellation_share_one_interval() {
    use super::{
        BoundedFifthNativeBinaryTwoConditionSplitError as Error, CtfInventoryDeadlineGate,
    };

    let (mut fixture, conditions, owner) = native_two_condition_split_fixture(false);
    fixture.initial_clock_advance_ms = Some(500);
    let deadline_gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(deadline_gate.clone());
    let request_capture = fixture.rpc_capture.clone();
    tokio::time::pause();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let owner_for_task = owner.clone();
    let parent_hash = opening["hash"].as_str().unwrap().to_owned();
    let end_hash = closing["hash"].as_str().unwrap().to_owned();
    let started = tokio::time::Instant::now();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_splits_bounded(
                &owner_for_task,
                [condition_text[0].as_str(), condition_text[1].as_str()],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(1),
            )
            .await
    });
    tokio::select! {
        _ = deadline_gate.started.notified() => {}
        result = &mut task => panic!("deadline gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("deadline gate not reached"),
    }
    assert_eq!(
        tokio::time::Instant::now().duration_since(started),
        Duration::from_millis(500)
    );
    assert!(
        request_capture
            .lock()
            .unwrap()
            .iter()
            .any(|row| { row["method"] == "eth_getBlockReceipts" && row["params"][0] == "0x64" })
    );
    tokio::time::advance(Duration::from_millis(600)).await;
    let result = tokio::select! {
        result = &mut task => result.unwrap(),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("shared split deadline did not settle"),
    };
    deadline_gate.release.send_replace(true);
    assert_eq!(result, Err(Error::Timeout));
    tokio::time::resume();

    let (mut fixture, conditions, owner) = native_two_condition_split_fixture(false);
    let cancel_gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(cancel_gate.clone());
    let capture = fixture.rpc_capture.clone();
    let send_counter = fixture.requests.clone();
    let (opening, _, closing, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let parent_hash = opening["hash"].as_str().unwrap().to_owned();
    let end_hash = closing["hash"].as_str().unwrap().to_owned();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_splits_bounded(
                &owner,
                [condition_text[0].as_str(), condition_text[1].as_str()],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(10),
            )
            .await
    });
    tokio::select! {
        _ = cancel_gate.started.notified() => {}
        result = &mut task => panic!("cancel gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("cancel gate not reached"),
    }
    let before_abort = send_counter.load(Ordering::Relaxed);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    cancel_gate.release.send_replace(true);
    test_wall_timeout(Duration::from_millis(50)).await;
    assert_eq!(send_counter.load(Ordering::Relaxed), before_abort);
    assert!(
        !capture
            .lock()
            .unwrap()
            .iter()
            .any(|row| { row["method"] == "eth_getBlockByNumber" && row["params"][0] == "0x66" })
    );
}

#[tokio::test]
async fn native_two_condition_accepts_advancing_provider_finality_heights() {
    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    fixture.finalized_height_reads =
        Some(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)));
    let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            parent["hash"].as_str().unwrap(),
            end["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap();

    let left = report.opening()[0]
        .native_context()
        .selected_balances()
        .code_context();
    let right = report.opening()[1]
        .native_context()
        .selected_balances()
        .code_context();
    assert_ne!(
        (
            left.primary_finalized_height(),
            left.secondary_finalized_height()
        ),
        (
            right.primary_finalized_height(),
            right.secondary_finalized_height()
        )
    );
    assert_eq!(left.block_number(), right.block_number());
    assert_eq!(left.block_hash(), right.block_hash());
    assert_eq!(left.state_root(), right.state_root());
    assert_eq!(
        left.exchange_implementation_version(),
        right.exchange_implementation_version()
    );
}

#[tokio::test]
async fn native_two_condition_trade_budget_is_shared_and_all_or_error() {
    use super::BoundedFifthNativeBinaryTwoConditionTradeError as Error;

    let (fixture, conditions, owner) = native_two_condition_trade_fixture();
    let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
    let condition_text = conditions.map(|condition| format!("{condition:#x}"));
    let run = |limit| {
        let fixture = fixture.clone();
        let owner = owner.clone();
        let parent_hash = parent["hash"].as_str().unwrap().to_owned();
        let end_hash = end["hash"].as_str().unwrap().to_owned();
        let conditions = [condition_text[0].clone(), condition_text[1].clone()];
        async move {
            let primary = ctf_inventory_provider(fixture.clone()).await;
            let secondary = ctf_inventory_provider(fixture.clone()).await;
            ChainLogVerifier::new(&primary, &secondary)
                .unwrap()
                .verify_fifth_native_binary_two_condition_trades_bounded(
                    &owner,
                    [conditions[0].as_str(), conditions[1].as_str()],
                    100,
                    101,
                    &parent_hash,
                    &end_hash,
                    limit,
                    Duration::from_secs(45),
                )
                .await
        }
    };

    let before = fixture.requests.load(Ordering::Relaxed);
    run(5_000).await.unwrap();
    let exact_budget = fixture.requests.load(Ordering::Relaxed) - before;
    assert!(exact_budget > 1);

    let before = fixture.requests.load(Ordering::Relaxed);
    run(exact_budget).await.unwrap();
    assert_eq!(
        fixture.requests.load(Ordering::Relaxed) - before,
        exact_budget
    );

    let before = fixture.requests.load(Ordering::Relaxed);
    assert_eq!(
        run(exact_budget - 1).await.unwrap_err(),
        Error::RequestBudgetExceeded
    );
    assert!(fixture.requests.load(Ordering::Relaxed) - before < exact_budget);
}

#[tokio::test]
async fn native_two_condition_trade_rejects_equal_conditions_before_rpc() {
    let (fixture, conditions, owner) = native_two_condition_trade_fixture();
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&primary, &secondary).unwrap();
    let condition = format!("{:#x}", conditions[0]);
    let error = verifier
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [&condition, &condition],
            100,
            101,
            &format!("0x{}", "11".repeat(32)),
            &format!("0x{}", "22".repeat(32)),
            500,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        super::BoundedFifthNativeBinaryTwoConditionTradeError::Verification(
            ChainLogAuditError::InvalidInput
        )
    );
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);
}

fn native_two_condition_unrouted_fixture(mixed: bool) -> (CtfInventoryFixture, [B256; 2], String) {
    use super::fifth_match_orders_call::{FifthOrderSide, FifthTakerAmounts};

    let (mut fixture, conditions, owner_text) = native_two_condition_trade_fixture();
    let owner = Address::from_str(&owner_text).unwrap();
    let maker = Address::repeat_byte(0x57);
    let selected_token = U256::from_be_bytes(conditions[0].0);
    let mut foreign = [0_u8; 32];
    foreign[0] = 1;
    foreign[1] = 0xc3;
    foreign[16] = 0x42;
    let foreign_token = U256::from_be_bytes(foreign);
    let taker_token = if mixed { selected_token } else { foreign_token };
    let maker_token = if mixed {
        U256::from_be_bytes(conditions[1].0)
    } else {
        foreign_token
    };
    let taker = fifth_source_order(207, owner, taker_token, 3, 6, FifthOrderSide::Buy, 0xd1);
    let maker_order = fifth_source_order(208, maker, maker_token, 6, 3, FifthOrderSide::Sell, 0xd2);
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker,
        std::slice::from_ref(&maker_order),
        &[U256::from(6_u64)],
        &[U256::ZERO],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(3_u64),
            taker_receive_amount: U256::from(6_u64),
            taker_fee_amount: U256::ZERO,
        },
    );
    let (unrouted, recovered) =
        signed_polygon_owner_call(super::fifth_code_context::EXCHANGE_PROXY, &input, 0);
    assert_eq!(recovered, owner_text);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions[0] = unrouted;
    rooted.receipt_logs[0] = Vec::new();
    (fixture, conditions, owner_text)
}

#[tokio::test]
async fn native_two_condition_trade_rejects_foreign_and_mixed_pair_calls() {
    for mixed in [false, true] {
        let (fixture, conditions, owner) = native_two_condition_unrouted_fixture(mixed);
        let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
        let primary = ctf_inventory_provider(fixture.clone()).await;
        let secondary = ctf_inventory_provider(fixture.clone()).await;
        let error = ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_two_condition_trades_bounded(
                &owner,
                [
                    format!("{:#x}", conditions[0]).as_str(),
                    format!("{:#x}", conditions[1]).as_str(),
                ],
                100,
                101,
                parent["hash"].as_str().unwrap(),
                end["hash"].as_str().unwrap(),
                5_000,
                Duration::from_secs(45),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            super::BoundedFifthNativeBinaryTwoConditionTradeError::Verification(_)
        ));
        assert!(fixture.requests.load(Ordering::Relaxed) > 0);
    }
}

#[tokio::test]
async fn native_two_condition_trade_rejects_third_pair_owner_movement() {
    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    let mut foreign = [0_u8; 32];
    foreign[0] = 1;
    foreign[1] = 0xc3;
    foreign[16] = 0x42;
    let foreign_position = U256::from_be_bytes(foreign);
    let from = Address::repeat_byte(0x58);
    let from_text = format!("{from:#x}");
    let movement = fifth_source_position(
        "0x3535353535353535353535353535353535353535",
        &from_text,
        &owner,
        foreign_position,
        1,
        0,
    );
    let (router_call, recovered) =
        signed_polygon_owner_call("0x3535353535353535353535353535353535353535", &[], 0);
    assert_eq!(recovered, owner);
    let rooted = fixture.rooted_gas_block.as_mut().unwrap();
    rooted.transactions[0] = router_call;
    rooted.receipt_logs[0] = vec![native_accounting_log_json(&movement)];
    let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            parent["hash"].as_str().unwrap(),
            end["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        super::BoundedFifthNativeBinaryTwoConditionTradeError::Verification(_)
    ));
}

#[tokio::test]
async fn native_two_condition_trade_keeps_failed_empty_receipts_quiet() {
    for target in [super::fifth_code_context::EXCHANGE_PROXY, MODULE] {
        let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
        let input = if target == MODULE {
            &[0xde, 0xad, 0xbe, 0xef][..]
        } else {
            &[]
        };
        let (failed, recovered) = signed_polygon_owner_call(target, input, 2);
        assert_eq!(recovered, owner);
        let rooted = fixture.rooted_gas_block.as_mut().unwrap();
        rooted.transactions.push(failed);
        rooted.receipt_logs.push(Vec::new());
        rooted.receipt_statuses.push(0);
        rooted.cumulative_gas_used.push(63_000);
        rooted.receipt_types.push(0);
        let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
        let primary = ctf_inventory_provider(fixture.clone()).await;
        let secondary = ctf_inventory_provider(fixture.clone()).await;
        let report = ChainLogVerifier::new(&primary, &secondary)
            .unwrap()
            .verify_fifth_native_binary_two_condition_trades_bounded(
                &owner,
                [
                    format!("{:#x}", conditions[0]).as_str(),
                    format!("{:#x}", conditions[1]).as_str(),
                ],
                100,
                101,
                parent["hash"].as_str().unwrap(),
                end["hash"].as_str().unwrap(),
                5_000,
                Duration::from_secs(45),
            )
            .await
            .unwrap();
        assert_eq!(report.transactions().len(), 3);
        let receipt_transactions = report.evidence().blocks()[0].transactions();
        assert_eq!(receipt_transactions.len(), 3);
        assert_eq!(receipt_transactions[2].status(), 0);
        assert!(receipt_transactions[2].logs().is_empty());
    }
}

#[tokio::test]
async fn native_two_condition_trade_requires_both_pair_proofs_at_each_shared_root() {
    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    super::fifth_legacy_binary_balances::test_tamper_native_position_proof(
        fixture
            .fifth_code_proofs_by_block
            .as_mut()
            .unwrap()
            .get_mut(&100)
            .unwrap(),
        &owner,
        conditions[1],
    );
    let (parent, _, end, _) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            101,
            parent["hash"].as_str().unwrap(),
            end["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        super::BoundedFifthNativeBinaryTwoConditionTradeError::Verification(_)
    ));
}

#[tokio::test]
async fn native_two_condition_trade_refuses_late_direct_module_call_without_report_prefix() {
    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    let closing_root = fixture.extra_post_state.as_ref().unwrap().0.clone();
    fixture.third_post_state = Some((closing_root, Value::Null));
    let closing_proofs = fixture
        .fifth_code_proofs_by_block
        .as_ref()
        .unwrap()
        .get(&101)
        .unwrap()
        .clone();
    fixture
        .fifth_code_proofs_by_block
        .as_mut()
        .unwrap()
        .insert(102, closing_proofs);
    let (unsupported, recovered) = signed_polygon_owner_call(MODULE, &[0xde, 0xad, 0xbe, 0xef], 3);
    assert_eq!(recovered, owner);
    fixture.third_direct_call_transaction = Some(unsupported);
    fixture.third_inventory_logs = Some(Vec::new());
    let (parent, _, _, end) = ctf_inventory_headers_with_102(&fixture);
    let primary = ctf_inventory_provider(fixture.clone()).await;
    let secondary = ctf_inventory_provider(fixture.clone()).await;
    let error = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
        .verify_fifth_native_binary_two_condition_trades_bounded(
            &owner,
            [
                format!("{:#x}", conditions[0]).as_str(),
                format!("{:#x}", conditions[1]).as_str(),
            ],
            100,
            102,
            parent["hash"].as_str().unwrap(),
            end["hash"].as_str().unwrap(),
            5_000,
            Duration::from_secs(45),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        super::BoundedFifthNativeBinaryTwoConditionTradeError::Verification(
            ChainLogAuditError::Unverified
        )
    );
}

#[tokio::test]
async fn native_two_condition_deadline_and_abort_cover_both_opening_proofs() {
    use super::{
        BoundedFifthNativeBinaryTwoConditionTradeError as Error, CtfInventoryDeadlineGate,
    };

    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    fixture.initial_clock_advance_ms = Some(500);
    let deadline_gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(deadline_gate.clone());
    tokio::time::pause();
    let (parent, _, _, end) = ctf_inventory_headers_with_102(&fixture);
    let first = ctf_inventory_provider(fixture.clone()).await;
    let second = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&first, &second).unwrap();
    let owner_for_task = owner.clone();
    let conditions_for_task = conditions.map(|condition| format!("{condition:#x}"));
    let parent_hash = parent["hash"].as_str().unwrap().to_owned();
    let end_hash = end["hash"].as_str().unwrap().to_owned();
    let started = tokio::time::Instant::now();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_trades_bounded(
                &owner_for_task,
                [
                    conditions_for_task[0].as_str(),
                    conditions_for_task[1].as_str(),
                ],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(1),
            )
            .await
    });
    tokio::select! {
        _ = deadline_gate.started.notified() => {}
        result = &mut task => panic!("receipt deadline gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("shared deadline gate was not reached"),
    }
    assert_eq!(
        tokio::time::Instant::now().duration_since(started),
        Duration::from_millis(500)
    );
    tokio::time::advance(Duration::from_millis(600)).await;
    let result = tokio::select! {
        result = &mut task => result.unwrap(),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("shared deadline did not settle"),
    };
    deadline_gate.release.send_replace(true);
    assert_eq!(result, Err(Error::Timeout));
    tokio::time::resume();

    let (mut fixture, conditions, owner) = native_two_condition_trade_fixture();
    let cancel_gate = std::sync::Arc::new(CtfInventoryDeadlineGate::new());
    fixture.deadline_gate = Some(cancel_gate.clone());
    let (parent, _, _, end) = ctf_inventory_headers_with_102(&fixture);
    let first = ctf_inventory_provider(fixture.clone()).await;
    let second = ctf_inventory_provider(fixture.clone()).await;
    let verifier = ChainLogVerifier::new(&first, &second).unwrap();
    let conditions_for_task = conditions.map(|condition| format!("{condition:#x}"));
    let parent_hash = parent["hash"].as_str().unwrap().to_owned();
    let end_hash = end["hash"].as_str().unwrap().to_owned();
    let mut task = tokio::spawn(async move {
        verifier
            .verify_fifth_native_binary_two_condition_trades_bounded(
                &owner,
                [
                    conditions_for_task[0].as_str(),
                    conditions_for_task[1].as_str(),
                ],
                100,
                101,
                &parent_hash,
                &end_hash,
                5_000,
                Duration::from_secs(10),
            )
            .await
    });
    tokio::select! {
        _ = cancel_gate.started.notified() => {}
        result = &mut task => panic!("cancel gate returned early: {result:?}"),
        _ = test_wall_timeout(Duration::from_secs(30)) => panic!("cancel gate was not reached"),
    }
    let before_abort = fixture.requests.load(Ordering::Relaxed);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    cancel_gate.release.send_replace(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fixture.requests.load(Ordering::Relaxed), before_abort);
}
