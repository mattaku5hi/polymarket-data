use super::fifth_match_orders_call::{FifthOrderSide, FifthTakerAmounts, fifth_order_eip712_hash};
use super::*;
use std::str::FromStr;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const MODULE_ADDRESS: &str = "0x3333333333333333333333333333333333333333";
const FEE_RECEIVER: &str = "0x115f48dc2a731aa16251c6d6e1befc42f92accc9";

fn native_trade_source_with_logs(
    mut source: ChainReceiptIntervalTransaction,
    input: Vec<u8>,
    mut logs: Vec<ChainReceiptLog>,
) -> ChainReceiptIntervalTransaction {
    let (signed_transaction, recovered_from) = super::signed_polygon_transaction_with_key(
        super::fifth_code_context::EXCHANGE_PROXY,
        &input,
        0x42,
    );
    let encoded =
        super::encode_signed_transaction_with_sender_recovery(&signed_transaction, true).unwrap();
    let transaction_hash = format!("{:#x}", encoded.hash);
    for log in &mut logs {
        log.transaction_hash.clone_from(&transaction_hash);
    }
    source.transaction_hash = transaction_hash;
    source.input = Some(input);
    source.to = signed_transaction["to"].as_str().map(str::to_owned);
    source.recovered_from = Some(recovered_from);
    source.logs = logs;
    source
}

#[tokio::test]
async fn native_binary_mint_reconciles_independent_source_legs() {
    let (source, owner, position_ids) =
        super::fifth_binary_trades::tests::native_pair_source_trade();
    let owner_text = format!("{owner:#x}");
    let owner_address = owner;
    let maker = Address::repeat_byte(0x46);
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let taker_order = super::fifth_source_order(
        31,
        owner_address,
        U256::from_be_bytes(position_ids[0].0),
        40,
        100,
        FifthOrderSide::Buy,
        0x62,
    );
    let maker_order = super::fifth_source_order(
        32,
        maker,
        U256::from_be_bytes(position_ids[1].0),
        60,
        100,
        FifthOrderSide::Buy,
        0x72,
    );
    let taker_hash = fifth_order_eip712_hash(&taker_order, exchange);
    let maker_hash = fifth_order_eip712_hash(&maker_order, exchange);
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        std::slice::from_ref(&maker_order),
        &[U256::from(60_u64)],
        &[U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(40_u64),
            taker_receive_amount: U256::from(100_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let maker_text = format!("{maker:#x}");
    let mut logs = vec![
        super::fifth_source_pusd(
            &owner_text,
            super::fifth_code_context::EXCHANGE_PROXY,
            41,
            0,
        ),
        super::fifth_source_pusd(
            &maker_text,
            super::fifth_code_context::EXCHANGE_PROXY,
            61,
            1,
        ),
        super::fifth_source_order_filled(&maker_order, maker_hash, owner_address, 60, 100, 1, 2),
        super::fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            MODULE_ADDRESS,
            100,
            3,
        ),
        super::fifth_source_position(
            MODULE_ADDRESS,
            ZERO_ADDRESS,
            super::fifth_code_context::EXCHANGE_PROXY,
            U256::from_be_bytes(position_ids[0].0),
            100,
            4,
        ),
        super::fifth_source_position(
            MODULE_ADDRESS,
            ZERO_ADDRESS,
            super::fifth_code_context::EXCHANGE_PROXY,
            U256::from_be_bytes(position_ids[1].0),
            100,
            5,
        ),
        super::fifth_source_pusd(MODULE_ADDRESS, ZERO_ADDRESS, 100, 6),
        super::fifth_source_module_event(true, position_ids[0], 100, 7),
        super::fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            super::fifth_code_context::EXCHANGE_PROXY,
            &maker_text,
            U256::from_be_bytes(position_ids[1].0),
            100,
            8,
        ),
        super::fifth_source_fee(1, 9),
        super::fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            U256::from_be_bytes(position_ids[0].0),
            100,
            10,
        ),
        super::fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            FEE_RECEIVER,
            2,
            11,
        ),
        super::fifth_source_fee(1, 12),
    ];
    logs.extend(super::fifth_source_taker_events(
        &taker_order,
        taker_hash,
        40,
        100,
        1,
        13,
    ));
    let source = native_trade_source_with_logs(source, input, logs);
    let fixture = super::fifth_native_trade_fixture_with_ending_balances(
        source,
        owner,
        position_ids[0],
        [U256::from(200_u64), U256::from(200_u64)],
        U256::from(959_u64),
    );
    let (opening, _, ending, _) = super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
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

    assert_eq!(report.status(), &FifthNativeBinaryTradeStatus::Matched);
    assert_eq!(report.transactions().len(), 1);
    let fact = &report.transactions()[0];
    assert_eq!(fact.branch(), FifthTradeBranch::Mint);
    assert_eq!(
        fact.owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(fact.owner_position_outflows(), [U256::ZERO; 2]);
    assert_eq!(fact.owner_pusd_outflow(), U256::from(41_u64));
    assert_eq!(fact.owner_fee_amount(), U256::ONE);
    assert_eq!(fact.order_fills().len(), 1);
    assert_eq!(fact.order_fills()[0].order_hash(), taker_hash);
    assert_eq!(
        fact.order_fills()[0].owner_role(),
        FifthTradeOwnerRole::Taker
    );
    assert_eq!(
        fact.order_fills()[0].token_id(),
        U256::from_be_bytes(position_ids[0].0)
    );
    assert_eq!(
        fixture.requests.load(Ordering::Relaxed),
        130,
        "native MINT must use the same-root native interval/control proof budget",
    );
    super::capture_fifth_native_trade_case(
        "mint",
        &fixture,
        &report,
        &owner_text,
        position_ids[0],
        &opening["hash"],
        &ending["hash"],
    );
}

#[tokio::test]
async fn native_binary_merge_reconciles_independent_source_legs() {
    let (source, owner, position_ids) =
        super::fifth_binary_trades::tests::native_pair_source_trade();
    let owner_text = format!("{owner:#x}");
    let maker = Address::repeat_byte(0x47);
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let taker_order = super::fifth_source_order(
        41,
        owner,
        U256::from_be_bytes(position_ids[0].0),
        100,
        40,
        FifthOrderSide::Sell,
        0x63,
    );
    let maker_order = super::fifth_source_order(
        42,
        maker,
        U256::from_be_bytes(position_ids[1].0),
        100,
        60,
        FifthOrderSide::Sell,
        0x73,
    );
    let taker_hash = fifth_order_eip712_hash(&taker_order, exchange);
    let maker_hash = fifth_order_eip712_hash(&maker_order, exchange);
    let input = super::fifth_match_orders_call::tests::encode_call(
        &taker_order,
        std::slice::from_ref(&maker_order),
        &[U256::from(100_u64)],
        &[U256::ONE],
        FifthTakerAmounts {
            taker_fill_amount: U256::from(100_u64),
            taker_receive_amount: U256::from(40_u64),
            taker_fee_amount: U256::ONE,
        },
    );
    let maker_text = format!("{maker:#x}");
    let mut logs = vec![
        super::fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &maker_text,
            MODULE_ADDRESS,
            U256::from_be_bytes(position_ids[1].0),
            100,
            0,
        ),
        super::fifth_source_order_filled(&maker_order, maker_hash, owner, 100, 60, 1, 1),
        super::fifth_source_position(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            MODULE_ADDRESS,
            U256::from_be_bytes(position_ids[0].0),
            100,
            2,
        ),
        super::fifth_source_pusd(
            ZERO_ADDRESS,
            super::fifth_code_context::EXCHANGE_PROXY,
            100,
            3,
        ),
        super::fifth_source_position(
            MODULE_ADDRESS,
            MODULE_ADDRESS,
            ZERO_ADDRESS,
            U256::from_be_bytes(position_ids[0].0),
            100,
            4,
        ),
        super::fifth_source_position(
            MODULE_ADDRESS,
            MODULE_ADDRESS,
            ZERO_ADDRESS,
            U256::from_be_bytes(position_ids[1].0),
            100,
            5,
        ),
        super::fifth_source_module_event(false, position_ids[0], 100, 6),
        super::fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            &maker_text,
            59,
            7,
        ),
        super::fifth_source_fee(1, 8),
        super::fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            &owner_text,
            39,
            9,
        ),
        super::fifth_source_pusd(
            super::fifth_code_context::EXCHANGE_PROXY,
            FEE_RECEIVER,
            2,
            10,
        ),
        super::fifth_source_fee(1, 11),
    ];
    logs.extend(super::fifth_source_taker_events(
        &taker_order,
        taker_hash,
        100,
        40,
        1,
        12,
    ));
    let source = native_trade_source_with_logs(source, input, logs);
    let fixture = super::fifth_native_trade_fixture_with_ending_balances(
        source,
        owner,
        position_ids[0],
        [U256::ZERO, U256::from(200_u64)],
        U256::from(1_039_u64),
    );
    let (opening, _, ending, _) = super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
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

    assert_eq!(report.status(), &FifthNativeBinaryTradeStatus::Matched);
    assert_eq!(report.transactions().len(), 1);
    let fact = &report.transactions()[0];
    assert_eq!(fact.branch(), FifthTradeBranch::Merge);
    assert_eq!(
        fact.owner_position_outflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(fact.owner_position_inflows(), [U256::ZERO; 2]);
    assert_eq!(fact.owner_pusd_inflow(), U256::from(39_u64));
    assert_eq!(fact.owner_fee_amount(), U256::ONE);
    assert_eq!(fact.order_fills().len(), 1);
    assert_eq!(fact.order_fills()[0].order_hash(), taker_hash);
    assert_eq!(
        fact.order_fills()[0].owner_role(),
        FifthTradeOwnerRole::Taker
    );
    assert_eq!(
        fact.order_fills()[0].token_id(),
        U256::from_be_bytes(position_ids[0].0)
    );
    assert_eq!(
        fixture.requests.load(Ordering::Relaxed),
        130,
        "native MERGE must use the same-root native interval/control proof budget",
    );
    super::capture_fifth_native_trade_case(
        "merge",
        &fixture,
        &report,
        &owner_text,
        position_ids[0],
        &opening["hash"],
        &ending["hash"],
    );
}

fn exchange_control_words_for_distinct_submitters(
    submitters: &[(Address, U256)],
    makers: &[Address],
) -> Vec<(B256, U256)> {
    const ROLE_SEED: [u8; 4] = [0x8b, 0x78, 0xc6, 0xd8];
    let mut words = vec![
        (B256::ZERO, U256::ZERO),
        (B256::with_last_byte(1), U256::from(7_u64)),
    ];
    for (submitter, roles) in submitters {
        let mut preimage = [0_u8; 32];
        preimage[..20].copy_from_slice(submitter.as_slice());
        preimage[28..].copy_from_slice(&ROLE_SEED);
        words.push((B256::from_slice(&Keccak256::digest(preimage)), *roles));
    }
    for maker in makers {
        let mut preimage = [0_u8; 64];
        preimage[12..32].copy_from_slice(maker.as_slice());
        preimage[63] = 3;
        words.push((B256::from_slice(&Keccak256::digest(preimage)), U256::ZERO));
    }
    words
}

#[tokio::test]
async fn native_binary_trade_keeps_distinct_operator_role_words_keyed_by_submitter() {
    use super::fifth_match_orders_call::{
        decode_fifth_match_orders_calldata, fifth_order_eip712_hash,
    };

    let (first_source, owner, position_ids) =
        super::fifth_binary_trades::tests::native_pair_source_trade();
    let owner_text = format!("{owner:#x}");
    let first_call =
        decode_fifth_match_orders_calldata(first_source.input.as_deref().unwrap()).unwrap();
    let exchange = Address::from_str(super::fifth_code_context::EXCHANGE_PROXY).unwrap();
    let old_taker_hash = fifth_order_eip712_hash(&first_call.taker_order, exchange);
    let old_maker_hash = fifth_order_eip712_hash(&first_call.maker_orders[0], exchange);
    let mut second_call = first_call.clone();
    second_call.taker_order.salt = U256::from(111_u64);
    second_call.maker_orders[0].salt = U256::from(112_u64);
    let new_taker_hash = fifth_order_eip712_hash(&second_call.taker_order, exchange);
    let new_maker_hash = fifth_order_eip712_hash(&second_call.maker_orders[0], exchange);
    let second_input = super::fifth_match_orders_call::tests::encode_call(
        &second_call.taker_order,
        &second_call.maker_orders,
        &second_call.maker_fill_amounts,
        &second_call.maker_fee_amounts,
        second_call.taker_amounts,
    );
    let (second_transaction, second_submitter_text) = super::signed_polygon_transaction_with_key(
        super::fifth_code_context::EXCHANGE_PROXY,
        &second_input,
        0x43,
    );
    let second_encoded =
        super::encode_signed_transaction_with_sender_recovery(&second_transaction, true).unwrap();
    let second_hash = format!("{:#x}", second_encoded.hash);
    let second_submitter = Address::from_str(&second_submitter_text).unwrap();
    let first_submitter =
        Address::from_str(first_source.recovered_from.as_deref().unwrap()).unwrap();

    let mut second_logs = first_source.logs.clone();
    let order_filled_topic = super::movement_topic(
        "OrderFilled(bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,bytes32)",
    );
    let orders_matched_topic =
        super::movement_topic("OrdersMatched(bytes32,address,uint8,uint256,uint256,uint256)");
    for log in &mut second_logs {
        if log.topics.first() == Some(&order_filled_topic) {
            if log.topics[1] == format!("{old_taker_hash:#x}") {
                log.topics[1] = format!("{new_taker_hash:#x}");
            } else if log.topics[1] == format!("{old_maker_hash:#x}") {
                log.topics[1] = format!("{new_maker_hash:#x}");
            }
        } else if log.topics.first() == Some(&orders_matched_topic) {
            log.topics[1] = format!("{new_taker_hash:#x}");
        }
        log.transaction_hash.clone_from(&second_hash);
    }

    let mut fixture = super::fifth_native_trade_fixture_with_ending_balances(
        first_source.clone(),
        owner,
        position_ids[0],
        [U256::from(200_u64), U256::from(200_u64)],
        U256::from(949_u64),
    );
    fixture.extra_direct_call_transaction = Some(second_transaction);
    fixture.extra_inventory_logs = Some(
        second_logs
            .iter()
            .map(|log| json!({"address":log.address,"topics":log.topics,"data":log.data}))
            .collect(),
    );
    let maker = first_call.maker_orders[0].maker;
    let control_words = exchange_control_words_for_distinct_submitters(
        &[
            (first_submitter, U256::from(2_u64)),
            (second_submitter, U256::from(7_u64)),
        ],
        &[owner, maker],
    );
    let owner_text_for_proofs = owner_text.clone();
    let proof_packet = |positions, cash| {
        super::fifth_legacy_binary_balances::test_rooted_native_module_operation_point_packet_with_exchange_storage(
            &owner_text_for_proofs,
            position_ids[0],
            positions,
            cash,
            [U256::ZERO; 2],
            U256::ZERO,
            U256::ONE,
            [U256::ZERO; 3],
            &control_words,
        )
    };
    let (root99, proofs99) = proof_packet(
        [U256::from(100_u64), U256::from(200_u64)],
        U256::from(1_000_u64),
    );
    let (root100, proofs100) = proof_packet(
        [U256::from(200_u64), U256::from(200_u64)],
        U256::from(949_u64),
    );
    let (root101, proofs101) = proof_packet(
        [U256::from(300_u64), U256::from(200_u64)],
        U256::from(898_u64),
    );
    fixture.state_root = root99;
    fixture.post_state = Some((root100, Value::Null));
    fixture.extra_post_state = Some((root101, Value::Null));
    fixture.fifth_code_proofs_by_block = Some(BTreeMap::from([
        (99, proofs99),
        (100, proofs100),
        (101, proofs101),
    ]));
    fixture.inventory_logs = Some(
        first_source
            .logs
            .iter()
            .map(|log| json!({"address":log.address,"topics":log.topics,"data":log.data}))
            .collect(),
    );
    fixture.filter_fifth_code_proofs_by_requested_keys = true;

    let (opening, _, ending, _) = super::ctf_inventory_headers_with_102(&fixture);
    let primary = super::ctf_inventory_provider(fixture.clone()).await;
    let secondary = super::ctf_inventory_provider(fixture.clone()).await;
    let report = ChainLogVerifier::new(&primary, &secondary)
        .unwrap()
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

    assert_eq!(report.status(), &FifthNativeBinaryTradeStatus::Matched);
    assert_eq!(report.transactions().len(), 2);
    assert_eq!(
        report.transactions()[0].owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(
        report.transactions()[1].owner_position_inflows(),
        [U256::from(100_u64), U256::ZERO]
    );
    assert_eq!(report.controls().len(), 12);
    for control in report.controls() {
        if control.submitter() == first_submitter {
            assert_eq!(control.submitter_role_bitmap(), U256::from(2_u64));
        } else if control.submitter() == second_submitter {
            assert_eq!(control.submitter_role_bitmap(), U256::from(7_u64));
        } else {
            panic!("unexpected proven submitter");
        }
        assert!(control.submitter_has_operator_role());
    }
    assert_eq!(
        fixture.requests.load(Ordering::Relaxed),
        142,
        "two submitters require independently rooted role words at all boundaries",
    );
}
