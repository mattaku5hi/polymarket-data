use super::*;

pub(super) fn storage_keys(condition_id: B256) -> [B256; 4] {
    let length = mapping_key(condition_id, 3);
    let denominator = mapping_key(condition_id, 4);
    let numerator_zero = B256::from_slice(&Keccak256::digest(length.as_slice()));
    let numerator_one = add_one(numerator_zero);
    [length, denominator, numerator_zero, numerator_one]
}

fn mapping_key(condition_id: B256, slot: u8) -> B256 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(condition_id.as_slice());
    preimage[63] = slot;
    B256::from_slice(&Keccak256::digest(preimage))
}

fn add_one(value: B256) -> B256 {
    let mut bytes = value.0;
    for byte in bytes.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
    B256::from(bytes)
}

pub(super) fn interpret(
    count: U256,
    denominator: U256,
    numerators: [U256; 2],
) -> Result<CtfConditionStateStatus, ChainLogAuditError> {
    if count.is_zero() {
        return if denominator.is_zero() && numerators == [U256::ZERO; 2] {
            Ok(CtfConditionStateStatus::Unprepared)
        } else {
            Err(ChainLogAuditError::Unverified)
        };
    }
    if count == U256::from(1) || count > U256::from(256) {
        return Err(ChainLogAuditError::Unverified);
    }
    let sum = numerators[0].checked_add(numerators[1]);
    if denominator.is_zero() {
        if numerators != [U256::ZERO; 2] {
            return Err(ChainLogAuditError::Unverified);
        }
    } else if sum.is_none_or(|sum| sum > denominator)
        || (count == U256::from(2) && sum != Some(denominator))
    {
        return Err(ChainLogAuditError::Unverified);
    }
    if count == U256::from(2) {
        Ok(if denominator.is_zero() {
            CtfConditionStateStatus::PreparedBinaryUnresolved
        } else {
            CtfConditionStateStatus::ResolvedBinary
        })
    } else {
        Ok(CtfConditionStateStatus::UnsupportedNonBinary)
    }
}

pub(super) fn transition_is_valid(
    before: &CtfConditionStateBlockProof,
    after: &CtfConditionStateBlockProof,
) -> bool {
    if before.status == CtfConditionStateStatus::Unprepared {
        return true;
    }
    if after.status == CtfConditionStateStatus::Unprepared
        || before.payout_numerator_count != after.payout_numerator_count
    {
        return false;
    }
    match before.status {
        CtfConditionStateStatus::Unprepared => true,
        CtfConditionStateStatus::PreparedBinaryUnresolved => matches!(
            after.status,
            CtfConditionStateStatus::PreparedBinaryUnresolved
                | CtfConditionStateStatus::ResolvedBinary
        ),
        CtfConditionStateStatus::ResolvedBinary => {
            after.status == CtfConditionStateStatus::ResolvedBinary
                && before.payout_denominator == after.payout_denominator
                && before.payout_numerators == after.payout_numerators
        }
        CtfConditionStateStatus::UnsupportedNonBinary => {
            after.status == CtfConditionStateStatus::UnsupportedNonBinary
                && if before.payout_denominator.is_zero() {
                    after.payout_denominator.is_zero()
                        || (after.payout_numerators[0] >= before.payout_numerators[0]
                            && after.payout_numerators[1] >= before.payout_numerators[1])
                } else {
                    before.payout_denominator == after.payout_denominator
                        && before.payout_numerators == after.payout_numerators
                }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_storage_slots_are_fixed_width_and_adjacent() {
        for (condition, expected) in [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                [
                    "3617319a054d772f909f7c479a2cebe5066e836a939412e32403c99029b92eff",
                    "17ef568e3e12ab5b9c7254a8d58478811de00f9e6eb34345acd53bf8fd09d3ec",
                    "cfb339bd1c51c488f6134f4ac63d1594afad827b3401c3fc51ed1da74a8ca14e",
                    "cfb339bd1c51c488f6134f4ac63d1594afad827b3401c3fc51ed1da74a8ca14f",
                ],
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                [
                    "b1ee3b3d0d99532dd9f14b22c0b908d4eec0e052c3827bbed2d6c3986954d08c",
                    "d8c80a9840ed58f33f2186a8fbc29ecd8c3610d196f1da047301bd51988eb95c",
                    "c63114cd48f1e620ea69dfbfec38c3db64defb68cd54f9f66169d69468a8d820",
                    "c63114cd48f1e620ea69dfbfec38c3db64defb68cd54f9f66169d69468a8d821",
                ],
            ),
            (
                "3bdb7de3d0860745c0cac9c1dcc8e0d9cb7d33e6a899c2c298343ccedf1d66cf",
                [
                    "97ea015a56a6bf35107aac5169fc07e09b5f7da05343f527f7f8d71818f3eb74",
                    "b3fc0897fe5f77aba4bbe70b9826566569b44eba3593c01b1ad6a1dbba524bc2",
                    "6af4516802be93c2fe658e0a1c6cf3b81260f08fba1b2640d23fbdecbb33d82d",
                    "6af4516802be93c2fe658e0a1c6cf3b81260f08fba1b2640d23fbdecbb33d82e",
                ],
            ),
        ] {
            let condition = B256::from_slice(&hex::decode(condition).unwrap());
            let actual = storage_keys(condition).map(|key| format!("{key:064x}"));
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn condition_state_accepts_unprepared_unresolved_fractional_and_nonbinary() {
        assert_eq!(
            interpret(U256::ZERO, U256::ZERO, [U256::ZERO; 2]).unwrap(),
            CtfConditionStateStatus::Unprepared
        );
        assert_eq!(
            interpret(U256::from(2), U256::ZERO, [U256::ZERO; 2]).unwrap(),
            CtfConditionStateStatus::PreparedBinaryUnresolved
        );
        assert_eq!(
            interpret(U256::from(2), U256::from(4), [U256::from(1), U256::from(3)]).unwrap(),
            CtfConditionStateStatus::ResolvedBinary
        );
        assert_eq!(
            interpret(U256::from(3), U256::from(5), [U256::from(1), U256::from(3)]).unwrap(),
            CtfConditionStateStatus::UnsupportedNonBinary
        );
        assert_eq!(
            interpret(U256::from(2), U256::MAX, [U256::MAX - U256::ONE, U256::ONE]).unwrap(),
            CtfConditionStateStatus::ResolvedBinary
        );
        assert!(interpret(U256::from(2), U256::MAX, [U256::MAX, U256::ONE]).is_err());
        assert!(interpret(U256::from(2), U256::from(4), [U256::from(1), U256::from(2)]).is_err());
        assert!(interpret(U256::from(1), U256::ZERO, [U256::ZERO; 2]).is_err());
        assert!(interpret(U256::from(257), U256::ZERO, [U256::ZERO; 2]).is_err());
        assert!(interpret(U256::ZERO, U256::ONE, [U256::ZERO; 2]).is_err());
        assert!(interpret(U256::from(2), U256::ZERO, [U256::ONE, U256::ZERO]).is_err());
        assert!(interpret(U256::from(3), U256::from(4), [U256::from(2), U256::from(3)]).is_err());
    }

    #[test]
    fn condition_state_transitions_preserve_preparation_and_resolved_values() {
        let make =
            |block_number: u64,
             count: u64,
             denominator: u64,
             numerators: [u64; 2],
             status: CtfConditionStateStatus| CtfConditionStateBlockProof {
                block_number,
                block_hash: String::new(),
                state_root: String::new(),
                payout_numerator_count: U256::from(count),
                payout_denominator: U256::from(denominator),
                payout_numerators: numerators.map(U256::from),
                status,
            };
        let unprepared = make(1, 0, 0, [0, 0], CtfConditionStateStatus::Unprepared);
        let prepared = make(
            2,
            2,
            0,
            [0, 0],
            CtfConditionStateStatus::PreparedBinaryUnresolved,
        );
        let resolved = make(3, 2, 4, [1, 3], CtfConditionStateStatus::ResolvedBinary);
        let reversed = make(
            4,
            2,
            0,
            [0, 0],
            CtfConditionStateStatus::PreparedBinaryUnresolved,
        );
        let changed = make(5, 2, 5, [2, 3], CtfConditionStateStatus::ResolvedBinary);
        assert!(transition_is_valid(&unprepared, &prepared));
        assert!(transition_is_valid(&prepared, &resolved));
        assert!(!transition_is_valid(&resolved, &reversed));
        assert!(!transition_is_valid(&resolved, &changed));
        let nonbinary_unresolved = make(
            6,
            3,
            0,
            [0, 0],
            CtfConditionStateStatus::UnsupportedNonBinary,
        );
        let nonbinary_resolved = make(
            7,
            3,
            7,
            [2, 3],
            CtfConditionStateStatus::UnsupportedNonBinary,
        );
        assert!(transition_is_valid(
            &nonbinary_unresolved,
            &nonbinary_resolved
        ));
        assert!(!transition_is_valid(&prepared, &nonbinary_unresolved));
    }
}
