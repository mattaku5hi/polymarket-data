use super::*;

const BASE_FIELD: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const SQRT_EXPONENT: &str =
    "5472060717959818805561601436314318772174077789324455915672259473661306552146";
const MAX_CANDIDATES: usize = 128;
const EXCHANGE_REGISTRY_SLOT: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DerivedRootBinaryIdentity {
    pub condition_id: B256,
    pub collection_ids: [B256; 2],
    pub position_ids: [B256; 2],
    pub registry_keys: [B256; 4],
    pub selected_index_set: u8,
}

pub(super) async fn derive_root_binary_identity_bounded(
    condition_id: B256,
    selected_token_id: U256,
    deadline: tokio::time::Instant,
) -> Result<DerivedRootBinaryIdentity, BoundedV1TradeAttributionError> {
    let collateral = parse_fixed_address(USDC_E_PROXY_ADDRESS)
        .map_err(BoundedV1TradeAttributionError::Verification)?;
    let collection_ids = [
        get_root_collection_id_bounded(condition_id, 1, MAX_CANDIDATES, deadline).await?,
        get_root_collection_id_bounded(condition_id, 2, MAX_CANDIDATES, deadline).await?,
    ];
    let position_ids = [
        position_id(collateral, collection_ids[0]),
        position_id(collateral, collection_ids[1]),
    ];
    let selected_index_set = if U256::from_be_bytes(position_ids[0].0) == selected_token_id {
        1
    } else if U256::from_be_bytes(position_ids[1].0) == selected_token_id {
        2
    } else {
        return Err(BoundedV1TradeAttributionError::Verification(
            ChainLogAuditError::InvalidInput,
        ));
    };
    let registry_keys = [
        registry_mapping_key(position_ids[0]),
        registry_condition_key(position_ids[0]),
        registry_mapping_key(position_ids[1]),
        registry_condition_key(position_ids[1]),
    ];
    Ok(DerivedRootBinaryIdentity {
        condition_id,
        collection_ids,
        position_ids,
        registry_keys,
        selected_index_set,
    })
}

pub(super) async fn get_root_collection_id_bounded(
    condition_id: B256,
    index_set: u8,
    candidate_limit: usize,
    deadline: tokio::time::Instant,
) -> Result<B256, BoundedV1TradeAttributionError> {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(condition_id.as_slice());
    preimage[63] = index_set;
    let initial_hash = Keccak256::digest(preimage);
    let odd = (initial_hash[0] & 0x80) != 0;
    let prime = BigUint::parse_bytes(BASE_FIELD.as_bytes(), 10).ok_or(
        BoundedV1TradeAttributionError::Verification(ChainLogAuditError::Unverified),
    )?;
    let exponent = BigUint::parse_bytes(SQRT_EXPONENT.as_bytes(), 10).ok_or(
        BoundedV1TradeAttributionError::Verification(ChainLogAuditError::Unverified),
    )?;
    let hash_value = BigUint::from_bytes_be(&initial_hash);
    let mut x = (hash_value % &prime + BigUint::from(1_u8)) % &prime;
    for _ in 0..candidate_limit.min(MAX_CANDIDATES) {
        if tokio::time::Instant::now() >= deadline {
            return Err(BoundedV1TradeAttributionError::Timeout);
        }
        tokio::task::yield_now().await;
        let yy = ((&x * &x % &prime) * &x + BigUint::from(3_u8)) % &prime;
        let y = yy.modpow(&exponent, &prime);
        if (&y * &y) % &prime == yy {
            let y_is_odd = (&y & BigUint::from(1_u8)) == BigUint::from(1_u8);
            let y = if y_is_odd == odd { y } else { &prime - y };
            let encoded_x = x.to_bytes_be();
            if encoded_x.len() > 32 {
                return Err(BoundedV1TradeAttributionError::Verification(
                    ChainLogAuditError::Unverified,
                ));
            }
            let mut collection = [0_u8; 32];
            collection[32 - encoded_x.len()..].copy_from_slice(&encoded_x);
            if (&y & BigUint::from(1_u8)) == BigUint::from(1_u8) {
                collection[0] |= 0x40;
            }
            return Ok(B256::from(collection));
        }
        x = (x + BigUint::from(1_u8)) % &prime;
    }
    Err(BoundedV1TradeAttributionError::Verification(
        ChainLogAuditError::Unverified,
    ))
}

pub(super) fn position_id(collateral: Address, collection_id: B256) -> B256 {
    let mut preimage = [0_u8; 52];
    preimage[..20].copy_from_slice(collateral.as_slice());
    preimage[20..].copy_from_slice(collection_id.as_slice());
    B256::from_slice(&Keccak256::digest(preimage))
}

fn registry_mapping_key(position_id: B256) -> B256 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(position_id.as_slice());
    preimage[63] = EXCHANGE_REGISTRY_SLOT as u8;
    B256::from_slice(&Keccak256::digest(preimage))
}

fn registry_condition_key(position_id: B256) -> B256 {
    let mut key = registry_mapping_key(position_id).0;
    for byte in key.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
    B256::from(key)
}

fn parse_fixed_address(value: &str) -> Result<Address, ChainLogAuditError> {
    let value = validate_hex(value, 20)?;
    let bytes = hex::decode(&value[2..]).map_err(|_| ChainLogAuditError::Unverified)?;
    Ok(Address::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_b256(hex_value: &str) -> B256 {
        B256::from_slice(&hex::decode(hex_value).unwrap())
    }

    #[tokio::test]
    async fn production_curve_helper_matches_published_even_parity_and_packed_position_vectors() {
        let condition = B256::from_slice(
            &hex::decode("67eb23e8932765c1d7a094838c928476df8c50d1d3898f278ef1fb2a62afab63")
                .unwrap(),
        );
        let collection = get_root_collection_id_bounded(
            condition,
            3,
            MAX_CANDIDATES,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(
            format!("{collection:#x}"),
            "0x229b067e142fce0aea84afb935095c6ecbea8647b8a013e795cc0ced3210a3d5"
        );
        let collateral = parse_fixed_address("0xd011ad011ad011ad011ad011ad011ad011ad011a").unwrap();
        let position = position_id(collateral, collection);
        assert_eq!(
            format!("{position:#x}"),
            "0x5355fd8106a08b14aedf99935210b2c22a7f92abaf8bb00b60fcece1032436b7"
        );
        assert_eq!(
            format!("{:#x}", registry_mapping_key(position)),
            "0x37df12f438276cee1679ad81d1bd0e4aec279119e6354d971479589eb9709af0"
        );
        assert_eq!(
            format!("{:#x}", registry_condition_key(position)),
            "0x37df12f438276cee1679ad81d1bd0e4aec279119e6354d971479589eb9709af1"
        );
    }

    #[tokio::test]
    async fn production_curve_helper_matches_odd_parity_and_root_binary_position_vectors() {
        let condition = B256::from_slice(
            &hex::decode("3bdb7de3d0860745c0cac9c1dcc8e0d9cb7d33e6a899c2c298343ccedf1d66cf")
                .unwrap(),
        );
        assert_eq!(
            format!(
                "{:#x}",
                get_root_collection_id_bounded(
                    condition,
                    1,
                    MAX_CANDIDATES,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .await
                .unwrap()
            ),
            "0x560ae373ed304932b6f424c8a243842092c117645533390a3c1c95ff481587c2"
        );
        let selected = U256::from_be_bytes(
            fixed_b256("671b37a9252e1e8eaffb3168d52f05f5b4a132b7852cb6953e37d29414e51f41").0,
        );
        let derived = derive_root_binary_identity_bounded(
            condition,
            selected,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(derived.selected_index_set, 1);
        assert_eq!(
            format!("{:#x}", derived.position_ids[0]),
            "0x671b37a9252e1e8eaffb3168d52f05f5b4a132b7852cb6953e37d29414e51f41"
        );
        assert_eq!(
            format!("{:#x}", derived.position_ids[1]),
            "0x261ba86d11f0ffd2801251237d76ed91f491d702dcd3568a16cde6c6a156aa1e"
        );
        assert_eq!(
            format!("{:#x}", derived.registry_keys[0]),
            "0xf039ded1491c4834fbdfb6378ec50c6fb98d5b5f9c215949989ef654b91f8d74"
        );
        assert_eq!(
            format!("{:#x}", derived.registry_keys[1]),
            "0xf039ded1491c4834fbdfb6378ec50c6fb98d5b5f9c215949989ef654b91f8d75"
        );
        assert_eq!(
            format!("{:#x}", derived.registry_keys[2]),
            "0x1fac7c93df45c68b1c8e45c2f91daa3bfe668dd078ffd6b8da9871777411d229"
        );
        assert_eq!(
            format!("{:#x}", derived.registry_keys[3]),
            "0x1fac7c93df45c68b1c8e45c2f91daa3bfe668dd078ffd6b8da9871777411d22a"
        );
        let index_two = derive_root_binary_identity_bounded(
            condition,
            U256::from_be_bytes(derived.position_ids[1].0),
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(index_two.selected_index_set, 2);
    }

    #[tokio::test]
    async fn production_curve_helper_enforces_candidate_cap_and_deadline() {
        let condition =
            fixed_b256("67eb23e8932765c1d7a094838c928476df8c50d1d3898f278ef1fb2a62afab63");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        assert_eq!(
            get_root_collection_id_bounded(condition, 3, 3, deadline).await,
            Err(BoundedV1TradeAttributionError::Verification(
                ChainLogAuditError::Unverified
            ))
        );
        assert_eq!(
            get_root_collection_id_bounded(
                condition,
                3,
                MAX_CANDIDATES,
                tokio::time::Instant::now() - Duration::from_secs(1),
            )
            .await,
            Err(BoundedV1TradeAttributionError::Timeout)
        );
    }
}
