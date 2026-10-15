//! Authenticated absence of the two fixed ERC-1155 ledgers at Polygon genesis.
//! This establishes only their zero balance namespace at block zero.

use super::{
    CTF_CONDITIONAL_TOKENS_ADDRESS, ChainLogAuditError, POLYGON_CHAIN_ID,
    fifth_code_context::POSITION_MANAGER_PROXY, header_binding::bind_header,
};
use crate::position_history::PositionLedger;
use alloy_primitives::{B256, Bytes};
use alloy_trie::{Nibbles, proof::verify_proof};
use serde::Deserialize;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;

const GENESIS_BLOCK_HASH: &str =
    "0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b";
const GENESIS_STATE_ROOT: &str =
    "0x654f28d19b44239d1012f27038f1f71b3d4465dc415a382fb2b7009cba1527c8";
const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const MAX_PROOF_NODES: usize = 128;
const MAX_PROOF_BYTES: usize = 4096;

pub const GENESIS_POSITION_OPENING_SOURCE_REVISION: &str =
    "9c445ef603e71469e1c176d8e57e7cf94864ade7";

/// Untrusted account-trie absence claims. Verification binds all fields to the pinned genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolygonGenesisPositionOpeningEvidence {
    pub chain_id: u64,
    pub header: Value,
    pub ctf_account_proof: Vec<String>,
    pub position_manager_account_proof: Vec<String>,
}

/// Locally verified genesis absence for the two fixed position ledgers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolygonGenesisPositionOpening {
    block_hash: String,
    state_root: String,
}

impl PolygonGenesisPositionOpening {
    pub fn chain_id(&self) -> u64 {
        POLYGON_CHAIN_ID
    }

    pub fn block_number(&self) -> u64 {
        0
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    pub fn state_root(&self) -> &str {
        &self.state_root
    }

    pub fn source_revision(&self) -> &'static str {
        GENESIS_POSITION_OPENING_SOURCE_REVISION
    }

    pub fn emitter(&self, ledger: PositionLedger) -> &'static str {
        match ledger {
            PositionLedger::Ctf => CTF_CONDITIONAL_TOKENS_ADDRESS,
            PositionLedger::PositionManager => POSITION_MANAGER_PROXY,
        }
    }

    /// Decimal base units at Polygon block zero for the selected fixed ledger.
    pub fn zero_balance_base_units_at_genesis(&self, _ledger: PositionLedger) -> &'static str {
        "0"
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmbeddedReference {
    chain_id: u64,
    header: Value,
    ctf_account_proof: Vec<String>,
    position_manager_account_proof: Vec<String>,
}

/// Verify the pinned Polygon genesis header and both fixed-contract non-inclusion proofs.
pub fn verify_polygon_genesis_position_opening(
    evidence: &PolygonGenesisPositionOpeningEvidence,
) -> Result<PolygonGenesisPositionOpening, ChainLogAuditError> {
    if evidence.chain_id != POLYGON_CHAIN_ID {
        return Err(ChainLogAuditError::Unverified);
    }
    let header = bind_header(&evidence.header)?;
    if header.number != 0
        || header.parent_hash != ZERO_HASH
        || header.hash != GENESIS_BLOCK_HASH
        || header.state_root != GENESIS_STATE_ROOT
    {
        return Err(ChainLogAuditError::Unverified);
    }

    verify_account_absence(
        &header.state_root,
        CTF_CONDITIONAL_TOKENS_ADDRESS,
        &evidence.ctf_account_proof,
    )?;
    verify_account_absence(
        &header.state_root,
        POSITION_MANAGER_PROXY,
        &evidence.position_manager_account_proof,
    )?;

    Ok(PolygonGenesisPositionOpening {
        block_hash: header.hash,
        state_root: header.state_root,
    })
}

/// Verify the public bundled reference proof offline before returning its sealed result.
pub fn polygon_genesis_position_opening()
-> Result<PolygonGenesisPositionOpening, ChainLogAuditError> {
    let reference: EmbeddedReference =
        serde_json::from_str(include_str!("genesis_position_opening_reference.json"))
            .map_err(|_| ChainLogAuditError::Unverified)?;
    verify_polygon_genesis_position_opening(&PolygonGenesisPositionOpeningEvidence {
        chain_id: reference.chain_id,
        header: reference.header,
        ctf_account_proof: reference.ctf_account_proof,
        position_manager_account_proof: reference.position_manager_account_proof,
    })
}

fn verify_account_absence(
    state_root: &str,
    address: &str,
    proof: &[String],
) -> Result<(), ChainLogAuditError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_NODES {
        return Err(ChainLogAuditError::Unverified);
    }
    let mut encoded_nodes = Vec::with_capacity(proof.len());
    let mut distinct = BTreeSet::new();
    for node in proof {
        let raw = node
            .strip_prefix("0x")
            .ok_or(ChainLogAuditError::Unverified)?;
        if raw.is_empty() || raw.len() % 2 != 0 || raw.len() / 2 > MAX_PROOF_BYTES {
            return Err(ChainLogAuditError::Unverified);
        }
        let bytes = hex::decode(raw).map_err(|_| ChainLogAuditError::Unverified)?;
        if !distinct.insert(bytes.clone()) {
            return Err(ChainLogAuditError::Unverified);
        }
        encoded_nodes.push(Bytes::from(bytes));
    }

    let address = address
        .strip_prefix("0x")
        .ok_or(ChainLogAuditError::Unverified)?;
    let address = hex::decode(address).map_err(|_| ChainLogAuditError::Unverified)?;
    if address.len() != 20 {
        return Err(ChainLogAuditError::Unverified);
    }
    let state_root = state_root
        .strip_prefix("0x")
        .ok_or(ChainLogAuditError::Unverified)?;
    let state_root = hex::decode(state_root).map_err(|_| ChainLogAuditError::Unverified)?;
    let root = B256::from_slice(&state_root);
    let key = B256::from_slice(&Keccak256::digest(address));
    verify_proof(root, Nibbles::unpack(key), None, &encoded_nodes)
        .map_err(|_| ChainLogAuditError::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference_evidence() -> PolygonGenesisPositionOpeningEvidence {
        let reference: EmbeddedReference =
            serde_json::from_str(include_str!("genesis_position_opening_reference.json"))
                .expect("embedded reference parses");
        PolygonGenesisPositionOpeningEvidence {
            chain_id: reference.chain_id,
            header: reference.header,
            ctf_account_proof: reference.ctf_account_proof,
            position_manager_account_proof: reference.position_manager_account_proof,
        }
    }

    #[test]
    fn embedded_and_supplied_proofs_bind_fixed_ledgers_to_genesis() {
        let result = polygon_genesis_position_opening().expect("reference proof verifies");
        assert_eq!(result.chain_id(), POLYGON_CHAIN_ID);
        assert_eq!(result.block_number(), 0);
        assert_eq!(result.block_hash(), GENESIS_BLOCK_HASH);
        assert_eq!(result.state_root(), GENESIS_STATE_ROOT);
        assert_eq!(
            result.source_revision(),
            GENESIS_POSITION_OPENING_SOURCE_REVISION
        );
        assert_eq!(
            result.emitter(PositionLedger::Ctf),
            CTF_CONDITIONAL_TOKENS_ADDRESS
        );
        assert_eq!(
            result.emitter(PositionLedger::PositionManager),
            POSITION_MANAGER_PROXY
        );
        assert_eq!(
            result.zero_balance_base_units_at_genesis(PositionLedger::Ctf),
            "0"
        );
        assert_eq!(
            result.zero_balance_base_units_at_genesis(PositionLedger::PositionManager),
            "0"
        );
        assert_eq!(
            verify_polygon_genesis_position_opening(&reference_evidence()),
            Ok(result)
        );
    }

    #[test]
    fn refuses_wrong_chain_header_roots_and_invalid_absence_proofs() {
        let original = reference_evidence();
        let mut changed = original.clone();
        changed.chain_id = 1;
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());

        for (field, value) in [
            ("number", json!("0x1")),
            ("parentHash", json!(format!("0x{}", "11".repeat(32)))),
            ("stateRoot", json!(format!("0x{}", "11".repeat(32)))),
        ] {
            let mut changed = original.clone();
            changed.header[field] = value;
            assert!(verify_polygon_genesis_position_opening(&changed).is_err());
        }
        let mut changed = original.clone();
        changed.ctf_account_proof[0].replace_range(4..6, "00");
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());
        let mut changed = original.clone();
        changed.ctf_account_proof.pop();
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());
        let mut changed = original.clone();
        changed
            .ctf_account_proof
            .push(changed.ctf_account_proof[0].clone());
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());
        let mut changed = original.clone();
        changed.ctf_account_proof.push("0x01".to_owned());
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());
    }

    #[test]
    fn rejects_empty_oversized_and_present_account_proofs() {
        let mut changed = reference_evidence();
        changed.ctf_account_proof.clear();
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());
        let mut changed = reference_evidence();
        changed.ctf_account_proof = vec!["0x01".to_owned(); 129];
        assert!(verify_polygon_genesis_position_opening(&changed).is_err());

        let present_control: Value = serde_json::from_str(include_str!(
            "genesis_position_opening_present_control.json"
        ))
        .expect("present-account control parses");
        let address = present_control["address"]
            .as_str()
            .expect("control address");
        let nodes = present_control["proof_nodes"]
            .as_array()
            .expect("control nodes")
            .iter()
            .map(|node| node.as_str().expect("node string").to_owned())
            .collect::<Vec<_>>();
        assert!(verify_account_absence(GENESIS_STATE_ROOT, address, &nodes).is_err());

        let mut present = reference_evidence();
        present.ctf_account_proof = nodes;
        assert!(verify_polygon_genesis_position_opening(&present).is_err());

        let mut oversized_node = reference_evidence();
        oversized_node.ctf_account_proof = vec![format!("0x{}", "00".repeat(MAX_PROOF_BYTES + 1))];
        assert!(verify_polygon_genesis_position_opening(&oversized_node).is_err());
    }
}
