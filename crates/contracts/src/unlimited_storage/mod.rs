use std::sync::Arc;

use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::elements::{Script, Transaction};
use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::simplicity::{Cmr, RedeemNode, leaf_version};
use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::{CompiledProgram, TemplateProgram, WitnessValues};
use simplicityhl_core::{RunnerLogLevel, run_program};

mod build_arguments;
mod build_witness;

pub use build_arguments::{UnlimitedStorageArguments, build_unlimited_storage_arguments};
pub use build_witness::{MAX_VAL, build_unlimited_storage_witness};

pub const UNLIMITED_STORAGE_SOURCE: &str = include_str!("source_simf/array.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_unlimited_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(UNLIMITED_STORAGE_SOURCE)
        .expect("INTERNAL: expected to compile successfully.")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_unlimited_storage_compiled_program(args: &UnlimitedStorageArguments) -> CompiledProgram {
    let program = get_unlimited_storage_template_program();

    program
        .instantiate(build_unlimited_storage_arguments(args), true)
        .unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_unlimited_storage_program(
    storage: [u8; MAX_VAL],
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {
    let witness_values = build_unlimited_storage_witness(storage);
    Ok(run_program(compiled_program, witness_values, env, RunnerLogLevel::Trace)?.0)
}

fn script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (Script::from(cmr.as_ref().to_vec()), leaf_version())
}

/// Given a Simplicity CMR and an internal key, computes the [`TaprootSpendInfo`]
/// for a Taptree with this CMR as its single leaf.
pub fn taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    storage: &[u8; MAX_VAL],
    len: usize,
    cmr: Cmr,
) -> TaprootSpendInfo {
    let (script, version) = script_ver(cmr);

    // Compute TapData-tagged hash of the state
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&storage[..len]);
    let storage_hash = sha256::Hash::from_engine(eng);

    // Build taproot tree with hidden leaf
    let builder = TaprootBuilder::new()
        .add_leaf_with_ver(1, script, version)
        .expect("tap tree should be valid")
        .add_hidden(1, storage_hash)
        .expect("tap tree should be valid");

    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

#[cfg(test)]
mod unlimited_storage_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    #[test]
    fn test_unlimited_storage_mint_path() -> Result<()> {
        let mut old_storage = [0u8; MAX_VAL];
        old_storage[3] = 0xff;

        let unlimited_storage_arguments = UnlimitedStorageArguments {
            len: 5,
        };

        let program = get_unlimited_storage_compiled_program(&unlimited_storage_arguments);
        let cmr = program.commit().cmr();

        let internal_key = secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32])?;

        let spend_info = taproot_spend_info(
            internal_key,
            &old_storage,
            unlimited_storage_arguments.len as usize,
            cmr
        );
        let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

        // minimal tx
        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint = OutPoint::new(Txid::from_slice(&[0; 32])?, 0);
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_output(Output::new_explicit(script_pubkey.clone(), 0, AssetId::default(), None));

        let control_block = spend_info
            .control_block(&script_ver(cmr))
            .expect("must get control block");
        
        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?,
            None,
            BlockHash::all_zeros(),
        );

        assert!(
            execute_unlimited_storage_program(old_storage, &program, &env).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
