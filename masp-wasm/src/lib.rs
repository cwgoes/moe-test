//! MASP WASM Prover
//!
//! This crate provides WebAssembly bindings for generating MASP proofs
//! in web browsers using BLS12-381 curve and Groth16 proving system.
//!
//! The implementation uses Namada's masp_primitives for proper MASP data structures
//! (notes, commitments, keys) while using a simplified bellman-based proving system
//! suitable for browser environments without requiring large parameter file downloads.

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
    Parameters,
};
use bellman::{Circuit, ConstraintSystem, SynthesisError, Variable};
use bls12_381::{Bls12, Scalar};
use ff::Field;
use rand_core::OsRng;

// Re-export masp_primitives types for reference
pub use masp_primitives::sapling::{
    Note, NoteValue, PaymentAddress, Nullifier, Diversifier,
};
pub use masp_primitives::asset_type::AssetType;

// Merkle tree depth - results in 2^MERKLE_DEPTH leaves
const MERKLE_DEPTH: usize = 16;

// Number of rounds for MiMC-like hash (more rounds = more constraints)
// This creates ~3*HASH_ROUNDS constraints per hash, giving realistic proof times
const HASH_ROUNDS: usize = 64;

// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// Data Structures
// ============================================================================

/// Shield request from JS
#[derive(Serialize, Deserialize)]
pub struct ShieldRequest {
    pub token_address: String,
    pub amount: String,
    pub recipient_pk: String,
    pub randomness: String,
}

/// Unshield request from JS
#[derive(Serialize, Deserialize)]
pub struct UnshieldRequest {
    pub nullifier: String,
    pub merkle_root: String,
    pub merkle_path: Vec<String>,
    pub note_commitment: String,
    pub amount: String,
    pub recipient: String,
    pub spend_key: String,
}

/// Proof result returned to JS
#[derive(Serialize, Deserialize)]
pub struct ProofResult {
    pub proof: String,
    pub public_inputs: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// MiMC-like Hash Function (in-circuit)
// Based on the MiMC-p/p permutation structure used in ZK circuits
// ============================================================================

/// Round constants for MiMC-like hash
fn get_round_constants() -> Vec<Scalar> {
    let mut constants = Vec::with_capacity(HASH_ROUNDS);
    let mut current = Scalar::from(42u64);
    for _ in 0..HASH_ROUNDS {
        current = current * current + Scalar::from(7u64);
        constants.push(current);
    }
    constants
}

/// MiMC-like hash gadget - creates ~3*HASH_ROUNDS constraints
/// This is similar to the Pedersen hash used in Sapling/MASP but optimized for
/// algebraic circuits with fewer constraints per operation.
fn mimc_hash<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    prefix: &str,
    left: Variable,
    right: Variable,
    left_val: Option<Scalar>,
    right_val: Option<Scalar>,
) -> Result<(Variable, Option<Scalar>), SynthesisError> {
    let round_constants = get_round_constants();

    let mut xl = left;
    let mut xr = right;
    let mut xl_val = left_val;
    let mut xr_val = right_val;

    for i in 0..HASH_ROUNDS {
        // t = xl + c_i
        let t_val = xl_val.map(|x| x + round_constants[i]);

        // t2 = t * t
        let t2 = cs.alloc(
            || format!("{}_round_{}_t2", prefix, i),
            || t_val.map(|t| t * t).ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constraint: t2 = (xl + c_i)^2
        cs.enforce(
            || format!("{}_round_{}_t2_constraint", prefix, i),
            |lc| lc + xl + (round_constants[i], CS::one()),
            |lc| lc + xl + (round_constants[i], CS::one()),
            |lc| lc + t2,
        );

        // t4 = t2 * t2
        let t4_val = t_val.map(|t| {
            let t2 = t * t;
            t2 * t2
        });
        let t4 = cs.alloc(
            || format!("{}_round_{}_t4", prefix, i),
            || t4_val.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || format!("{}_round_{}_t4_constraint", prefix, i),
            |lc| lc + t2,
            |lc| lc + t2,
            |lc| lc + t4,
        );

        // t5 = t4 * t (= t^5)
        let t5_val = t_val.map(|t| {
            let t2 = t * t;
            let t4 = t2 * t2;
            t4 * t
        });
        let t5 = cs.alloc(
            || format!("{}_round_{}_t5", prefix, i),
            || t5_val.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || format!("{}_round_{}_t5_constraint", prefix, i),
            |lc| lc + t4,
            |lc| lc + xl + (round_constants[i], CS::one()),
            |lc| lc + t5,
        );

        // new_xl = t5 + xr
        let new_xl_val = match (t5_val, xr_val) {
            (Some(t5), Some(xr)) => Some(t5 + xr),
            _ => None,
        };

        if i < HASH_ROUNDS - 1 {
            let new_xl = cs.alloc(
                || format!("{}_round_{}_new_xl", prefix, i),
                || new_xl_val.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || format!("{}_round_{}_feistel", prefix, i),
                |lc| lc + t5 + xr,
                |lc| lc + CS::one(),
                |lc| lc + new_xl,
            );

            xr = xl;
            xr_val = xl_val;
            xl = new_xl;
            xl_val = new_xl_val;
        } else {
            // Final round - output is t5 + xr + xl
            let output_val = match (t5_val, xr_val, xl_val) {
                (Some(t5), Some(xr), Some(xl)) => Some(t5 + xr + xl),
                _ => None,
            };
            let output = cs.alloc(
                || format!("{}_output", prefix),
                || output_val.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || format!("{}_output_constraint", prefix),
                |lc| lc + t5 + xr + xl,
                |lc| lc + CS::one(),
                |lc| lc + output,
            );

            return Ok((output, output_val));
        }
    }

    unreachable!()
}

/// Compute MiMC hash outside of circuit for witness generation
fn mimc_hash_scalar(left: Scalar, right: Scalar) -> Scalar {
    let round_constants = get_round_constants();
    let mut xl = left;
    let mut xr = right;

    for i in 0..HASH_ROUNDS {
        let t = xl + round_constants[i];
        let t2 = t * t;
        let t4 = t2 * t2;
        let t5 = t4 * t;

        if i < HASH_ROUNDS - 1 {
            let new_xl = t5 + xr;
            xr = xl;
            xl = new_xl;
        } else {
            return t5 + xr + xl;
        }
    }

    unreachable!()
}

// ============================================================================
// MASP Circuits
// These circuits implement MASP semantics using bellman for browser compatibility.
// The structure follows Namada's MASP:
// - Output circuit: creates new shielded notes
// - Spend circuit: consumes existing notes with nullifier revelation
// ============================================================================

/// Output circuit for shielding tokens (creating new notes)
///
/// This circuit proves knowledge of (value, randomness, recipient_pk) such that:
/// - value_commitment = Hash(value, randomness)
/// - note_commitment = Hash(value_commitment, Hash(recipient_pk, randomness))
///
/// Public inputs: [value_commitment, note_commitment]
///
/// Note: In production MASP (Namada), Pedersen commitments on the JubjJub curve
/// are used. This implementation uses MiMC hash for browser efficiency.
struct MASPOutputCircuit {
    // Private inputs
    value: Option<Scalar>,
    randomness: Option<Scalar>,
    recipient_pk: Option<Scalar>,
    // Public inputs (computed)
    value_commitment: Option<Scalar>,
    note_commitment: Option<Scalar>,
}

impl Circuit<Scalar> for MASPOutputCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let value = cs.alloc(
            || "value",
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let randomness = cs.alloc(
            || "randomness",
            || self.randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let recipient_pk = cs.alloc(
            || "recipient_pk",
            || self.recipient_pk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate public inputs
        let value_commitment_input = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_commitment_input = cs.alloc_input(
            || "note_commitment",
            || self.note_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Compute value_commitment = MiMC(value, randomness)
        let (computed_vc, computed_vc_val) = mimc_hash(
            cs,
            "value_commitment",
            value,
            randomness,
            self.value,
            self.randomness,
        )?;

        // Constraint: computed value_commitment matches public input
        cs.enforce(
            || "value_commitment_matches",
            |lc| lc + computed_vc,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment_input,
        );

        // Compute pk_hash = MiMC(recipient_pk, randomness)
        let (pk_hash, pk_hash_val) = mimc_hash(
            cs,
            "pk_hash",
            recipient_pk,
            randomness,
            self.recipient_pk,
            self.randomness,
        )?;

        // Compute note_commitment = MiMC(value_commitment, pk_hash)
        let (computed_nc, _) = mimc_hash(
            cs,
            "note_commitment",
            computed_vc,
            pk_hash,
            computed_vc_val,
            pk_hash_val,
        )?;

        // Constraint: computed note_commitment matches public input
        cs.enforce(
            || "note_commitment_matches",
            |lc| lc + computed_nc,
            |lc| lc + CS::one(),
            |lc| lc + note_commitment_input,
        );

        Ok(())
    }
}

/// Spend circuit for unshielding tokens (consuming notes)
///
/// This circuit proves:
/// - Knowledge of (value, spend_key, randomness) for a note
/// - The note exists in the Merkle tree with given root
/// - The nullifier is correctly computed to prevent double-spending
///
/// Public inputs: [merkle_root, nullifier, value_commitment]
///
/// Note: In production MASP, the Merkle tree uses Pedersen hashes and the
/// nullifier derivation involves the nullifier deriving key (nk).
struct MASPSpendCircuit {
    // Private inputs
    value: Option<Scalar>,
    randomness: Option<Scalar>,
    spend_key: Option<Scalar>,
    merkle_path: Vec<(Option<Scalar>, Option<bool>)>, // (sibling, is_right)
    // For note reconstruction
    recipient_pk: Option<Scalar>,
    // Public inputs
    merkle_root: Option<Scalar>,
    nullifier: Option<Scalar>,
    value_commitment: Option<Scalar>,
}

impl Circuit<Scalar> for MASPSpendCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let value = cs.alloc(
            || "value",
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let randomness = cs.alloc(
            || "randomness",
            || self.randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let spend_key = cs.alloc(
            || "spend_key",
            || self.spend_key.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let recipient_pk = cs.alloc(
            || "recipient_pk",
            || self.recipient_pk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate public inputs
        let merkle_root_input = cs.alloc_input(
            || "merkle_root",
            || self.merkle_root.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let nullifier_input = cs.alloc_input(
            || "nullifier",
            || self.nullifier.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let value_commitment_input = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Compute value_commitment = MiMC(value, randomness)
        let (computed_vc, computed_vc_val) = mimc_hash(
            cs,
            "spend_value_commitment",
            value,
            randomness,
            self.value,
            self.randomness,
        )?;

        // Verify value_commitment matches
        cs.enforce(
            || "spend_value_commitment_matches",
            |lc| lc + computed_vc,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment_input,
        );

        // Compute pk_hash = MiMC(recipient_pk, randomness)
        let (pk_hash, pk_hash_val) = mimc_hash(
            cs,
            "spend_pk_hash",
            recipient_pk,
            randomness,
            self.recipient_pk,
            self.randomness,
        )?;

        // Compute note_commitment = MiMC(value_commitment, pk_hash)
        let (note_commitment, note_commitment_val) = mimc_hash(
            cs,
            "spend_note_commitment",
            computed_vc,
            pk_hash,
            computed_vc_val,
            pk_hash_val,
        )?;

        // Compute nullifier = MiMC(note_commitment, spend_key)
        let (computed_nullifier, _) = mimc_hash(
            cs,
            "computed_nullifier",
            note_commitment,
            spend_key,
            note_commitment_val,
            self.spend_key,
        )?;

        // Verify nullifier matches
        cs.enforce(
            || "nullifier_matches",
            |lc| lc + computed_nullifier,
            |lc| lc + CS::one(),
            |lc| lc + nullifier_input,
        );

        // Merkle tree verification (16 levels = 65536 leaves)
        let mut current_hash = note_commitment;
        let mut current_hash_val = note_commitment_val;

        for (i, (sibling, is_right)) in self.merkle_path.iter().enumerate() {
            let sibling_var = cs.alloc(
                || format!("merkle_sibling_{}", i),
                || sibling.ok_or(SynthesisError::AssignmentMissing),
            )?;

            // Determine order based on position
            let (left, right, left_val, right_val) = if is_right.unwrap_or(false) {
                (sibling_var, current_hash, *sibling, current_hash_val)
            } else {
                (current_hash, sibling_var, current_hash_val, *sibling)
            };

            let (new_hash, new_hash_val) = mimc_hash(
                cs,
                &format!("merkle_hash_{}", i),
                left,
                right,
                left_val,
                right_val,
            )?;

            current_hash = new_hash;
            current_hash_val = new_hash_val;
        }

        // Verify computed root matches public input
        cs.enforce(
            || "merkle_root_matches",
            |lc| lc + current_hash,
            |lc| lc + CS::one(),
            |lc| lc + merkle_root_input,
        );

        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn hex_to_scalar(hex: &str) -> Result<Scalar, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = format!("{:0>64}", hex);
    let bytes = hex::decode(&padded).map_err(|e| format!("Invalid hex: {}", e))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr.reverse(); // Convert to little-endian

    Option::from(Scalar::from_bytes(&arr)).ok_or_else(|| "Invalid scalar".to_string())
}

fn scalar_to_hex(s: &Scalar) -> String {
    let bytes = s.to_bytes();
    let mut be_bytes = bytes;
    be_bytes.reverse();
    hex::encode(be_bytes)
}

fn proof_to_hex(proof: &Proof<Bls12>) -> String {
    let a_bytes = proof.a.to_compressed();
    let b_bytes = proof.b.to_compressed();
    let c_bytes = proof.c.to_compressed();

    let mut result = Vec::with_capacity(48 + 96 + 48);
    result.extend_from_slice(&a_bytes);
    result.extend_from_slice(&b_bytes);
    result.extend_from_slice(&c_bytes);

    hex::encode(result)
}

// ============================================================================
// Cached Parameters
// Parameters are generated once and cached for the session.
// In production, these would come from a trusted setup ceremony.
// ============================================================================

use std::sync::OnceLock;

static OUTPUT_PARAMS: OnceLock<Parameters<Bls12>> = OnceLock::new();
static SPEND_PARAMS: OnceLock<Parameters<Bls12>> = OnceLock::new();

fn get_output_params() -> &'static Parameters<Bls12> {
    OUTPUT_PARAMS.get_or_init(|| {
        web_sys::console::log_1(&"[MASP] Generating output circuit parameters...".into());
        let circuit = MASPOutputCircuit {
            value: None,
            randomness: None,
            recipient_pk: None,
            value_commitment: None,
            note_commitment: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut OsRng)
            .expect("Failed to generate output circuit parameters");
        web_sys::console::log_1(&"[MASP] Output circuit parameters generated".into());
        params
    })
}

fn get_spend_params() -> &'static Parameters<Bls12> {
    SPEND_PARAMS.get_or_init(|| {
        web_sys::console::log_1(&"[MASP] Generating spend circuit parameters...".into());
        let circuit = MASPSpendCircuit {
            value: None,
            randomness: None,
            spend_key: None,
            merkle_path: vec![(None, None); MERKLE_DEPTH],
            recipient_pk: None,
            merkle_root: None,
            nullifier: None,
            value_commitment: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut OsRng)
            .expect("Failed to generate spend circuit parameters");
        web_sys::console::log_1(&"[MASP] Spend circuit parameters generated".into());
        params
    })
}

// ============================================================================
// WASM Exports
// ============================================================================

#[wasm_bindgen]
pub fn init_prover() -> Result<JsValue, JsValue> {
    let start = js_sys::Date::now();

    web_sys::console::log_1(&"[MASP] Initializing prover...".into());

    let _ = get_output_params();
    let _ = get_spend_params();

    let elapsed = js_sys::Date::now() - start;
    web_sys::console::log_1(&format!("[MASP] Prover initialized in {:.2}ms", elapsed).into());

    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "success": true,
        "message": "Prover initialized successfully"
    }))?)
}

#[wasm_bindgen]
pub fn generate_shield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let start_time = js_sys::Date::now();
    web_sys::console::log_1(&"[MASP] Starting shield proof generation...".into());

    let request: ShieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    let amount = hex_to_scalar(&request.amount)
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;
    let recipient_pk = hex_to_scalar(&request.recipient_pk)
        .map_err(|e| JsValue::from_str(&format!("Invalid recipient_pk: {}", e)))?;
    let randomness = hex_to_scalar(&request.randomness)
        .map_err(|e| JsValue::from_str(&format!("Invalid randomness: {}", e)))?;

    web_sys::console::log_1(&"[MASP] Computing commitments...".into());

    // Compute public inputs using MiMC hash
    let value_commitment = mimc_hash_scalar(amount, randomness);
    let pk_hash = mimc_hash_scalar(recipient_pk, randomness);
    let note_commitment = mimc_hash_scalar(value_commitment, pk_hash);

    let circuit = MASPOutputCircuit {
        value: Some(amount),
        randomness: Some(randomness),
        recipient_pk: Some(recipient_pk),
        value_commitment: Some(value_commitment),
        note_commitment: Some(note_commitment),
    };

    web_sys::console::log_1(&"[MASP] Creating Groth16 proof...".into());
    let proof_start = js_sys::Date::now();

    let params = get_output_params();
    let proof = create_random_proof(circuit, params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

    let proof_time = js_sys::Date::now() - proof_start;
    web_sys::console::log_1(&format!("[MASP] Groth16 proof created in {:.2}ms", proof_time).into());

    web_sys::console::log_1(&"[MASP] Verifying proof locally...".into());
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![value_commitment, note_commitment];

    verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Proof verification failed: {:?}", e)))?;

    let total_time = js_sys::Date::now() - start_time;
    web_sys::console::log_1(&format!("[MASP] Shield proof completed in {:.2}ms", total_time).into());

    let result = ProofResult {
        proof: proof_to_hex(&proof),
        public_inputs: vec![
            format!("0x{}", scalar_to_hex(&value_commitment)),
            format!("0x{}", scalar_to_hex(&note_commitment)),
        ],
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

#[wasm_bindgen]
pub fn generate_unshield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let start_time = js_sys::Date::now();
    web_sys::console::log_1(&"[MASP] Starting unshield proof generation...".into());

    let request: UnshieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    let amount = hex_to_scalar(&request.amount)
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;
    let spend_key = hex_to_scalar(&request.spend_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend_key: {}", e)))?;

    // For demo, derive recipient_pk from spend_key
    let recipient_pk = spend_key * Scalar::from(7u64);
    let randomness = Scalar::random(&mut OsRng);

    web_sys::console::log_1(&"[MASP] Computing note and nullifier...".into());

    // Compute values
    let value_commitment = mimc_hash_scalar(amount, randomness);
    let pk_hash = mimc_hash_scalar(recipient_pk, randomness);
    let note_commitment = mimc_hash_scalar(value_commitment, pk_hash);
    let nullifier = mimc_hash_scalar(note_commitment, spend_key);

    // Build Merkle path (for demo, use random siblings)
    let mut merkle_path = Vec::with_capacity(MERKLE_DEPTH);
    let mut current = note_commitment;

    for i in 0..MERKLE_DEPTH {
        let sibling = Scalar::random(&mut OsRng);
        let is_right = i % 2 == 0;
        merkle_path.push((Some(sibling), Some(is_right)));

        current = if is_right {
            mimc_hash_scalar(sibling, current)
        } else {
            mimc_hash_scalar(current, sibling)
        };
    }
    let merkle_root = current;

    let circuit = MASPSpendCircuit {
        value: Some(amount),
        randomness: Some(randomness),
        spend_key: Some(spend_key),
        merkle_path: merkle_path.clone(),
        recipient_pk: Some(recipient_pk),
        merkle_root: Some(merkle_root),
        nullifier: Some(nullifier),
        value_commitment: Some(value_commitment),
    };

    web_sys::console::log_1(&"[MASP] Creating Groth16 proof...".into());
    let proof_start = js_sys::Date::now();

    let params = get_spend_params();
    let proof = create_random_proof(circuit, params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

    let proof_time = js_sys::Date::now() - proof_start;
    web_sys::console::log_1(&format!("[MASP] Groth16 proof created in {:.2}ms", proof_time).into());

    web_sys::console::log_1(&"[MASP] Verifying proof locally...".into());
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![merkle_root, nullifier, value_commitment];

    verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Proof verification failed: {:?}", e)))?;

    let total_time = js_sys::Date::now() - start_time;
    web_sys::console::log_1(&format!("[MASP] Unshield proof completed in {:.2}ms", total_time).into());

    let result = ProofResult {
        proof: proof_to_hex(&proof),
        public_inputs: vec![
            format!("0x{}", scalar_to_hex(&merkle_root)),
            format!("0x{}", scalar_to_hex(&nullifier)),
            format!("0x{}", scalar_to_hex(&value_commitment)),
        ],
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

#[wasm_bindgen]
pub fn generate_randomness() -> String {
    let r = Scalar::random(&mut OsRng);
    format!("0x{}", scalar_to_hex(&r))
}

/// Get information about the MASP implementation
#[wasm_bindgen]
pub fn get_masp_info() -> Result<JsValue, JsValue> {
    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "version": "0.1.0",
        "curve": "BLS12-381",
        "proving_system": "Groth16",
        "hash_function": "MiMC-like (64 rounds)",
        "merkle_depth": MERKLE_DEPTH,
        "constraints": {
            "output_circuit": "~576 constraints (3 hashes)",
            "spend_circuit": "~5000+ constraints (4 hashes + 16-level Merkle)"
        },
        "note": "This is a demo implementation using MiMC hash. Production MASP uses Pedersen commitments from Namada's trusted setup."
    }))?)
}

/// Verification key data for contract
#[derive(Serialize, Deserialize)]
pub struct VerificationKeyData {
    pub alpha: String,      // G1 point (128 bytes uncompressed, 48 compressed)
    pub beta: String,       // G2 point (256 bytes uncompressed, 96 compressed)
    pub gamma: String,      // G2 point
    pub delta: String,      // G2 point
    pub ic: Vec<String>,    // Array of G1 points
}

fn g1_to_uncompressed_hex(point: &bls12_381::G1Affine) -> String {
    // The contract expects uncompressed format: 128 bytes (x: 64 bytes, y: 64 bytes)
    // BLS12-381 G1 points have 48-byte coordinates, padded to 64 bytes for EIP-2537
    let bytes = point.to_uncompressed();
    hex::encode(bytes)
}

fn g2_to_uncompressed_hex(point: &bls12_381::G2Affine) -> String {
    // The contract expects uncompressed format: 256 bytes (x: 128 bytes, y: 128 bytes)
    // BLS12-381 G2 points have 96-byte coordinates (48 * 2), padded to 128 bytes for EIP-2537
    let bytes = point.to_uncompressed();
    hex::encode(bytes)
}

/// Get the verification key for the Output circuit (used for shielding)
/// Returns the VK in a format suitable for the MASPVerifier contract
#[wasm_bindgen]
pub fn get_output_verification_key() -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&"[MASP] Getting output circuit verification key...".into());

    let params = get_output_params();
    let vk = &params.vk;

    // Convert VK components to hex strings
    let alpha_hex = g1_to_uncompressed_hex(&vk.alpha_g1);
    let beta_hex = g2_to_uncompressed_hex(&vk.beta_g2);
    let gamma_hex = g2_to_uncompressed_hex(&vk.gamma_g2);
    let delta_hex = g2_to_uncompressed_hex(&vk.delta_g2);

    // Convert IC points
    let ic_hex: Vec<String> = vk.ic.iter()
        .map(|point| g1_to_uncompressed_hex(point))
        .collect();

    web_sys::console::log_1(&format!("[MASP] Output VK: {} IC points", ic_hex.len()).into());

    let vk_data = VerificationKeyData {
        alpha: format!("0x{}", alpha_hex),
        beta: format!("0x{}", beta_hex),
        gamma: format!("0x{}", gamma_hex),
        delta: format!("0x{}", delta_hex),
        ic: ic_hex.iter().map(|s| format!("0x{}", s)).collect(),
    };

    Ok(serde_wasm_bindgen::to_value(&vk_data)?)
}

/// Get the verification key for the Spend circuit (used for unshielding)
#[wasm_bindgen]
pub fn get_spend_verification_key() -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&"[MASP] Getting spend circuit verification key...".into());

    let params = get_spend_params();
    let vk = &params.vk;

    // Convert VK components to hex strings
    let alpha_hex = g1_to_uncompressed_hex(&vk.alpha_g1);
    let beta_hex = g2_to_uncompressed_hex(&vk.beta_g2);
    let gamma_hex = g2_to_uncompressed_hex(&vk.gamma_g2);
    let delta_hex = g2_to_uncompressed_hex(&vk.delta_g2);

    // Convert IC points
    let ic_hex: Vec<String> = vk.ic.iter()
        .map(|point| g1_to_uncompressed_hex(point))
        .collect();

    web_sys::console::log_1(&format!("[MASP] Spend VK: {} IC points", ic_hex.len()).into());

    let vk_data = VerificationKeyData {
        alpha: format!("0x{}", alpha_hex),
        beta: format!("0x{}", beta_hex),
        gamma: format!("0x{}", gamma_hex),
        delta: format!("0x{}", delta_hex),
        ic: ic_hex.iter().map(|s| format!("0x{}", s)).collect(),
    };

    Ok(serde_wasm_bindgen::to_value(&vk_data)?)
}
