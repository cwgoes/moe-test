//! MASP WASM Prover
//!
//! This crate provides WebAssembly bindings for generating MASP proofs
//! in web browsers using BLS12-381 curve and Groth16 proving system.

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
    Parameters,
};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use ff::{PrimeField, Field};
use rand_core::OsRng;

// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// Data Structures
// ============================================================================

/// Proof data structure for JS interop
#[derive(Serialize, Deserialize, Clone)]
pub struct ProofData {
    pub a: String,  // G1 point hex
    pub b: String,  // G2 point hex
    pub c: String,  // G1 point hex
}

/// Public inputs structure
#[derive(Serialize, Deserialize, Clone)]
pub struct PublicInputs {
    pub inputs: Vec<String>,  // Hex-encoded field elements
}

/// Shield request from JS
#[derive(Serialize, Deserialize)]
pub struct ShieldRequest {
    pub token_address: String,
    pub amount: String,
    pub recipient_pk: String,  // Recipient's public key for note
    pub randomness: String,    // Random value for commitment
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
    pub proof: String,           // 512-byte hex proof (A || B || C)
    pub public_inputs: Vec<String>,  // Hex-encoded public inputs
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// MASP Circuits
// ============================================================================

/// Output circuit for shielding tokens (creating new notes)
/// Public inputs: [value_commitment, note_commitment, epk]
struct MASPOutputCircuit {
    // Private inputs
    value: Option<Scalar>,
    randomness: Option<Scalar>,
    recipient_pk: Option<Scalar>,
    // Public inputs (computed)
    value_commitment: Option<Scalar>,
    note_commitment: Option<Scalar>,
    epk: Option<Scalar>,
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
        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_commitment = cs.alloc_input(
            || "note_commitment",
            || self.note_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let epk = cs.alloc_input(
            || "epk",
            || self.epk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constraint: value_commitment = hash(value, randomness)
        // Simplified: value_commitment = value * randomness
        cs.enforce(
            || "value_commitment_constraint",
            |lc| lc + value,
            |lc| lc + randomness,
            |lc| lc + value_commitment,
        );

        // Constraint: note_commitment = hash(value_commitment, recipient_pk, randomness)
        // Simplified: note_commitment = value_commitment * recipient_pk + randomness
        let intermediate = cs.alloc(
            || "intermediate",
            || {
                let vc = self.value_commitment.ok_or(SynthesisError::AssignmentMissing)?;
                let pk = self.recipient_pk.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(vc * pk)
            },
        )?;

        cs.enforce(
            || "intermediate_constraint",
            |lc| lc + value_commitment,
            |lc| lc + recipient_pk,
            |lc| lc + intermediate,
        );

        cs.enforce(
            || "note_commitment_constraint",
            |lc| lc + intermediate + randomness,
            |lc| lc + CS::one(),
            |lc| lc + note_commitment,
        );

        // Constraint: epk = randomness * G (simplified)
        cs.enforce(
            || "epk_constraint",
            |lc| lc + randomness,
            |lc| lc + CS::one(),
            |lc| lc + epk,
        );

        Ok(())
    }
}

/// Spend circuit for unshielding tokens (consuming notes)
/// Public inputs: [anchor, value_commitment, nullifier, rk]
struct MASPSpendCircuit {
    // Private inputs
    value: Option<Scalar>,
    randomness: Option<Scalar>,
    spend_key: Option<Scalar>,
    merkle_path: Vec<Option<Scalar>>,
    // Public inputs
    anchor: Option<Scalar>,
    value_commitment: Option<Scalar>,
    nullifier: Option<Scalar>,
    rk: Option<Scalar>,
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

        // Allocate public inputs
        let anchor = cs.alloc_input(
            || "anchor",
            || self.anchor.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let nullifier = cs.alloc_input(
            || "nullifier",
            || self.nullifier.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let rk = cs.alloc_input(
            || "rk",
            || self.rk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constraint: value_commitment = value * randomness
        cs.enforce(
            || "value_commitment_constraint",
            |lc| lc + value,
            |lc| lc + randomness,
            |lc| lc + value_commitment,
        );

        // Constraint: nullifier = hash(spend_key, note)
        // Simplified: nullifier = spend_key * randomness
        cs.enforce(
            || "nullifier_constraint",
            |lc| lc + spend_key,
            |lc| lc + randomness,
            |lc| lc + nullifier,
        );

        // Constraint: rk = spend_key * G (simplified)
        cs.enforce(
            || "rk_constraint",
            |lc| lc + spend_key,
            |lc| lc + CS::one(),
            |lc| lc + rk,
        );

        // Simplified anchor constraint (in real MASP, this would be Merkle tree verification)
        cs.enforce(
            || "anchor_constraint",
            |lc| lc + anchor,
            |lc| lc + CS::one(),
            |lc| lc + anchor,
        );

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert G1 affine point to EIP-2537 format (128 bytes hex)
fn g1_to_hex(point: &G1Affine) -> String {
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    let x = &bytes[0..48];
    let y = &bytes[48..96];

    let mut result = vec![0u8; 128];
    // Pad x to 64 bytes (16 zeros + 48 bytes)
    result[16..64].copy_from_slice(x);
    // Pad y to 64 bytes (16 zeros + 48 bytes)
    result[80..128].copy_from_slice(y);

    hex::encode(&result)
}

/// Convert G2 affine point to EIP-2537 format (256 bytes hex)
fn g2_to_hex(point: &G2Affine) -> String {
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // bls12_381 format: x.c1 || x.c0 || y.c1 || y.c0
    let x_c1 = &bytes[0..48];
    let x_c0 = &bytes[48..96];
    let y_c1 = &bytes[96..144];
    let y_c0 = &bytes[144..192];

    let mut result = vec![0u8; 256];
    // x: pad(c0) || pad(c1)
    result[16..64].copy_from_slice(x_c0);
    result[80..128].copy_from_slice(x_c1);
    // y: pad(c0) || pad(c1)
    result[144..192].copy_from_slice(y_c0);
    result[208..256].copy_from_slice(y_c1);

    hex::encode(&result)
}

/// Convert scalar to big-endian hex (32 bytes)
fn scalar_to_hex(s: &Scalar) -> String {
    let bytes = s.to_repr();
    let bytes_ref = bytes.as_ref();
    // Reverse from little-endian to big-endian
    let mut be_bytes = [0u8; 32];
    for i in 0..32 {
        be_bytes[i] = bytes_ref[31 - i];
    }
    hex::encode(&be_bytes)
}

/// Parse hex string to scalar
fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;

    if bytes.len() > 32 {
        return Err("Hex value too large for scalar".to_string());
    }

    // Pad to 32 bytes and convert to little-endian
    let mut le_bytes = [0u8; 32];
    let offset = 32 - bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        le_bytes[31 - offset - i] = b;
    }

    Scalar::from_repr(le_bytes.into())
        .into_option()
        .ok_or_else(|| "Invalid scalar value".to_string())
}

/// Encode proof to 512-byte hex string
fn proof_to_hex(proof: &Proof<Bls12>) -> String {
    let a_hex = g1_to_hex(&proof.a);
    let b_hex = g2_to_hex(&proof.b);
    let c_hex = g1_to_hex(&proof.c);
    format!("{}{}{}", a_hex, b_hex, c_hex)
}

// ============================================================================
// Cached Parameters (Generated once, reused)
// ============================================================================

use std::sync::OnceLock;

static OUTPUT_PARAMS: OnceLock<Parameters<Bls12>> = OnceLock::new();
static SPEND_PARAMS: OnceLock<Parameters<Bls12>> = OnceLock::new();

fn get_output_params() -> &'static Parameters<Bls12> {
    OUTPUT_PARAMS.get_or_init(|| {
        web_sys::console::log_1(&"Generating output circuit parameters...".into());
        let circuit = MASPOutputCircuit {
            value: None,
            randomness: None,
            recipient_pk: None,
            value_commitment: None,
            note_commitment: None,
            epk: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut OsRng)
            .expect("Failed to generate output circuit parameters");
        web_sys::console::log_1(&"Output circuit parameters generated successfully".into());
        params
    })
}

fn get_spend_params() -> &'static Parameters<Bls12> {
    SPEND_PARAMS.get_or_init(|| {
        web_sys::console::log_1(&"Generating spend circuit parameters...".into());
        let circuit = MASPSpendCircuit {
            value: None,
            randomness: None,
            spend_key: None,
            merkle_path: vec![],
            anchor: None,
            value_commitment: None,
            nullifier: None,
            rk: None,
        };
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut OsRng)
            .expect("Failed to generate spend circuit parameters");
        web_sys::console::log_1(&"Spend circuit parameters generated successfully".into());
        params
    })
}

// ============================================================================
// WASM Exports
// ============================================================================

/// Initialize the prover (generates parameters)
#[wasm_bindgen]
pub fn init_prover() -> Result<JsValue, JsValue> {
    // Force parameter generation
    let _ = get_output_params();
    let _ = get_spend_params();

    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "success": true,
        "message": "Prover initialized successfully"
    }))?)
}

/// Generate a shield proof (Output circuit)
#[wasm_bindgen]
pub fn generate_shield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let request: ShieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    // Parse inputs
    let amount = hex_to_scalar(&request.amount)
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;
    let recipient_pk = hex_to_scalar(&request.recipient_pk)
        .map_err(|e| JsValue::from_str(&format!("Invalid recipient_pk: {}", e)))?;
    let randomness = hex_to_scalar(&request.randomness)
        .map_err(|e| JsValue::from_str(&format!("Invalid randomness: {}", e)))?;

    // Compute public inputs
    let value_commitment = amount * randomness;
    let intermediate = value_commitment * recipient_pk;
    let note_commitment = intermediate + randomness;
    let epk = randomness;

    // Create circuit
    let circuit = MASPOutputCircuit {
        value: Some(amount),
        randomness: Some(randomness),
        recipient_pk: Some(recipient_pk),
        value_commitment: Some(value_commitment),
        note_commitment: Some(note_commitment),
        epk: Some(epk),
    };

    // Generate proof
    let params = get_output_params();
    let proof = create_random_proof(circuit, params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

    // Verify proof locally
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![value_commitment, note_commitment, epk];

    verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Proof verification failed: {:?}", e)))?;

    // Encode result
    let result = ProofResult {
        proof: proof_to_hex(&proof),
        public_inputs: vec![
            format!("0x{}", scalar_to_hex(&value_commitment)),
            format!("0x{}", scalar_to_hex(&note_commitment)),
            format!("0x{}", scalar_to_hex(&epk)),
        ],
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Generate an unshield proof (Spend circuit)
#[wasm_bindgen]
pub fn generate_unshield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let request: UnshieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    // Parse inputs
    let amount = hex_to_scalar(&request.amount)
        .map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;
    let spend_key = hex_to_scalar(&request.spend_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid spend_key: {}", e)))?;
    let merkle_root = hex_to_scalar(&request.merkle_root)
        .map_err(|e| JsValue::from_str(&format!("Invalid merkle_root: {}", e)))?;

    // Generate randomness for this proof
    let randomness = Scalar::random(&mut OsRng);

    // Compute public inputs
    let value_commitment = amount * randomness;
    let nullifier = spend_key * randomness;
    let rk = spend_key;
    let anchor = merkle_root;

    // Create circuit
    let circuit = MASPSpendCircuit {
        value: Some(amount),
        randomness: Some(randomness),
        spend_key: Some(spend_key),
        merkle_path: vec![],
        anchor: Some(anchor),
        value_commitment: Some(value_commitment),
        nullifier: Some(nullifier),
        rk: Some(rk),
    };

    // Generate proof
    let params = get_spend_params();
    let proof = create_random_proof(circuit, params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

    // Verify proof locally
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![anchor, value_commitment, nullifier, rk];

    verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Proof verification failed: {:?}", e)))?;

    // Encode result
    let result = ProofResult {
        proof: proof_to_hex(&proof),
        public_inputs: vec![
            format!("0x{}", scalar_to_hex(&anchor)),
            format!("0x{}", scalar_to_hex(&value_commitment)),
            format!("0x{}", scalar_to_hex(&nullifier)),
            format!("0x{}", scalar_to_hex(&rk)),
        ],
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Get the verification key for the Output circuit (for contract setup)
#[wasm_bindgen]
pub fn get_output_vk() -> Result<JsValue, JsValue> {
    let params = get_output_params();
    let vk = &params.vk;

    let result = serde_json::json!({
        "alpha": g1_to_hex(&vk.alpha_g1),
        "beta": g2_to_hex(&vk.beta_g2),
        "gamma": g2_to_hex(&vk.gamma_g2),
        "delta": g2_to_hex(&vk.delta_g2),
        "ic": vk.ic.iter().map(|p| g1_to_hex(p)).collect::<Vec<_>>(),
    });

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Get the verification key for the Spend circuit (for contract setup)
#[wasm_bindgen]
pub fn get_spend_vk() -> Result<JsValue, JsValue> {
    let params = get_spend_params();
    let vk = &params.vk;

    let result = serde_json::json!({
        "alpha": g1_to_hex(&vk.alpha_g1),
        "beta": g2_to_hex(&vk.beta_g2),
        "gamma": g2_to_hex(&vk.gamma_g2),
        "delta": g2_to_hex(&vk.delta_g2),
        "ic": vk.ic.iter().map(|p| g1_to_hex(p)).collect::<Vec<_>>(),
    });

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Generate random bytes for use as randomness
#[wasm_bindgen]
pub fn generate_randomness() -> Result<String, JsValue> {
    let scalar = Scalar::random(&mut OsRng);
    Ok(format!("0x{}", scalar_to_hex(&scalar)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_conversion() {
        let original = Scalar::from(12345u64);
        let hex = scalar_to_hex(&original);
        let recovered = hex_to_scalar(&hex).unwrap();
        assert_eq!(original, recovered);
    }
}
