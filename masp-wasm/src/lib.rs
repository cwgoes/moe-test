//! MASP WASM Prover
//!
//! This crate provides WebAssembly bindings for generating real Namada MASP proofs
//! in web browsers using BLS12-381 curve and Groth16 proving system.
//!
//! The implementation uses Namada's masp_proofs crate for actual MASP circuits
//! with parameters from the Namada trusted setup.

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::io::Cursor;
use std::sync::Mutex;

// Use types re-exported from masp_proofs to ensure compatibility
use masp_proofs::bellman::groth16::{
    prepare_verifying_key, Proof, Parameters, PreparedVerifyingKey,
    create_random_proof,
};
use masp_proofs::bls12_381::Bls12;
use masp_proofs::group::Curve;
use masp_proofs::group::ff::Field;
use masp_proofs::jubjub;

// Re-export masp_primitives types
pub use masp_primitives::sapling::{
    Note, PaymentAddress, Nullifier, Diversifier, ProofGenerationKey, Rseed,
    ValueCommitment,
};
pub use masp_primitives::asset_type::AssetType;
pub use masp_primitives::merkle_tree::MerklePath;

// MASP circuit types
use masp_proofs::circuit::sapling::{Output as OutputCircuit, Spend as SpendCircuit};

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

/// Shield request from JS - matches real MASP Output circuit
#[derive(Serialize, Deserialize)]
pub struct ShieldRequest {
    pub token_address: String,
    pub amount: String,
    pub asset_type: String,
    pub recipient_diversifier: String,
    pub recipient_pk_d: String,
    pub rcm: String,
    pub esk: String,
    pub rcv: String,
}

/// Unshield request from JS - matches real MASP Spend circuit
#[derive(Serialize, Deserialize)]
pub struct UnshieldRequest {
    pub amount: String,
    pub asset_type: String,
    pub proof_generation_key_ak: String,
    pub proof_generation_key_nsk: String,
    pub diversifier: String,
    pub rcm: String,
    pub ar: String,
    pub anchor: String,
    pub merkle_path: Vec<MerkleNode>,
    pub rcv: String,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub is_right: bool,
}

/// Output proof result with specific public inputs
#[derive(Serialize, Deserialize)]
pub struct OutputProofResult {
    pub proof: String,
    pub cv_u: String,
    pub cv_v: String,
    pub epk_u: String,
    pub epk_v: String,
    pub cm: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Spend proof result with specific public inputs
#[derive(Serialize, Deserialize)]
pub struct SpendProofResult {
    pub proof: String,
    pub rk_u: String,
    pub rk_v: String,
    pub cv_u: String,
    pub cv_v: String,
    pub anchor: String,
    pub nf_0: String,
    pub nf_1: String,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// Parameter Storage
// ============================================================================

struct MaspParams {
    output_params: Parameters<Bls12>,
    #[allow(dead_code)]
    output_vk: PreparedVerifyingKey<Bls12>,
    spend_params: Parameters<Bls12>,
    #[allow(dead_code)]
    spend_vk: PreparedVerifyingKey<Bls12>,
}

static MASP_PARAMS: Mutex<Option<MaspParams>> = Mutex::new(None);

// ============================================================================
// EIP-2537 Point Encoding
// Using bytes representation compatible with masp_proofs types
// ============================================================================

/// Convert G1 affine point to EIP-2537 format (128 bytes)
fn g1_affine_to_eip2537(point: &masp_proofs::bls12_381::G1Affine) -> Vec<u8> {
    // EIP-2537 expects: 16 zero bytes + 48 byte x + 16 zero bytes + 48 byte y
    let uncompressed = point.to_uncompressed();
    let x = &uncompressed.as_ref()[0..48];
    let y = &uncompressed.as_ref()[48..96];

    let mut result = Vec::with_capacity(128);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(x);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(y);
    result
}

/// Convert G2 affine point to EIP-2537 format (256 bytes)
fn g2_affine_to_eip2537(point: &masp_proofs::bls12_381::G2Affine) -> Vec<u8> {
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // Format: x.c1 (48) || x.c0 (48) || y.c1 (48) || y.c0 (48)
    let x_c1 = &bytes[0..48];
    let x_c0 = &bytes[48..96];
    let y_c1 = &bytes[96..144];
    let y_c0 = &bytes[144..192];

    let mut result = Vec::with_capacity(256);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(x_c1);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(x_c0);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(y_c1);
    result.extend_from_slice(&[0u8; 16]);
    result.extend_from_slice(y_c0);
    result
}

/// Encode proof to EIP-2537 format (512 bytes)
fn proof_to_eip2537(proof: &Proof<Bls12>) -> Vec<u8> {
    let mut result = Vec::with_capacity(512);
    result.extend_from_slice(&g1_affine_to_eip2537(&proof.a));
    result.extend_from_slice(&g2_affine_to_eip2537(&proof.b));
    result.extend_from_slice(&g1_affine_to_eip2537(&proof.c));
    result
}

fn proof_to_hex(proof: &Proof<Bls12>) -> String {
    format!("0x{}", hex::encode(proof_to_eip2537(proof)))
}

fn g1_to_eip2537_hex(point: &masp_proofs::bls12_381::G1Affine) -> String {
    hex::encode(g1_affine_to_eip2537(point))
}

fn g2_to_eip2537_hex(point: &masp_proofs::bls12_381::G2Affine) -> String {
    hex::encode(g2_affine_to_eip2537(point))
}

// ============================================================================
// Scalar Conversion Helpers
// ============================================================================

fn hex_to_bls_scalar(hex: &str) -> Result<masp_proofs::bls12_381::Scalar, String> {
    use masp_proofs::group::ff::PrimeField;

    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = format!("{:0>64}", hex);
    let bytes = hex::decode(&padded).map_err(|e| format!("Invalid hex: {}", e))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr.reverse(); // Convert to little-endian

    Option::from(masp_proofs::bls12_381::Scalar::from_repr(arr))
        .ok_or_else(|| "Invalid BLS scalar".to_string())
}

fn hex_to_jubjub_fr(hex: &str) -> Result<jubjub::Fr, String> {
    use masp_proofs::group::ff::PrimeField;

    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = format!("{:0>64}", hex);
    let bytes = hex::decode(&padded).map_err(|e| format!("Invalid hex: {}", e))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr.reverse();

    Option::from(jubjub::Fr::from_repr(arr))
        .ok_or_else(|| "Invalid jubjub::Fr".to_string())
}

fn bls_scalar_to_hex(s: &masp_proofs::bls12_381::Scalar) -> String {
    use masp_proofs::group::ff::PrimeField;
    let bytes = s.to_repr();
    let mut be_bytes = bytes;
    be_bytes.reverse();
    format!("0x{}", hex::encode(be_bytes))
}

// ============================================================================
// WASM Exports - Parameter Loading
// ============================================================================

/// Load MASP parameters from bytes (downloaded by webapp)
#[wasm_bindgen]
pub fn load_masp_parameters(
    spend_params_bytes: &[u8],
    output_params_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&format!(
        "[MASP] Loading parameters: spend={} bytes, output={} bytes",
        spend_params_bytes.len(),
        output_params_bytes.len()
    ).into());

    let start = js_sys::Date::now();

    // Parse spend parameters
    web_sys::console::log_1(&"[MASP] Parsing spend parameters...".into());
    let spend_params = Parameters::<Bls12>::read(
        &mut Cursor::new(spend_params_bytes),
        false,
    ).map_err(|e| JsValue::from_str(&format!("Failed to parse spend params: {:?}", e)))?;

    let spend_vk = prepare_verifying_key(&spend_params.vk);
    web_sys::console::log_1(&format!(
        "[MASP] Spend VK: {} IC points",
        spend_params.vk.ic.len()
    ).into());

    // Parse output parameters
    web_sys::console::log_1(&"[MASP] Parsing output parameters...".into());
    let output_params = Parameters::<Bls12>::read(
        &mut Cursor::new(output_params_bytes),
        false,
    ).map_err(|e| JsValue::from_str(&format!("Failed to parse output params: {:?}", e)))?;

    let output_vk = prepare_verifying_key(&output_params.vk);
    web_sys::console::log_1(&format!(
        "[MASP] Output VK: {} IC points",
        output_params.vk.ic.len()
    ).into());

    // Store parameters
    let mut params = MASP_PARAMS.lock().map_err(|e| JsValue::from_str(&format!("Lock error: {}", e)))?;
    *params = Some(MaspParams {
        output_params,
        output_vk,
        spend_params,
        spend_vk,
    });

    let elapsed = js_sys::Date::now() - start;
    web_sys::console::log_1(&format!("[MASP] Parameters loaded in {:.2}ms", elapsed).into());

    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "success": true,
        "message": "MASP parameters loaded successfully",
        "elapsed_ms": elapsed
    }))?)
}

/// Check if MASP parameters are loaded
#[wasm_bindgen]
pub fn is_initialized() -> bool {
    MASP_PARAMS.lock().map(|p| p.is_some()).unwrap_or(false)
}

/// Initialize prover (for backwards compatibility)
#[wasm_bindgen]
pub fn init_prover() -> Result<JsValue, JsValue> {
    let is_init = is_initialized();

    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "success": is_init,
        "message": if is_init {
            "Prover ready with loaded parameters"
        } else {
            "Parameters not loaded - call load_masp_parameters first"
        },
        "requires_params": !is_init
    }))?)
}

// ============================================================================
// WASM Exports - Proof Generation (Real MASP)
// ============================================================================

/// Generate an Output proof for shielding tokens
#[wasm_bindgen]
pub fn generate_output_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let start_time = js_sys::Date::now();
    web_sys::console::log_1(&"[MASP] Starting output proof generation...".into());

    // Get parameters
    let params_guard = MASP_PARAMS.lock()
        .map_err(|e| JsValue::from_str(&format!("Lock error: {}", e)))?;
    let params = params_guard.as_ref()
        .ok_or_else(|| JsValue::from_str("MASP parameters not loaded"))?;

    // Parse request
    let request: ShieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    // Parse inputs
    let value: u64 = u64::from_str_radix(
        request.amount.strip_prefix("0x").unwrap_or(&request.amount),
        16
    ).map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    let asset_type = parse_asset_type(&request.asset_type)?;
    let rcm = hex_to_jubjub_fr(&request.rcm)?;
    let esk = hex_to_jubjub_fr(&request.esk)?;
    let rcv = hex_to_jubjub_fr(&request.rcv)?;
    let payment_address = parse_payment_address(&request.recipient_diversifier, &request.recipient_pk_d)?;

    web_sys::console::log_1(&format!(
        "[MASP] Output: value={}, asset_type={:?}",
        value,
        hex::encode(&asset_type.get_identifier())
    ).into());

    // Create value commitment
    let value_commitment = asset_type.value_commitment(value, rcv);
    let cv: jubjub::ExtendedPoint = value_commitment.commitment().into();

    // Compute note commitment
    let note = payment_address
        .create_note(asset_type, value, Rseed::BeforeZip212(rcm))
        .ok_or_else(|| JsValue::from_str("Failed to create note"))?;
    let cm = note.cmu();

    // Compute ephemeral public key
    let g_d = payment_address.g_d()
        .ok_or_else(|| JsValue::from_str("Invalid diversifier"))?;
    let epk: jubjub::ExtendedPoint = (g_d * esk).into();

    web_sys::console::log_1(&"[MASP] Creating Output circuit...".into());

    // Create the circuit
    let circuit = OutputCircuit {
        value_commitment: Some(value_commitment),
        payment_address: Some(payment_address),
        commitment_randomness: Some(rcm),
        esk: Some(esk),
        asset_identifier: asset_type.identifier_bits(),
    };

    // Generate proof
    web_sys::console::log_1(&"[MASP] Generating Groth16 proof...".into());
    let proof_start = js_sys::Date::now();

    let proof = create_random_proof(circuit, &params.output_params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {:?}", e)))?;

    let proof_time = js_sys::Date::now() - proof_start;
    web_sys::console::log_1(&format!("[MASP] Proof created in {:.2}ms", proof_time).into());

    // Get affine coordinates for public inputs
    let cv_affine = cv.to_affine();
    let epk_affine = epk.to_affine();

    // Note: We skip local verification to save time - proof is verified on-chain
    let total_time = js_sys::Date::now() - start_time;
    web_sys::console::log_1(&format!("[MASP] Output proof completed in {:.2}ms", total_time).into());

    let result = OutputProofResult {
        proof: proof_to_hex(&proof),
        cv_u: bls_scalar_to_hex(&cv_affine.get_u()),
        cv_v: bls_scalar_to_hex(&cv_affine.get_v()),
        epk_u: bls_scalar_to_hex(&epk_affine.get_u()),
        epk_v: bls_scalar_to_hex(&epk_affine.get_v()),
        cm: bls_scalar_to_hex(&cm),
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Generate a Spend proof for unshielding tokens
#[wasm_bindgen]
pub fn generate_spend_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    let start_time = js_sys::Date::now();
    web_sys::console::log_1(&"[MASP] Starting spend proof generation...".into());

    // Get parameters
    let params_guard = MASP_PARAMS.lock()
        .map_err(|e| JsValue::from_str(&format!("Lock error: {}", e)))?;
    let params = params_guard.as_ref()
        .ok_or_else(|| JsValue::from_str("MASP parameters not loaded"))?;

    // Parse request
    let request: UnshieldRequest = serde_wasm_bindgen::from_value(request_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {}", e)))?;

    // Parse inputs
    let value: u64 = u64::from_str_radix(
        request.amount.strip_prefix("0x").unwrap_or(&request.amount),
        16
    ).map_err(|e| JsValue::from_str(&format!("Invalid amount: {}", e)))?;

    let asset_type = parse_asset_type(&request.asset_type)?;
    let rcm = hex_to_jubjub_fr(&request.rcm)?;
    let ar = hex_to_jubjub_fr(&request.ar)?;
    let rcv = hex_to_jubjub_fr(&request.rcv)?;
    let anchor = hex_to_bls_scalar(&request.anchor)?;
    let proof_generation_key = parse_proof_generation_key(
        &request.proof_generation_key_ak,
        &request.proof_generation_key_nsk,
    )?;

    let diversifier = parse_diversifier(&request.diversifier)?;
    let merkle_path = parse_merkle_path(&request.merkle_path)?;

    web_sys::console::log_1(&format!(
        "[MASP] Spend: value={}, merkle_depth={}",
        value, merkle_path.auth_path.len()
    ).into());

    // Create value commitment
    let value_commitment = asset_type.value_commitment(value, rcv);
    let cv: jubjub::ExtendedPoint = value_commitment.commitment().into();

    // Compute viewing key and payment address
    let viewing_key = proof_generation_key.to_viewing_key();
    let payment_address = viewing_key.to_payment_address(diversifier)
        .ok_or_else(|| JsValue::from_str("Invalid diversifier for viewing key"))?;

    // Compute rk (re-randomized key)
    let spending_key_generator = masp_primitives::constants::spending_key_generator();
    let rk = masp_primitives::sapling::redjubjub::PublicKey(proof_generation_key.ak.into())
        .randomize(ar, spending_key_generator);

    // Create note and compute nullifier
    let g_d = diversifier.g_d()
        .ok_or_else(|| JsValue::from_str("Invalid diversifier"))?;
    let note = Note {
        asset_type,
        value,
        g_d,
        pk_d: *payment_address.pk_d(),
        rseed: Rseed::BeforeZip212(rcm),
    };
    let nullifier = note.nf(&viewing_key.nk, merkle_path.position);

    web_sys::console::log_1(&"[MASP] Creating Spend circuit...".into());

    // Create the circuit
    let circuit = SpendCircuit {
        value_commitment: Some(value_commitment),
        proof_generation_key: Some(proof_generation_key),
        payment_address: Some(payment_address),
        commitment_randomness: Some(rcm),
        ar: Some(ar),
        auth_path: merkle_path.auth_path.iter()
            .map(|(node, b)| Some(((*node).into(), *b)))
            .collect(),
        anchor: Some(anchor),
    };

    // Generate proof
    web_sys::console::log_1(&"[MASP] Generating Groth16 proof...".into());
    let proof_start = js_sys::Date::now();

    let proof = create_random_proof(circuit, &params.spend_params, &mut OsRng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {:?}", e)))?;

    let proof_time = js_sys::Date::now() - proof_start;
    web_sys::console::log_1(&format!("[MASP] Proof created in {:.2}ms", proof_time).into());

    // Get affine coordinates for public inputs
    let rk_affine = rk.0.to_affine();
    let cv_affine = cv.to_affine();

    // Pack nullifier into two field elements
    let nf_bits = masp_proofs::bellman::gadgets::multipack::bytes_to_bits_le(&nullifier.0);
    let nf_packed = masp_proofs::bellman::gadgets::multipack::compute_multipacking(&nf_bits);

    // Note: We skip local verification to save time - proof is verified on-chain
    let total_time = js_sys::Date::now() - start_time;
    web_sys::console::log_1(&format!("[MASP] Spend proof completed in {:.2}ms", total_time).into());

    let result = SpendProofResult {
        proof: proof_to_hex(&proof),
        rk_u: bls_scalar_to_hex(&rk_affine.get_u()),
        rk_v: bls_scalar_to_hex(&rk_affine.get_v()),
        cv_u: bls_scalar_to_hex(&cv_affine.get_u()),
        cv_v: bls_scalar_to_hex(&cv_affine.get_v()),
        anchor: bls_scalar_to_hex(&anchor),
        nf_0: bls_scalar_to_hex(&nf_packed[0]),
        nf_1: bls_scalar_to_hex(&nf_packed[1]),
        success: true,
        error: None,
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

// ============================================================================
// Parsing Helpers
// ============================================================================

fn parse_asset_type(hex: &str) -> Result<AssetType, JsValue> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid asset_type hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "asset_type must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);

    AssetType::from_identifier(&arr)
        .ok_or_else(|| JsValue::from_str("Invalid asset type identifier"))
}

fn parse_diversifier(hex: &str) -> Result<Diversifier, JsValue> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid diversifier hex: {}", e)))?;

    if bytes.len() != 11 {
        return Err(JsValue::from_str(&format!(
            "diversifier must be 11 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 11];
    arr.copy_from_slice(&bytes);

    Ok(Diversifier(arr))
}

fn parse_payment_address(diversifier_hex: &str, pk_d_hex: &str) -> Result<PaymentAddress, JsValue> {
    use masp_proofs::group::GroupEncoding;

    let diversifier = parse_diversifier(diversifier_hex)?;

    let pk_d_hex = pk_d_hex.strip_prefix("0x").unwrap_or(pk_d_hex);
    let pk_d_bytes = hex::decode(pk_d_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid pk_d hex: {}", e)))?;

    if pk_d_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "pk_d must be 32 bytes, got {}",
            pk_d_bytes.len()
        )));
    }

    let mut pk_d_arr = [0u8; 32];
    pk_d_arr.copy_from_slice(&pk_d_bytes);

    let pk_d = jubjub::SubgroupPoint::from_bytes(&pk_d_arr);
    if pk_d.is_none().into() {
        return Err(JsValue::from_str("Invalid pk_d point"));
    }

    PaymentAddress::from_parts(diversifier, pk_d.unwrap())
        .ok_or_else(|| JsValue::from_str("Invalid payment address"))
}

fn parse_proof_generation_key(ak_hex: &str, nsk_hex: &str) -> Result<ProofGenerationKey, JsValue> {
    use masp_proofs::group::GroupEncoding;

    let ak_hex = ak_hex.strip_prefix("0x").unwrap_or(ak_hex);
    let ak_bytes = hex::decode(ak_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid ak hex: {}", e)))?;

    if ak_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "ak must be 32 bytes, got {}",
            ak_bytes.len()
        )));
    }

    let mut ak_arr = [0u8; 32];
    ak_arr.copy_from_slice(&ak_bytes);

    let ak = jubjub::SubgroupPoint::from_bytes(&ak_arr);
    if ak.is_none().into() {
        return Err(JsValue::from_str("Invalid ak point"));
    }

    let nsk = hex_to_jubjub_fr(nsk_hex)?;

    Ok(ProofGenerationKey {
        ak: ak.unwrap(),
        nsk,
    })
}

fn parse_merkle_path(nodes: &[MerkleNode]) -> Result<MerklePath<masp_primitives::sapling::Node>, JsValue> {
    use masp_primitives::sapling::Node;

    let mut auth_path = Vec::with_capacity(nodes.len());
    let mut position: u64 = 0;

    for (i, node) in nodes.iter().enumerate() {
        let hash = hex_to_bls_scalar(&node.hash)?;
        let node_val = Node::from_scalar(hash);
        auth_path.push((node_val, node.is_right));

        if node.is_right {
            position |= 1u64 << i;
        }
    }

    Ok(MerklePath {
        auth_path,
        position,
    })
}

// ============================================================================
// Verification Key Export
// ============================================================================

#[derive(Serialize, Deserialize)]
pub struct VerificationKeyData {
    pub alpha: String,
    pub beta: String,
    pub gamma: String,
    pub delta: String,
    pub ic: Vec<String>,
}

/// Get the Output circuit verification key in EIP-2537 format
#[wasm_bindgen]
pub fn get_output_verification_key() -> Result<JsValue, JsValue> {
    let params_guard = MASP_PARAMS.lock()
        .map_err(|e| JsValue::from_str(&format!("Lock error: {}", e)))?;
    let params = params_guard.as_ref()
        .ok_or_else(|| JsValue::from_str("MASP parameters not loaded"))?;

    let vk = &params.output_params.vk;

    let vk_data = VerificationKeyData {
        alpha: format!("0x{}", g1_to_eip2537_hex(&vk.alpha_g1)),
        beta: format!("0x{}", g2_to_eip2537_hex(&vk.beta_g2)),
        gamma: format!("0x{}", g2_to_eip2537_hex(&vk.gamma_g2)),
        delta: format!("0x{}", g2_to_eip2537_hex(&vk.delta_g2)),
        ic: vk.ic.iter().map(|p| format!("0x{}", g1_to_eip2537_hex(p))).collect(),
    };

    web_sys::console::log_1(&format!(
        "[MASP] Output VK: {} IC points (for {} public inputs)",
        vk_data.ic.len(),
        vk_data.ic.len() - 1
    ).into());

    Ok(serde_wasm_bindgen::to_value(&vk_data)?)
}

/// Get the Spend circuit verification key in EIP-2537 format
#[wasm_bindgen]
pub fn get_spend_verification_key() -> Result<JsValue, JsValue> {
    let params_guard = MASP_PARAMS.lock()
        .map_err(|e| JsValue::from_str(&format!("Lock error: {}", e)))?;
    let params = params_guard.as_ref()
        .ok_or_else(|| JsValue::from_str("MASP parameters not loaded"))?;

    let vk = &params.spend_params.vk;

    let vk_data = VerificationKeyData {
        alpha: format!("0x{}", g1_to_eip2537_hex(&vk.alpha_g1)),
        beta: format!("0x{}", g2_to_eip2537_hex(&vk.beta_g2)),
        gamma: format!("0x{}", g2_to_eip2537_hex(&vk.gamma_g2)),
        delta: format!("0x{}", g2_to_eip2537_hex(&vk.delta_g2)),
        ic: vk.ic.iter().map(|p| format!("0x{}", g1_to_eip2537_hex(p))).collect(),
    };

    web_sys::console::log_1(&format!(
        "[MASP] Spend VK: {} IC points (for {} public inputs)",
        vk_data.ic.len(),
        vk_data.ic.len() - 1
    ).into());

    Ok(serde_wasm_bindgen::to_value(&vk_data)?)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Generate random scalars for use in proof generation
#[wasm_bindgen]
pub fn generate_randomness() -> String {
    use masp_proofs::group::ff::PrimeField;
    let r = jubjub::Fr::random(&mut OsRng);
    let bytes = r.to_repr();
    let mut be_bytes = bytes;
    be_bytes.reverse();
    format!("0x{}", hex::encode(be_bytes))
}

/// Generate a random valid diversifier
/// This tries random diversifiers until finding one that maps to a valid curve point
#[wasm_bindgen]
pub fn generate_diversifier() -> String {
    loop {
        let mut bytes = [0u8; 11];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        let diversifier = Diversifier(bytes);
        // Check if this diversifier maps to a valid curve point
        if diversifier.g_d().is_some() {
            return format!("0x{}", hex::encode(bytes));
        }
    }
}

/// Random payment address data for testing
#[derive(Serialize, Deserialize)]
pub struct RandomPaymentAddress {
    pub diversifier: String,
    pub pk_d: String,
}

/// Generate a random valid payment address (for testing)
/// Returns diversifier and pk_d that can be used together for shielding
#[wasm_bindgen]
pub fn generate_random_payment_address() -> Result<JsValue, JsValue> {
    use masp_proofs::group::GroupEncoding;

    // Generate a random incoming viewing key (ivk)
    let ivk = jubjub::Fr::random(&mut OsRng);

    // Generate a valid diversifier
    let diversifier = loop {
        let mut bytes = [0u8; 11];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        let d = Diversifier(bytes);
        if d.g_d().is_some() {
            break d;
        }
    };

    // Compute pk_d = ivk * g_d(diversifier)
    let g_d = diversifier.g_d()
        .ok_or_else(|| JsValue::from_str("Invalid diversifier"))?;
    let pk_d: jubjub::SubgroupPoint = (g_d * ivk).into();

    // Verify we can create a valid payment address
    PaymentAddress::from_parts(diversifier, pk_d)
        .ok_or_else(|| JsValue::from_str("Failed to create payment address"))?;

    let result = RandomPaymentAddress {
        diversifier: format!("0x{}", hex::encode(diversifier.0)),
        pk_d: format!("0x{}", hex::encode(pk_d.to_bytes())),
    };

    web_sys::console::log_1(&format!(
        "[MASP] Generated payment address: div={}, pk_d={}",
        result.diversifier, result.pk_d
    ).into());

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Get the default asset type identifier for the native token
#[wasm_bindgen]
pub fn get_native_asset_type() -> String {
    let asset = AssetType::new(b"native").expect("native asset type");
    format!("0x{}", hex::encode(asset.get_identifier()))
}

/// Derive asset type from token address
#[wasm_bindgen]
pub fn derive_asset_type(token_address: &str) -> Result<String, JsValue> {
    let addr = token_address.strip_prefix("0x").unwrap_or(token_address);
    let bytes = hex::decode(addr)
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?;

    let asset = AssetType::new(&bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive asset type: {:?}", e)))?;

    Ok(format!("0x{}", hex::encode(asset.get_identifier())))
}

/// Get MASP implementation info
#[wasm_bindgen]
pub fn get_masp_info() -> Result<JsValue, JsValue> {
    let is_init = is_initialized();

    let params_info = if is_init {
        let params_guard = MASP_PARAMS.lock().ok();
        params_guard.as_ref().and_then(|p| p.as_ref()).map(|params| {
            serde_json::json!({
                "output_ic_count": params.output_params.vk.ic.len(),
                "spend_ic_count": params.spend_params.vk.ic.len(),
            })
        })
    } else {
        None
    };

    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "version": "1.0.0",
        "implementation": "Namada MASP (masp_proofs)",
        "curve": "BLS12-381",
        "proving_system": "Groth16",
        "circuits": {
            "output": {
                "public_inputs": 5,
                "description": "cv.u, cv.v, epk.u, epk.v, cm"
            },
            "spend": {
                "public_inputs": 7,
                "description": "rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]"
            }
        },
        "initialized": is_init,
        "params": params_info,
        "parameter_urls": {
            "spend": "https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params",
            "output": "https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params"
        },
        "parameter_sizes": {
            "spend": "49.8 MB",
            "output": "16.4 MB"
        }
    }))?)
}

// ============================================================================
// Backwards Compatibility
// ============================================================================

#[wasm_bindgen]
pub fn generate_shield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    generate_output_proof(request_js)
}

#[wasm_bindgen]
pub fn generate_unshield_proof(request_js: JsValue) -> Result<JsValue, JsValue> {
    generate_spend_proof(request_js)
}
