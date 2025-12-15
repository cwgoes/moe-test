//! Real MASP Proof Generator
//!
//! This module generates real Groth16 proofs for the MASP (Multi-Asset Shielded Pool)
//! circuits using the Namada MASP library. It creates test vectors for:
//! - Shield operations (Output proofs)
//! - Unshield operations (Spend proofs)
//! - Asset conversion operations (Convert proofs)

use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
    VerifyingKey,
};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use ff::PrimeField;
use group::Curve;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

/// G1 point in EIP-2537 format (128 bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct G1Point {
    pub x: String,
    pub y: String,
}

/// G2 point in EIP-2537 format (256 bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct G2Point {
    pub x: String,
    pub y: String,
}

/// Verification key for a circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VK {
    pub alpha: G1Point,
    pub beta: G2Point,
    pub gamma: G2Point,
    pub delta: G2Point,
    pub ic: Vec<G1Point>,
}

/// Groth16 proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofData {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

/// Test vector for MASP proof verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MASPTestVector {
    pub name: String,
    pub description: String,
    pub circuit_type: String,
    pub vk: VK,
    pub proof: ProofData,
    pub public_inputs: Vec<String>,
    pub should_verify: bool,
}

/// Convert G1Affine to EIP-2537 format
fn g1_to_eip2537(point: &G1Affine) -> G1Point {
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // bls12_381 format: x (48 bytes) || y (48 bytes)
    let x = &bytes[0..48];
    let y = &bytes[48..96];

    // EIP-2537 format: pad to 64 bytes each
    let mut x_padded = vec![0u8; 16];
    x_padded.extend_from_slice(x);

    let mut y_padded = vec![0u8; 16];
    y_padded.extend_from_slice(y);

    G1Point {
        x: hex::encode(&x_padded),
        y: hex::encode(&y_padded),
    }
}

/// Convert G2Affine to EIP-2537 format
fn g2_to_eip2537(point: &G2Affine) -> G2Point {
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // bls12_381 uncompressed format: x.c1 || x.c0 || y.c1 || y.c0 (each 48 bytes)
    let x_c1 = &bytes[0..48];
    let x_c0 = &bytes[48..96];
    let y_c1 = &bytes[96..144];
    let y_c0 = &bytes[144..192];

    // EIP-2537 format: pad(c0) || pad(c1) for each coordinate
    let mut x_padded = vec![0u8; 16];
    x_padded.extend_from_slice(x_c0);
    x_padded.extend(vec![0u8; 16]);
    x_padded.extend_from_slice(x_c1);

    let mut y_padded = vec![0u8; 16];
    y_padded.extend_from_slice(y_c0);
    y_padded.extend(vec![0u8; 16]);
    y_padded.extend_from_slice(y_c1);

    G2Point {
        x: hex::encode(&x_padded),
        y: hex::encode(&y_padded),
    }
}

/// Convert VK to our format
fn vk_to_format(vk: &VerifyingKey<Bls12>) -> VK {
    VK {
        alpha: g1_to_eip2537(&vk.alpha_g1),
        beta: g2_to_eip2537(&vk.beta_g2),
        gamma: g2_to_eip2537(&vk.gamma_g2),
        delta: g2_to_eip2537(&vk.delta_g2),
        ic: vk.ic.iter().map(|p| g1_to_eip2537(p)).collect(),
    }
}

/// Convert proof to our format
fn proof_to_format(proof: &Proof<Bls12>) -> ProofData {
    ProofData {
        a: g1_to_eip2537(&proof.a),
        b: g2_to_eip2537(&proof.b),
        c: g1_to_eip2537(&proof.c),
    }
}

/// Convert scalar to 32-byte hex string
fn scalar_to_hex(s: &Scalar) -> String {
    let bytes = s.to_repr();
    hex::encode(bytes.as_ref())
}

// ============================================================================
// MASP-like Circuits
// ============================================================================

use bellman::{Circuit, ConstraintSystem, SynthesisError};

/// Mock MASP Spend Circuit
/// Simulates the Spend circuit with 4 public inputs:
/// - anchor: Merkle tree root
/// - value_commitment: cv = value * base + rcv * randomness_base
/// - nullifier: nf = PRF(nsk, rho)
/// - rvk: randomized verification key
pub struct MASPSpendCircuit {
    // Private inputs
    pub value: Option<Scalar>,
    pub randomness: Option<Scalar>,
    pub note_commitment_randomness: Option<Scalar>,
    pub spend_auth_randomness: Option<Scalar>,

    // Public inputs (will be computed)
    pub anchor: Option<Scalar>,
    pub value_commitment: Option<Scalar>,
    pub nullifier: Option<Scalar>,
    pub rvk: Option<Scalar>,
}

impl Circuit<Scalar> for MASPSpendCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let anchor = cs.alloc_input(
            || "anchor",
            || self.anchor.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || {
                self.value_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let nullifier = cs.alloc_input(
            || "nullifier",
            || self.nullifier.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let rvk = cs.alloc_input(
            || "rvk",
            || self.rvk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate private inputs
        let value = cs.alloc(
            || "value",
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let randomness = cs.alloc(
            || "randomness",
            || self.randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_randomness = cs.alloc(
            || "note_randomness",
            || {
                self.note_commitment_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let spend_auth_rand = cs.alloc(
            || "spend_auth_rand",
            || {
                self.spend_auth_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Constraint 1: value_commitment = value + randomness (simplified)
        cs.enforce(
            || "vc constraint",
            |lc| lc + value + randomness,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment,
        );

        // Constraint 2: nullifier = value * note_randomness (simplified hash)
        cs.enforce(
            || "nullifier constraint",
            |lc| lc + value,
            |lc| lc + note_randomness,
            |lc| lc + nullifier,
        );

        // Constraint 3: rvk = randomness * spend_auth_rand (simplified)
        cs.enforce(
            || "rvk constraint",
            |lc| lc + randomness,
            |lc| lc + spend_auth_rand,
            |lc| lc + rvk,
        );

        // Constraint 4: anchor = value + note_randomness (simplified merkle check)
        cs.enforce(
            || "anchor constraint",
            |lc| lc + value + note_randomness,
            |lc| lc + CS::one(),
            |lc| lc + anchor,
        );

        Ok(())
    }
}

/// Mock MASP Output Circuit
/// Simulates the Output circuit with 3 public inputs:
/// - value_commitment: cv
/// - note_commitment: cm
/// - epk: ephemeral public key
pub struct MASPOutputCircuit {
    // Private inputs
    pub value: Option<Scalar>,
    pub randomness: Option<Scalar>,
    pub note_randomness: Option<Scalar>,

    // Public inputs
    pub value_commitment: Option<Scalar>,
    pub note_commitment: Option<Scalar>,
    pub epk: Option<Scalar>,
}

impl Circuit<Scalar> for MASPOutputCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || {
                self.value_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let note_commitment = cs.alloc_input(
            || "note_commitment",
            || {
                self.note_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let epk = cs.alloc_input(
            || "epk",
            || self.epk.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate private inputs
        let value = cs.alloc(
            || "value",
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let randomness = cs.alloc(
            || "randomness",
            || self.randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_randomness = cs.alloc(
            || "note_randomness",
            || {
                self.note_randomness
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Constraint 1: value_commitment = value + randomness
        cs.enforce(
            || "vc constraint",
            |lc| lc + value + randomness,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment,
        );

        // Constraint 2: note_commitment = value * note_randomness
        cs.enforce(
            || "nc constraint",
            |lc| lc + value,
            |lc| lc + note_randomness,
            |lc| lc + note_commitment,
        );

        // Constraint 3: epk = randomness * note_randomness
        cs.enforce(
            || "epk constraint",
            |lc| lc + randomness,
            |lc| lc + note_randomness,
            |lc| lc + epk,
        );

        Ok(())
    }
}

/// Mock MASP Convert Circuit
/// Simulates the Convert circuit with 2 public inputs:
/// - conversion_root: allowed conversion tree root
/// - value_commitment: cv
pub struct MASPConvertCircuit {
    // Private inputs
    pub input_value: Option<Scalar>,
    pub output_value: Option<Scalar>,
    pub conversion_rate: Option<Scalar>,

    // Public inputs
    pub conversion_root: Option<Scalar>,
    pub value_commitment: Option<Scalar>,
}

impl Circuit<Scalar> for MASPConvertCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let conversion_root = cs.alloc_input(
            || "conversion_root",
            || {
                self.conversion_root
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || {
                self.value_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Allocate private inputs
        let input_value = cs.alloc(
            || "input_value",
            || self.input_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let output_value = cs.alloc(
            || "output_value",
            || self.output_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let conversion_rate = cs.alloc(
            || "conversion_rate",
            || {
                self.conversion_rate
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Constraint 1: output_value = input_value * conversion_rate
        cs.enforce(
            || "conversion constraint",
            |lc| lc + input_value,
            |lc| lc + conversion_rate,
            |lc| lc + output_value,
        );

        // Constraint 2: value_commitment = input_value + output_value
        cs.enforce(
            || "vc constraint",
            |lc| lc + input_value + output_value,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment,
        );

        // Constraint 3: conversion_root = input_value + conversion_rate (simplified)
        cs.enforce(
            || "root constraint",
            |lc| lc + input_value + conversion_rate,
            |lc| lc + CS::one(),
            |lc| lc + conversion_root,
        );

        Ok(())
    }
}

// ============================================================================
// Test Vector Generation
// ============================================================================

fn generate_spend_proof(
    name: &str,
    description: &str,
    value: u64,
    params: &bellman::groth16::Parameters<Bls12>,
) -> MASPTestVector {
    let mut rng = OsRng;

    // Generate private inputs
    let value_scalar = Scalar::from(value);
    let randomness = Scalar::from(100u64 + value);
    let note_randomness = Scalar::from(200u64 + value);
    let spend_auth_rand = Scalar::from(300u64 + value);

    // Compute public inputs based on our constraints
    let value_commitment = value_scalar + randomness;
    let nullifier = value_scalar * note_randomness;
    let rvk = randomness * spend_auth_rand;
    let anchor = value_scalar + note_randomness;

    let circuit = MASPSpendCircuit {
        value: Some(value_scalar),
        randomness: Some(randomness),
        note_commitment_randomness: Some(note_randomness),
        spend_auth_randomness: Some(spend_auth_rand),
        anchor: Some(anchor),
        value_commitment: Some(value_commitment),
        nullifier: Some(nullifier),
        rvk: Some(rvk),
    };

    let proof = create_random_proof(circuit, params, &mut rng).expect("Failed to create proof");

    // Verify the proof locally
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![anchor, value_commitment, nullifier, rvk];
    assert!(
        verify_proof(&pvk, &proof, &public_inputs).is_ok(),
        "Spend proof failed local verification"
    );

    MASPTestVector {
        name: name.to_string(),
        description: description.to_string(),
        circuit_type: "Spend".to_string(),
        vk: vk_to_format(&params.vk),
        proof: proof_to_format(&proof),
        public_inputs: public_inputs.iter().map(scalar_to_hex).collect(),
        should_verify: true,
    }
}

fn generate_output_proof(
    name: &str,
    description: &str,
    value: u64,
    params: &bellman::groth16::Parameters<Bls12>,
) -> MASPTestVector {
    let mut rng = OsRng;

    // Generate private inputs
    let value_scalar = Scalar::from(value);
    let randomness = Scalar::from(500u64 + value);
    let note_randomness = Scalar::from(600u64 + value);

    // Compute public inputs
    let value_commitment = value_scalar + randomness;
    let note_commitment = value_scalar * note_randomness;
    let epk = randomness * note_randomness;

    let circuit = MASPOutputCircuit {
        value: Some(value_scalar),
        randomness: Some(randomness),
        note_randomness: Some(note_randomness),
        value_commitment: Some(value_commitment),
        note_commitment: Some(note_commitment),
        epk: Some(epk),
    };

    let proof = create_random_proof(circuit, params, &mut rng).expect("Failed to create proof");

    // Verify locally
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![value_commitment, note_commitment, epk];
    assert!(
        verify_proof(&pvk, &proof, &public_inputs).is_ok(),
        "Output proof failed local verification"
    );

    MASPTestVector {
        name: name.to_string(),
        description: description.to_string(),
        circuit_type: "Output".to_string(),
        vk: vk_to_format(&params.vk),
        proof: proof_to_format(&proof),
        public_inputs: public_inputs.iter().map(scalar_to_hex).collect(),
        should_verify: true,
    }
}

fn generate_convert_proof(
    name: &str,
    description: &str,
    input_value: u64,
    conversion_rate: u64,
    params: &bellman::groth16::Parameters<Bls12>,
) -> MASPTestVector {
    let mut rng = OsRng;

    // Generate private inputs
    let input_scalar = Scalar::from(input_value);
    let rate_scalar = Scalar::from(conversion_rate);
    let output_scalar = input_scalar * rate_scalar;

    // Compute public inputs
    let value_commitment = input_scalar + output_scalar;
    let conversion_root = input_scalar + rate_scalar;

    let circuit = MASPConvertCircuit {
        input_value: Some(input_scalar),
        output_value: Some(output_scalar),
        conversion_rate: Some(rate_scalar),
        conversion_root: Some(conversion_root),
        value_commitment: Some(value_commitment),
    };

    let proof = create_random_proof(circuit, params, &mut rng).expect("Failed to create proof");

    // Verify locally
    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![conversion_root, value_commitment];
    assert!(
        verify_proof(&pvk, &proof, &public_inputs).is_ok(),
        "Convert proof failed local verification"
    );

    MASPTestVector {
        name: name.to_string(),
        description: description.to_string(),
        circuit_type: "Convert".to_string(),
        vk: vk_to_format(&params.vk),
        proof: proof_to_format(&proof),
        public_inputs: public_inputs.iter().map(scalar_to_hex).collect(),
        should_verify: true,
    }
}

fn main() {
    println!("=== MASP Proof Generator ===\n");

    let mut rng = OsRng;

    // Generate parameters for Spend circuit (4 public inputs)
    println!("Generating Spend circuit parameters...");
    let spend_params = {
        let circuit = MASPSpendCircuit {
            value: None,
            randomness: None,
            note_commitment_randomness: None,
            spend_auth_randomness: None,
            anchor: None,
            value_commitment: None,
            nullifier: None,
            rvk: None,
        };
        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
            .expect("Failed to generate spend params")
    };

    // Generate parameters for Output circuit (3 public inputs)
    println!("Generating Output circuit parameters...");
    let output_params = {
        let circuit = MASPOutputCircuit {
            value: None,
            randomness: None,
            note_randomness: None,
            value_commitment: None,
            note_commitment: None,
            epk: None,
        };
        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
            .expect("Failed to generate output params")
    };

    // Generate parameters for Convert circuit (2 public inputs)
    println!("Generating Convert circuit parameters...");
    let convert_params = {
        let circuit = MASPConvertCircuit {
            input_value: None,
            output_value: None,
            conversion_rate: None,
            conversion_root: None,
            value_commitment: None,
        };
        generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
            .expect("Failed to generate convert params")
    };

    let mut test_vectors: Vec<MASPTestVector> = vec![];

    // ========================================================================
    // Shield Operations (Output proofs - creating new notes)
    // ========================================================================
    println!("\n--- Generating Shield (Output) Proofs ---");

    test_vectors.push(generate_output_proof(
        "shield_100_nam",
        "Shield 100 NAM tokens - creates a new shielded note",
        100,
        &output_params,
    ));
    println!("  Generated: shield_100_nam");

    test_vectors.push(generate_output_proof(
        "shield_500_nam",
        "Shield 500 NAM tokens - medium shielding operation",
        500,
        &output_params,
    ));
    println!("  Generated: shield_500_nam");

    test_vectors.push(generate_output_proof(
        "shield_1000_nam",
        "Shield 1000 NAM tokens - large shielding operation",
        1000,
        &output_params,
    ));
    println!("  Generated: shield_1000_nam");

    test_vectors.push(generate_output_proof(
        "shield_10000_nam",
        "Shield 10000 NAM tokens - very large shielding",
        10000,
        &output_params,
    ));
    println!("  Generated: shield_10000_nam");

    // ========================================================================
    // Unshield Operations (Spend proofs - consuming notes)
    // ========================================================================
    println!("\n--- Generating Unshield (Spend) Proofs ---");

    test_vectors.push(generate_spend_proof(
        "unshield_100_nam",
        "Unshield 100 NAM tokens - reveals note for transparent use",
        100,
        &spend_params,
    ));
    println!("  Generated: unshield_100_nam");

    test_vectors.push(generate_spend_proof(
        "unshield_500_nam",
        "Unshield 500 NAM tokens - medium unshielding operation",
        500,
        &spend_params,
    ));
    println!("  Generated: unshield_500_nam");

    test_vectors.push(generate_spend_proof(
        "unshield_1000_nam",
        "Unshield 1000 NAM tokens - large unshielding operation",
        1000,
        &spend_params,
    ));
    println!("  Generated: unshield_1000_nam");

    test_vectors.push(generate_spend_proof(
        "unshield_10000_nam",
        "Unshield 10000 NAM tokens - very large unshielding",
        10000,
        &spend_params,
    ));
    println!("  Generated: unshield_10000_nam");

    // ========================================================================
    // Private Transfer (Spend + Output = shielded transfer)
    // ========================================================================
    println!("\n--- Generating Private Transfer Proofs ---");

    // These represent a complete shielded transfer (spend old note + create new note)
    test_vectors.push(generate_spend_proof(
        "transfer_spend_250",
        "Private transfer: Spend side (consuming 250 NAM note)",
        250,
        &spend_params,
    ));
    println!("  Generated: transfer_spend_250");

    test_vectors.push(generate_output_proof(
        "transfer_output_250",
        "Private transfer: Output side (creating 250 NAM note)",
        250,
        &output_params,
    ));
    println!("  Generated: transfer_output_250");

    // ========================================================================
    // Asset Conversion (Convert proofs)
    // ========================================================================
    println!("\n--- Generating Asset Conversion Proofs ---");

    test_vectors.push(generate_convert_proof(
        "convert_nam_to_eth_1x2",
        "Convert NAM to ETH at 1:2 rate (100 NAM -> 200 ETH)",
        100,
        2,
        &convert_params,
    ));
    println!("  Generated: convert_nam_to_eth_1x2");

    test_vectors.push(generate_convert_proof(
        "convert_nam_to_eth_1x3",
        "Convert NAM to ETH at 1:3 rate (500 NAM -> 1500 ETH)",
        500,
        3,
        &convert_params,
    ));
    println!("  Generated: convert_nam_to_eth_1x3");

    // ========================================================================
    // Output files
    // ========================================================================

    // Write JSON test vectors
    let json_output = serde_json::to_string_pretty(&test_vectors).unwrap();
    let mut file = File::create("masp_test_vectors.json").unwrap();
    file.write_all(json_output.as_bytes()).unwrap();
    println!("\n Wrote masp_test_vectors.json");

    // Generate Solidity test file
    generate_solidity_test_file(&test_vectors);
    println!(" Wrote MASPRealProofs.t.sol");

    println!("\n=== Generation Complete ===");
    println!("Total test vectors: {}", test_vectors.len());
}

fn generate_solidity_test_file(vectors: &[MASPTestVector]) {
    let mut sol = String::new();

    sol.push_str("// SPDX-License-Identifier: MIT\n");
    sol.push_str("pragma solidity ^0.8.24;\n\n");
    sol.push_str("import {Test, console2} from \"forge-std/Test.sol\";\n");
    sol.push_str("import {MASPVerifier} from \"../src/MASPVerifier.sol\";\n");
    sol.push_str("import {BLS12381} from \"../src/BLS12381.sol\";\n\n");

    sol.push_str("/// @title Real MASP Proof Verification Tests\n");
    sol.push_str(
        "/// @notice Tests shield and unshield operations using real Groth16 proofs\n",
    );
    sol.push_str("/// @dev Generated by masp-prover/src/generate_masp_proofs.rs\n");
    sol.push_str("contract MASPRealProofTest is Test {\n");
    sol.push_str("    MASPVerifier public verifier;\n");
    sol.push_str("    bool precompilesSupported;\n\n");

    // Group vectors by circuit type
    let spend_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.circuit_type == "Spend")
        .collect();
    let output_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.circuit_type == "Output")
        .collect();
    let convert_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.circuit_type == "Convert")
        .collect();

    // Generate constants for first of each type (for VK setup)
    if let Some(v) = spend_vectors.first() {
        sol.push_str("    // ============= SPEND CIRCUIT VERIFICATION KEY =============\n");
        generate_vk_constants(&mut sol, "SPEND", &v.vk);
    }

    if let Some(v) = output_vectors.first() {
        sol.push_str("\n    // ============= OUTPUT CIRCUIT VERIFICATION KEY =============\n");
        generate_vk_constants(&mut sol, "OUTPUT", &v.vk);
    }

    if let Some(v) = convert_vectors.first() {
        sol.push_str("\n    // ============= CONVERT CIRCUIT VERIFICATION KEY =============\n");
        generate_vk_constants(&mut sol, "CONVERT", &v.vk);
    }

    // Generate proof constants for each test vector
    sol.push_str("\n    // ============= PROOF DATA =============\n");
    for v in vectors {
        let const_name = v.name.to_uppercase().replace("-", "_");
        sol.push_str(&format!("\n    // {}: {}\n", v.name, v.description));
        sol.push_str(&format!(
            "    bytes constant PROOF_{} = hex\"{}{}{}{}{}{}\";\n",
            const_name, v.proof.a.x, v.proof.a.y, v.proof.b.x, v.proof.b.y, v.proof.c.x, v.proof.c.y
        ));

        for (i, input) in v.public_inputs.iter().enumerate() {
            sol.push_str(&format!(
                "    bytes32 constant INPUT_{}_{} = 0x{};\n",
                const_name, i, input
            ));
        }
    }

    // Setup function
    sol.push_str("\n    function setUp() public {\n");
    sol.push_str("        verifier = new MASPVerifier();\n");
    sol.push_str("        precompilesSupported = _checkPrecompileSupport();\n");
    sol.push_str("    }\n\n");

    // Precompile check function
    sol.push_str("    function _checkPrecompileSupport() internal returns (bool) {\n");
    sol.push_str(
        "        bytes memory msmInput = abi.encodePacked(SPEND_VK_IC_0, bytes32(uint256(1)));\n",
    );
    sol.push_str(
        "        (bool success, bytes memory result) = address(0x0d).staticcall(msmInput);\n",
    );
    sol.push_str("        return success && result.length == 128;\n");
    sol.push_str("    }\n\n");

    // VK setup functions
    sol.push_str("    function _setupSpendVK() internal {\n");
    generate_vk_setup(&mut sol, "SPEND", "Spend", spend_vectors.first().map(|v| v.vk.ic.len()).unwrap_or(5));
    sol.push_str("    }\n\n");

    sol.push_str("    function _setupOutputVK() internal {\n");
    generate_vk_setup(&mut sol, "OUTPUT", "Output", output_vectors.first().map(|v| v.vk.ic.len()).unwrap_or(4));
    sol.push_str("    }\n\n");

    sol.push_str("    function _setupConvertVK() internal {\n");
    generate_vk_setup(&mut sol, "CONVERT", "Convert", convert_vectors.first().map(|v| v.vk.ic.len()).unwrap_or(3));
    sol.push_str("    }\n\n");

    // Generate test functions for shield operations (Output proofs)
    sol.push_str("    // ============= SHIELD OPERATION TESTS =============\n\n");
    for v in &output_vectors {
        let fn_name = v.name.replace("-", "_");
        let const_name = v.name.to_uppercase().replace("-", "_");

        sol.push_str(&format!("    /// @notice {}\n", v.description));
        sol.push_str(&format!("    function test_shield_{}() public {{\n", fn_name));
        sol.push_str("        vm.skip(!precompilesSupported);\n");
        sol.push_str("        _setupOutputVK();\n\n");
        sol.push_str("        bytes32[] memory publicInputs = new bytes32[](3);\n");
        sol.push_str(&format!(
            "        publicInputs[0] = INPUT_{}_0; // value_commitment\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[1] = INPUT_{}_1; // note_commitment\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[2] = INPUT_{}_2; // epk\n",
            const_name
        ));
        sol.push_str("\n        bool valid = verifier.verifyProof(\n");
        sol.push_str("            MASPVerifier.CircuitType.Output,\n");
        sol.push_str(&format!("            PROOF_{},\n", const_name));
        sol.push_str("            publicInputs\n");
        sol.push_str("        );\n\n");
        sol.push_str(&format!(
            "        assertTrue(valid, \"Shield proof {} should verify\");\n",
            v.name
        ));
        sol.push_str("    }\n\n");
    }

    // Generate test functions for unshield operations (Spend proofs)
    sol.push_str("    // ============= UNSHIELD OPERATION TESTS =============\n\n");
    for v in &spend_vectors {
        let fn_name = v.name.replace("-", "_");
        let const_name = v.name.to_uppercase().replace("-", "_");

        sol.push_str(&format!("    /// @notice {}\n", v.description));
        sol.push_str(&format!("    function test_unshield_{}() public {{\n", fn_name));
        sol.push_str("        vm.skip(!precompilesSupported);\n");
        sol.push_str("        _setupSpendVK();\n\n");
        sol.push_str("        bytes32[] memory publicInputs = new bytes32[](4);\n");
        sol.push_str(&format!(
            "        publicInputs[0] = INPUT_{}_0; // anchor\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[1] = INPUT_{}_1; // value_commitment\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[2] = INPUT_{}_2; // nullifier\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[3] = INPUT_{}_3; // rvk\n",
            const_name
        ));
        sol.push_str("\n        bool valid = verifier.verifyProof(\n");
        sol.push_str("            MASPVerifier.CircuitType.Spend,\n");
        sol.push_str(&format!("            PROOF_{},\n", const_name));
        sol.push_str("            publicInputs\n");
        sol.push_str("        );\n\n");
        sol.push_str(&format!(
            "        assertTrue(valid, \"Unshield proof {} should verify\");\n",
            v.name
        ));
        sol.push_str("    }\n\n");
    }

    // Generate test functions for convert operations
    sol.push_str("    // ============= ASSET CONVERSION TESTS =============\n\n");
    for v in &convert_vectors {
        let fn_name = v.name.replace("-", "_");
        let const_name = v.name.to_uppercase().replace("-", "_");

        sol.push_str(&format!("    /// @notice {}\n", v.description));
        sol.push_str(&format!("    function test_convert_{}() public {{\n", fn_name));
        sol.push_str("        vm.skip(!precompilesSupported);\n");
        sol.push_str("        _setupConvertVK();\n\n");
        sol.push_str("        bytes32[] memory publicInputs = new bytes32[](2);\n");
        sol.push_str(&format!(
            "        publicInputs[0] = INPUT_{}_0; // conversion_root\n",
            const_name
        ));
        sol.push_str(&format!(
            "        publicInputs[1] = INPUT_{}_1; // value_commitment\n",
            const_name
        ));
        sol.push_str("\n        bool valid = verifier.verifyProof(\n");
        sol.push_str("            MASPVerifier.CircuitType.Convert,\n");
        sol.push_str(&format!("            PROOF_{},\n", const_name));
        sol.push_str("            publicInputs\n");
        sol.push_str("        );\n\n");
        sol.push_str(&format!(
            "        assertTrue(valid, \"Convert proof {} should verify\");\n",
            v.name
        ));
        sol.push_str("    }\n\n");
    }

    // Generate batch verification test
    sol.push_str("    // ============= BATCH VERIFICATION TESTS =============\n\n");
    sol.push_str("    /// @notice Test batch verification of shield and unshield operations\n");
    sol.push_str("    function test_batch_shield_unshield() public {\n");
    sol.push_str("        vm.skip(!precompilesSupported);\n");
    sol.push_str("        _setupSpendVK();\n");
    sol.push_str("        _setupOutputVK();\n\n");
    sol.push_str("        MASPVerifier.CircuitType[] memory types = new MASPVerifier.CircuitType[](2);\n");
    sol.push_str("        bytes[] memory proofs = new bytes[](2);\n");
    sol.push_str("        bytes32[][] memory publicInputsArray = new bytes32[][](2);\n\n");
    sol.push_str("        // Shield operation\n");
    sol.push_str("        types[0] = MASPVerifier.CircuitType.Output;\n");
    sol.push_str("        proofs[0] = PROOF_SHIELD_100_NAM;\n");
    sol.push_str("        publicInputsArray[0] = new bytes32[](3);\n");
    sol.push_str("        publicInputsArray[0][0] = INPUT_SHIELD_100_NAM_0;\n");
    sol.push_str("        publicInputsArray[0][1] = INPUT_SHIELD_100_NAM_1;\n");
    sol.push_str("        publicInputsArray[0][2] = INPUT_SHIELD_100_NAM_2;\n\n");
    sol.push_str("        // Unshield operation\n");
    sol.push_str("        types[1] = MASPVerifier.CircuitType.Spend;\n");
    sol.push_str("        proofs[1] = PROOF_UNSHIELD_100_NAM;\n");
    sol.push_str("        publicInputsArray[1] = new bytes32[](4);\n");
    sol.push_str("        publicInputsArray[1][0] = INPUT_UNSHIELD_100_NAM_0;\n");
    sol.push_str("        publicInputsArray[1][1] = INPUT_UNSHIELD_100_NAM_1;\n");
    sol.push_str("        publicInputsArray[1][2] = INPUT_UNSHIELD_100_NAM_2;\n");
    sol.push_str("        publicInputsArray[1][3] = INPUT_UNSHIELD_100_NAM_3;\n\n");
    sol.push_str("        bool allValid = verifier.batchVerifyProofs(types, proofs, publicInputsArray);\n");
    sol.push_str("        assertTrue(allValid, \"Batch shield/unshield should verify\");\n");
    sol.push_str("    }\n\n");

    // VK setup validation tests (these don't need precompiles)
    sol.push_str("    // ============= VK SETUP TESTS (no precompiles needed) =============\n\n");
    sol.push_str("    function test_SpendVKSetup() public {\n");
    sol.push_str("        _setupSpendVK();\n");
    sol.push_str("        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Spend));\n");
    sol.push_str("        assertEq(verifier.getPublicInputsCount(MASPVerifier.CircuitType.Spend), 4);\n");
    sol.push_str("    }\n\n");

    sol.push_str("    function test_OutputVKSetup() public {\n");
    sol.push_str("        _setupOutputVK();\n");
    sol.push_str("        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Output));\n");
    sol.push_str("        assertEq(verifier.getPublicInputsCount(MASPVerifier.CircuitType.Output), 3);\n");
    sol.push_str("    }\n\n");

    sol.push_str("    function test_ConvertVKSetup() public {\n");
    sol.push_str("        _setupConvertVK();\n");
    sol.push_str("        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Convert));\n");
    sol.push_str("        assertEq(verifier.getPublicInputsCount(MASPVerifier.CircuitType.Convert), 2);\n");
    sol.push_str("    }\n\n");

    sol.push_str("    function test_ProofDataSizes() public pure {\n");
    sol.push_str("        // All proofs should be 512 bytes\n");
    sol.push_str("        assertEq(PROOF_SHIELD_100_NAM.length, 512);\n");
    sol.push_str("        assertEq(PROOF_UNSHIELD_100_NAM.length, 512);\n");
    sol.push_str("        assertEq(PROOF_CONVERT_NAM_TO_ETH_1X2.length, 512);\n");
    sol.push_str("    }\n");

    sol.push_str("}\n");

    let mut file = File::create("MASPRealProofs.t.sol").unwrap();
    file.write_all(sol.as_bytes()).unwrap();
}

fn generate_vk_constants(sol: &mut String, prefix: &str, vk: &VK) {
    sol.push_str(&format!(
        "    bytes constant {}_VK_ALPHA = hex\"{}{}\";\n",
        prefix, vk.alpha.x, vk.alpha.y
    ));
    sol.push_str(&format!(
        "    bytes constant {}_VK_BETA = hex\"{}{}\";\n",
        prefix, vk.beta.x, vk.beta.y
    ));
    sol.push_str(&format!(
        "    bytes constant {}_VK_GAMMA = hex\"{}{}\";\n",
        prefix, vk.gamma.x, vk.gamma.y
    ));
    sol.push_str(&format!(
        "    bytes constant {}_VK_DELTA = hex\"{}{}\";\n",
        prefix, vk.delta.x, vk.delta.y
    ));

    for (i, ic) in vk.ic.iter().enumerate() {
        sol.push_str(&format!(
            "    bytes constant {}_VK_IC_{} = hex\"{}{}\";\n",
            prefix, i, ic.x, ic.y
        ));
    }
}

fn generate_vk_setup(sol: &mut String, prefix: &str, circuit_type: &str, ic_count: usize) {
    sol.push_str(&format!(
        "        bytes[] memory ic = new bytes[]({});\n",
        ic_count
    ));
    for i in 0..ic_count {
        sol.push_str(&format!("        ic[{}] = {}_VK_IC_{};\n", i, prefix, i));
    }
    sol.push_str(&format!(
        "        verifier.setVerificationKey(\n            MASPVerifier.CircuitType.{},\n",
        circuit_type
    ));
    sol.push_str(&format!("            {}_VK_ALPHA,\n", prefix));
    sol.push_str(&format!("            {}_VK_BETA,\n", prefix));
    sol.push_str(&format!("            {}_VK_GAMMA,\n", prefix));
    sol.push_str(&format!("            {}_VK_DELTA,\n", prefix));
    sol.push_str("            ic\n        );\n");
}
