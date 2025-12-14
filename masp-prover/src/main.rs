//! BLS12-381 Groth16 Proof Generator for Ethereum Verification Tests
//!
//! This tool generates valid Groth16 proofs on the BLS12-381 curve
//! and outputs them in EIP-2537 format for Solidity contract verification.
//!
//! The proofs are for a simple "multiplication" circuit: x * y = z
//! where x and y are private inputs and z is a public input.

use anyhow::{Context, Result};
use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
        Proof, VerifyingKey,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use clap::{Parser, Subcommand};
use group::prime::PrimeCurveAffine;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A simple multiplication circuit: x * y = z
/// where x, y are private and z is public
#[derive(Clone)]
struct MultiplyCircuit {
    x: Option<Scalar>,
    y: Option<Scalar>,
}

impl Circuit<Scalar> for MultiplyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate private input x
        let x = cs.alloc(
            || "x",
            || self.x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate private input y
        let y = cs.alloc(
            || "y",
            || self.y.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Compute z = x * y
        let z_val = self.x.and_then(|x| self.y.map(|y| x * y));

        // Allocate public input z
        let z = cs.alloc_input(
            || "z",
            || z_val.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Enforce x * y = z
        cs.enforce(|| "x * y = z", |lc| lc + x, |lc| lc + y, |lc| lc + z);

        Ok(())
    }
}

/// Output format for proofs compatible with EIP-2537
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Groth16Proof {
    /// Proof point A in G1 (128 bytes hex in EIP-2537 format)
    pub a: String,
    /// Proof point B in G2 (256 bytes hex in EIP-2537 format)
    pub b: String,
    /// Proof point C in G1 (128 bytes hex in EIP-2537 format)
    pub c: String,
    /// Complete proof (A || B || C) for direct use (512 bytes hex)
    pub proof: String,
    /// Public inputs as hex field elements
    pub public_inputs: Vec<String>,
}

/// Verification key output format for EIP-2537
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Groth16VerificationKey {
    /// Alpha G1 point (128 bytes hex)
    pub alpha: String,
    /// Beta G2 point (256 bytes hex)
    pub beta: String,
    /// Gamma G2 point (256 bytes hex)
    pub gamma: String,
    /// Delta G2 point (256 bytes hex)
    pub delta: String,
    /// IC points array (each 128 bytes hex)
    pub ic: Vec<String>,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

/// Complete test vector
#[derive(Serialize, Deserialize, Debug)]
pub struct TestVector {
    pub name: String,
    pub description: String,
    pub verification_key: Groth16VerificationKey,
    pub valid_proofs: Vec<Groth16Proof>,
    pub invalid_proofs: Vec<Groth16Proof>,
}

#[derive(Parser)]
#[command(name = "masp-prover")]
#[command(about = "Generate BLS12-381 Groth16 proofs for Ethereum verification tests")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate test vectors with proofs and verification keys
    Generate {
        /// Output file for test vectors
        #[arg(short, long, default_value = "test_vectors.json")]
        output: PathBuf,

        /// Number of valid proofs to generate
        #[arg(short, long, default_value = "5")]
        num_proofs: usize,
    },
    /// Generate a single proof with specific inputs
    Prove {
        /// Private input x
        #[arg(short = 'x', long)]
        x: u64,

        /// Private input y
        #[arg(short = 'y', long)]
        y: u64,

        /// Output file
        #[arg(short, long, default_value = "proof.json")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output, num_proofs } => {
            generate_test_vectors(&output, num_proofs)?;
        }
        Commands::Prove { x, y, output } => {
            generate_single_proof(x, y, &output)?;
        }
    }

    Ok(())
}

/// Convert G1Affine point to EIP-2537 format (128 bytes)
fn g1_to_eip2537(point: &G1Affine) -> Vec<u8> {
    let mut result = vec![0u8; 128];

    if bool::from(point.is_identity()) {
        // Identity point is all zeros
        return result;
    }

    // Get uncompressed bytes (96 bytes: x || y, each 48 bytes, big-endian)
    let uncompressed = point.to_uncompressed();

    // EIP-2537 format: each coordinate is 64 bytes (16 zero bytes prefix + 48 byte coordinate)
    // x coordinate (48 bytes) goes into bytes 16-63
    result[16..64].copy_from_slice(&uncompressed[0..48]);
    // y coordinate (48 bytes) goes into bytes 80-127
    result[80..128].copy_from_slice(&uncompressed[48..96]);

    result
}

/// Convert G2Affine point to EIP-2537 format (256 bytes)
fn g2_to_eip2537(point: &G2Affine) -> Vec<u8> {
    let mut result = vec![0u8; 256];

    if bool::from(point.is_identity()) {
        // Identity point is all zeros
        return result;
    }

    // Get uncompressed bytes (192 bytes)
    // bls12_381 crate format: x.c1 || x.c0 || y.c1 || y.c0 (each 48 bytes big-endian)
    // EIP-2537 expects: x.c0 || x.c1 || y.c0 || y.c1 (each 64 bytes with 16 zero prefix)
    let uncompressed = point.to_uncompressed();

    // EIP-2537 format for G2 (swap c0/c1 order):
    // x.c0 (48 bytes from uncompressed[48..96]) -> bytes 16-63
    result[16..64].copy_from_slice(&uncompressed[48..96]);
    // x.c1 (48 bytes from uncompressed[0..48]) -> bytes 80-127
    result[80..128].copy_from_slice(&uncompressed[0..48]);
    // y.c0 (48 bytes from uncompressed[144..192]) -> bytes 144-191
    result[144..192].copy_from_slice(&uncompressed[144..192]);
    // y.c1 (48 bytes from uncompressed[96..144]) -> bytes 208-255
    result[208..256].copy_from_slice(&uncompressed[96..144]);

    result
}

/// Convert a scalar to 32-byte big-endian hex
fn scalar_to_hex(scalar: &Scalar) -> String {
    let bytes = scalar.to_bytes();
    // Bytes are little-endian, reverse to big-endian
    let mut be_bytes = bytes;
    be_bytes.reverse();
    hex::encode(be_bytes)
}

/// Convert bellman Proof to our format
fn convert_proof(proof: &Proof<Bls12>, public_inputs: &[Scalar]) -> Groth16Proof {
    let a_bytes = g1_to_eip2537(&proof.a);
    let b_bytes = g2_to_eip2537(&proof.b);
    let c_bytes = g1_to_eip2537(&proof.c);

    let mut proof_bytes = Vec::with_capacity(512);
    proof_bytes.extend_from_slice(&a_bytes);
    proof_bytes.extend_from_slice(&b_bytes);
    proof_bytes.extend_from_slice(&c_bytes);

    Groth16Proof {
        a: hex::encode(&a_bytes),
        b: hex::encode(&b_bytes),
        c: hex::encode(&c_bytes),
        proof: hex::encode(&proof_bytes),
        public_inputs: public_inputs.iter().map(scalar_to_hex).collect(),
    }
}

/// Convert bellman VerifyingKey to our format
fn convert_vk(vk: &VerifyingKey<Bls12>) -> Groth16VerificationKey {
    Groth16VerificationKey {
        alpha: hex::encode(g1_to_eip2537(&vk.alpha_g1)),
        beta: hex::encode(g2_to_eip2537(&vk.beta_g2)),
        gamma: hex::encode(g2_to_eip2537(&vk.gamma_g2)),
        delta: hex::encode(g2_to_eip2537(&vk.delta_g2)),
        ic: vk.ic.iter().map(|p| hex::encode(g1_to_eip2537(p))).collect(),
        num_public_inputs: vk.ic.len() - 1,
    }
}

/// Generate test vectors with proofs
fn generate_test_vectors(output: &PathBuf, num_proofs: usize) -> Result<()> {
    let mut rng = OsRng;

    println!("Generating circuit parameters...");

    // Create the circuit for parameter generation (no values needed)
    let circuit = MultiplyCircuit { x: None, y: None };

    // Generate random parameters
    let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
        .context("Failed to generate parameters")?;

    println!("Parameters generated successfully.");

    // Prepare the verification key
    let pvk = prepare_verifying_key(&params.vk);

    // Convert verification key to our format
    let vk = convert_vk(&params.vk);

    println!("Generating {} valid proofs...", num_proofs);

    let mut valid_proofs = Vec::new();

    // Generate valid proofs with different inputs
    let test_cases = [
        (3u64, 7u64),     // 3 * 7 = 21
        (2u64, 5u64),     // 2 * 5 = 10
        (4u64, 6u64),     // 4 * 6 = 24
        (10u64, 10u64),   // 10 * 10 = 100
        (1u64, 1u64),     // 1 * 1 = 1
        (100u64, 200u64), // 100 * 200 = 20000
        (7u64, 11u64),    // 7 * 11 = 77
        (13u64, 17u64),   // 13 * 17 = 221
    ];

    for (i, (x, y)) in test_cases.iter().take(num_proofs).enumerate() {
        println!("  Generating proof {} for {} * {} = {}...", i + 1, x, y, x * y);

        let x_scalar = Scalar::from(*x);
        let y_scalar = Scalar::from(*y);
        let z_scalar = x_scalar * y_scalar;

        let circuit = MultiplyCircuit {
            x: Some(x_scalar),
            y: Some(y_scalar),
        };

        let proof = create_random_proof(circuit, &params, &mut rng)
            .context("Failed to create proof")?;

        // Verify the proof locally first
        let public_inputs = vec![z_scalar];
        verify_proof(&pvk, &proof, &public_inputs)
            .context("Proof verification failed")?;

        valid_proofs.push(convert_proof(&proof, &public_inputs));
    }

    println!("Generating invalid proofs...");

    let mut invalid_proofs = Vec::new();

    // Generate an invalid proof (wrong public input)
    {
        let x_scalar = Scalar::from(3u64);
        let y_scalar = Scalar::from(7u64);
        // Correct z would be 21, but we'll claim it's 22
        let wrong_z = Scalar::from(22u64);

        let circuit = MultiplyCircuit {
            x: Some(x_scalar),
            y: Some(y_scalar),
        };

        let proof = create_random_proof(circuit, &params, &mut rng)
            .context("Failed to create proof")?;

        // This should fail verification
        let public_inputs = vec![wrong_z];

        invalid_proofs.push(convert_proof(&proof, &public_inputs));
    }

    let test_vector = TestVector {
        name: "multiply_circuit".to_string(),
        description: "Groth16 proofs for x * y = z circuit on BLS12-381".to_string(),
        verification_key: vk,
        valid_proofs,
        invalid_proofs,
    };

    let json = serde_json::to_string_pretty(&test_vector)?;
    fs::write(output, &json)?;
    println!("\nTest vectors written to {:?}", output);
    println!(
        "Verification key has {} IC points ({} public inputs)",
        test_vector.verification_key.ic.len(),
        test_vector.verification_key.num_public_inputs
    );

    Ok(())
}

/// Generate a single proof with specific inputs
fn generate_single_proof(x: u64, y: u64, output: &PathBuf) -> Result<()> {
    let mut rng = OsRng;

    println!("Generating parameters for circuit...");

    let circuit = MultiplyCircuit { x: None, y: None };
    let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
        .context("Failed to generate parameters")?;

    let pvk = prepare_verifying_key(&params.vk);

    println!("Generating proof for {} * {} = {}...", x, y, x * y);

    let x_scalar = Scalar::from(x);
    let y_scalar = Scalar::from(y);
    let z_scalar = x_scalar * y_scalar;

    let circuit = MultiplyCircuit {
        x: Some(x_scalar),
        y: Some(y_scalar),
    };

    let proof = create_random_proof(circuit, &params, &mut rng)
        .context("Failed to create proof")?;

    let public_inputs = vec![z_scalar];
    let verification_result = verify_proof(&pvk, &proof, &public_inputs);
    let verified = verification_result.is_ok();
    println!(
        "Local verification: {}",
        if verified { "PASSED" } else { "FAILED" }
    );

    let output_data = serde_json::json!({
        "verification_key": convert_vk(&params.vk),
        "proof": convert_proof(&proof, &public_inputs),
        "x": x,
        "y": y,
        "z": x * y,
    });

    let json = serde_json::to_string_pretty(&output_data)?;
    fs::write(output, &json)?;
    println!("Proof written to {:?}", output);

    Ok(())
}
