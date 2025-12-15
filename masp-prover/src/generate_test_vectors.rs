//! Generate real Groth16 test vectors for Solidity verifier testing
//!
//! This creates actual cryptographic proofs using BLS12-381 that can be
//! verified by the Ethereum smart contracts.

use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
        Proof, VerifyingKey,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::{G1Affine, G2Affine, Scalar};
use group::Curve;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;

// Re-export the pairing engine
type Bls12 = bls12_381::Bls12;

/// G1 point in EIP-2537 format (128 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct G1Point {
    pub x_hex: String,
    pub y_hex: String,
}

impl G1Point {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = hex::decode(&self.x_hex).unwrap();
        result.extend(hex::decode(&self.y_hex).unwrap());
        result
    }

    pub fn to_solidity_hex(&self) -> String {
        format!("0x{}{}", self.x_hex, self.y_hex)
    }
}

/// G2 point in EIP-2537 format (256 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct G2Point {
    pub x_hex: String, // 128 bytes = c0 (64) + c1 (64)
    pub y_hex: String, // 128 bytes = c0 (64) + c1 (64)
}

impl G2Point {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = hex::decode(&self.x_hex).unwrap();
        result.extend(hex::decode(&self.y_hex).unwrap());
        result
    }

    pub fn to_solidity_hex(&self) -> String {
        format!("0x{}{}", self.x_hex, self.y_hex)
    }
}

/// Groth16 proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

impl ProofData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.a.to_bytes();
        result.extend(self.b.to_bytes());
        result.extend(self.c.to_bytes());
        result
    }

    pub fn to_solidity_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

/// Verification key data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKeyData {
    pub alpha: G1Point,
    pub beta: G2Point,
    pub gamma: G2Point,
    pub delta: G2Point,
    pub ic: Vec<G1Point>,
}

/// Complete test vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    pub name: String,
    pub description: String,
    pub verification_key: VerificationKeyData,
    pub proof: ProofData,
    pub public_inputs: Vec<String>, // hex-encoded scalars
    pub should_verify: bool,
}

/// Serialize a G1 affine point to EIP-2537 format
fn g1_to_eip2537(point: &G1Affine) -> G1Point {
    if bool::from(point.is_identity()) {
        // Identity point is all zeros
        return G1Point {
            x_hex: "0".repeat(128),
            y_hex: "0".repeat(128),
        };
    }

    // Get uncompressed bytes (96 bytes: 48 for x, 48 for y)
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // First 48 bytes are x, next 48 bytes are y
    let x_bytes = &bytes[0..48];
    let y_bytes = &bytes[48..96];

    // Pad to 64 bytes each (EIP-2537 format: 16 zero bytes + 48 byte coordinate)
    let mut x_padded = vec![0u8; 16];
    x_padded.extend_from_slice(x_bytes);

    let mut y_padded = vec![0u8; 16];
    y_padded.extend_from_slice(y_bytes);

    G1Point {
        x_hex: hex::encode(&x_padded),
        y_hex: hex::encode(&y_padded),
    }
}

/// Serialize a G2 affine point to EIP-2537 format
fn g2_to_eip2537(point: &G2Affine) -> G2Point {
    if bool::from(point.is_identity()) {
        return G2Point {
            x_hex: "0".repeat(256),
            y_hex: "0".repeat(256),
        };
    }

    // Get uncompressed bytes (192 bytes total)
    // Format: x.c1 (48) | x.c0 (48) | y.c1 (48) | y.c0 (48)
    let uncompressed = point.to_uncompressed();
    let bytes = uncompressed.as_ref();

    // BLS12-381 G2 uncompressed format: x.c1 || x.c0 || y.c1 || y.c0
    let x_c1 = &bytes[0..48];
    let x_c0 = &bytes[48..96];
    let y_c1 = &bytes[96..144];
    let y_c0 = &bytes[144..192];

    // EIP-2537 format: c0 || c1 for each coordinate, each padded to 64 bytes
    // So x = pad(x.c0) || pad(x.c1)
    let mut x_padded = vec![0u8; 16];
    x_padded.extend_from_slice(x_c0);
    x_padded.extend(vec![0u8; 16]);
    x_padded.extend_from_slice(x_c1);

    let mut y_padded = vec![0u8; 16];
    y_padded.extend_from_slice(y_c0);
    y_padded.extend(vec![0u8; 16]);
    y_padded.extend_from_slice(y_c1);

    G2Point {
        x_hex: hex::encode(&x_padded),
        y_hex: hex::encode(&y_padded),
    }
}

/// Convert a Groth16 proof to our serializable format
fn proof_to_data(proof: &Proof<Bls12>) -> ProofData {
    ProofData {
        a: g1_to_eip2537(&proof.a),
        b: g2_to_eip2537(&proof.b),
        c: g1_to_eip2537(&proof.c),
    }
}

/// Convert a verification key to our serializable format
fn vk_to_data(vk: &VerifyingKey<Bls12>) -> VerificationKeyData {
    VerificationKeyData {
        alpha: g1_to_eip2537(&vk.alpha_g1),
        beta: g2_to_eip2537(&vk.beta_g2),
        gamma: g2_to_eip2537(&vk.gamma_g2),
        delta: g2_to_eip2537(&vk.delta_g2),
        ic: vk.ic.iter().map(|p| g1_to_eip2537(p)).collect(),
    }
}

/// A simple circuit for testing: proves knowledge of x such that x^3 + x + 5 = out
#[derive(Clone)]
struct CubeCircuit {
    x: Option<Scalar>,
}

impl Circuit<Scalar> for CubeCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate private input x
        let x = cs.alloc(
            || "x",
            || self.x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // x^2
        let x_sq = cs.alloc(
            || "x_sq",
            || {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val)
            },
        )?;

        // x * x = x^2
        cs.enforce(|| "x_sq constraint", |lc| lc + x, |lc| lc + x, |lc| lc + x_sq);

        // x^3
        let x_cubed = cs.alloc(
            || "x_cubed",
            || {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val * x_val)
            },
        )?;

        // x^2 * x = x^3
        cs.enforce(
            || "x_cubed constraint",
            |lc| lc + x_sq,
            |lc| lc + x,
            |lc| lc + x_cubed,
        );

        // Compute output = x^3 + x + 5
        let five = Scalar::from(5u64);
        let out = cs.alloc_input(
            || "out",
            || {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val * x_val + x_val + five)
            },
        )?;

        // x^3 + x + 5 = out
        cs.enforce(
            || "output constraint",
            |lc| lc + x_cubed + x + (five, CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + out,
        );

        Ok(())
    }
}

/// A multiplication circuit: proves knowledge of a, b such that a * b = c
#[derive(Clone)]
struct MultiplyCircuit {
    a: Option<Scalar>,
    b: Option<Scalar>,
}

impl Circuit<Scalar> for MultiplyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let a = cs.alloc(
            || "a",
            || self.a.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let b = cs.alloc(
            || "b",
            || self.b.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let c = cs.alloc_input(
            || "c (public output)",
            || {
                let a_val = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b_val = self.b.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a_val * b_val)
            },
        )?;

        // a * b = c
        cs.enforce(|| "multiplication", |lc| lc + a, |lc| lc + b, |lc| lc + c);

        Ok(())
    }
}

/// Circuit simulating MASP Spend: proves knowledge of note details for spending
/// Public inputs: anchor, value_commitment, nullifier, rk
#[derive(Clone)]
struct MockSpendCircuit {
    // Private inputs
    note_value: Option<Scalar>,
    note_randomness: Option<Scalar>,
    spending_key: Option<Scalar>,

    // Values for public inputs (derived from private)
    anchor: Option<Scalar>,
    value_commitment: Option<Scalar>,
    nullifier: Option<Scalar>,
    rk: Option<Scalar>,
}

impl Circuit<Scalar> for MockSpendCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let note_value = cs.alloc(
            || "note_value",
            || self.note_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_randomness = cs.alloc(
            || "note_randomness",
            || self.note_randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let spending_key = cs.alloc(
            || "spending_key",
            || self.spending_key.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate public inputs
        let _anchor = cs.alloc_input(
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

        // Simplified constraints (in real MASP these would be cryptographic)
        // Value commitment = note_value + note_randomness (simplified)
        cs.enforce(
            || "value_commitment_check",
            |lc| lc + note_value + note_randomness,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment,
        );

        // Nullifier = spending_key * note_value (simplified)
        cs.enforce(
            || "nullifier_check",
            |lc| lc + spending_key,
            |lc| lc + note_value,
            |lc| lc + nullifier,
        );

        // RK = spending_key (simplified)
        cs.enforce(
            || "rk_check",
            |lc| lc + spending_key,
            |lc| lc + CS::one(),
            |lc| lc + rk,
        );

        Ok(())
    }
}

/// Circuit simulating MASP Output: proves creation of a new note
/// Public inputs: value_commitment, note_commitment, ephemeral_key
#[derive(Clone)]
struct MockOutputCircuit {
    note_value: Option<Scalar>,
    note_randomness: Option<Scalar>,
    recipient_key: Option<Scalar>,

    value_commitment: Option<Scalar>,
    note_commitment: Option<Scalar>,
    ephemeral_key: Option<Scalar>,
}

impl Circuit<Scalar> for MockOutputCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let note_value = cs.alloc(
            || "note_value",
            || self.note_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_randomness = cs.alloc(
            || "note_randomness",
            || self.note_randomness.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let recipient_key = cs.alloc(
            || "recipient_key",
            || self.recipient_key.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let note_commitment = cs.alloc_input(
            || "note_commitment",
            || self.note_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let ephemeral_key = cs.alloc_input(
            || "ephemeral_key",
            || self.ephemeral_key.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Simplified constraints
        cs.enforce(
            || "value_commitment_check",
            |lc| lc + note_value + note_randomness,
            |lc| lc + CS::one(),
            |lc| lc + value_commitment,
        );

        cs.enforce(
            || "note_commitment_check",
            |lc| lc + note_value,
            |lc| lc + recipient_key,
            |lc| lc + note_commitment,
        );

        cs.enforce(
            || "ephemeral_key_check",
            |lc| lc + note_randomness,
            |lc| lc + CS::one(),
            |lc| lc + ephemeral_key,
        );

        Ok(())
    }
}

/// Circuit simulating MASP Convert: proves asset conversion
/// Public inputs: allowed_conversion, value_commitment
#[derive(Clone)]
struct MockConvertCircuit {
    input_value: Option<Scalar>,
    conversion_rate: Option<Scalar>,

    allowed_conversion: Option<Scalar>,
    value_commitment: Option<Scalar>,
}

impl Circuit<Scalar> for MockConvertCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let input_value = cs.alloc(
            || "input_value",
            || self.input_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let conversion_rate = cs.alloc(
            || "conversion_rate",
            || self.conversion_rate.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let allowed_conversion = cs.alloc_input(
            || "allowed_conversion",
            || self.allowed_conversion.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let value_commitment = cs.alloc_input(
            || "value_commitment",
            || self.value_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Simplified constraints
        cs.enforce(
            || "conversion_check",
            |lc| lc + input_value,
            |lc| lc + conversion_rate,
            |lc| lc + value_commitment,
        );

        cs.enforce(
            || "allowed_conversion_check",
            |lc| lc + conversion_rate,
            |lc| lc + CS::one(),
            |lc| lc + allowed_conversion,
        );

        Ok(())
    }
}

fn scalar_to_hex(s: Scalar) -> String {
    // Convert scalar to 32-byte representation
    let bytes = s.to_bytes();
    // Reverse to get big-endian (Solidity expectation)
    let mut be_bytes = bytes;
    be_bytes.reverse();
    format!("0x{}", hex::encode(be_bytes))
}

fn main() {
    println!("Generating Groth16 test vectors for Solidity verifier...\n");

    let mut all_vectors: Vec<TestVector> = Vec::new();

    // =========================================================================
    // Test Vector 1: Simple multiplication circuit (3 * 7 = 21)
    // =========================================================================
    println!("Generating multiplication circuit proofs...");

    let mul_circuit = MultiplyCircuit { a: None, b: None };
    let mul_params = generate_random_parameters::<Bls12, _, _>(mul_circuit.clone(), &mut OsRng)
        .expect("Failed to generate parameters");
    let mul_vk_data = vk_to_data(&mul_params.vk);

    // Generate valid proofs for different inputs
    let test_cases = [
        (3u64, 7u64, "3 * 7 = 21"),
        (2u64, 5u64, "2 * 5 = 10"),
        (4u64, 6u64, "4 * 6 = 24"),
        (10u64, 10u64, "10 * 10 = 100"),
        (1u64, 1u64, "1 * 1 = 1"),
        (100u64, 200u64, "100 * 200 = 20000"),
    ];

    for (i, (a, b, desc)) in test_cases.iter().enumerate() {
        let circuit = MultiplyCircuit {
            a: Some(Scalar::from(*a)),
            b: Some(Scalar::from(*b)),
        };

        let proof = create_random_proof(circuit, &mul_params, &mut OsRng)
            .expect("Failed to create proof");

        let c = Scalar::from(*a * *b);
        let pvk = prepare_verifying_key(&mul_params.vk);
        let verified = verify_proof(&pvk, &proof, &[c]);
        assert!(verified.is_ok(), "Verification failed for {}", desc);

        all_vectors.push(TestVector {
            name: format!("multiply_{}", i + 1),
            description: format!("Multiplication proof: {}", desc),
            verification_key: mul_vk_data.clone(),
            proof: proof_to_data(&proof),
            public_inputs: vec![scalar_to_hex(c)],
            should_verify: true,
        });

        println!("  Generated proof for {}", desc);
    }

    // Generate an invalid proof (wrong public input)
    let invalid_circuit = MultiplyCircuit {
        a: Some(Scalar::from(3u64)),
        b: Some(Scalar::from(7u64)),
    };
    let invalid_proof = create_random_proof(invalid_circuit, &mul_params, &mut OsRng)
        .expect("Failed to create proof");

    all_vectors.push(TestVector {
        name: "multiply_invalid".to_string(),
        description: "Invalid multiplication proof: claims 3 * 7 = 42".to_string(),
        verification_key: mul_vk_data.clone(),
        proof: proof_to_data(&invalid_proof),
        public_inputs: vec![scalar_to_hex(Scalar::from(42u64))], // Wrong!
        should_verify: false,
    });
    println!("  Generated invalid proof (wrong public input)");

    // =========================================================================
    // Test Vector 2: Mock Spend Circuit
    // =========================================================================
    println!("\nGenerating mock Spend circuit proofs...");

    let spend_circuit = MockSpendCircuit {
        note_value: None,
        note_randomness: None,
        spending_key: None,
        anchor: None,
        value_commitment: None,
        nullifier: None,
        rk: None,
    };

    let spend_params = generate_random_parameters::<Bls12, _, _>(spend_circuit.clone(), &mut OsRng)
        .expect("Failed to generate spend parameters");
    let spend_vk_data = vk_to_data(&spend_params.vk);

    // Generate spend proofs for different note values
    let spend_cases = [
        (100u64, 50u64, 7u64, "100 NAM note"),
        (500u64, 100u64, 13u64, "500 NAM note"),
        (1000u64, 200u64, 29u64, "1000 NAM note"),
    ];

    for (i, (value, randomness, key, desc)) in spend_cases.iter().enumerate() {
        let note_value = Scalar::from(*value);
        let note_randomness = Scalar::from(*randomness);
        let spending_key = Scalar::from(*key);

        let value_commitment = note_value + note_randomness;
        let nullifier = spending_key * note_value;
        let rk = spending_key;
        let anchor = Scalar::from(12345u64); // Simplified anchor

        let circuit = MockSpendCircuit {
            note_value: Some(note_value),
            note_randomness: Some(note_randomness),
            spending_key: Some(spending_key),
            anchor: Some(anchor),
            value_commitment: Some(value_commitment),
            nullifier: Some(nullifier),
            rk: Some(rk),
        };

        let proof = create_random_proof(circuit, &spend_params, &mut OsRng)
            .expect("Failed to create spend proof");

        let pvk = prepare_verifying_key(&spend_params.vk);
        let verified = verify_proof(&pvk, &proof, &[anchor, value_commitment, nullifier, rk]);
        assert!(verified.is_ok(), "Spend verification failed for {}", desc);

        all_vectors.push(TestVector {
            name: format!("spend_{}", i + 1),
            description: format!("Spend proof: {}", desc),
            verification_key: spend_vk_data.clone(),
            proof: proof_to_data(&proof),
            public_inputs: vec![
                scalar_to_hex(anchor),
                scalar_to_hex(value_commitment),
                scalar_to_hex(nullifier),
                scalar_to_hex(rk),
            ],
            should_verify: true,
        });

        println!("  Generated spend proof for {}", desc);
    }

    // =========================================================================
    // Test Vector 3: Mock Output Circuit
    // =========================================================================
    println!("\nGenerating mock Output circuit proofs...");

    let output_circuit = MockOutputCircuit {
        note_value: None,
        note_randomness: None,
        recipient_key: None,
        value_commitment: None,
        note_commitment: None,
        ephemeral_key: None,
    };

    let output_params = generate_random_parameters::<Bls12, _, _>(output_circuit.clone(), &mut OsRng)
        .expect("Failed to generate output parameters");
    let output_vk_data = vk_to_data(&output_params.vk);

    let output_cases = [
        (100u64, 25u64, 3u64, "100 NAM output"),
        (250u64, 75u64, 5u64, "250 NAM output"),
        (1000u64, 300u64, 11u64, "1000 NAM output"),
    ];

    for (i, (value, randomness, recipient, desc)) in output_cases.iter().enumerate() {
        let note_value = Scalar::from(*value);
        let note_randomness = Scalar::from(*randomness);
        let recipient_key = Scalar::from(*recipient);

        let value_commitment = note_value + note_randomness;
        let note_commitment = note_value * recipient_key;
        let ephemeral_key = note_randomness;

        let circuit = MockOutputCircuit {
            note_value: Some(note_value),
            note_randomness: Some(note_randomness),
            recipient_key: Some(recipient_key),
            value_commitment: Some(value_commitment),
            note_commitment: Some(note_commitment),
            ephemeral_key: Some(ephemeral_key),
        };

        let proof = create_random_proof(circuit, &output_params, &mut OsRng)
            .expect("Failed to create output proof");

        let pvk = prepare_verifying_key(&output_params.vk);
        let verified = verify_proof(&pvk, &proof, &[value_commitment, note_commitment, ephemeral_key]);
        assert!(verified.is_ok(), "Output verification failed for {}", desc);

        all_vectors.push(TestVector {
            name: format!("output_{}", i + 1),
            description: format!("Output proof: {}", desc),
            verification_key: output_vk_data.clone(),
            proof: proof_to_data(&proof),
            public_inputs: vec![
                scalar_to_hex(value_commitment),
                scalar_to_hex(note_commitment),
                scalar_to_hex(ephemeral_key),
            ],
            should_verify: true,
        });

        println!("  Generated output proof for {}", desc);
    }

    // =========================================================================
    // Test Vector 4: Mock Convert Circuit
    // =========================================================================
    println!("\nGenerating mock Convert circuit proofs...");

    let convert_circuit = MockConvertCircuit {
        input_value: None,
        conversion_rate: None,
        allowed_conversion: None,
        value_commitment: None,
    };

    let convert_params =
        generate_random_parameters::<Bls12, _, _>(convert_circuit.clone(), &mut OsRng)
            .expect("Failed to generate convert parameters");
    let convert_vk_data = vk_to_data(&convert_params.vk);

    let convert_cases = [
        (100u64, 2u64, "100 NAM -> 200 ETH (2x rate)"),
        (500u64, 3u64, "500 NAM -> 1500 ETH (3x rate)"),
    ];

    for (i, (value, rate, desc)) in convert_cases.iter().enumerate() {
        let input_value = Scalar::from(*value);
        let conversion_rate = Scalar::from(*rate);

        let value_commitment = input_value * conversion_rate;
        let allowed_conversion = conversion_rate;

        let circuit = MockConvertCircuit {
            input_value: Some(input_value),
            conversion_rate: Some(conversion_rate),
            allowed_conversion: Some(allowed_conversion),
            value_commitment: Some(value_commitment),
        };

        let proof = create_random_proof(circuit, &convert_params, &mut OsRng)
            .expect("Failed to create convert proof");

        let pvk = prepare_verifying_key(&convert_params.vk);
        let verified = verify_proof(&pvk, &proof, &[allowed_conversion, value_commitment]);
        assert!(verified.is_ok(), "Convert verification failed for {}", desc);

        all_vectors.push(TestVector {
            name: format!("convert_{}", i + 1),
            description: format!("Convert proof: {}", desc),
            verification_key: convert_vk_data.clone(),
            proof: proof_to_data(&proof),
            public_inputs: vec![
                scalar_to_hex(allowed_conversion),
                scalar_to_hex(value_commitment),
            ],
            should_verify: true,
        });

        println!("  Generated convert proof for {}", desc);
    }

    // =========================================================================
    // Write all test vectors to JSON
    // =========================================================================
    let json = serde_json::to_string_pretty(&all_vectors).expect("Failed to serialize");
    fs::write("test_vectors.json", &json).expect("Failed to write test vectors");

    println!("\n=================================================");
    println!("Generated {} test vectors", all_vectors.len());
    println!("Written to: test_vectors.json");
    println!("=================================================");

    // Also generate Solidity-compatible constants
    generate_solidity_constants(&all_vectors);
}

fn generate_solidity_constants(vectors: &[TestVector]) {
    let mut sol_output = String::new();

    sol_output.push_str("// SPDX-License-Identifier: MIT\n");
    sol_output.push_str("// Auto-generated test vectors from Rust Groth16 prover\n");
    sol_output.push_str("pragma solidity ^0.8.24;\n\n");
    sol_output.push_str("library TestVectors {\n");

    for vector in vectors.iter() {
        let name_upper = vector.name.to_uppercase().replace(" ", "_");

        sol_output.push_str(&format!("    // {}: {}\n", vector.name, vector.description));

        // Proof bytes
        let proof_hex = vector.proof.to_solidity_hex();
        sol_output.push_str(&format!(
            "    bytes constant {}_PROOF = hex\"{}\";\n",
            name_upper,
            &proof_hex[2..] // Remove 0x prefix
        ));

        // Public inputs
        for (j, input) in vector.public_inputs.iter().enumerate() {
            sol_output.push_str(&format!(
                "    bytes32 constant {}_INPUT_{} = {};\n",
                name_upper, j, input
            ));
        }

        sol_output.push_str("\n");
    }

    // Add verification key bytes for each circuit type
    let circuit_types = ["multiply", "spend", "output", "convert"];
    for ct in circuit_types.iter() {
        if let Some(vector) = vectors.iter().find(|v| v.name.starts_with(ct)) {
            let vk = &vector.verification_key;
            let name = ct.to_uppercase();

            sol_output.push_str(&format!("    // {} Verification Key\n", name));
            sol_output.push_str(&format!(
                "    bytes constant {}_VK_ALPHA = hex\"{}\";\n",
                name,
                format!("{}{}", vk.alpha.x_hex, vk.alpha.y_hex)
            ));
            sol_output.push_str(&format!(
                "    bytes constant {}_VK_BETA = hex\"{}\";\n",
                name,
                format!("{}{}", vk.beta.x_hex, vk.beta.y_hex)
            ));
            sol_output.push_str(&format!(
                "    bytes constant {}_VK_GAMMA = hex\"{}\";\n",
                name,
                format!("{}{}", vk.gamma.x_hex, vk.gamma.y_hex)
            ));
            sol_output.push_str(&format!(
                "    bytes constant {}_VK_DELTA = hex\"{}\";\n",
                name,
                format!("{}{}", vk.delta.x_hex, vk.delta.y_hex)
            ));

            for (j, ic) in vk.ic.iter().enumerate() {
                sol_output.push_str(&format!(
                    "    bytes constant {}_VK_IC_{} = hex\"{}\";\n",
                    name,
                    j,
                    format!("{}{}", ic.x_hex, ic.y_hex)
                ));
            }
            sol_output.push_str("\n");
        }
    }

    sol_output.push_str("}\n");

    fs::write("TestVectors.sol", &sol_output).expect("Failed to write Solidity file");
    println!("Solidity constants written to: TestVectors.sol");
}
