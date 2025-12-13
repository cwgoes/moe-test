// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";

/// @title Groth16 Verifier for BLS12-381
/// @notice Verifies Groth16 zk-SNARK proofs using EIP-2537 BLS12-381 precompiles
/// @dev Implements the Groth16 verification equation:
///      e(A, B) = e(alpha, beta) * e(sum(a_i * IC_i), gamma) * e(C, delta)
///      Rewritten as: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
///      where vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
library Groth16Verifier {
    using BLS12381 for BLS12381.G1Point;
    using BLS12381 for BLS12381.G2Point;

    /// @notice Groth16 proof structure
    /// @dev Contains three curve points: A in G1, B in G2, C in G1
    struct Proof {
        BLS12381.G1Point a;  // pi_A in G1
        BLS12381.G2Point b;  // pi_B in G2
        BLS12381.G1Point c;  // pi_C in G1
    }

    /// @notice Groth16 verification key structure
    /// @dev Contains curve points from the trusted setup
    struct VerifyingKey {
        BLS12381.G1Point alpha;     // [alpha]_1
        BLS12381.G2Point beta;      // [beta]_2
        BLS12381.G2Point gamma;     // [gamma]_2
        BLS12381.G2Point delta;     // [delta]_2
        BLS12381.G1Point[] ic;      // IC[0..l] where l is number of public inputs
    }

    /// @notice Error when public inputs length doesn't match verification key
    error InvalidPublicInputsLength();

    /// @notice Error when proof verification fails
    error ProofVerificationFailed();

    /// @notice Verifies a Groth16 proof
    /// @param vk The verification key
    /// @param proof The proof to verify
    /// @param publicInputs The public inputs (field elements as bytes32)
    /// @return True if the proof is valid
    function verify(
        VerifyingKey memory vk,
        Proof memory proof,
        bytes32[] memory publicInputs
    ) internal view returns (bool) {
        // Check public inputs length matches IC length - 1
        if (publicInputs.length + 1 != vk.ic.length) revert InvalidPublicInputsLength();

        // Compute vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
        BLS12381.G1Point memory vkX = computeVkX(vk.ic, publicInputs);

        // Prepare points for pairing check
        // e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        BLS12381.G1Point[] memory g1Points = new BLS12381.G1Point[](4);
        BLS12381.G2Point[] memory g2Points = new BLS12381.G2Point[](4);

        // e(A, B)
        g1Points[0] = proof.a;
        g2Points[0] = proof.b;

        // e(-alpha, beta)
        g1Points[1] = BLS12381.g1Negate(vk.alpha);
        g2Points[1] = vk.beta;

        // e(-vk_x, gamma)
        g1Points[2] = BLS12381.g1Negate(vkX);
        g2Points[2] = vk.gamma;

        // e(-C, delta)
        g1Points[3] = BLS12381.g1Negate(proof.c);
        g2Points[3] = vk.delta;

        // Perform the pairing check
        return BLS12381.pairingCheck(g1Points, g2Points);
    }

    /// @notice Computes vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
    /// @dev Uses MSM for efficient multi-scalar multiplication
    /// @param ic The IC points from the verification key
    /// @param publicInputs The public inputs
    /// @return The computed vk_x point
    function computeVkX(
        BLS12381.G1Point[] memory ic,
        bytes32[] memory publicInputs
    ) internal view returns (BLS12381.G1Point memory) {
        if (publicInputs.length == 0) {
            return ic[0];
        }

        // Prepare arrays for MSM: IC[1..l] with their corresponding scalars
        BLS12381.G1Point[] memory points = new BLS12381.G1Point[](publicInputs.length);
        bytes32[] memory scalars = new bytes32[](publicInputs.length);

        for (uint256 i = 0; i < publicInputs.length; i++) {
            points[i] = ic[i + 1];
            scalars[i] = publicInputs[i];
        }

        // Compute sum(publicInputs[i] * IC[i+1]) using MSM
        BLS12381.G1Point memory msmResult = BLS12381.g1Msm(points, scalars);

        // Add IC[0] to the MSM result
        return BLS12381.g1Add(ic[0], msmResult);
    }

    /// @notice Creates a proof from raw bytes
    /// @param proofData The encoded proof (A || B || C)
    /// @return The decoded proof structure
    function decodeProof(bytes memory proofData) internal pure returns (Proof memory) {
        require(proofData.length == 128 + 256 + 128, "Invalid proof length");

        Proof memory proof;

        // Decode A (G1 point, 128 bytes)
        bytes memory aData = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            aData[i] = proofData[i];
        }
        proof.a = BLS12381.decodeG1(aData);

        // Decode B (G2 point, 256 bytes)
        bytes memory bData = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            bData[i] = proofData[128 + i];
        }
        proof.b = BLS12381.decodeG2(bData);

        // Decode C (G1 point, 128 bytes)
        bytes memory cData = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            cData[i] = proofData[384 + i];
        }
        proof.c = BLS12381.decodeG1(cData);

        return proof;
    }
}
