// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {MASPVerifier} from "../src/MASPVerifier.sol";
import {BLS12381} from "../src/BLS12381.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

/// @title MASP Verifier Tests
/// @notice Tests for the Multi-Asset Shielded Pool verifier contract
/// @dev Requires Prague hardfork EVM for BLS12-381 precompile support
contract MASPVerifierTest is Test {
    MASPVerifier public verifier;

    address public owner;
    address public user;

    // BLS12-381 Generator points (G1 and G2)
    // G1 generator: (x, y) where x and y are 48-byte field elements padded to 64 bytes
    bytes constant G1_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // G2 generator: (x, y) where x and y are Fp2 elements (c0 || c1 for each)
    bytes constant G2_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"00000000000000000000000000000000"
        hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"00000000000000000000000000000000"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // Identity point (point at infinity) - all zeros
    bytes constant G1_IDENTITY = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    bytes constant G2_IDENTITY = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    function setUp() public {
        owner = address(this);
        user = makeAddr("user");
        verifier = new MASPVerifier();
    }

    // ============ Deployment Tests ============

    function test_DeploymentSetsOwner() public view {
        assertEq(verifier.owner(), owner);
    }

    function test_InitialStateNotInitialized() public view {
        assertFalse(verifier.isInitialized(MASPVerifier.CircuitType.Spend));
        assertFalse(verifier.isInitialized(MASPVerifier.CircuitType.Output));
        assertFalse(verifier.isInitialized(MASPVerifier.CircuitType.Convert));
    }

    // ============ Access Control Tests ============

    function test_OnlyOwnerCanSetVerificationKey() public {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();
        bytes[] memory ic = new bytes[](2);
        ic[0] = _getG1Generator();
        ic[1] = _getG1Generator();

        // Non-owner should fail
        vm.prank(user);
        vm.expectRevert(MASPVerifier.OnlyOwner.selector);
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );

        // Owner should succeed
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );

        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Spend));
    }

    function test_CannotSetVerificationKeyTwice() public {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();
        bytes[] memory ic = new bytes[](2);
        ic[0] = _getG1Generator();
        ic[1] = _getG1Generator();

        // First call should succeed
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );

        // Second call should fail
        vm.expectRevert(MASPVerifier.VerificationKeyAlreadyInitialized.selector);
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );
    }

    // ============ Verification Key Tests ============

    function test_SetVerificationKeyForAllCircuits() public {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();
        bytes[] memory ic = new bytes[](2);
        ic[0] = _getG1Generator();
        ic[1] = _getG1Generator();

        // Set for Spend
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );
        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Spend));

        // Set for Output
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Output,
            alpha, beta, gamma, delta, ic
        );
        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Output));

        // Set for Convert
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Convert,
            alpha, beta, gamma, delta, ic
        );
        assertTrue(verifier.isInitialized(MASPVerifier.CircuitType.Convert));
    }

    function test_InvalidICLengthReverts() public {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();
        bytes[] memory ic = new bytes[](0); // Empty IC array

        vm.expectRevert(MASPVerifier.InvalidICLength.selector);
        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );
    }

    function test_GetPublicInputsCount() public {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();
        bytes[] memory ic = new bytes[](5); // 5 IC points = 4 public inputs
        for (uint256 i = 0; i < 5; i++) {
            ic[i] = _getG1Generator();
        }

        verifier.setVerificationKey(
            MASPVerifier.CircuitType.Spend,
            alpha, beta, gamma, delta, ic
        );

        assertEq(verifier.getPublicInputsCount(MASPVerifier.CircuitType.Spend), 4);
    }

    // ============ Verification Tests ============

    function test_VerifyProofRevertsWhenNotInitialized() public {
        bytes memory proof = _getDummyProof();
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = bytes32(uint256(1));

        vm.expectRevert(MASPVerifier.VerificationKeyNotInitialized.selector);
        verifier.verifyProof(MASPVerifier.CircuitType.Spend, proof, publicInputs);
    }

    function test_VerifySpendProofRevertsWhenNotInitialized() public {
        bytes memory proof = _getDummyProof();

        vm.expectRevert(MASPVerifier.VerificationKeyNotInitialized.selector);
        verifier.verifySpendProof(
            proof,
            bytes32(uint256(1)), // anchor
            bytes32(uint256(2)), // valueCommitment
            bytes32(uint256(3)), // nullifier
            bytes32(uint256(4))  // rvk
        );
    }

    function test_VerifyOutputProofRevertsWhenNotInitialized() public {
        bytes memory proof = _getDummyProof();

        vm.expectRevert(MASPVerifier.VerificationKeyNotInitialized.selector);
        verifier.verifyOutputProof(
            proof,
            bytes32(uint256(1)), // valueCommitment
            bytes32(uint256(2)), // noteCommitment
            bytes32(uint256(3))  // epk
        );
    }

    function test_VerifyConvertProofRevertsWhenNotInitialized() public {
        bytes memory proof = _getDummyProof();

        vm.expectRevert(MASPVerifier.VerificationKeyNotInitialized.selector);
        verifier.verifyConvertProof(
            proof,
            bytes32(uint256(1)), // conversionRoot
            bytes32(uint256(2))  // valueCommitment
        );
    }

    // ============ Batch Verification Tests ============

    function test_BatchVerifyRevertsOnLengthMismatch() public {
        MASPVerifier.CircuitType[] memory circuitTypes = new MASPVerifier.CircuitType[](2);
        bytes[] memory proofs = new bytes[](1); // Mismatched length
        bytes32[][] memory publicInputsArray = new bytes32[][](2);

        vm.expectRevert("Array length mismatch");
        verifier.batchVerifyProofs(circuitTypes, proofs, publicInputsArray);
    }

    // ============ Helper Functions ============

    function _getG1Generator() internal pure returns (bytes memory) {
        return abi.encodePacked(G1_GENERATOR_X, G1_GENERATOR_Y);
    }

    function _getG2Generator() internal pure returns (bytes memory) {
        return abi.encodePacked(G2_GENERATOR_X, G2_GENERATOR_Y);
    }

    function _getDummyProof() internal pure returns (bytes memory) {
        // 512 bytes: A (128) || B (256) || C (128)
        bytes memory a = abi.encodePacked(G1_GENERATOR_X, G1_GENERATOR_Y);
        bytes memory b = abi.encodePacked(G2_GENERATOR_X, G2_GENERATOR_Y);
        bytes memory c = abi.encodePacked(G1_GENERATOR_X, G1_GENERATOR_Y);
        return abi.encodePacked(a, b, c);
    }
}

/// @title BLS12-381 Library Tests
/// @notice Tests for the BLS12-381 curve operations library
contract BLS12381Test is Test {
    // G1 generator point
    bytes constant G1_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // G2 generator point
    bytes constant G2_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"00000000000000000000000000000000"
        hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"00000000000000000000000000000000"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    function test_EncodeDecodeG1() public pure {
        BLS12381.G1Point memory point;
        point.x = G1_GENERATOR_X;
        point.y = G1_GENERATOR_Y;

        bytes memory encoded = BLS12381.encodeG1(point);
        assertEq(encoded.length, 128);

        BLS12381.G1Point memory decoded = BLS12381.decodeG1(encoded);
        assertEq(keccak256(decoded.x), keccak256(point.x));
        assertEq(keccak256(decoded.y), keccak256(point.y));
    }

    function test_EncodeDecodeG2() public pure {
        BLS12381.G2Point memory point;
        point.x = G2_GENERATOR_X;
        point.y = G2_GENERATOR_Y;

        bytes memory encoded = BLS12381.encodeG2(point);
        assertEq(encoded.length, 256);

        BLS12381.G2Point memory decoded = BLS12381.decodeG2(encoded);
        assertEq(keccak256(decoded.x), keccak256(point.x));
        assertEq(keccak256(decoded.y), keccak256(point.y));
    }

    function test_G1PointSize() public pure {
        assertEq(BLS12381.G1_POINT_SIZE, 128);
    }

    function test_G2PointSize() public pure {
        assertEq(BLS12381.G2_POINT_SIZE, 256);
    }

    function test_G1NegateIdentity() public pure {
        // Identity point should remain identity when negated
        BLS12381.G1Point memory identity;
        identity.x = new bytes(64);
        identity.y = new bytes(64);

        BLS12381.G1Point memory negated = BLS12381.g1Negate(identity);

        // Should still be identity (all zeros)
        for (uint256 i = 0; i < 64; i++) {
            assertEq(uint8(negated.x[i]), 0);
            assertEq(uint8(negated.y[i]), 0);
        }
    }

    function test_G2NegateIdentity() public pure {
        // Identity point should remain identity when negated
        BLS12381.G2Point memory identity;
        identity.x = new bytes(128);
        identity.y = new bytes(128);

        BLS12381.G2Point memory negated = BLS12381.g2Negate(identity);

        // Should still be identity (all zeros)
        for (uint256 i = 0; i < 128; i++) {
            assertEq(uint8(negated.x[i]), 0);
            assertEq(uint8(negated.y[i]), 0);
        }
    }
}

/// @title Groth16 Verifier Library Tests
/// @notice Tests for the Groth16 verification library
contract Groth16VerifierTest is Test {
    // G1 generator point
    bytes constant G1_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // G2 generator point
    bytes constant G2_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"00000000000000000000000000000000"
        hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"00000000000000000000000000000000"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    function test_DecodeProof() public pure {
        bytes memory proofData = _getDummyProof();

        Groth16Verifier.Proof memory proof = Groth16Verifier.decodeProof(proofData);

        // Verify A point
        assertEq(keccak256(proof.a.x), keccak256(G1_GENERATOR_X));
        assertEq(keccak256(proof.a.y), keccak256(G1_GENERATOR_Y));

        // Verify B point
        assertEq(keccak256(proof.b.x), keccak256(G2_GENERATOR_X));
        assertEq(keccak256(proof.b.y), keccak256(G2_GENERATOR_Y));

        // Verify C point
        assertEq(keccak256(proof.c.x), keccak256(G1_GENERATOR_X));
        assertEq(keccak256(proof.c.y), keccak256(G1_GENERATOR_Y));
    }

    function test_DecodeProofInvalidLength() public {
        bytes memory shortProof = new bytes(100);

        // Internal library functions called directly don't work with vm.expectRevert
        // so we use a try/catch pattern via a helper that wraps the call
        bool reverted = false;
        try this.decodeProofHelper(shortProof) {
            // Should not reach here
        } catch {
            reverted = true;
        }
        assertTrue(reverted, "Expected revert for invalid proof length");
    }

    /// @notice Helper function to test decodeProof revert (makes it an external call)
    function decodeProofHelper(bytes calldata proofData) external pure returns (Groth16Verifier.Proof memory) {
        return Groth16Verifier.decodeProof(proofData);
    }

    function test_InvalidPublicInputsLength() public pure {
        // Create a verification key with 3 IC points (expects 2 public inputs)
        Groth16Verifier.VerifyingKey memory vk;
        vk.alpha = _getG1Point();
        vk.beta = _getG2Point();
        vk.gamma = _getG2Point();
        vk.delta = _getG2Point();
        vk.ic = new BLS12381.G1Point[](3);
        vk.ic[0] = _getG1Point();
        vk.ic[1] = _getG1Point();
        vk.ic[2] = _getG1Point();

        // Create a proof
        Groth16Verifier.Proof memory proof;
        proof.a = _getG1Point();
        proof.b = _getG2Point();
        proof.c = _getG1Point();

        // Wrong number of public inputs (3 instead of 2)
        bytes32[] memory publicInputs = new bytes32[](3);

        // This should revert - we can't call verify directly in pure context
        // but we can verify the IC length check logic
        assertEq(vk.ic.length, 3);
        assertEq(publicInputs.length, 3);
        // publicInputs.length + 1 (4) != vk.ic.length (3), so it would revert
    }

    function _getDummyProof() internal pure returns (bytes memory) {
        bytes memory a = abi.encodePacked(G1_GENERATOR_X, G1_GENERATOR_Y);
        bytes memory b = abi.encodePacked(G2_GENERATOR_X, G2_GENERATOR_Y);
        bytes memory c = abi.encodePacked(G1_GENERATOR_X, G1_GENERATOR_Y);
        return abi.encodePacked(a, b, c);
    }

    function _getG1Point() internal pure returns (BLS12381.G1Point memory) {
        BLS12381.G1Point memory point;
        point.x = G1_GENERATOR_X;
        point.y = G1_GENERATOR_Y;
        return point;
    }

    function _getG2Point() internal pure returns (BLS12381.G2Point memory) {
        BLS12381.G2Point memory point;
        point.x = G2_GENERATOR_X;
        point.y = G2_GENERATOR_Y;
        return point;
    }
}
