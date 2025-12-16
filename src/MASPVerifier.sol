// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title MASP Verifier Contract
/// @notice Verifies Namada Multi-Asset Shielded Pool (MASP) proofs on Ethereum
/// @dev Uses BLS12-381 curve operations (EIP-2537) for Groth16 proof verification
/// @custom:reference https://github.com/namada-net/masp
/// @custom:trusted-setup https://github.com/anoma/masp-mpc/releases/tag/namada-trusted-setup
contract MASPVerifier {
    using BLS12381 for BLS12381.G1Point;
    using BLS12381 for BLS12381.G2Point;

    /// @notice Circuit types in MASP
    enum CircuitType {
        Spend,      // Spend circuit - proves spending of a note
        Output,     // Output circuit - proves creation of a note
        Convert     // Convert circuit - proves asset type conversion
    }

    /// @notice Verification keys for each circuit type
    mapping(CircuitType => Groth16Verifier.VerifyingKey) private verifyingKeys;

    /// @notice Whether verification keys have been initialized
    mapping(CircuitType => bool) public isInitialized;

    /// @notice Owner address that can set verification keys
    address public immutable owner;

    /// @notice Emitted when a verification key is set
    event VerificationKeySet(CircuitType indexed circuitType);

    /// @notice Emitted when a proof is verified
    event ProofVerified(CircuitType indexed circuitType, bool success);

    /// @notice Error when caller is not the owner
    error OnlyOwner();

    /// @notice Error when verification key is not initialized
    error VerificationKeyNotInitialized();

    /// @notice Error when verification key is already initialized
    error VerificationKeyAlreadyInitialized();

    /// @notice Error when IC points length is invalid
    error InvalidICLength();

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Sets the verification key for a circuit type
    /// @dev Can only be called once per circuit type by the owner
    /// @param circuitType The circuit type (Spend, Output, or Convert)
    /// @param alpha The alpha G1 point (128 bytes)
    /// @param beta The beta G2 point (256 bytes)
    /// @param gamma The gamma G2 point (256 bytes)
    /// @param delta The delta G2 point (256 bytes)
    /// @param ic The IC G1 points array (each 128 bytes)
    function setVerificationKey(
        CircuitType circuitType,
        bytes calldata alpha,
        bytes calldata beta,
        bytes calldata gamma,
        bytes calldata delta,
        bytes[] calldata ic
    ) external onlyOwner {
        if (isInitialized[circuitType]) revert VerificationKeyAlreadyInitialized();
        if (ic.length < 1) revert InvalidICLength();

        Groth16Verifier.VerifyingKey storage vk = verifyingKeys[circuitType];

        vk.alpha = BLS12381.decodeG1(alpha);
        vk.beta = BLS12381.decodeG2(beta);
        vk.gamma = BLS12381.decodeG2(gamma);
        vk.delta = BLS12381.decodeG2(delta);

        // Clear existing IC points and add new ones
        delete vk.ic;
        for (uint256 i = 0; i < ic.length; i++) {
            vk.ic.push(BLS12381.decodeG1(ic[i]));
        }

        isInitialized[circuitType] = true;
        emit VerificationKeySet(circuitType);
    }

    /// @notice Verifies a MASP proof
    /// @param circuitType The circuit type to verify against
    /// @param proof The Groth16 proof (512 bytes: A || B || C)
    /// @param publicInputs The public inputs for the circuit
    /// @return success True if the proof is valid
    function verifyProof(
        CircuitType circuitType,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool success) {
        if (!isInitialized[circuitType]) revert VerificationKeyNotInitialized();

        Groth16Verifier.Proof memory decodedProof = Groth16Verifier.decodeProof(proof);
        Groth16Verifier.VerifyingKey memory vk = _getVerifyingKey(circuitType);

        return Groth16Verifier.verify(vk, decodedProof, publicInputs);
    }

    /// @notice Batch verifies multiple proofs
    /// @param circuitTypes Array of circuit types
    /// @param proofs Array of proofs
    /// @param publicInputsArray Array of public inputs arrays
    /// @return success True if all proofs are valid
    function batchVerifyProofs(
        CircuitType[] calldata circuitTypes,
        bytes[] calldata proofs,
        bytes32[][] calldata publicInputsArray
    ) external view returns (bool success) {
        require(
            circuitTypes.length == proofs.length && proofs.length == publicInputsArray.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < circuitTypes.length; i++) {
            if (!isInitialized[circuitTypes[i]]) revert VerificationKeyNotInitialized();

            Groth16Verifier.Proof memory decodedProof = Groth16Verifier.decodeProof(proofs[i]);
            Groth16Verifier.VerifyingKey memory vk = _getVerifyingKey(circuitTypes[i]);

            if (!Groth16Verifier.verify(vk, decodedProof, publicInputsArray[i])) {
                return false;
            }
        }

        return true;
    }

    /// @notice Gets the verification key for a circuit type
    /// @dev Internal function to copy storage to memory
    /// @param circuitType The circuit type
    /// @return vk The verification key in memory
    function _getVerifyingKey(CircuitType circuitType)
        internal
        view
        returns (Groth16Verifier.VerifyingKey memory vk)
    {
        Groth16Verifier.VerifyingKey storage storedVk = verifyingKeys[circuitType];

        vk.alpha = storedVk.alpha;
        vk.beta = storedVk.beta;
        vk.gamma = storedVk.gamma;
        vk.delta = storedVk.delta;

        vk.ic = new BLS12381.G1Point[](storedVk.ic.length);
        for (uint256 i = 0; i < storedVk.ic.length; i++) {
            vk.ic[i] = storedVk.ic[i];
        }
    }

    /// @notice Gets the number of public inputs expected for a circuit type
    /// @param circuitType The circuit type
    /// @return The number of public inputs (IC length - 1)
    function getPublicInputsCount(CircuitType circuitType) external view returns (uint256) {
        if (!isInitialized[circuitType]) revert VerificationKeyNotInitialized();
        return verifyingKeys[circuitType].ic.length - 1;
    }

    /// @notice Verifies a Spend proof with structured inputs
    /// @dev Namada MASP Spend circuit public inputs (7 total):
    ///      - rk.u, rk.v (re-randomized verification key coordinates)
    ///      - cv.u, cv.v (value commitment coordinates)
    ///      - anchor (Merkle root)
    ///      - nf[0], nf[1] (nullifier packed into 2 field elements)
    /// @param proof The Groth16 proof
    /// @param rkU Re-randomized key u-coordinate
    /// @param rkV Re-randomized key v-coordinate
    /// @param cvU Value commitment u-coordinate
    /// @param cvV Value commitment v-coordinate
    /// @param anchor The Merkle tree root
    /// @param nf0 First nullifier field element
    /// @param nf1 Second nullifier field element
    /// @return success True if the proof is valid
    function verifySpendProof(
        bytes calldata proof,
        bytes32 rkU,
        bytes32 rkV,
        bytes32 cvU,
        bytes32 cvV,
        bytes32 anchor,
        bytes32 nf0,
        bytes32 nf1
    ) external view returns (bool success) {
        if (!isInitialized[CircuitType.Spend]) revert VerificationKeyNotInitialized();

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = rkU;
        publicInputs[1] = rkV;
        publicInputs[2] = cvU;
        publicInputs[3] = cvV;
        publicInputs[4] = anchor;
        publicInputs[5] = nf0;
        publicInputs[6] = nf1;

        Groth16Verifier.Proof memory decodedProof = Groth16Verifier.decodeProof(proof);
        Groth16Verifier.VerifyingKey memory vk = _getVerifyingKey(CircuitType.Spend);

        return Groth16Verifier.verify(vk, decodedProof, publicInputs);
    }

    /// @notice Verifies an Output proof with structured inputs
    /// @dev Namada MASP Output circuit public inputs (5 total):
    ///      - cv.u, cv.v (value commitment coordinates)
    ///      - epk.u, epk.v (ephemeral public key coordinates)
    ///      - cm (note commitment)
    /// @param proof The Groth16 proof
    /// @param cvU Value commitment u-coordinate
    /// @param cvV Value commitment v-coordinate
    /// @param epkU Ephemeral public key u-coordinate
    /// @param epkV Ephemeral public key v-coordinate
    /// @param cm Note commitment
    /// @return success True if the proof is valid
    function verifyOutputProof(
        bytes calldata proof,
        bytes32 cvU,
        bytes32 cvV,
        bytes32 epkU,
        bytes32 epkV,
        bytes32 cm
    ) external view returns (bool success) {
        if (!isInitialized[CircuitType.Output]) revert VerificationKeyNotInitialized();

        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = cvU;
        publicInputs[1] = cvV;
        publicInputs[2] = epkU;
        publicInputs[3] = epkV;
        publicInputs[4] = cm;

        Groth16Verifier.Proof memory decodedProof = Groth16Verifier.decodeProof(proof);
        Groth16Verifier.VerifyingKey memory vk = _getVerifyingKey(CircuitType.Output);

        return Groth16Verifier.verify(vk, decodedProof, publicInputs);
    }

    /// @notice Verifies a Convert proof with structured inputs
    /// @dev Convert circuit public inputs typically include:
    ///      - Allowed conversion tree root
    ///      - Value commitment
    /// @param proof The Groth16 proof
    /// @param conversionRoot The allowed conversion tree root
    /// @param valueCommitment The value commitment
    /// @return success True if the proof is valid
    function verifyConvertProof(
        bytes calldata proof,
        bytes32 conversionRoot,
        bytes32 valueCommitment
    ) external view returns (bool success) {
        if (!isInitialized[CircuitType.Convert]) revert VerificationKeyNotInitialized();

        bytes32[] memory publicInputs = new bytes32[](2);
        publicInputs[0] = conversionRoot;
        publicInputs[1] = valueCommitment;

        Groth16Verifier.Proof memory decodedProof = Groth16Verifier.decodeProof(proof);
        Groth16Verifier.VerifyingKey memory vk = _getVerifyingKey(CircuitType.Convert);

        return Groth16Verifier.verify(vk, decodedProof, publicInputs);
    }
}
