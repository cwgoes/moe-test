// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {MASPVerifier} from "./MASPVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title MASP Pool Contract
/// @notice Multi-Asset Shielded Pool for private ERC20 token transfers
/// @dev Uses BLS12-381 curve operations (EIP-2537) for Groth16 proof verification
contract MASPPool {
    // ============================================================================
    // State Variables
    // ============================================================================

    /// @notice The verifier contract for MASP proofs
    MASPVerifier public immutable verifier;

    /// @notice Mapping of nullifiers that have been spent
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Mapping of note commitments that have been created
    mapping(bytes32 => bool) public commitments;

    /// @notice Array of all commitments (for Merkle tree construction)
    bytes32[] public commitmentHistory;

    /// @notice Current Merkle root
    bytes32 public merkleRoot;

    /// @notice Mapping of historical roots (for valid anchor check)
    mapping(bytes32 => bool) public validRoots;

    /// @notice Merkle tree depth
    uint256 public constant TREE_DEPTH = 20;

    /// @notice Zero values for Merkle tree
    bytes32[21] public zeroValues;

    /// @notice Owner address for setup
    address public immutable owner;

    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when tokens are shielded (deposited)
    event Shield(
        address indexed token,
        uint256 amount,
        bytes32 indexed commitment,
        uint256 leafIndex
    );

    /// @notice Emitted when tokens are unshielded (withdrawn)
    event Unshield(
        address indexed token,
        uint256 amount,
        address indexed recipient,
        bytes32 indexed nullifier
    );

    /// @notice Emitted when a private transfer occurs
    event PrivateTransfer(
        bytes32 indexed nullifier,
        bytes32 indexed newCommitment
    );

    // ============================================================================
    // Errors
    // ============================================================================

    error InvalidProof();
    error NullifierAlreadySpent();
    error InvalidMerkleRoot();
    error TransferFailed();
    error InvalidCommitment();
    error Unauthorized();

    // ============================================================================
    // Constructor
    // ============================================================================

    constructor(address _verifier) {
        verifier = MASPVerifier(_verifier);
        owner = msg.sender;

        // Initialize zero values for Merkle tree
        zeroValues[0] = keccak256(abi.encodePacked(uint256(0)));
        for (uint256 i = 1; i <= TREE_DEPTH; i++) {
            zeroValues[i] = keccak256(abi.encodePacked(zeroValues[i - 1], zeroValues[i - 1]));
        }
        merkleRoot = zeroValues[TREE_DEPTH];
        validRoots[merkleRoot] = true;
    }

    // ============================================================================
    // Shield (Deposit) Functions
    // ============================================================================

    /// @notice Shield (deposit) ERC20 tokens into the pool
    /// @param token The ERC20 token address
    /// @param amount The amount to deposit
    /// @param proof The Groth16 proof for the Output circuit
    /// @param publicInputs The public inputs [valueCommitment, noteCommitment, epk]
    function shield(
        address token,
        uint256 amount,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        require(publicInputs.length == 3, "Invalid public inputs");

        bytes32 noteCommitment = publicInputs[1];

        // Verify the commitment hasn't been used
        if (commitments[noteCommitment]) revert InvalidCommitment();

        // Verify the Output proof
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            proof,
            publicInputs
        );
        if (!valid) revert InvalidProof();

        // Transfer tokens from sender
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();

        // Add commitment to the tree
        uint256 leafIndex = commitmentHistory.length;
        commitments[noteCommitment] = true;
        commitmentHistory.push(noteCommitment);

        // Update Merkle root
        merkleRoot = _computeRoot(noteCommitment, leafIndex);
        validRoots[merkleRoot] = true;

        emit Shield(token, amount, noteCommitment, leafIndex);
    }

    /// @notice Shield ETH into the pool
    /// @param proof The Groth16 proof for the Output circuit
    /// @param publicInputs The public inputs [valueCommitment, noteCommitment, epk]
    function shieldETH(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external payable {
        require(publicInputs.length == 3, "Invalid public inputs");
        require(msg.value > 0, "Must send ETH");

        bytes32 noteCommitment = publicInputs[1];

        // Verify the commitment hasn't been used
        if (commitments[noteCommitment]) revert InvalidCommitment();

        // Verify the Output proof
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            proof,
            publicInputs
        );
        if (!valid) revert InvalidProof();

        // Add commitment to the tree
        uint256 leafIndex = commitmentHistory.length;
        commitments[noteCommitment] = true;
        commitmentHistory.push(noteCommitment);

        // Update Merkle root
        merkleRoot = _computeRoot(noteCommitment, leafIndex);
        validRoots[merkleRoot] = true;

        emit Shield(address(0), msg.value, noteCommitment, leafIndex);
    }

    // ============================================================================
    // Unshield (Withdraw) Functions
    // ============================================================================

    /// @notice Unshield (withdraw) ERC20 tokens from the pool
    /// @param token The ERC20 token address
    /// @param amount The amount to withdraw
    /// @param recipient The recipient address
    /// @param proof The Groth16 proof for the Spend circuit
    /// @param publicInputs The public inputs [anchor, valueCommitment, nullifier, rk]
    function unshield(
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        require(publicInputs.length == 4, "Invalid public inputs");

        bytes32 anchor = publicInputs[0];
        bytes32 nullifier = publicInputs[2];

        // Verify the anchor is valid (historical root)
        if (!validRoots[anchor]) revert InvalidMerkleRoot();

        // Verify the nullifier hasn't been spent
        if (nullifiers[nullifier]) revert NullifierAlreadySpent();

        // Verify the Spend proof
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            proof,
            publicInputs
        );
        if (!valid) revert InvalidProof();

        // Mark nullifier as spent
        nullifiers[nullifier] = true;

        // Transfer tokens to recipient
        bool success = IERC20(token).transfer(recipient, amount);
        if (!success) revert TransferFailed();

        emit Unshield(token, amount, recipient, nullifier);
    }

    /// @notice Unshield ETH from the pool
    /// @param amount The amount to withdraw
    /// @param recipient The recipient address
    /// @param proof The Groth16 proof for the Spend circuit
    /// @param publicInputs The public inputs [anchor, valueCommitment, nullifier, rk]
    function unshieldETH(
        uint256 amount,
        address payable recipient,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        require(publicInputs.length == 4, "Invalid public inputs");

        bytes32 anchor = publicInputs[0];
        bytes32 nullifier = publicInputs[2];

        // Verify the anchor is valid (historical root)
        if (!validRoots[anchor]) revert InvalidMerkleRoot();

        // Verify the nullifier hasn't been spent
        if (nullifiers[nullifier]) revert NullifierAlreadySpent();

        // Verify the Spend proof
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            proof,
            publicInputs
        );
        if (!valid) revert InvalidProof();

        // Mark nullifier as spent
        nullifiers[nullifier] = true;

        // Transfer ETH to recipient
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Unshield(address(0), amount, recipient, nullifier);
    }

    // ============================================================================
    // View Functions
    // ============================================================================

    /// @notice Get the current Merkle root
    function getMerkleRoot() external view returns (bytes32) {
        return merkleRoot;
    }

    /// @notice Get the number of commitments
    function getCommitmentCount() external view returns (uint256) {
        return commitmentHistory.length;
    }

    /// @notice Check if a nullifier has been spent
    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Check if a root is valid (historical)
    function isValidRoot(bytes32 root) external view returns (bool) {
        return validRoots[root];
    }

    // ============================================================================
    // Internal Functions
    // ============================================================================

    /// @notice Compute new Merkle root after inserting a leaf
    /// @param leaf The leaf to insert
    /// @param index The index to insert at
    /// @return The new Merkle root
    function _computeRoot(bytes32 leaf, uint256 index) internal view returns (bytes32) {
        bytes32 current = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (index % 2 == 0) {
                // Left child
                bytes32 right = _getSibling(index, i);
                current = keccak256(abi.encodePacked(current, right));
            } else {
                // Right child
                bytes32 left = _getSibling(index - 1, i);
                current = keccak256(abi.encodePacked(left, current));
            }
            index = index / 2;
        }

        return current;
    }

    /// @notice Get the sibling node at a given level
    /// @param index The index of the node
    /// @param level The level in the tree
    /// @return The sibling hash
    function _getSibling(uint256 index, uint256 level) internal view returns (bytes32) {
        // Calculate the sibling index
        uint256 siblingIndex = index ^ 1;

        // Calculate the actual leaf index at this level
        uint256 levelStartIndex = 1 << level;
        uint256 leafIndex = siblingIndex * levelStartIndex;

        if (leafIndex < commitmentHistory.length) {
            // There's an actual commitment at this position
            // For simplicity, we use the commitment directly
            // In a real implementation, we'd need to track the tree structure
            return commitmentHistory[leafIndex < commitmentHistory.length ? leafIndex : 0];
        } else {
            // Use zero value for empty nodes
            return zeroValues[level];
        }
    }

    // ============================================================================
    // ETH Receive
    // ============================================================================

    receive() external payable {}
}
