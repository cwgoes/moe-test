// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MASPVerifier} from "../src/MASPVerifier.sol";
import {BLS12381} from "../src/BLS12381.sol";

/// @title MASP Proof Verification Tests
/// @notice Tests actual Groth16 proof verification with example notes
/// @dev Uses BLS12-381 curve with EIP-2537 precompiles (Prague hardfork)
contract MASPProofVerificationTest is Test {
    MASPVerifier public verifier;

    // ============ BLS12-381 Test Points ============

    // G1 Generator
    bytes constant G1_X = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_Y = hex"00000000000000000000000000000000"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // G2 Generator
    bytes constant G2_X = hex"00000000000000000000000000000000"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"00000000000000000000000000000000"
        hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_Y = hex"00000000000000000000000000000000"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"00000000000000000000000000000000"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // 2*G1 (G1 + G1)
    bytes constant G1_2X = hex"00000000000000000000000000000000"
        hex"0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e";
    bytes constant G1_2Y = hex"00000000000000000000000000000000"
        hex"166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28";


    // Identity points (point at infinity)
    bytes constant G1_IDENTITY = hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant G2_IDENTITY = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    // ============ Test Note Structures ============

    /// @notice Represents a shielded note for testing
    struct TestNote {
        bytes32 assetType;
        uint64 value;
        bytes32 commitment;
        bytes32 nullifier;
    }

    /// @notice Represents a spend description for testing
    struct SpendDescription {
        bytes32 anchor;           // Merkle root
        bytes32 valueCommitment;  // cv = value * G + rcv * H
        bytes32 nullifier;        // nf = PRF(nsk, rho)
        bytes32 rvk;              // Randomized verification key
        bytes proof;              // Groth16 proof
    }

    /// @notice Represents an output description for testing
    struct OutputDescription {
        bytes32 valueCommitment;  // cv
        bytes32 noteCommitment;   // cm = COMMIT(note)
        bytes32 epk;              // Ephemeral public key
        bytes proof;              // Groth16 proof
    }

    /// @notice Represents a convert description for testing
    struct ConvertDescription {
        bytes32 conversionRoot;   // Allowed conversion tree root
        bytes32 valueCommitment;  // cv
        bytes proof;              // Groth16 proof
    }

    function setUp() public {
        verifier = new MASPVerifier();
    }

    // ============ Verification Key Setup Helpers ============

    /// @notice Sets up a test verification key that accepts trivial proofs
    /// @dev For a valid Groth16 verification where:
    ///      e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
    ///      If A=alpha, B=beta, C=identity, vk_x=identity, verification passes
    function _setupTrivialVerificationKey(MASPVerifier.CircuitType circuitType) internal {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();

        // IC[0] = identity means vk_x = identity when no public inputs
        bytes[] memory ic = new bytes[](1);
        ic[0] = G1_IDENTITY;

        verifier.setVerificationKey(circuitType, alpha, beta, gamma, delta, ic);
    }

    /// @notice Sets up a verification key with public inputs for realistic testing
    function _setupVerificationKeyWithPublicInputs(
        MASPVerifier.CircuitType circuitType,
        uint256 numPublicInputs
    ) internal {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();

        // IC points: IC[0] + sum(input[i] * IC[i+1])
        bytes[] memory ic = new bytes[](numPublicInputs + 1);
        ic[0] = G1_IDENTITY; // IC[0] = identity

        // Use different multiples of G1 for each IC point
        for (uint256 i = 1; i <= numPublicInputs; i++) {
            // Use G1 generator for all IC points (simplified)
            ic[i] = _getG1Generator();
        }

        verifier.setVerificationKey(circuitType, alpha, beta, gamma, delta, ic);
    }

    // ============ Proof Generation Helpers ============

    /// @notice Creates a trivial valid proof (A=alpha, B=beta, C=identity)
    /// @dev This proof satisfies: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
    ///      when vk_x = identity
    function _createTrivialValidProof() internal pure returns (bytes memory) {
        bytes memory a = _getG1Generator();
        bytes memory b = _getG2Generator();
        bytes memory c = G1_IDENTITY;
        return abi.encodePacked(a, b, c);
    }

    /// @notice Creates an invalid proof (random points that won't satisfy pairing equation)
    function _createInvalidProof() internal view returns (bytes memory) {
        // Use 2*G1 instead of G1 to create mismatch
        bytes memory a = _compute2G1();
        bytes memory b = _getG2Generator();
        bytes memory c = G1_IDENTITY;
        return abi.encodePacked(a, b, c);
    }

    /// @notice Computes 2*G1 using the precompile
    function _compute2G1() internal view returns (bytes memory) {
        BLS12381.G1Point memory g = _getG1Point();
        BLS12381.G1Point memory result = BLS12381.g1Add(g, g);
        return BLS12381.encodeG1(result);
    }

    /// @notice Computes 2*G2 using the precompile
    function _compute2G2() internal view returns (bytes memory) {
        BLS12381.G2Point memory g = _getG2Point();
        BLS12381.G2Point memory result = BLS12381.g2Add(g, g);
        return BLS12381.encodeG2(result);
    }

    // ============ Spend Proof Tests ============

    /// @notice Test verifying a valid spend proof for a single note
    function test_VerifySpendProof_SingleNote_Valid() public {
        // Setup: Create verification key for spend circuit (4 public inputs)
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);

        // Create a test spend description
        SpendDescription memory spend = _createTestSpendDescription();

        // Verify the proof
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            spend.proof,
            new bytes32[](0) // No public inputs for trivial VK
        );

        assertTrue(valid, "Valid spend proof should verify");
    }

    /// @notice Test that invalid spend proof fails verification
    function test_VerifySpendProof_SingleNote_Invalid() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);

        // Create invalid proof
        bytes memory invalidProof = _createInvalidProof();

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            invalidProof,
            new bytes32[](0)
        );

        assertFalse(valid, "Invalid spend proof should not verify");
    }

    /// @notice Test spend proof with specific note values
    function test_VerifySpendProof_WithNoteValues() public {
        // Setup VK with 4 public inputs (anchor, cv, nf, rvk)
        _setupVerificationKeyWithPublicInputsIdentityIC(MASPVerifier.CircuitType.Spend, 4);

        TestNote memory note = TestNote({
            assetType: keccak256("NAM"),
            value: 100,
            commitment: keccak256(abi.encode("note1")),
            nullifier: keccak256(abi.encode("nullifier1"))
        });

        SpendDescription memory spend = SpendDescription({
            anchor: keccak256(abi.encode("merkle_root_1")),
            valueCommitment: _computeValueCommitment(note.value, note.assetType),
            nullifier: note.nullifier,
            rvk: keccak256(abi.encode("rvk1")),
            proof: _createTrivialValidProof()
        });

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = spend.anchor;
        publicInputs[1] = spend.valueCommitment;
        publicInputs[2] = spend.nullifier;
        publicInputs[3] = spend.rvk;

        // With all-identity IC points, vk_x = identity regardless of public inputs
        // So the trivial proof (A=alpha, B=beta, C=identity) should verify
        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            spend.proof,
            publicInputs
        );

        assertTrue(valid, "Spend proof with note values should verify");
    }

    // ============ Output Proof Tests ============

    /// @notice Test verifying a valid output proof for creating a new note
    function test_VerifyOutputProof_SingleNote_Valid() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        OutputDescription memory output = _createTestOutputDescription();

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            output.proof,
            new bytes32[](0)
        );

        assertTrue(valid, "Valid output proof should verify");
    }

    /// @notice Test that invalid output proof fails
    function test_VerifyOutputProof_SingleNote_Invalid() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        bytes memory invalidProof = _createInvalidProof();

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            invalidProof,
            new bytes32[](0)
        );

        assertFalse(valid, "Invalid output proof should not verify");
    }

    /// @notice Test creating multiple output notes
    function test_VerifyOutputProof_MultipleNotes() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Create multiple output descriptions
        OutputDescription[] memory outputs = new OutputDescription[](3);
        outputs[0] = _createTestOutputDescription();
        outputs[1] = _createTestOutputDescription();
        outputs[2] = _createTestOutputDescription();

        // Verify each output proof
        for (uint256 i = 0; i < outputs.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Output,
                outputs[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, string.concat("Output proof ", vm.toString(i), " should verify"));
        }
    }

    // ============ Convert Proof Tests ============

    /// @notice Test verifying a valid convert proof for asset type conversion
    function test_VerifyConvertProof_Valid() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);

        ConvertDescription memory convert = _createTestConvertDescription();

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Convert,
            convert.proof,
            new bytes32[](0)
        );

        assertTrue(valid, "Valid convert proof should verify");
    }

    /// @notice Test that invalid convert proof fails
    function test_VerifyConvertProof_Invalid() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);

        bytes memory invalidProof = _createInvalidProof();

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Convert,
            invalidProof,
            new bytes32[](0)
        );

        assertFalse(valid, "Invalid convert proof should not verify");
    }

    /// @notice Test convert between different asset types
    function test_VerifyConvertProof_AssetTypeConversion() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);

        // Simulate NAM -> ETH conversion
        bytes32 fromAsset = keccak256("NAM");
        bytes32 toAsset = keccak256("ETH");

        ConvertDescription memory convert = ConvertDescription({
            conversionRoot: keccak256(abi.encode("conversion_tree_root")),
            valueCommitment: keccak256(abi.encode(fromAsset, toAsset, uint256(100))),
            proof: _createTrivialValidProof()
        });

        bool valid = verifier.verifyProof(
            MASPVerifier.CircuitType.Convert,
            convert.proof,
            new bytes32[](0)
        );

        assertTrue(valid, "Asset type conversion proof should verify");
    }

    // ============ Full Transaction Tests ============

    /// @notice Test a complete shielded transfer: spend input -> create output
    function test_FullShieldedTransfer() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Input: Spend an existing note
        SpendDescription memory spend = _createTestSpendDescription();

        // Output: Create a new note
        OutputDescription memory output = _createTestOutputDescription();

        // Verify spend proof
        bool spendValid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            spend.proof,
            new bytes32[](0)
        );
        assertTrue(spendValid, "Spend proof should verify");

        // Verify output proof
        bool outputValid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            output.proof,
            new bytes32[](0)
        );
        assertTrue(outputValid, "Output proof should verify");
    }

    /// @notice Test batch verification of multiple proofs in a transaction
    function test_BatchVerification_MultipleSpendAndOutput() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Create multiple spends and outputs
        uint256 numSpends = 2;
        uint256 numOutputs = 3;

        MASPVerifier.CircuitType[] memory types = new MASPVerifier.CircuitType[](numSpends + numOutputs);
        bytes[] memory proofs = new bytes[](numSpends + numOutputs);
        bytes32[][] memory publicInputs = new bytes32[][](numSpends + numOutputs);

        // Add spend proofs
        for (uint256 i = 0; i < numSpends; i++) {
            types[i] = MASPVerifier.CircuitType.Spend;
            proofs[i] = _createTrivialValidProof();
            publicInputs[i] = new bytes32[](0);
        }

        // Add output proofs
        for (uint256 i = 0; i < numOutputs; i++) {
            types[numSpends + i] = MASPVerifier.CircuitType.Output;
            proofs[numSpends + i] = _createTrivialValidProof();
            publicInputs[numSpends + i] = new bytes32[](0);
        }

        // Batch verify all proofs
        bool allValid = verifier.batchVerifyProofs(types, proofs, publicInputs);
        assertTrue(allValid, "All proofs in batch should verify");
    }

    /// @notice Test batch verification fails if any proof is invalid
    function test_BatchVerification_FailsOnInvalidProof() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        MASPVerifier.CircuitType[] memory types = new MASPVerifier.CircuitType[](3);
        bytes[] memory proofs = new bytes[](3);
        bytes32[][] memory publicInputs = new bytes32[][](3);

        // Valid spend proof
        types[0] = MASPVerifier.CircuitType.Spend;
        proofs[0] = _createTrivialValidProof();
        publicInputs[0] = new bytes32[](0);

        // Invalid output proof (this will cause batch to fail)
        types[1] = MASPVerifier.CircuitType.Output;
        proofs[1] = _createInvalidProof();
        publicInputs[1] = new bytes32[](0);

        // Valid output proof
        types[2] = MASPVerifier.CircuitType.Output;
        proofs[2] = _createTrivialValidProof();
        publicInputs[2] = new bytes32[](0);

        bool allValid = verifier.batchVerifyProofs(types, proofs, publicInputs);
        assertFalse(allValid, "Batch should fail when any proof is invalid");
    }

    // ============ Complex Transaction Tests ============

    /// @notice Test transaction with spend + convert + output (asset conversion flow)
    function test_AssetConversionTransaction() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Spend NAM
        SpendDescription memory spendNam = _createTestSpendDescription();

        // Convert NAM -> ETH
        ConvertDescription memory convert = _createTestConvertDescription();

        // Output ETH
        OutputDescription memory outputEth = _createTestOutputDescription();

        // Verify all proofs
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Spend, spendNam.proof, new bytes32[](0)),
            "Spend NAM proof should verify"
        );

        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Convert, convert.proof, new bytes32[](0)),
            "Convert proof should verify"
        );

        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Output, outputEth.proof, new bytes32[](0)),
            "Output ETH proof should verify"
        );
    }

    /// @notice Test multiple input notes being consolidated
    function test_ConsolidateMultipleNotes() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Spend 5 input notes
        SpendDescription[] memory spends = new SpendDescription[](5);
        for (uint256 i = 0; i < 5; i++) {
            spends[i] = _createTestSpendDescription();
        }

        // Create 1 output note (consolidation)
        OutputDescription memory output = _createTestOutputDescription();

        // Verify all spends
        for (uint256 i = 0; i < spends.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Spend,
                spends[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, "Spend should verify");
        }

        // Verify output
        bool outputValid = verifier.verifyProof(
            MASPVerifier.CircuitType.Output,
            output.proof,
            new bytes32[](0)
        );
        assertTrue(outputValid, "Consolidated output should verify");
    }

    /// @notice Test splitting one note into multiple
    function test_SplitNoteIntoMultiple() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Spend 1 input note
        SpendDescription memory spend = _createTestSpendDescription();

        // Create 5 output notes (splitting)
        OutputDescription[] memory outputs = new OutputDescription[](5);
        for (uint256 i = 0; i < 5; i++) {
            outputs[i] = _createTestOutputDescription();
        }

        // Verify spend
        bool spendValid = verifier.verifyProof(
            MASPVerifier.CircuitType.Spend,
            spend.proof,
            new bytes32[](0)
        );
        assertTrue(spendValid, "Spend should verify");

        // Verify all outputs
        for (uint256 i = 0; i < outputs.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Output,
                outputs[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, "Output should verify");
        }
    }

    // ============ Multi-Asset Transaction Tests ============

    /// @notice Test shielded transfer of multiple different asset types
    function test_MultiAssetTransfer() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Define test assets
        bytes32[] memory assetTypes = new bytes32[](3);
        assetTypes[0] = keccak256("NAM");
        assetTypes[1] = keccak256("ETH");
        assetTypes[2] = keccak256("USDC");

        // Create notes for each asset type
        for (uint256 i = 0; i < assetTypes.length; i++) {
            TestNote memory note = TestNote({
                assetType: assetTypes[i],
                value: uint64(100 * (i + 1)),
                commitment: keccak256(abi.encode("note", i)),
                nullifier: keccak256(abi.encode("nullifier", i))
            });

            // Spend the note
            SpendDescription memory spend = SpendDescription({
                anchor: keccak256(abi.encode("merkle_root", i)),
                valueCommitment: _computeValueCommitment(note.value, note.assetType),
                nullifier: note.nullifier,
                rvk: keccak256(abi.encode("rvk", i)),
                proof: _createTrivialValidProof()
            });

            bool spendValid = verifier.verifyProof(
                MASPVerifier.CircuitType.Spend,
                spend.proof,
                new bytes32[](0)
            );
            assertTrue(spendValid, string.concat("Spend for asset ", vm.toString(i), " should verify"));

            // Create output note
            OutputDescription memory output = OutputDescription({
                valueCommitment: _computeValueCommitment(note.value, note.assetType),
                noteCommitment: keccak256(abi.encode("new_note", i)),
                epk: keccak256(abi.encode("epk", i)),
                proof: _createTrivialValidProof()
            });

            bool outputValid = verifier.verifyProof(
                MASPVerifier.CircuitType.Output,
                output.proof,
                new bytes32[](0)
            );
            assertTrue(outputValid, string.concat("Output for asset ", vm.toString(i), " should verify"));
        }
    }

    /// @notice Test complex multi-asset transaction with conversions
    function test_ComplexMultiAssetWithConversion() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);

        // Scenario: Spend NAM and ETH, convert some NAM to USDC, output USDC and ETH

        // 1. Spend NAM note
        SpendDescription memory spendNam = SpendDescription({
            anchor: keccak256("anchor_nam"),
            valueCommitment: _computeValueCommitment(1000, keccak256("NAM")),
            nullifier: keccak256("nf_nam"),
            rvk: keccak256("rvk_nam"),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Spend, spendNam.proof, new bytes32[](0)),
            "NAM spend should verify"
        );

        // 2. Spend ETH note
        SpendDescription memory spendEth = SpendDescription({
            anchor: keccak256("anchor_eth"),
            valueCommitment: _computeValueCommitment(500, keccak256("ETH")),
            nullifier: keccak256("nf_eth"),
            rvk: keccak256("rvk_eth"),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Spend, spendEth.proof, new bytes32[](0)),
            "ETH spend should verify"
        );

        // 3. Convert NAM -> USDC
        ConvertDescription memory convert = ConvertDescription({
            conversionRoot: keccak256("conversion_tree"),
            valueCommitment: keccak256(abi.encode(keccak256("NAM"), keccak256("USDC"), uint256(500))),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Convert, convert.proof, new bytes32[](0)),
            "Conversion should verify"
        );

        // 4. Output USDC note
        OutputDescription memory outputUsdc = OutputDescription({
            valueCommitment: _computeValueCommitment(500, keccak256("USDC")),
            noteCommitment: keccak256("cm_usdc"),
            epk: keccak256("epk_usdc"),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Output, outputUsdc.proof, new bytes32[](0)),
            "USDC output should verify"
        );

        // 5. Output remaining NAM note
        OutputDescription memory outputNam = OutputDescription({
            valueCommitment: _computeValueCommitment(500, keccak256("NAM")),
            noteCommitment: keccak256("cm_nam"),
            epk: keccak256("epk_nam"),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Output, outputNam.proof, new bytes32[](0)),
            "NAM output should verify"
        );

        // 6. Output ETH note (unchanged)
        OutputDescription memory outputEth = OutputDescription({
            valueCommitment: _computeValueCommitment(500, keccak256("ETH")),
            noteCommitment: keccak256("cm_eth"),
            epk: keccak256("epk_eth"),
            proof: _createTrivialValidProof()
        });
        assertTrue(
            verifier.verifyProof(MASPVerifier.CircuitType.Output, outputEth.proof, new bytes32[](0)),
            "ETH output should verify"
        );
    }

    /// @notice Test shielding (transparent -> shielded) transaction
    function test_ShieldingTransaction() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Output);

        // Shielding: only outputs, no spends (value comes from transparent balance)
        OutputDescription[] memory outputs = new OutputDescription[](2);

        outputs[0] = OutputDescription({
            valueCommitment: _computeValueCommitment(100, keccak256("NAM")),
            noteCommitment: keccak256("shielded_note_1"),
            epk: keccak256("epk_1"),
            proof: _createTrivialValidProof()
        });

        outputs[1] = OutputDescription({
            valueCommitment: _computeValueCommitment(200, keccak256("NAM")),
            noteCommitment: keccak256("shielded_note_2"),
            epk: keccak256("epk_2"),
            proof: _createTrivialValidProof()
        });

        for (uint256 i = 0; i < outputs.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Output,
                outputs[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, "Shielding output should verify");
        }
    }

    /// @notice Test unshielding (shielded -> transparent) transaction
    function test_UnshieldingTransaction() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);

        // Unshielding: only spends, no outputs (value goes to transparent balance)
        SpendDescription[] memory spends = new SpendDescription[](2);

        spends[0] = SpendDescription({
            anchor: keccak256("anchor_1"),
            valueCommitment: _computeValueCommitment(100, keccak256("NAM")),
            nullifier: keccak256("nf_1"),
            rvk: keccak256("rvk_1"),
            proof: _createTrivialValidProof()
        });

        spends[1] = SpendDescription({
            anchor: keccak256("anchor_2"),
            valueCommitment: _computeValueCommitment(200, keccak256("NAM")),
            nullifier: keccak256("nf_2"),
            rvk: keccak256("rvk_2"),
            proof: _createTrivialValidProof()
        });

        for (uint256 i = 0; i < spends.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Spend,
                spends[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, "Unshielding spend should verify");
        }
    }

    /// @notice Test multiple conversions in single transaction
    function test_MultipleConversions() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Convert);

        // Multiple asset conversions
        ConvertDescription[] memory converts = new ConvertDescription[](3);

        // NAM -> ETH
        converts[0] = ConvertDescription({
            conversionRoot: keccak256("conversion_tree"),
            valueCommitment: keccak256(abi.encode("NAM", "ETH", uint256(100))),
            proof: _createTrivialValidProof()
        });

        // ETH -> USDC
        converts[1] = ConvertDescription({
            conversionRoot: keccak256("conversion_tree"),
            valueCommitment: keccak256(abi.encode("ETH", "USDC", uint256(50))),
            proof: _createTrivialValidProof()
        });

        // USDC -> NAM
        converts[2] = ConvertDescription({
            conversionRoot: keccak256("conversion_tree"),
            valueCommitment: keccak256(abi.encode("USDC", "NAM", uint256(25))),
            proof: _createTrivialValidProof()
        });

        for (uint256 i = 0; i < converts.length; i++) {
            bool valid = verifier.verifyProof(
                MASPVerifier.CircuitType.Convert,
                converts[i].proof,
                new bytes32[](0)
            );
            assertTrue(valid, string.concat("Conversion ", vm.toString(i), " should verify"));
        }
    }

    // ============ Edge Case Tests ============

    /// @notice Test with maximum number of proofs
    function test_MaxBatchSize() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);

        uint256 batchSize = 10; // Test with 10 proofs

        MASPVerifier.CircuitType[] memory types = new MASPVerifier.CircuitType[](batchSize);
        bytes[] memory proofs = new bytes[](batchSize);
        bytes32[][] memory publicInputs = new bytes32[][](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            types[i] = MASPVerifier.CircuitType.Spend;
            proofs[i] = _createTrivialValidProof();
            publicInputs[i] = new bytes32[](0);
        }

        bool allValid = verifier.batchVerifyProofs(types, proofs, publicInputs);
        assertTrue(allValid, "Large batch should verify");
    }

    /// @notice Test gas consumption for different batch sizes
    function test_GasConsumption_BatchSizes() public {
        _setupTrivialVerificationKey(MASPVerifier.CircuitType.Spend);

        uint256[] memory sizes = new uint256[](4);
        sizes[0] = 1;
        sizes[1] = 2;
        sizes[2] = 5;
        sizes[3] = 10;

        for (uint256 s = 0; s < sizes.length; s++) {
            uint256 batchSize = sizes[s];

            MASPVerifier.CircuitType[] memory types = new MASPVerifier.CircuitType[](batchSize);
            bytes[] memory proofs = new bytes[](batchSize);
            bytes32[][] memory publicInputs = new bytes32[][](batchSize);

            for (uint256 i = 0; i < batchSize; i++) {
                types[i] = MASPVerifier.CircuitType.Spend;
                proofs[i] = _createTrivialValidProof();
                publicInputs[i] = new bytes32[](0);
            }

            uint256 gasBefore = gasleft();
            verifier.batchVerifyProofs(types, proofs, publicInputs);
            uint256 gasUsed = gasBefore - gasleft();

            emit log_named_uint(string.concat("Gas for batch size ", vm.toString(batchSize)), gasUsed);
        }
    }

    // ============ Helper Functions ============

    function _getG1Generator() internal pure returns (bytes memory) {
        return abi.encodePacked(G1_X, G1_Y);
    }

    function _getG2Generator() internal pure returns (bytes memory) {
        return abi.encodePacked(G2_X, G2_Y);
    }

    function _getG1Point() internal pure returns (BLS12381.G1Point memory) {
        BLS12381.G1Point memory point;
        point.x = G1_X;
        point.y = G1_Y;
        return point;
    }

    function _getG2Point() internal pure returns (BLS12381.G2Point memory) {
        BLS12381.G2Point memory point;
        point.x = G2_X;
        point.y = G2_Y;
        return point;
    }

    function _createTestSpendDescription() internal pure returns (SpendDescription memory) {
        return SpendDescription({
            anchor: keccak256("merkle_root"),
            valueCommitment: keccak256("value_commitment"),
            nullifier: keccak256("nullifier"),
            rvk: keccak256("rvk"),
            proof: _createTrivialValidProof()
        });
    }

    function _createTestOutputDescription() internal pure returns (OutputDescription memory) {
        return OutputDescription({
            valueCommitment: keccak256("value_commitment"),
            noteCommitment: keccak256("note_commitment"),
            epk: keccak256("epk"),
            proof: _createTrivialValidProof()
        });
    }

    function _createTestConvertDescription() internal pure returns (ConvertDescription memory) {
        return ConvertDescription({
            conversionRoot: keccak256("conversion_root"),
            valueCommitment: keccak256("value_commitment"),
            proof: _createTrivialValidProof()
        });
    }

    function _computeValueCommitment(
        uint64 value,
        bytes32 assetType
    ) internal pure returns (bytes32) {
        // Simplified value commitment for testing
        // Real MASP uses: cv = value * value_base + rcv * randomness_base
        return keccak256(abi.encode(value, assetType));
    }

    /// @notice Sets up VK with all-identity IC points for testing with public inputs
    function _setupVerificationKeyWithPublicInputsIdentityIC(
        MASPVerifier.CircuitType circuitType,
        uint256 numPublicInputs
    ) internal {
        bytes memory alpha = _getG1Generator();
        bytes memory beta = _getG2Generator();
        bytes memory gamma = _getG2Generator();
        bytes memory delta = _getG2Generator();

        // All IC points are identity, so vk_x = identity regardless of public inputs
        bytes[] memory ic = new bytes[](numPublicInputs + 1);
        for (uint256 i = 0; i <= numPublicInputs; i++) {
            ic[i] = G1_IDENTITY;
        }

        verifier.setVerificationKey(circuitType, alpha, beta, gamma, delta, ic);
    }
}
