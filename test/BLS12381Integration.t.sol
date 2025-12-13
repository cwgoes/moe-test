// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BLS12381} from "../src/BLS12381.sol";

/// @title BLS12-381 Precompile Integration Tests
/// @notice Tests that exercise the actual EIP-2537 precompiles
/// @dev Requires Prague hardfork EVM (Anvil with --hardfork prague or foundry.toml evm_version = "prague")
contract BLS12381IntegrationTest is Test {
    // BLS12-381 G1 Generator point
    bytes constant G1_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // BLS12-381 G2 Generator point
    bytes constant G2_GENERATOR_X = hex"00000000000000000000000000000000"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"00000000000000000000000000000000"
        hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_GENERATOR_Y = hex"00000000000000000000000000000000"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"00000000000000000000000000000000"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // Negated G1 Generator (for pairing tests)
    // -G1 has the same x but negated y: y' = p - y
    bytes constant G1_GENERATOR_NEG_Y = hex"00000000000000000000000000000000"
        hex"114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// @notice Test G1 point addition: G + G = 2G
    function test_G1Add() public view {
        BLS12381.G1Point memory g = _getG1Generator();

        // Add G + G
        BLS12381.G1Point memory result = BLS12381.g1Add(g, g);

        // Result should be 2G (a valid point, not identity)
        // Verify result is not identity (all zeros)
        bool isNotIdentity = false;
        for (uint256 i = 0; i < 64; i++) {
            if (result.x[i] != 0 || result.y[i] != 0) {
                isNotIdentity = true;
                break;
            }
        }
        assertTrue(isNotIdentity, "2G should not be identity");

        // Result should be different from G
        assertFalse(
            keccak256(result.x) == keccak256(g.x) && keccak256(result.y) == keccak256(g.y),
            "2G should be different from G"
        );
    }

    /// @notice Test G1 MSM: 2 * G = G + G
    function test_G1Msm() public view {
        BLS12381.G1Point memory g = _getG1Generator();

        // Compute 2*G via MSM
        BLS12381.G1Point[] memory points = new BLS12381.G1Point[](1);
        points[0] = g;
        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = bytes32(uint256(2));

        BLS12381.G1Point memory msmResult = BLS12381.g1Msm(points, scalars);

        // Compute G + G via addition
        BLS12381.G1Point memory addResult = BLS12381.g1Add(g, g);

        // Results should match
        assertEq(keccak256(msmResult.x), keccak256(addResult.x), "MSM x should equal add x");
        assertEq(keccak256(msmResult.y), keccak256(addResult.y), "MSM y should equal add y");
    }

    /// @notice Test G2 point addition: G2 + G2 = 2*G2
    function test_G2Add() public view {
        BLS12381.G2Point memory g2 = _getG2Generator();

        // Add G2 + G2
        BLS12381.G2Point memory result = BLS12381.g2Add(g2, g2);

        // Result should be 2*G2 (a valid point, not identity)
        bool isNotIdentity = false;
        for (uint256 i = 0; i < 128; i++) {
            if (result.x[i] != 0 || result.y[i] != 0) {
                isNotIdentity = true;
                break;
            }
        }
        assertTrue(isNotIdentity, "2*G2 should not be identity");
    }

    /// @notice Test pairing check: e(G1, G2) * e(-G1, G2) = 1
    /// @dev This tests that e(P, Q) * e(-P, Q) = e(P-P, Q) = e(O, Q) = 1
    function test_PairingCheckBasic() public view {
        BLS12381.G1Point memory g1 = _getG1Generator();
        BLS12381.G2Point memory g2 = _getG2Generator();
        BLS12381.G1Point memory negG1 = BLS12381.g1Negate(g1);

        BLS12381.G1Point[] memory g1Points = new BLS12381.G1Point[](2);
        BLS12381.G2Point[] memory g2Points = new BLS12381.G2Point[](2);

        g1Points[0] = g1;
        g2Points[0] = g2;
        g1Points[1] = negG1;
        g2Points[1] = g2;

        // e(G1, G2) * e(-G1, G2) should equal 1
        bool result = BLS12381.pairingCheck(g1Points, g2Points);
        assertTrue(result, "Pairing check should pass for e(G, G2) * e(-G, G2)");
    }

    /// @notice Test that pairing check fails for non-matching pairs
    /// @dev e(G1, G2) * e(G1, G2) != 1 (it equals e(G1, G2)^2)
    function test_PairingCheckFailsForNonMatchingPairs() public view {
        BLS12381.G1Point memory g1 = _getG1Generator();
        BLS12381.G2Point memory g2 = _getG2Generator();

        BLS12381.G1Point[] memory g1Points = new BLS12381.G1Point[](2);
        BLS12381.G2Point[] memory g2Points = new BLS12381.G2Point[](2);

        // Same point twice - e(G1, G2)^2 != 1
        g1Points[0] = g1;
        g2Points[0] = g2;
        g1Points[1] = g1;
        g2Points[1] = g2;

        bool result = BLS12381.pairingCheck(g1Points, g2Points);
        assertFalse(result, "Pairing check should fail for e(G, G2) * e(G, G2)");
    }

    /// @notice Test identity point behavior in pairing
    /// @dev e(O, G2) = 1 for any G2 point, where O is the identity in G1
    function test_PairingWithIdentity() public view {
        BLS12381.G1Point memory identity;
        identity.x = new bytes(64);
        identity.y = new bytes(64);

        BLS12381.G2Point memory g2 = _getG2Generator();

        BLS12381.G1Point[] memory g1Points = new BLS12381.G1Point[](1);
        BLS12381.G2Point[] memory g2Points = new BLS12381.G2Point[](1);

        g1Points[0] = identity;
        g2Points[0] = g2;

        // e(O, G2) should equal 1
        bool result = BLS12381.pairingCheck(g1Points, g2Points);
        assertTrue(result, "Pairing with identity should equal 1");
    }

    /// @notice Test MSM with multiple points
    function test_G1MsmMultiplePoints() public view {
        BLS12381.G1Point memory g = _getG1Generator();

        // Compute 3*G + 2*G = 5*G via MSM
        BLS12381.G1Point[] memory points = new BLS12381.G1Point[](2);
        points[0] = g;
        points[1] = g;
        bytes32[] memory scalars = new bytes32[](2);
        scalars[0] = bytes32(uint256(3));
        scalars[1] = bytes32(uint256(2));

        BLS12381.G1Point memory msmResult = BLS12381.g1Msm(points, scalars);

        // Compare with 5*G computed directly
        BLS12381.G1Point[] memory singlePoint = new BLS12381.G1Point[](1);
        singlePoint[0] = g;
        bytes32[] memory singleScalar = new bytes32[](1);
        singleScalar[0] = bytes32(uint256(5));

        BLS12381.G1Point memory directResult = BLS12381.g1Msm(singlePoint, singleScalar);

        assertEq(keccak256(msmResult.x), keccak256(directResult.x), "MSM multi-point x should equal direct");
        assertEq(keccak256(msmResult.y), keccak256(directResult.y), "MSM multi-point y should equal direct");
    }

    /// @notice Test scalar multiplication by 0 gives identity
    function test_G1MsmWithZeroScalar() public view {
        BLS12381.G1Point memory g = _getG1Generator();

        BLS12381.G1Point[] memory points = new BLS12381.G1Point[](1);
        points[0] = g;
        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = bytes32(uint256(0));

        BLS12381.G1Point memory result = BLS12381.g1Msm(points, scalars);

        // 0*G should be identity (all zeros)
        for (uint256 i = 0; i < 64; i++) {
            assertEq(uint8(result.x[i]), 0, "0*G x should be zero");
            assertEq(uint8(result.y[i]), 0, "0*G y should be zero");
        }
    }

    // ============ Helper Functions ============

    function _getG1Generator() internal pure returns (BLS12381.G1Point memory) {
        BLS12381.G1Point memory point;
        point.x = G1_GENERATOR_X;
        point.y = G1_GENERATOR_Y;
        return point;
    }

    function _getG2Generator() internal pure returns (BLS12381.G2Point memory) {
        BLS12381.G2Point memory point;
        point.x = G2_GENERATOR_X;
        point.y = G2_GENERATOR_Y;
        return point;
    }
}
