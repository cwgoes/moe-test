// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BLS12-381 Curve Operations Library
/// @notice Wraps EIP-2537 precompiles for BLS12-381 curve operations
/// @dev Uses Prague hardfork precompiles at addresses 0x0b-0x11
library BLS12381 {
    // EIP-2537 Precompile addresses
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_G2MSM = address(0x0e);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP_TO_G1 = address(0x10);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);

    // Point sizes in bytes
    uint256 internal constant FP_SIZE = 64;  // Fp element padded to 64 bytes
    uint256 internal constant G1_POINT_SIZE = 128;  // 2 * FP_SIZE
    uint256 internal constant G2_POINT_SIZE = 256;  // 4 * FP_SIZE
    uint256 internal constant SCALAR_SIZE = 32;

    // Curve parameters
    // Field modulus p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    // Subgroup order r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    /// @notice G1 point representation (affine coordinates)
    /// @dev Each coordinate is a 48-byte field element, stored in 64 bytes (16 zero prefix + 48 bytes)
    struct G1Point {
        bytes x;  // 64 bytes
        bytes y;  // 64 bytes
    }

    /// @notice G2 point representation (affine coordinates in Fp2)
    /// @dev Each Fp2 element is two 48-byte field elements, stored as (c0, c1) each in 64 bytes
    struct G2Point {
        bytes x;  // 128 bytes (x.c0 || x.c1)
        bytes y;  // 128 bytes (y.c0 || y.c1)
    }

    /// @notice Error when precompile call fails
    error PrecompileCallFailed();

    /// @notice Encodes a G1 point to bytes for precompile input
    /// @param p The G1 point to encode
    /// @return The 128-byte encoding
    function encodeG1(G1Point memory p) internal pure returns (bytes memory) {
        return abi.encodePacked(p.x, p.y);
    }

    /// @notice Encodes a G2 point to bytes for precompile input
    /// @param p The G2 point to encode
    /// @return The 256-byte encoding
    function encodeG2(G2Point memory p) internal pure returns (bytes memory) {
        return abi.encodePacked(p.x, p.y);
    }

    /// @notice Decodes bytes to a G1 point
    /// @param data The 128-byte encoded point
    /// @return p The decoded G1 point
    function decodeG1(bytes memory data) internal pure returns (G1Point memory p) {
        require(data.length == G1_POINT_SIZE, "Invalid G1 point length");
        p.x = new bytes(FP_SIZE);
        p.y = new bytes(FP_SIZE);
        for (uint256 i = 0; i < FP_SIZE; i++) {
            p.x[i] = data[i];
            p.y[i] = data[FP_SIZE + i];
        }
    }

    /// @notice Decodes bytes to a G2 point
    /// @param data The 256-byte encoded point
    /// @return p The decoded G2 point
    function decodeG2(bytes memory data) internal pure returns (G2Point memory p) {
        require(data.length == G2_POINT_SIZE, "Invalid G2 point length");
        p.x = new bytes(G1_POINT_SIZE);
        p.y = new bytes(G1_POINT_SIZE);
        for (uint256 i = 0; i < G1_POINT_SIZE; i++) {
            p.x[i] = data[i];
            p.y[i] = data[G1_POINT_SIZE + i];
        }
    }

    /// @notice Adds two G1 points
    /// @param p1 First G1 point
    /// @param p2 Second G1 point
    /// @return result The sum p1 + p2
    function g1Add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory result) {
        bytes memory input = abi.encodePacked(encodeG1(p1), encodeG1(p2));

        (bool success, bytes memory output) = BLS12_G1ADD.staticcall(input);
        if (!success || output.length != G1_POINT_SIZE) revert PrecompileCallFailed();

        return decodeG1(output);
    }

    /// @notice Computes multi-scalar multiplication in G1
    /// @dev Input is array of (point, scalar) pairs
    /// @param points Array of G1 points
    /// @param scalars Array of 32-byte scalars
    /// @return result The MSM result: sum(scalars[i] * points[i])
    function g1Msm(G1Point[] memory points, bytes32[] memory scalars) internal view returns (G1Point memory result) {
        require(points.length == scalars.length, "Length mismatch");
        require(points.length > 0, "Empty input");

        // Build input: for each pair, 128 bytes (G1) + 32 bytes (scalar)
        bytes memory input = new bytes(points.length * (G1_POINT_SIZE + SCALAR_SIZE));

        uint256 offset = 0;
        for (uint256 i = 0; i < points.length; i++) {
            bytes memory encodedPoint = encodeG1(points[i]);
            for (uint256 j = 0; j < G1_POINT_SIZE; j++) {
                input[offset + j] = encodedPoint[j];
            }
            offset += G1_POINT_SIZE;

            bytes32 scalar = scalars[i];
            for (uint256 j = 0; j < SCALAR_SIZE; j++) {
                input[offset + j] = scalar[j];
            }
            offset += SCALAR_SIZE;
        }

        (bool success, bytes memory output) = BLS12_G1MSM.staticcall(input);
        if (!success || output.length != G1_POINT_SIZE) revert PrecompileCallFailed();

        return decodeG1(output);
    }

    /// @notice Adds two G2 points
    /// @param p1 First G2 point
    /// @param p2 Second G2 point
    /// @return result The sum p1 + p2
    function g2Add(G2Point memory p1, G2Point memory p2) internal view returns (G2Point memory result) {
        bytes memory input = abi.encodePacked(encodeG2(p1), encodeG2(p2));

        (bool success, bytes memory output) = BLS12_G2ADD.staticcall(input);
        if (!success || output.length != G2_POINT_SIZE) revert PrecompileCallFailed();

        return decodeG2(output);
    }

    /// @notice Performs pairing check: e(p1[0], p2[0]) * ... * e(p1[n], p2[n]) == 1
    /// @param g1Points Array of G1 points
    /// @param g2Points Array of G2 points
    /// @return success True if the pairing product equals 1 (identity in GT)
    function pairingCheck(G1Point[] memory g1Points, G2Point[] memory g2Points) internal view returns (bool success) {
        require(g1Points.length == g2Points.length, "Length mismatch");
        require(g1Points.length > 0, "Empty input");

        // Build input: for each pair, 128 bytes (G1) + 256 bytes (G2)
        bytes memory input = new bytes(g1Points.length * (G1_POINT_SIZE + G2_POINT_SIZE));

        uint256 offset = 0;
        for (uint256 i = 0; i < g1Points.length; i++) {
            bytes memory encodedG1 = encodeG1(g1Points[i]);
            bytes memory encodedG2 = encodeG2(g2Points[i]);

            for (uint256 j = 0; j < G1_POINT_SIZE; j++) {
                input[offset + j] = encodedG1[j];
            }
            offset += G1_POINT_SIZE;

            for (uint256 j = 0; j < G2_POINT_SIZE; j++) {
                input[offset + j] = encodedG2[j];
            }
            offset += G2_POINT_SIZE;
        }

        (bool callSuccess, bytes memory output) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!callSuccess || output.length != 32) revert PrecompileCallFailed();

        // Result is 1 if pairing check passes (product equals identity)
        return output[31] == 0x01;
    }

    /// @notice Negates a G1 point by negating the y-coordinate
    /// @dev For BLS12-381, negation means y' = p - y where p is the field modulus
    /// @param p The point to negate
    /// @return The negated point
    function g1Negate(G1Point memory p) internal pure returns (G1Point memory) {
        // BLS12-381 field modulus p
        bytes memory fieldModulus = hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

        // Check if point is the identity (both coordinates zero)
        bool isIdentity = true;
        for (uint256 i = 0; i < FP_SIZE; i++) {
            if (p.x[i] != 0 || p.y[i] != 0) {
                isIdentity = false;
                break;
            }
        }
        if (isIdentity) return p;

        // Negate y-coordinate: y' = p - y
        bytes memory negY = new bytes(FP_SIZE);
        uint256 borrow = 0;

        // Subtract from right to left (least significant byte first for the actual coordinate)
        for (uint256 i = FP_SIZE; i > 0; i--) {
            uint256 idx = i - 1;
            uint256 a = uint8(fieldModulus[idx]);
            uint256 b = uint8(p.y[idx]) + borrow;

            if (a >= b) {
                negY[idx] = bytes1(uint8(a - b));
                borrow = 0;
            } else {
                negY[idx] = bytes1(uint8(256 + a - b));
                borrow = 1;
            }
        }

        return G1Point(p.x, negY);
    }

    /// @notice Negates a G2 point by negating the y-coordinate
    /// @param p The point to negate
    /// @return The negated point
    function g2Negate(G2Point memory p) internal pure returns (G2Point memory) {
        // BLS12-381 field modulus p (twice, for Fp2 elements)
        bytes memory fieldModulus = hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

        // Check if point is the identity
        bool isIdentity = true;
        for (uint256 i = 0; i < G1_POINT_SIZE; i++) {
            if (p.x[i] != 0 || p.y[i] != 0) {
                isIdentity = false;
                break;
            }
        }
        if (isIdentity) return p;

        // Negate y-coordinate (both Fp elements in Fp2)
        bytes memory negY = new bytes(G1_POINT_SIZE);

        // Negate first Fp element (y.c0)
        uint256 borrow = 0;
        for (uint256 i = FP_SIZE; i > 0; i--) {
            uint256 idx = i - 1;
            uint256 a = uint8(fieldModulus[idx]);
            uint256 b = uint8(p.y[idx]) + borrow;

            if (a >= b) {
                negY[idx] = bytes1(uint8(a - b));
                borrow = 0;
            } else {
                negY[idx] = bytes1(uint8(256 + a - b));
                borrow = 1;
            }
        }

        // Negate second Fp element (y.c1)
        borrow = 0;
        for (uint256 i = FP_SIZE; i > 0; i--) {
            uint256 idx = i - 1;
            uint256 a = uint8(fieldModulus[idx]);
            uint256 b = uint8(p.y[FP_SIZE + idx]) + borrow;

            if (a >= b) {
                negY[FP_SIZE + idx] = bytes1(uint8(a - b));
                borrow = 0;
            } else {
                negY[FP_SIZE + idx] = bytes1(uint8(256 + a - b));
                borrow = 1;
            }
        }

        return G2Point(p.x, negY);
    }
}
