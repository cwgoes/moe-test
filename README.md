# MASP Verifier

An Ethereum smart contract implementation of a verifier for the [Namada Multi-Asset Shielded Pool (MASP)](https://github.com/namada-net/masp), using the BLS12-381 curve operations available via EIP-2537 precompiles (Prague hardfork).

## Overview

This project implements Groth16 zk-SNARK proof verification for the MASP circuits using the Namada trusted setup ceremony parameters.

### Contracts

- **`BLS12381.sol`** - Library wrapping EIP-2537 BLS12-381 precompiles
- **`Groth16Verifier.sol`** - Generic Groth16 verification library
- **`MASPVerifier.sol`** - MASP-specific verifier with support for Spend, Output, and Convert circuits

### MASP Circuit Types

1. **Spend Circuit** - Proves spending of a shielded note
2. **Output Circuit** - Proves creation of a new shielded note
3. **Convert Circuit** - Proves asset type conversion according to allowed conversion ratios

## Requirements

- [Foundry](https://book.getfoundry.sh/)
- Solidity ^0.8.24
- Ethereum network with Prague hardfork (EIP-2537 BLS12-381 precompiles)

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd masp-verifier

# Install dependencies
forge install
```

## Build

```bash
forge build
```

## Test

```bash
forge test
```

Run with verbose output:

```bash
forge test -vvv
```

## Usage

### Setting Verification Keys

Before verifying proofs, the contract owner must set the verification keys for each circuit type. The verification keys are derived from the [Namada Trusted Setup](https://github.com/anoma/masp-mpc/releases/tag/namada-trusted-setup).

```solidity
// Set verification key for Spend circuit
verifier.setVerificationKey(
    MASPVerifier.CircuitType.Spend,
    alpha,  // G1 point (128 bytes)
    beta,   // G2 point (256 bytes)
    gamma,  // G2 point (256 bytes)
    delta,  // G2 point (256 bytes)
    ic      // Array of G1 points
);
```

### Verifying Proofs

```solidity
// Verify a spend proof
bool valid = verifier.verifySpendProof(
    proof,            // 512 bytes (A || B || C)
    anchor,           // Merkle root
    valueCommitment,  // Value commitment
    nullifier,        // Nullifier
    rvk               // Randomized verification key
);

// Verify an output proof
bool valid = verifier.verifyOutputProof(
    proof,
    valueCommitment,
    noteCommitment,
    epk               // Ephemeral public key
);

// Verify a convert proof
bool valid = verifier.verifyConvertProof(
    proof,
    conversionRoot,   // Allowed conversion tree root
    valueCommitment
);

// Generic verification
bool valid = verifier.verifyProof(
    MASPVerifier.CircuitType.Spend,
    proof,
    publicInputs
);
```

## EIP-2537 BLS12-381 Precompiles

This contract uses the following precompiles introduced in the Prague hardfork:

| Operation | Address | Description |
|-----------|---------|-------------|
| BLS12_G1ADD | 0x0b | G1 point addition |
| BLS12_G1MSM | 0x0c | G1 multi-scalar multiplication |
| BLS12_G2ADD | 0x0d | G2 point addition |
| BLS12_G2MSM | 0x0e | G2 multi-scalar multiplication |
| BLS12_PAIRING_CHECK | 0x0f | Pairing product check |

## Point Encoding

- **G1 Points**: 128 bytes (two 64-byte Fp elements for x, y)
- **G2 Points**: 256 bytes (four 64-byte Fp elements for x.c0, x.c1, y.c0, y.c1)
- **Fp Elements**: 48-byte big-endian integer padded to 64 bytes with 16 leading zeros
- **Proof**: 512 bytes (A || B || C where A, C are G1 and B is G2)

## Trusted Setup

The MASP circuit parameters are generated from the Namada Trusted Setup Ceremony completed on December 21, 2022:

- [Download Parameters](https://github.com/anoma/masp-mpc/releases/tag/namada-trusted-setup)
- [Ceremony Details](https://namada.net/trusted-setup)

Parameter files:
- `masp-spend.params` - Spend circuit parameters
- `masp-output.params` - Output circuit parameters
- `masp-convert.params` - Convert circuit parameters

## References

- [Namada MASP](https://github.com/namada-net/masp)
- [Namada Trusted Setup](https://github.com/anoma/namada-trusted-setup)
- [EIP-2537: Precompile for BLS12-381 curve operations](https://eips.ethereum.org/EIPS/eip-2537)
- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [BLS12-381 Curve](https://hackmd.io/@benjaminion/bls12-381)

## License

MIT
