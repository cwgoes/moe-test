//! Verify G2 serialization format against known EIP-2537 values

use bls12_381::G2Affine;

fn main() {
    println!("Verifying G2 serialization format against EIP-2537 spec...\n");

    let g2 = G2Affine::generator();

    // Get uncompressed bytes (192 bytes)
    let uncompressed = g2.to_uncompressed();
    let bytes = uncompressed.as_ref();

    println!("Raw uncompressed G2 generator (192 bytes from bls12_381 crate):");
    println!("  bytes[0..48]:    {}", hex::encode(&bytes[0..48]));
    println!("  bytes[48..96]:   {}", hex::encode(&bytes[48..96]));
    println!("  bytes[96..144]:  {}", hex::encode(&bytes[96..144]));
    println!("  bytes[144..192]: {}", hex::encode(&bytes[144..192]));

    // Known EIP-2537 G2 generator values
    // From: https://eips.ethereum.org/EIPS/eip-2537
    let expected_x_c0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    let expected_x_c1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    let expected_y_c0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
    let expected_y_c1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    println!("\nExpected EIP-2537 G2 generator:");
    println!("  x.c0: {}", expected_x_c0);
    println!("  x.c1: {}", expected_x_c1);
    println!("  y.c0: {}", expected_y_c0);
    println!("  y.c1: {}", expected_y_c1);

    // Determine the mapping
    println!("\nMapping analysis:");
    if hex::encode(&bytes[0..48]) == expected_x_c0 {
        println!("  bytes[0..48] = x.c0 ✓");
    } else if hex::encode(&bytes[0..48]) == expected_x_c1 {
        println!("  bytes[0..48] = x.c1 ✓");
    }
    if hex::encode(&bytes[48..96]) == expected_x_c0 {
        println!("  bytes[48..96] = x.c0 ✓");
    } else if hex::encode(&bytes[48..96]) == expected_x_c1 {
        println!("  bytes[48..96] = x.c1 ✓");
    }
    if hex::encode(&bytes[96..144]) == expected_y_c0 {
        println!("  bytes[96..144] = y.c0 ✓");
    } else if hex::encode(&bytes[96..144]) == expected_y_c1 {
        println!("  bytes[96..144] = y.c1 ✓");
    }
    if hex::encode(&bytes[144..192]) == expected_y_c0 {
        println!("  bytes[144..192] = y.c0 ✓");
    } else if hex::encode(&bytes[144..192]) == expected_y_c1 {
        println!("  bytes[144..192] = y.c1 ✓");
    }

    // Now construct the EIP-2537 format
    println!("\nConstructing EIP-2537 format (pad to 64 bytes each component):");

    // Determine actual order from bls12_381 crate
    let is_x_c1_first = hex::encode(&bytes[0..48]) == expected_x_c1;

    if is_x_c1_first {
        println!("  bls12_381 format: x.c1 || x.c0 || y.c1 || y.c0");
        println!("\n  For EIP-2537, need: pad(x.c0) || pad(x.c1) || pad(y.c0) || pad(y.c1)");
        println!("  So we use: pad(bytes[48..96]) || pad(bytes[0..48]) || pad(bytes[144..192]) || pad(bytes[96..144])");
    } else {
        println!("  bls12_381 format: x.c0 || x.c1 || y.c0 || y.c1");
        println!("\n  For EIP-2537, format matches directly!");
    }
}
