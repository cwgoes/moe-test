// MASP WASM Prover wrapper
// Loads and initializes the WASM prover module

export interface ProofResult {
  proof: string;
  public_inputs: string[];
  success: boolean;
  error?: string;
}

export interface ShieldRequest {
  token_address: string;
  amount: string;
  recipient_pk: string;
  randomness: string;
}

export interface UnshieldRequest {
  nullifier: string;
  merkle_root: string;
  merkle_path: string[];
  note_commitment: string;
  amount: string;
  recipient: string;
  spend_key: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmModule = any;

let wasmModule: WasmModule | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Load the WASM module by fetching the JS wrapper and creating a blob URL.
 * This approach avoids Vite's restriction on importing from /public.
 */
async function loadWasmModule(): Promise<WasmModule> {
  // Fetch the JS wrapper code
  const jsResponse = await fetch('/wasm/masp_wasm.js');
  if (!jsResponse.ok) {
    throw new Error(`Failed to fetch WASM JS wrapper: ${jsResponse.statusText}`);
  }
  let jsCode = await jsResponse.text();

  // The wasm-bindgen generated code uses import.meta.url to locate the WASM file.
  // Since we're loading from a blob URL, we need to patch this to use an absolute URL.
  // Find the line: module_or_path = new URL('masp_wasm_bg.wasm', import.meta.url);
  // And replace it with an absolute path
  jsCode = jsCode.replace(
    /new URL\(['"]masp_wasm_bg\.wasm['"],\s*import\.meta\.url\)/g,
    `'/wasm/masp_wasm_bg.wasm'`
  );

  // Create a blob URL for the module
  const blob = new Blob([jsCode], { type: 'application/javascript' });
  const blobUrl = URL.createObjectURL(blob);

  try {
    // Import the module from the blob URL
    const wasm = await import(/* @vite-ignore */ blobUrl);
    return wasm;
  } finally {
    // Clean up the blob URL after import
    // Note: We delay cleanup slightly to ensure the module is fully loaded
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  }
}

export async function initProver(): Promise<void> {
  if (wasmModule) return;

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      console.log('Loading MASP WASM module...');

      // Load the WASM module using fetch + blob URL approach
      const wasm = await loadWasmModule();

      console.log('WASM module loaded, initializing...');

      // Initialize WASM with the binary file
      // Pass the absolute path to the WASM binary
      await wasm.default('/wasm/masp_wasm_bg.wasm');

      console.log('WASM binary loaded, calling init...');

      // Initialize panic hook (this is the #[wasm_bindgen(start)] function,
      // but it may already be called automatically)
      try {
        wasm.init();
      } catch {
        // init() might throw if already called via wasm_bindgen(start)
        console.log('init() already called');
      }

      console.log('Generating proving parameters (this may take a moment)...');

      // Initialize the prover (generates parameters)
      // This may take several seconds as it generates cryptographic parameters
      // The wasm-bindgen wrapper throws on Rust Err results, so if we get here
      // without an exception, initialization succeeded
      const result = wasm.init_prover();
      console.log('Prover init result:', JSON.stringify(result));

      wasmModule = wasm;
      console.log('MASP WASM prover initialized successfully');
    } catch (error) {
      console.error('Prover initialization error:', error);
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

export function isProverReady(): boolean {
  return wasmModule !== null;
}

export async function generateShieldProof(request: ShieldRequest): Promise<ProofResult> {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.generate_shield_proof(request);
}

export async function generateUnshieldProof(request: UnshieldRequest): Promise<ProofResult> {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.generate_unshield_proof(request);
}

export function generateRandomness(): string {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.generate_randomness();
}

export function getOutputVK(): unknown {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.get_output_vk();
}

export function getSpendVK(): unknown {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.get_spend_vk();
}
