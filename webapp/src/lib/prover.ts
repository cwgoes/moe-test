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

export async function initProver(): Promise<void> {
  if (wasmModule) return;

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      console.log('Loading MASP WASM module...');

      // Dynamically import the WASM module
      // Using @vite-ignore to bypass Vite's static analysis
      // @ts-expect-error - dynamic import of runtime module
      const wasm = await import(/* @vite-ignore */ '/wasm/masp_wasm.js');

      console.log('WASM module loaded, initializing...');

      // Initialize WASM with the binary file
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
