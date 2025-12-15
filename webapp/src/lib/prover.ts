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

interface WasmExports {
  init: () => void;
  init_prover: () => { success: boolean; message: string };
  generate_shield_proof: (request: ShieldRequest) => ProofResult;
  generate_unshield_proof: (request: UnshieldRequest) => ProofResult;
  generate_randomness: () => string;
  get_output_vk: () => unknown;
  get_spend_vk: () => unknown;
  default: (path: string) => Promise<unknown>;
}

let wasmExports: WasmExports | null = null;
let initPromise: Promise<void> | null = null;

async function loadWasmModule(): Promise<WasmExports> {
  // Fetch the JS wrapper
  const jsResponse = await fetch('/wasm/masp_wasm.js');
  if (!jsResponse.ok) {
    throw new Error(`Failed to fetch WASM JS wrapper: ${jsResponse.statusText}`);
  }
  const jsCode = await jsResponse.text();

  // Create a blob URL for the module
  const blob = new Blob([jsCode], { type: 'application/javascript' });
  const blobUrl = URL.createObjectURL(blob);

  try {
    // Import the module from the blob URL
    const wasm = await import(/* @vite-ignore */ blobUrl);
    return wasm as WasmExports;
  } finally {
    URL.revokeObjectURL(blobUrl);
  }
}

export async function initProver(): Promise<void> {
  if (wasmExports) return;

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      // Load the WASM module dynamically
      const wasm = await loadWasmModule();

      // Initialize WASM with the binary file
      await wasm.default('/wasm/masp_wasm_bg.wasm');

      // Initialize panic hook
      wasm.init();

      // Initialize the prover (generates parameters)
      const result = wasm.init_prover();
      if (!result.success) {
        throw new Error('Prover initialization failed');
      }

      wasmExports = wasm;
      console.log('MASP WASM prover initialized successfully');
    } catch (error) {
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

export function isProverReady(): boolean {
  return wasmExports !== null;
}

export async function generateShieldProof(request: ShieldRequest): Promise<ProofResult> {
  if (!wasmExports) {
    throw new Error('Prover not initialized');
  }

  return wasmExports.generate_shield_proof(request);
}

export async function generateUnshieldProof(request: UnshieldRequest): Promise<ProofResult> {
  if (!wasmExports) {
    throw new Error('Prover not initialized');
  }

  return wasmExports.generate_unshield_proof(request);
}

export function generateRandomness(): string {
  if (!wasmExports) {
    throw new Error('Prover not initialized');
  }

  return wasmExports.generate_randomness();
}

export function getOutputVK(): unknown {
  if (!wasmExports) {
    throw new Error('Prover not initialized');
  }

  return wasmExports.get_output_vk();
}

export function getSpendVK(): unknown {
  if (!wasmExports) {
    throw new Error('Prover not initialized');
  }

  return wasmExports.get_spend_vk();
}
