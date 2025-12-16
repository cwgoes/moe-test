// MASP WASM Prover wrapper
// Loads and initializes the WASM prover module with real Namada MASP parameters

export interface OutputProofResult {
  proof: string;
  cv_u: string;
  cv_v: string;
  epk_u: string;
  epk_v: string;
  cm: string;
  success: boolean;
  error?: string;
}

export interface SpendProofResult {
  proof: string;
  rk_u: string;
  rk_v: string;
  cv_u: string;
  cv_v: string;
  anchor: string;
  nf_0: string;
  nf_1: string;
  success: boolean;
  error?: string;
}

// Legacy interface for backwards compatibility
export interface ProofResult {
  proof: string;
  public_inputs: string[];
  success: boolean;
  error?: string;
}

export interface ShieldRequest {
  token_address: string;
  amount: string;
  asset_type: string;
  recipient_diversifier: string;
  recipient_pk_d: string;
  rcm: string;
  esk: string;
  rcv: string;
}

export interface UnshieldRequest {
  amount: string;
  asset_type: string;
  proof_generation_key_ak: string;
  proof_generation_key_nsk: string;
  diversifier: string;
  rcm: string;
  ar: string;
  anchor: string;
  merkle_path: MerkleNode[];
  rcv: string;
}

export interface MerkleNode {
  hash: string;
  is_right: boolean;
}

export interface VerificationKeyData {
  alpha: string;      // G1 point hex
  beta: string;       // G2 point hex
  gamma: string;      // G2 point hex
  delta: string;      // G2 point hex
  ic: string[];       // Array of G1 point hexes
}

export interface MaspInfo {
  version: string;
  implementation: string;
  curve: string;
  proving_system: string;
  circuits: {
    output: { public_inputs: number; description: string };
    spend: { public_inputs: number; description: string };
  };
  initialized: boolean;
  parameter_urls: { spend: string; output: string };
  parameter_sizes: { spend: string; output: string };
}

// Parameter URLs from Namada trusted setup
const MASP_PARAMS = {
  spend: {
    url: 'https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params',
    size: 52_190_167, // ~49.8 MB
    key: 'masp-spend-params',
  },
  output: {
    url: 'https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params',
    size: 17_201_979, // ~16.4 MB
    key: 'masp-output-params',
  },
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmModule = any;

let wasmModule: WasmModule | null = null;
let initPromise: Promise<void> | null = null;
let paramsLoaded = false;

// IndexedDB helper for caching parameters
const DB_NAME = 'masp-params-cache';
const STORE_NAME = 'params';
const DB_VERSION = 1;

async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function getCachedParams(key: string): Promise<ArrayBuffer | null> {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(key);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result || null);
    });
  } catch (e) {
    console.warn('IndexedDB error, cache disabled:', e);
    return null;
  }
}

async function setCachedParams(key: string, data: ArrayBuffer): Promise<void> {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.put(data, key);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  } catch (e) {
    console.warn('IndexedDB cache write failed:', e);
  }
}

interface DownloadProgress {
  loaded: number;
  total: number;
  percent: number;
  file: string;
}

type ProgressCallback = (progress: DownloadProgress) => void;

async function downloadParams(
  name: 'spend' | 'output',
  onProgress?: ProgressCallback
): Promise<ArrayBuffer> {
  const config = MASP_PARAMS[name];

  // Check cache first
  console.log(`[MASP] Checking cache for ${name} params...`);
  const cached = await getCachedParams(config.key);
  if (cached && cached.byteLength > 0) {
    console.log(`[MASP] Found cached ${name} params (${(cached.byteLength / 1024 / 1024).toFixed(1)} MB)`);
    return cached;
  }

  console.log(`[MASP] Downloading ${name} params from ${config.url}...`);

  const response = await fetch(config.url);
  if (!response.ok) {
    throw new Error(`Failed to download ${name} params: ${response.statusText}`);
  }

  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error('No response body reader available');
  }

  const chunks: Uint8Array[] = [];
  let loaded = 0;
  const total = config.size;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    chunks.push(value);
    loaded += value.length;

    if (onProgress) {
      onProgress({
        loaded,
        total,
        percent: Math.round((loaded / total) * 100),
        file: name,
      });
    }
  }

  // Combine chunks into single ArrayBuffer
  const data = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }

  console.log(`[MASP] Downloaded ${name} params (${(loaded / 1024 / 1024).toFixed(1)} MB)`);

  // Cache for future use
  await setCachedParams(config.key, data.buffer);
  console.log(`[MASP] Cached ${name} params to IndexedDB`);

  return data.buffer;
}

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

export async function initProver(onProgress?: ProgressCallback): Promise<void> {
  if (wasmModule && paramsLoaded) return;

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      console.log('[MASP] Loading WASM module...');

      // Load the WASM module using fetch + blob URL approach
      const wasm = await loadWasmModule();

      console.log('[MASP] WASM module loaded, initializing...');

      // Initialize WASM with the binary file
      // Pass the absolute path to the WASM binary
      await wasm.default('/wasm/masp_wasm_bg.wasm');

      console.log('[MASP] WASM binary loaded, calling init...');

      // Initialize panic hook (this is the #[wasm_bindgen(start)] function,
      // but it may already be called automatically)
      try {
        wasm.init();
      } catch {
        // init() might throw if already called via wasm_bindgen(start)
        console.log('[MASP] init() already called');
      }

      wasmModule = wasm;

      // Download and load MASP parameters
      console.log('[MASP] Downloading trusted setup parameters...');

      // Download both parameters (can be done in parallel)
      const [spendParams, outputParams] = await Promise.all([
        downloadParams('spend', onProgress),
        downloadParams('output', onProgress),
      ]);

      console.log('[MASP] Loading parameters into prover...');

      // Convert ArrayBuffer to Uint8Array for WASM
      const spendBytes = new Uint8Array(spendParams);
      const outputBytes = new Uint8Array(outputParams);

      // Load parameters into the WASM prover
      const loadResult = wasm.load_masp_parameters(spendBytes, outputBytes);
      console.log('[MASP] Parameters load result:', JSON.stringify(loadResult));

      paramsLoaded = true;

      // Verify the prover is ready
      const isInit = wasm.is_initialized();
      console.log('[MASP] Prover initialized:', isInit);

      if (!isInit) {
        throw new Error('MASP prover failed to initialize after loading parameters');
      }

      // Get MASP info for logging
      const maspInfo = wasm.get_masp_info() as MaspInfo;
      console.log('[MASP] MASP Info:', JSON.stringify(maspInfo, null, 2));

      console.log('[MASP] MASP WASM prover initialized successfully with real Namada parameters');
    } catch (error) {
      console.error('[MASP] Prover initialization error:', error);
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

export function isProverReady(): boolean {
  return wasmModule !== null && paramsLoaded;
}

export async function generateShieldProof(request: ShieldRequest): Promise<OutputProofResult> {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  console.log('[MASP] Generating Output (shield) proof...', request);
  return wasmModule.generate_output_proof(request);
}

export async function generateUnshieldProof(request: UnshieldRequest): Promise<SpendProofResult> {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  console.log('[MASP] Generating Spend (unshield) proof...', request);
  return wasmModule.generate_spend_proof(request);
}

export function generateRandomness(): string {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.generate_randomness();
}

export function generateDiversifier(): string {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.generate_diversifier();
}

export function deriveAssetType(tokenAddress: string): string {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.derive_asset_type(tokenAddress);
}

export function getOutputVerificationKey(): VerificationKeyData {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.get_output_verification_key();
}

export function getSpendVerificationKey(): VerificationKeyData {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  return wasmModule.get_spend_verification_key();
}

export function getMaspInfo(): MaspInfo | null {
  if (!wasmModule) {
    return null;
  }

  return wasmModule.get_masp_info();
}

// Clear cached parameters (useful for debugging)
export async function clearParamsCache(): Promise<void> {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.clear();
    console.log('[MASP] Parameter cache cleared');
  } catch (e) {
    console.warn('Failed to clear cache:', e);
  }
}
