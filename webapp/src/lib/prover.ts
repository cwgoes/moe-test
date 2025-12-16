// MASP WASM Prover wrapper with Web Worker support
// Loads and initializes the WASM prover module with real Namada MASP parameters
// Proof generation runs in a Web Worker to avoid blocking the UI thread

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

export interface RandomPaymentAddress {
  diversifier: string;
  pk_d: string;
}

// Parameter configuration
// Local paths are tried first, then remote URLs as fallback
const MASP_PARAMS = {
  spend: {
    localPath: '/params/masp-spend.params',
    remoteUrl: 'https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params',
    size: 52_190_167, // ~49.8 MB
    key: 'masp-spend-params',
  },
  output: {
    localPath: '/params/masp-output.params',
    remoteUrl: 'https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params',
    size: 17_201_979, // ~16.4 MB
    key: 'masp-output-params',
  },
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmModule = any;

// Main thread WASM module (for fast utility functions)
let wasmModule: WasmModule | null = null;
let initPromise: Promise<void> | null = null;
let paramsLoaded = false;

// Web Worker for proof generation (to avoid blocking UI)
let proverWorker: Worker | null = null;
let workerReady = false;
let workerInitialized = false; // True only after WASM + params loaded in worker
let workerMessageId = 0;
const pendingWorkerMessages: Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }> = new Map();

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

/**
 * Try to fetch from a URL with proper error handling
 */
async function tryFetch(url: string): Promise<Response | null> {
  try {
    const response = await fetch(url, { mode: 'cors' });
    if (response.ok) {
      return response;
    }
    console.warn(`[MASP] Fetch failed for ${url}: ${response.status} ${response.statusText}`);
    return null;
  } catch (e) {
    console.warn(`[MASP] Fetch error for ${url}:`, e);
    return null;
  }
}

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

  // Try local path first (works when params are in public/params/)
  console.log(`[MASP] Trying local path: ${config.localPath}`);
  let response = await tryFetch(config.localPath);

  // If local fails, try remote (may fail due to CORS)
  if (!response) {
    console.log(`[MASP] Local not found, trying remote: ${config.remoteUrl}`);
    response = await tryFetch(config.remoteUrl);
  }

  if (!response) {
    throw new Error(
      `Failed to download ${name} params. ` +
      `Please download the file manually from:\n` +
      `${config.remoteUrl}\n` +
      `and place it in: public/params/${name === 'spend' ? 'masp-spend.params' : 'masp-output.params'}`
    );
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
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  }
}

/**
 * Send a message to the Web Worker and await the response
 */
function sendWorkerMessage<T>(type: string, data?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!proverWorker) {
      reject(new Error('Worker not initialized'));
      return;
    }

    const id = ++workerMessageId;
    pendingWorkerMessages.set(id, {
      resolve: resolve as (value: unknown) => void,
      reject,
    });

    proverWorker.postMessage({ id, type, data });
  });
}

/**
 * Initialize the Web Worker for proof generation
 */
async function initWorker(): Promise<void> {
  if (proverWorker && workerReady) return;

  return new Promise((resolve, reject) => {
    try {
      proverWorker = new Worker('/wasm/prover-worker.js');

      proverWorker.onmessage = (e) => {
        const { id, type, success, result, error } = e.data;

        // Handle 'ready' message from worker
        if (type === 'ready') {
          console.log('[MASP] Worker is ready');
          workerReady = true;
          resolve();
          return;
        }

        // Handle response to our message
        const pending = pendingWorkerMessages.get(id);
        if (pending) {
          pendingWorkerMessages.delete(id);
          if (success) {
            pending.resolve(result);
          } else {
            pending.reject(new Error(error || 'Worker operation failed'));
          }
        }
      };

      proverWorker.onerror = (err) => {
        console.error('[MASP] Worker error:', err);
        reject(new Error('Worker error: ' + err.message));
      };

      // Wait for ready message with timeout
      setTimeout(() => {
        if (!workerReady) {
          console.warn('[MASP] Worker ready timeout, continuing without worker');
          resolve();
        }
      }, 5000);
    } catch (err) {
      console.warn('[MASP] Failed to create worker, falling back to main thread:', err);
      resolve();
    }
  });
}

export async function initProver(onProgress?: ProgressCallback): Promise<void> {
  if (wasmModule && paramsLoaded) return;

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      console.log('[MASP] Loading WASM module...');

      // Try to initialize Web Worker first
      try {
        await initWorker();
      } catch (err) {
        console.warn('[MASP] Worker initialization failed, using main thread:', err);
      }

      // Load the WASM module on main thread (for utility functions)
      const wasm = await loadWasmModule();

      console.log('[MASP] WASM module loaded, initializing...');

      // Initialize WASM with the binary file
      await wasm.default('/wasm/masp_wasm_bg.wasm');

      console.log('[MASP] WASM binary loaded, calling init...');

      // Initialize panic hook
      try {
        wasm.init();
      } catch {
        console.log('[MASP] init() already called');
      }

      wasmModule = wasm;

      // Try to download and load MASP parameters
      console.log('[MASP] Downloading trusted setup parameters...');
      console.log('[MASP] Note: Parameters are ~66MB total. First load may take a while.');

      try {
        // Download both parameters
        const [spendParams, outputParams] = await Promise.all([
          downloadParams('spend', onProgress),
          downloadParams('output', onProgress),
        ]);

        console.log('[MASP] Loading parameters into prover...');

        // Convert to Uint8Array for WASM
        const spendBytes = new Uint8Array(spendParams);
        const outputBytes = new Uint8Array(outputParams);

        // Load parameters into the main thread WASM prover
        const loadResult = wasm.load_masp_parameters(spendBytes, outputBytes);
        console.log('[MASP] Main thread parameters load result:', JSON.stringify(loadResult));

        // Also load into worker if available
        if (proverWorker && workerReady) {
          try {
            console.log('[MASP] Initializing worker WASM...');
            await sendWorkerMessage('init');
            console.log('[MASP] Worker WASM initialized, loading params...');
            await sendWorkerMessage('loadParams', {
              spendParams: spendBytes,
              outputParams: outputBytes,
            });
            workerInitialized = true;
            console.log('[MASP] Worker fully initialized with parameters');
          } catch (err) {
            console.error('[MASP] Failed to initialize worker, will use main thread:', err);
            workerInitialized = false;
          }
        }

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
        console.log('[MASP] Web Worker available for non-blocking proof generation:', workerInitialized);
      } catch (paramError) {
        console.error('[MASP] Failed to load parameters:', paramError);

        // Provide helpful error message
        const errorMessage = paramError instanceof Error ? paramError.message : String(paramError);

        if (errorMessage.includes('NetworkError') || errorMessage.includes('CORS') || errorMessage.includes('Failed to download')) {
          throw new Error(
            'Failed to load MASP parameters. GitHub does not allow CORS requests.\n\n' +
            'To fix this, download the parameter files manually:\n' +
            '1. Download: https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params\n' +
            '2. Download: https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params\n' +
            '3. Place them in: webapp/public/params/\n' +
            '4. Refresh the page'
          );
        }

        throw paramError;
      }
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

/**
 * Generate shield proof - uses Web Worker if available for non-blocking operation
 */
export async function generateShieldProof(request: ShieldRequest): Promise<OutputProofResult> {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  console.log('[MASP] Generating Output (shield) proof...', request);
  console.log('[MASP] Worker status: proverWorker=%s, workerReady=%s, workerInitialized=%s',
    proverWorker !== null, workerReady, workerInitialized);
  const startTime = performance.now();

  // Try using worker for non-blocking proof generation
  if (proverWorker && workerInitialized) {
    try {
      console.log('[MASP] Sending proof generation request to Web Worker...');
      const result = await sendWorkerMessage<OutputProofResult>('generateOutputProof', request);
      const elapsed = performance.now() - startTime;
      console.log(`[MASP] Shield proof generated via Web Worker in ${(elapsed / 1000).toFixed(2)}s`);
      return result;
    } catch (err) {
      console.error('[MASP] Worker proof generation failed, falling back to main thread:', err);
    }
  } else {
    console.warn('[MASP] Web Worker not available (initialized=%s), using main thread', workerInitialized);
  }

  // Fallback to main thread (will block UI)
  console.warn('[MASP] Generating proof on main thread - UI WILL FREEZE');
  const result = wasmModule.generate_output_proof(request);
  const elapsed = performance.now() - startTime;
  console.log(`[MASP] Shield proof generated on main thread in ${(elapsed / 1000).toFixed(2)}s`);
  return result;
}

/**
 * Generate unshield proof - uses Web Worker if available for non-blocking operation
 */
export async function generateUnshieldProof(request: UnshieldRequest): Promise<SpendProofResult> {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }

  console.log('[MASP] Generating Spend (unshield) proof...', request);
  console.log('[MASP] Worker status: proverWorker=%s, workerReady=%s, workerInitialized=%s',
    proverWorker !== null, workerReady, workerInitialized);
  const startTime = performance.now();

  // Try using worker for non-blocking proof generation
  if (proverWorker && workerInitialized) {
    try {
      console.log('[MASP] Sending proof generation request to Web Worker...');
      const result = await sendWorkerMessage<SpendProofResult>('generateSpendProof', request);
      const elapsed = performance.now() - startTime;
      console.log(`[MASP] Spend proof generated via Web Worker in ${(elapsed / 1000).toFixed(2)}s`);
      return result;
    } catch (err) {
      console.error('[MASP] Worker proof generation failed, falling back to main thread:', err);
    }
  } else {
    console.warn('[MASP] Web Worker not available (initialized=%s), using main thread', workerInitialized);
  }

  // Fallback to main thread (will block UI)
  console.warn('[MASP] Generating proof on main thread - UI WILL FREEZE');
  const result = wasmModule.generate_spend_proof(request);
  const elapsed = performance.now() - startTime;
  console.log(`[MASP] Spend proof generated on main thread in ${(elapsed / 1000).toFixed(2)}s`);
  return result;
}

// Fast utility functions - run on main thread
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

export function generateRandomPaymentAddress(): RandomPaymentAddress {
  if (!wasmModule) {
    throw new Error('Prover not initialized');
  }
  return wasmModule.generate_random_payment_address();
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
