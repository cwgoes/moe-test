/**
 * MASP Prover Web Worker
 *
 * This worker runs proof generation in a background thread to avoid
 * blocking the main UI thread during the computationally intensive
 * Groth16 proof generation process.
 *
 * Uses wasm-bindgen's no-modules target for importScripts() compatibility.
 */

let wasmModule = null;
let paramsLoaded = false;

// Import the WASM module (no-modules build creates global wasm_bindgen)
importScripts('/wasm-worker/masp_wasm.js');

// Initialize the WASM module
async function initWasm() {
  if (wasmModule) return true;

  try {
    // wasm_bindgen is now a global function after importScripts
    await wasm_bindgen('/wasm-worker/masp_wasm_bg.wasm');
    wasmModule = wasm_bindgen;
    console.log('[Worker] WASM module initialized');
    return true;
  } catch (err) {
    console.error('[Worker] Failed to initialize WASM:', err);
    throw err;
  }
}

// Load MASP parameters
async function loadParameters(spendParams, outputParams) {
  if (!wasmModule) {
    throw new Error('WASM not initialized');
  }

  const result = wasmModule.load_masp_parameters(spendParams, outputParams);
  paramsLoaded = true;
  return result;
}

// Generate output proof (for shielding)
function generateOutputProof(request) {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }
  return wasmModule.generate_output_proof(request);
}

// Generate spend proof (for unshielding)
function generateSpendProof(request) {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }
  return wasmModule.generate_spend_proof(request);
}

// Generate random payment address
function generateRandomPaymentAddress() {
  if (!wasmModule) {
    throw new Error('WASM not initialized');
  }
  return wasmModule.generate_random_payment_address();
}

// Get verification keys
function getOutputVerificationKey() {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }
  return wasmModule.get_output_verification_key();
}

function getSpendVerificationKey() {
  if (!wasmModule || !paramsLoaded) {
    throw new Error('Prover not initialized');
  }
  return wasmModule.get_spend_verification_key();
}

// Handle messages from the main thread
self.onmessage = async function(e) {
  const { id, type, data } = e.data;

  try {
    let result;

    switch (type) {
      case 'init':
        await initWasm();
        result = { success: true };
        break;

      case 'loadParams':
        result = await loadParameters(data.spendParams, data.outputParams);
        break;

      case 'generateOutputProof':
        console.log('[Worker] Starting output proof generation...');
        const outputStart = performance.now();
        result = generateOutputProof(data);
        const outputTime = performance.now() - outputStart;
        console.log(`[Worker] Output proof generated in ${outputTime.toFixed(0)}ms`);
        break;

      case 'generateSpendProof':
        console.log('[Worker] Starting spend proof generation...');
        const spendStart = performance.now();
        result = generateSpendProof(data);
        const spendTime = performance.now() - spendStart;
        console.log(`[Worker] Spend proof generated in ${spendTime.toFixed(0)}ms`);
        break;

      case 'generateRandomPaymentAddress':
        result = generateRandomPaymentAddress();
        break;

      case 'getOutputVK':
        result = getOutputVerificationKey();
        break;

      case 'getSpendVK':
        result = getSpendVerificationKey();
        break;

      case 'isInitialized':
        result = wasmModule !== null && paramsLoaded;
        break;

      default:
        throw new Error(`Unknown message type: ${type}`);
    }

    self.postMessage({ id, success: true, result });
  } catch (err) {
    console.error('[Worker] Error:', err);
    self.postMessage({
      id,
      success: false,
      error: err.message || String(err)
    });
  }
};

// Signal that worker is ready
self.postMessage({ type: 'ready' });
