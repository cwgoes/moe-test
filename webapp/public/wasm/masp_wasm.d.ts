/* tslint:disable */
/* eslint-disable */

/**
 * Derive asset type from token address
 */
export function derive_asset_type(token_address: string): string;

/**
 * Generate a random valid diversifier
 * This tries random diversifiers until finding one that maps to a valid curve point
 */
export function generate_diversifier(): string;

/**
 * Generate an Output proof for shielding tokens
 */
export function generate_output_proof(request_js: any): any;

/**
 * Generate a random valid payment address (for testing)
 * Returns diversifier and pk_d that can be used together for shielding
 */
export function generate_random_payment_address(): any;

/**
 * Generate random scalars for use in proof generation
 */
export function generate_randomness(): string;

export function generate_shield_proof(request_js: any): any;

/**
 * Generate a Spend proof for unshielding tokens
 */
export function generate_spend_proof(request_js: any): any;

export function generate_unshield_proof(request_js: any): any;

/**
 * Get MASP implementation info
 */
export function get_masp_info(): any;

/**
 * Get the default asset type identifier for the native token
 */
export function get_native_asset_type(): string;

/**
 * Get the Output circuit verification key in EIP-2537 format
 */
export function get_output_verification_key(): any;

/**
 * Get the Spend circuit verification key in EIP-2537 format
 */
export function get_spend_verification_key(): any;

export function init(): void;

/**
 * Initialize prover (for backwards compatibility)
 */
export function init_prover(): any;

/**
 * Check if MASP parameters are loaded
 */
export function is_initialized(): boolean;

/**
 * Load MASP parameters from bytes (downloaded by webapp)
 */
export function load_masp_parameters(spend_params_bytes: Uint8Array, output_params_bytes: Uint8Array): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly derive_asset_type: (a: number, b: number) => [number, number, number, number];
  readonly generate_diversifier: () => [number, number];
  readonly generate_output_proof: (a: any) => [number, number, number];
  readonly generate_random_payment_address: () => [number, number, number];
  readonly generate_randomness: () => [number, number];
  readonly generate_spend_proof: (a: any) => [number, number, number];
  readonly get_masp_info: () => [number, number, number];
  readonly get_native_asset_type: () => [number, number];
  readonly get_output_verification_key: () => [number, number, number];
  readonly get_spend_verification_key: () => [number, number, number];
  readonly init: () => void;
  readonly init_prover: () => [number, number, number];
  readonly is_initialized: () => number;
  readonly load_masp_parameters: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly generate_shield_proof: (a: any) => [number, number, number];
  readonly generate_unshield_proof: (a: any) => [number, number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
