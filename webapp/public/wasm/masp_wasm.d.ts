/* tslint:disable */
/* eslint-disable */

/**
 * Generate random bytes for use as randomness
 */
export function generate_randomness(): string;

/**
 * Generate a shield proof (Output circuit)
 */
export function generate_shield_proof(request_js: any): any;

/**
 * Generate an unshield proof (Spend circuit)
 */
export function generate_unshield_proof(request_js: any): any;

/**
 * Get the verification key for the Output circuit (for contract setup)
 */
export function get_output_vk(): any;

/**
 * Get the verification key for the Spend circuit (for contract setup)
 */
export function get_spend_vk(): any;

export function init(): void;

/**
 * Initialize the prover (generates parameters)
 */
export function init_prover(): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generate_randomness: () => [number, number, number, number];
  readonly generate_shield_proof: (a: any) => [number, number, number];
  readonly generate_unshield_proof: (a: any) => [number, number, number];
  readonly get_output_vk: () => [number, number, number];
  readonly get_spend_vk: () => [number, number, number];
  readonly init: () => void;
  readonly init_prover: () => [number, number, number];
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
