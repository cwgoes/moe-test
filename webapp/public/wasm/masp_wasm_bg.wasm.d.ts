/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const derive_asset_type: (a: number, b: number) => [number, number, number, number];
export const generate_diversifier: () => [number, number];
export const generate_output_proof: (a: any) => [number, number, number];
export const generate_random_payment_address: () => [number, number, number];
export const generate_randomness: () => [number, number];
export const generate_spend_proof: (a: any) => [number, number, number];
export const get_masp_info: () => [number, number, number];
export const get_native_asset_type: () => [number, number];
export const get_output_verification_key: () => [number, number, number];
export const get_spend_verification_key: () => [number, number, number];
export const init_prover: () => [number, number, number];
export const is_initialized: () => number;
export const load_masp_parameters: (a: number, b: number, c: number, d: number) => [number, number, number];
export const init: () => void;
export const generate_shield_proof: (a: any) => [number, number, number];
export const generate_unshield_proof: (a: any) => [number, number, number];
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
