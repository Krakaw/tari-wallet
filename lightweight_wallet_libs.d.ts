/* tslint:disable */
/* eslint-disable */
/**
 * Derive a public key from a master key, returning it as a hex string.
 */
export function derive_public_key_hex(master_key: Uint8Array): string;
/**
 * Create a scanner from view key or seed phrase (WASM export)
 * Automatically detects the input type by trying view key first, then seed phrase
 */
export function create_wasm_scanner(data: string): WasmScanner;
/**
 * Initialize HTTP scanner (WASM export) - Returns a Promise
 */
export function initialize_http_scanner(scanner: WasmScanner, base_url: string): Promise<void>;
/**
 * Process HTTP block response with async support (WASM export)
 */
export function process_http_blocks_async(scanner: WasmScanner, http_response_json: string, base_url?: string | null): Promise<string>;
/**
 * Process HTTP block response (WASM export) - LEGACY METHOD for backward compatibility
 */
export function process_http_blocks(scanner: WasmScanner, http_response_json: string): string;
/**
 * Scan block data (WASM export) - LEGACY METHOD for backward compatibility
 */
export function scan_block_data(scanner: WasmScanner, block_data_json: string): string;
/**
 * Scan single block and return only block-specific data (WASM export) - LEGACY METHOD  
 */
export function scan_single_block(scanner: WasmScanner, block_data_json: string): string;
/**
 * Get cumulative scanner statistics (WASM export)
 */
export function get_scanner_stats(scanner: WasmScanner): string;
/**
 * Get scanner state (WASM export)
 */
export function get_scanner_state(scanner: WasmScanner): string;
/**
 * Reset scanner state (WASM export)
 */
export function reset_scanner(scanner: WasmScanner): void;
/**
 * Cleanup old transactions to prevent memory leaks (WASM export)
 */
export function cleanup_scanner_transactions(scanner: WasmScanner, max_transactions: number): void;
/**
 * Get tip info from HTTP scanner (WASM export)
 */
export function get_tip_info(scanner: WasmScanner): Promise<string>;
/**
 * Fetch specific blocks by height using HTTP scanner (WASM export)
 */
export function fetch_blocks_by_heights(scanner: WasmScanner, heights_json: string): Promise<string>;
/**
 * Search for UTXOs by commitment using HTTP scanner (WASM export)
 */
export function search_utxos(scanner: WasmScanner, commitments_json: string): Promise<string>;
/**
 * Create scan config for HTTP scanner (WASM export)
 */
export function create_scan_config(scanner: WasmScanner, start_height: bigint, end_height?: bigint | null): string;
/**
 * Get version information (WASM export)
 */
export function get_version(): string;
/**
 * WASM-compatible wallet scanner
 */
export class WasmScanner {
  private constructor();
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly derive_public_key_hex: (a: number, b: number) => [number, number, number, number];
  readonly __wbg_wasmscanner_free: (a: number, b: number) => void;
  readonly create_wasm_scanner: (a: number, b: number) => [number, number, number];
  readonly initialize_http_scanner: (a: number, b: number, c: number) => any;
  readonly process_http_blocks_async: (a: number, b: number, c: number, d: number, e: number) => any;
  readonly process_http_blocks: (a: number, b: number, c: number) => [number, number, number, number];
  readonly scan_block_data: (a: number, b: number, c: number) => [number, number, number, number];
  readonly scan_single_block: (a: number, b: number, c: number) => [number, number, number, number];
  readonly get_scanner_stats: (a: number) => [number, number, number, number];
  readonly get_scanner_state: (a: number) => [number, number];
  readonly reset_scanner: (a: number) => void;
  readonly cleanup_scanner_transactions: (a: number, b: number) => void;
  readonly get_tip_info: (a: number) => any;
  readonly fetch_blocks_by_heights: (a: number, b: number, c: number) => any;
  readonly search_utxos: (a: number, b: number, c: number) => any;
  readonly create_scan_config: (a: number, b: bigint, c: number, d: bigint) => [number, number, number, number];
  readonly get_version: () => [number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __wbindgen_export_5: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly closure114_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure160_externref_shim: (a: number, b: number, c: any, d: any) => void;
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
