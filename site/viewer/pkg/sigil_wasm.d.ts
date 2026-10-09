/* tslint:disable */
/* eslint-disable */

/**
 * What the input is: `session`, `aibom-v2`, `aibom-v1`, or `unknown`.
 */
export function detect(json: string): string;

/**
 * The HTML of a report's Markdown: only h1 h2 p ul li table thead tbody tr th td strong, no
 * attributes, all text escaped.
 */
export function markdown_html(md: string): string;

/**
 * The Markdown report of an AI-BOM v2.
 */
export function render_aibom_markdown(json: string): string;

/**
 * The Markdown report of a session (validated first) or an AI-BOM v2, whichever `json` is; an
 * error that says what it is otherwise.
 */
export function render_markdown(json: string): string;

/**
 * The Markdown report of a session (validated first).
 */
export function render_session_markdown(json: string): string;

/**
 * The formats this viewer reads.
 */
export function versions(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly detect: (a: number, b: number) => [number, number];
    readonly markdown_html: (a: number, b: number) => [number, number];
    readonly render_aibom_markdown: (a: number, b: number) => [number, number, number, number];
    readonly render_markdown: (a: number, b: number) => [number, number, number, number];
    readonly render_session_markdown: (a: number, b: number) => [number, number, number, number];
    readonly versions: () => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
