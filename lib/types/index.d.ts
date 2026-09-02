/**
 * Sensitive-path approval guard: a prepended `tools/pre-execute` policy that
 * turns a write/edit/editor call whose path names a protected location — and a
 * `bash` command that mentions one — into an approval `ask` instead of
 * letting it run. Reads are gated only for key material (SSH private keys and
 * `.pem` certificates), which must never enter model context without
 * approval; reading `.env`/`.git` stays allowed because loading environment
 * files into tools is routine, and the search-layer exclusion in
 * `@deepseek-ai/dsh-tool-fs-search` keeps those paths out of `glob`/`grep`
 * results regardless of this plugin's configuration. Enabled by default;
 * `sensitivePaths: false` makes the guard a true no-op.
 *
 * @module @deepseek-ai/dsh-guard-sensitive-paths
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
/** Cordis plugin name used by loader diagnostics. */
export declare const name = "sensitive-paths";
/** The tool registry service this guard gates (`tools/pre-execute`). */
export declare const inject: string[];
/**
 * The shared sensitive-path definition as glob patterns. Exported for reuse
 * and tests; the guard itself matches with the segment-based
 * {@link isSensitivePath}, and the search-layer exclusion globs in
 * `@deepseek-ai/dsh-tool-fs-search` mirror this set (`!`-prefixed, with
 * `*.pem` widened to match a basename at any depth).
 */
export declare const SENSITIVE_PATH_GLOBS: readonly ["**/.env*", "**/.git/**", "**/id_rsa*", "**/id_ed25519*", "*.pem", "**/.ssh/**"];
/** Plugin config; `sensitivePaths: false` disables the guard entirely. */
export interface Config {
    /** Whether write/edit/editor/bash calls that target a sensitive path require approval (default true). */
    sensitivePaths: boolean;
}
export declare const Config: z<Config>;
/**
 * Whether one path names key material: a basename equal to an SSH private
 * key (`id_rsa`, `id_ed25519`, with an optional dotted suffix) or a basename
 * ending in `.pem`. This is the narrower set read calls are gated on: reading
 * `.env`/`.git` stays allowed (loading environment files into tools is
 * routine), while key material must never enter model context without
 * approval. Backslashes are normalized to `/` first.
 *
 * @param path - the candidate path, in whatever form the tool received it.
 * @returns `true` when the path names key material.
 */
export declare function isKeyMaterialPath(path: string): boolean;
/**
 * Whether one path names a protected sensitive location. Backslashes are
 * normalized to `/` first; absolute and relative forms are tested as given.
 * A match is: a path segment equal to or starting with `.env` (`.env`,
 * `.env.local`), a segment equal to `.git`, a segment equal to `.ssh`, or a
 * basename naming key material (SSH private key or `.pem` certificate).
 *
 * @param path - the candidate path, in whatever form the tool received it.
 * @returns `true` when the path names a sensitive location.
 */
export declare function isSensitivePath(path: string): boolean;
/**
 * Register the pre-execute approval guard, PREPENDED so it runs before any
 * other `tools/pre-execute` listener (including permission grants). A call
 * that targets a sensitive path (or reads key material) returns an approval
 * `ask` with the reason instead of delegating; `sensitivePaths: false`
 * registers nothing.
 *
 * @param ctx - plugin context; the listener is an effect scoped to it.
 * @param config - resolved plugin configuration from schemastery.
 */
export declare function apply(ctx: Context, config: Config): void;
//# sourceMappingURL=index.d.ts.map
