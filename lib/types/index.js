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
import z from '@deepseek-ai/schemastery';
/** Cordis plugin name used by loader diagnostics. */
export const name = 'sensitive-paths';
/** The tool registry service this guard gates (`tools/pre-execute`). */
export const inject = ['tools'];
/**
 * The shared sensitive-path definition as glob patterns. Exported for reuse
 * and tests; the guard itself matches with the segment-based
 * {@link isSensitivePath}, and the search-layer exclusion globs in
 * `@deepseek-ai/dsh-tool-fs-search` mirror this set (`!`-prefixed, with
 * `*.pem` widened to match a basename at any depth).
 */
export const SENSITIVE_PATH_GLOBS = [
    '**/.env*',
    '**/.git/**',
    '**/id_rsa*',
    '**/id_ed25519*',
    '*.pem',
    '**/.ssh/**',
];
export const Config = z.object({
    sensitivePaths: z.boolean().default(true),
});
/**
 * Command scan for `bash` arguments: any of a `.env` word, a `.git`
 * directory reference, an SSH private-key name, a `.pem` file, or a
 * `~/.ssh/`-style path in the command string is a sensitive hit.
 */
const SENSITIVE_COMMAND_SCAN = /(\.env\b|\.git[/\\]|id_rsa|id_ed25519|\b\S*\.pem\b|~?\/?\.ssh[/\\])/;
/** Whether a basename names key material: an SSH private key (with an optional dotted suffix) or a `.pem` certificate. */
function isKeyMaterialBasename(basename) {
    return /^id_(rsa|ed25519)(\..*)?$/.test(basename) || basename.endsWith('.pem');
}
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
export function isKeyMaterialPath(path) {
    const normalized = path.replaceAll('\\', '/');
    const segments = normalized.split('/').filter(segment => segment.length > 0);
    if (segments.length === 0) return false;
    return isKeyMaterialBasename(segments[segments.length - 1]);
}
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
/* jscpd:ignore-start -- the guard owns the same policy as the fs-search post-filter; the packages must not depend on each other. */
export function isSensitivePath(path) {
    const normalized = path.replaceAll('\\', '/');
    const segments = normalized.split('/').filter(segment => segment.length > 0);
    if (segments.length === 0) return false;
    for (const segment of segments) {
        if (segment === '.git' || segment === '.ssh' || segment.startsWith('.env')) return true;
    }
    return isKeyMaterialBasename(segments[segments.length - 1]);
}
/* jscpd:ignore-end */
/**
 * The sensitive target one call names: the path argument for `write`/`edit`
 * (`file_path`) and `str_replace_editor` (`path`) gated on the full sensitive
 * set, the `read` `file_path` gated on key material only, or the matched
 * command fragment for `bash`. Every other tool names no target and passes
 * through.
 */
function sensitiveTarget(exec) {
    if (exec.name === 'write' || exec.name === 'edit' || exec.name === 'str_replace_editor') {
        const field = exec.name === 'str_replace_editor' ? 'path' : 'file_path';
        const args = exec.arguments;
        const candidate = typeof args === 'object' && args !== null
            ? args[field]
            : void 0;
        return typeof candidate === 'string' && isSensitivePath(candidate) ? candidate : void 0;
    }
    if (exec.name === 'read') {
        const args = exec.arguments;
        const candidate = typeof args === 'object' && args !== null
            ? args.file_path
            : void 0;
        return typeof candidate === 'string' && isKeyMaterialPath(candidate) ? candidate : void 0;
    }
    if (exec.name === 'bash') {
        const args = exec.arguments;
        const command = typeof args === 'object' && args !== null
            ? args.command
            : void 0;
        if (typeof command !== 'string') return void 0;
        return command.match(SENSITIVE_COMMAND_SCAN)?.[0];
    }
    return void 0;
}
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
export function apply(ctx, config) {
    if (!config.sensitivePaths) return;
    ctx.on('tools/pre-execute', (exec, next) => {
        const target = sensitiveTarget(exec);
        if (target !== void 0) {
            return Promise.resolve({
                kind: 'ask',
                reason: `${exec.name} targets the sensitive path ${target}; approval is required because it matches the sensitive-path policy`,
            });
        }
        return next();
    }, true);
}
//# sourceMappingURL=index.js.map
