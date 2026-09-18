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
 * This guard covers the tool-call surface only. A host-level component that
 * reads or archives files outside the tool loop (the ZCode silent-snapshot
 * class of incident) is out of scope by construction; see the README
 * threat-model boundary.
 *
 * @module @deepseek-ai/dsh-guard-sensitive-paths
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'sensitive-paths'

/** The tool registry service this guard gates (`tools/pre-execute`). */
export const inject = ['tools']

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
] as const

/** Plugin config; `sensitivePaths: false` disables the guard entirely. */
export interface Config {
  /** Whether write/edit/editor/bash calls that target a sensitive path require approval (default true). */
  sensitivePaths: boolean
}

export const Config: z<Config> = z.object({
  sensitivePaths: z.boolean().default(true),
})

/**
 * The sensitive-path category carried in the approval reason. Categories are
 * audit/presentation metadata only — they never change whether a call is
 * gated, only how the ask explains itself (the ZCode incident showed the
 * value of a self-explaining trace when a target silently leaves the
 * machine).
 */
export type SensitiveCategory =
  | 'environment-file'
  | 'git-metadata'
  | 'key-material'
  | 'certificate'
  | 'ssh-directory'

/**
 * Command scan for `bash` arguments: any of a `.env` word, a `.git`
 * directory reference, an SSH private-key name, a `.pem` file, or a
 * `~/.ssh/`-style path in the command string is a sensitive hit.
 *
 * `.git` is matched as a standalone path token: the lookbehind rejects a
 * `foo.git` basename and the lookahead rejects `.gitignore`/`.github`/`.gitx`,
 * while `.git` at end of command (`cp -r .git`) and after a separator
 * (`--git-dir=.git`) both match. The earlier `\.git[/\\]` required a trailing
 * separator and silently missed every `.git` reference that ended a command.
 */
const SENSITIVE_COMMAND_SCAN = /(\.env\b|(?<![\w.-])\.git(?![\w-])|id_rsa|id_ed25519|\b\S*\.pem\b|~?\/?\.ssh[/\\])/

/** Whether a basename names key material: an SSH private key (with an optional dotted suffix) or a `.pem` certificate. */
function isKeyMaterialBasename(basename: string): boolean {
  return /^id_(rsa|ed25519)(\..*)?$/.test(basename) || basename.endsWith('.pem')
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
export function isKeyMaterialPath(path: string): boolean {
  const normalized = path.replaceAll('\\', '/')
  const segments = normalized.split('/').filter(segment => segment.length > 0)
  if (segments.length === 0) return false
  return isKeyMaterialBasename(segments[segments.length - 1] as string)
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
export function isSensitivePath(path: string): boolean {
  const normalized = path.replaceAll('\\', '/')
  const segments = normalized.split('/').filter(segment => segment.length > 0)
  if (segments.length === 0) return false
  for (const segment of segments) {
    if (segment === '.git' || segment === '.ssh' || segment.startsWith('.env')) return true
  }
  return isKeyMaterialBasename(segments[segments.length - 1] as string)
}
/* jscpd:ignore-end */

/**
 * Classify one sensitive target for the approval reason. Key material wins
 * over the directory it sits in (`.ssh/id_rsa` is `key-material`, not
 * `ssh-directory`), then the first matching directory segment decides.
 * Total for every target {@link isSensitivePath} accepts.
 *
 * @param path - a path already known to be sensitive.
 * @returns the category naming why it is sensitive.
 */
function classifySensitivePath(path: string): SensitiveCategory {
  const normalized = path.replaceAll('\\', '/')
  const segments = normalized.split('/').filter(segment => segment.length > 0)
  const basename = segments[segments.length - 1]
  if (basename !== undefined && isKeyMaterialBasename(basename)) {
    return basename.endsWith('.pem') ? 'certificate' : 'key-material'
  }
  for (const segment of segments) {
    if (segment === '.git') return 'git-metadata'
    if (segment === '.ssh') return 'ssh-directory'
    if (segment.startsWith('.env')) return 'environment-file'
  }
  return 'key-material'
}

/** One gated call's sensitive target plus the category explaining the ask. */
interface SensitiveTarget {
  /** The path (or matched command fragment) the ask names. */
  target: string
  /** Why the target is sensitive. */
  category: SensitiveCategory
}

/**
 * The sensitive target one call names: the path argument for `write`/`edit`
 * (`file_path`) and `str_replace_editor` (`path`) gated on the full sensitive
 * set, the `read` `file_path` gated on key material only, or the matched
 * command fragment for `bash`. Every other tool names no target and passes
 * through.
 */
function sensitiveTarget(exec: ToolExecution): SensitiveTarget | undefined {
  if (exec.name === 'write' || exec.name === 'edit' || exec.name === 'str_replace_editor') {
    const field = exec.name === 'str_replace_editor' ? 'path' : 'file_path'
    const args = exec.arguments
    const candidate = typeof args === 'object' && args !== null
      ? (args as Record<string, unknown>)[field]
      : undefined
    return typeof candidate === 'string' && isSensitivePath(candidate)
      ? { target: candidate, category: classifySensitivePath(candidate) }
      : undefined
  }
  if (exec.name === 'read') {
    const args = exec.arguments
    const candidate = typeof args === 'object' && args !== null
      ? (args as Record<string, unknown>).file_path
      : undefined
    return typeof candidate === 'string' && isKeyMaterialPath(candidate)
      ? { target: candidate, category: classifySensitivePath(candidate) }
      : undefined
  }
  if (exec.name === 'bash') {
    const args = exec.arguments
    const command = typeof args === 'object' && args !== null
      ? (args as Record<string, unknown>).command
      : undefined
    if (typeof command !== 'string') return undefined
    const fragment = command.match(SENSITIVE_COMMAND_SCAN)?.[0]
    return fragment === undefined
      ? undefined
      : { target: fragment, category: classifySensitivePath(fragment) }
  }
  return undefined
}

/**
 * Register the pre-execute approval guard, PREPENDED so it runs before any
 * other `tools/pre-execute` listener (including permission grants). A call
 * that targets a sensitive path (or reads key material) returns an approval
 * `ask` carrying the target and its category instead of delegating;
 * `sensitivePaths: false` registers nothing.
 *
 * @param ctx - plugin context; the listener is an effect scoped to it.
 * @param config - resolved plugin configuration from schemastery.
 */
export function apply(ctx: Context, config: Config): void {
  if (!config.sensitivePaths) return
  ctx.on('tools/pre-execute', (exec, next): Promise<PreToolDecision> => {
    const target = sensitiveTarget(exec)
    if (target !== undefined) {
      return Promise.resolve({
        kind: 'ask',
        reason: `${exec.name} targets the sensitive path ${target.target} (${target.category}); approval is required because it matches the sensitive-path policy`,
      })
    }
    return next()
  }, true)
}
