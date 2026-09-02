/**
 * Unit + real-composition coverage for @deepseek-ai/dsh-guard-sensitive-paths:
 * the pure path matcher, the command scan, and the prepended pre-execute
 * approval gate exercised through a real ToolRuntime + dummy tool registry so
 * nothing bypasses the executor. Sensitive decisions degrade to denial with
 * the guard's reason because the test roots mount no approval seam; passing
 * calls reach the dummy tool bodies unchanged.
 */

import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineContentToolFixture, type ParameterSchemaSpec, type PreToolDecision, type ToolExecution } from '@deepseek-ai/dsh-tools'
import * as sensitivePaths from '../src/index.ts'
import { SENSITIVE_PATH_GLOBS, isKeyMaterialPath, isSensitivePath } from '../src/index.ts'

const testToolSignal = new AbortController().signal

let callCounter = 0

/** A minimal execution for the direct pre-execute waterfall drive. */
function fakeExec(name: string, argumentsValue: unknown): ToolExecution {
  return {
    name,
    arguments: argumentsValue,
    callId: ToolCallId(`fake-${name}-${callCounter}`),
    signal: testToolSignal,
  } as unknown as ToolExecution
}

/** One decision from the guard listener alone, driven through the waterfall. */
function preDecision(ctx: Context, exec: ToolExecution): Promise<PreToolDecision> {
  return ctx.waterfall('tools/pre-execute', exec, () => Promise.resolve({ kind: 'allow' as const }))
}

/** A dummy registry tool whose body records that it ran. */
function dummyTool(name: string, parameters: ParameterSchemaSpec = {}) {
  return defineContentToolFixture({
    name,
    description: `dummy ${name}`,
    parameters,
    async execute() {
      return [{ type: 'text' as const, text: `${name} ran` }]
    },
  })
}

function text(result: { content: { type: string; text?: string }[] }): string {
  return result.content.filter(block => block.type === 'text').map(block => block.text).join('')
}

/** Mount ToolRuntime + the guard (default enabled) and register the dummy tools. */
async function setup(config: { sensitivePaths?: boolean } = {}) {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const fiber = await ctx.plugin(sensitivePaths, { sensitivePaths: config.sensitivePaths ?? true })
  ctx.tools.register(dummyTool('write', { file_path: { type: 'string' } }))
  ctx.tools.register(dummyTool('edit', { file_path: { type: 'string' } }))
  ctx.tools.register(dummyTool('str_replace_editor', { path: { type: 'string' } }))
  ctx.tools.register(dummyTool('bash', { command: { type: 'string' } }))
  ctx.tools.register(dummyTool('read'))
  ctx.tools.register(dummyTool('grep'))
  return { ctx, fiber }
}

function call(ctx: Context, name: string, argumentsValue: unknown) {
  return ctx.tools.execute({
    signal: testToolSignal,
    callId: ToolCallId(`call-${++callCounter}`),
    name,
    arguments: argumentsValue,
  })
}

describe('SENSITIVE_PATH_GLOBS', () => {
  it('carries the shared sensitive-path definition', () => {
    expect(SENSITIVE_PATH_GLOBS).toEqual([
      '**/.env*',
      '**/.git/**',
      '**/id_rsa*',
      '**/id_ed25519*',
      '*.pem',
      '**/.ssh/**',
    ])
  })
})

describe('isSensitivePath', () => {
  it.each([
    ['.env'],
    ['.env.local'],
    ['src/.env'],
    ['a/b/.env.production'],
    ['.env.backup/keep'],
    ['.envx'],
  ])('matches a .env path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(true)
  })

  it.each([
    ['env'],
    ['x.env'],
    ['environment.ts'],
    ['src/env.txt'],
  ])('rejects a non-.env path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })

  it.each([
    ['.git'],
    ['a/.git'],
    ['a/.git/config'],
  ])('matches a .git path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(true)
  })

  it.each([
    ['.github'],
    ['x/.gitignore'],
    ['.gitx'],
  ])('rejects a non-.git path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })

  it.each([
    ['id_rsa'],
    ['id_rsa.pub'],
    ['~/.ssh/id_rsa'],
    ['keys/id_ed25519'],
    ['id_ed25519.pub'],
  ])('matches an SSH key path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(true)
  })

  it.each([
    ['id_rsa_backup'],
    ['my_id_rsa'],
    ['id_rsax'],
    ['id_ed25519x'],
  ])('rejects a non-key path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })

  it.each([
    ['server.pem'],
    ['certs/a.pem'],
    ['.pem'],
  ])('matches a .pem path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(true)
  })

  it.each([
    ['pemfile'],
    ['x.pemx'],
    ['foo.pem.bak'],
  ])('rejects a non-.pem path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })

  it.each([
    ['.ssh'],
    ['.ssh/config'],
    ['x/.ssh/known_hosts'],
  ])('matches a .ssh path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(true)
  })

  it.each([
    ['.sshx'],
    ['ssh/config'],
    ['not.ssh'],
  ])('rejects a non-.ssh path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })

  it('normalizes backslashes before segment matching', () => {
    expect(isSensitivePath('a\\.env\\b')).toBe(true)
    expect(isSensitivePath('keys\\id_rsa')).toBe(true)
    expect(isSensitivePath('src\\index.ts')).toBe(false)
  })

  it.each([
    ['src/index.ts'],
    ['package.json'],
    ['README.md'],
    ['~/notes.md'],
    ['/home/user/.sshx'],
    [''],
    ['/'],
  ])('rejects an ordinary path: %s', (path) => {
    expect(isSensitivePath(path)).toBe(false)
  })
})

describe('isKeyMaterialPath', () => {
  it.each([
    ['~/.ssh/id_rsa'],
    ['id_ed25519.pub'],
    ['keys/id_ed25519'],
    ['certs/server.pem'],
    ['keys\\id_rsa'],
  ])('matches key material: %s', (path) => {
    expect(isKeyMaterialPath(path)).toBe(true)
  })

  it.each([
    ['.env'],
    ['.env.local'],
    ['.ssh/config'],
    ['.git/config'],
    ['id_rsa_backup'],
    ['my_id_rsa'],
    ['src/index.ts'],
    ['pemfile'],
    ['x.pemx'],
  ])('rejects a non-key-material path: %s', (path) => {
    expect(isKeyMaterialPath(path)).toBe(false)
  })
})

describe('pre-execute decisions (direct waterfall drive)', () => {
  it('asks for a write targeting .env', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('write', { file_path: '.env' }))).resolves.toEqual({
      kind: 'ask',
      reason: 'write targets the sensitive path .env; approval is required because it matches the sensitive-path policy',
    })
  })

  it('asks for an edit targeting an SSH private key', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('edit', { file_path: 'id_rsa' }))).resolves.toEqual({
      kind: 'ask',
      reason: 'edit targets the sensitive path id_rsa; approval is required because it matches the sensitive-path policy',
    })
  })

  it('asks for str_replace_editor targeting .ssh/config', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('str_replace_editor', { path: '.ssh/config' }))).resolves.toEqual({
      kind: 'ask',
      reason: 'str_replace_editor targets the sensitive path .ssh/config; approval is required because it matches the sensitive-path policy',
    })
  })

  it('asks for a read of an SSH private key', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('read', { file_path: '~/.ssh/id_rsa' }))).resolves.toEqual({
      kind: 'ask',
      reason: 'read targets the sensitive path ~/.ssh/id_rsa; approval is required because it matches the sensitive-path policy',
    })
  })

  it('asks for a read of a .pem certificate', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('read', { file_path: 'certs/server.pem' }))).resolves.toMatchObject({ kind: 'ask' })
  })

  it('passes a read of .env, .git, .ssh/config, or an ordinary file through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('read', { file_path: '.env' }))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('read', { file_path: '.git/config' }))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('read', { file_path: '.ssh/config' }))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('read', { file_path: 'src/index.ts' }))).resolves.toEqual({ kind: 'allow' })
  })

  it('asks for a bash command mentioning a sensitive path', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('bash', { command: 'cat ~/.ssh/id_rsa' }))).resolves.toEqual({
      kind: 'ask',
      reason: 'bash targets the sensitive path ~/.ssh/; approval is required because it matches the sensitive-path policy',
    })
  })

  it('asks for a bash command mentioning .env or a .pem file', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('bash', { command: 'cp .env.local prod/' }))).resolves.toMatchObject({ kind: 'ask' })
    await expect(preDecision(ctx, fakeExec('bash', { command: 'openssl x509 -in server.pem' }))).resolves.toMatchObject({ kind: 'ask' })
  })

  it('passes a write on a normal path through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('write', { file_path: 'src/index.ts' }))).resolves.toEqual({ kind: 'allow' })
  })

  it('passes a read of a non-key file, grep, and web_fetch through untouched', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('read', { file_path: '.env' }))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('grep', { pattern: 'TOKEN' }))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('web_fetch', { url: 'https://example.com/.env' }))).resolves.toEqual({ kind: 'allow' })
  })

  it('passes a bash command with no sensitive mention through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('bash', { command: 'ls -la' }))).resolves.toEqual({ kind: 'allow' })
  })

  it('passes a write or bash whose arguments are not an object through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('write', null))).resolves.toEqual({ kind: 'allow' })
    await expect(preDecision(ctx, fakeExec('bash', null))).resolves.toEqual({ kind: 'allow' })
  })

  it('passes a write whose path is not a string through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('write', { file_path: 7 }))).resolves.toEqual({ kind: 'allow' })
  })

  it('passes a bash whose command is not a string through', async () => {
    const { ctx } = await setup()
    await expect(preDecision(ctx, fakeExec('bash', { command: 7 }))).resolves.toEqual({ kind: 'allow' })
  })
})

describe('pre-execute decisions through the executor (real composition)', () => {
  it('denies a sensitive write through the executor when no approval seam is mounted', async () => {
    const { ctx } = await setup()
    const result = await call(ctx, 'write', { file_path: '.env' })
    expect(result.isError).toBe(true)
    expect(text(result)).toBe('Error: write targets the sensitive path .env; approval is required because it matches the sensitive-path policy')
  })

  it('denies a sensitive bash through the executor', async () => {
    const { ctx } = await setup()
    const result = await call(ctx, 'bash', { command: 'cat ~/.ssh/id_rsa' })
    expect(result.isError).toBe(true)
    expect(text(result)).toBe('Error: bash targets the sensitive path ~/.ssh/; approval is required because it matches the sensitive-path policy')
  })

  it('denies a read of an SSH key through the executor', async () => {
    const { ctx } = await setup()
    const result = await call(ctx, 'read', { file_path: '~/.ssh/id_rsa' })
    expect(result.isError).toBe(true)
    expect(text(result)).toBe('Error: read targets the sensitive path ~/.ssh/id_rsa; approval is required because it matches the sensitive-path policy')
  })

  it('runs a write on a normal path through the executor', async () => {
    const { ctx } = await setup()
    const result = await call(ctx, 'write', { file_path: 'src/index.ts' })
    expect(result.isError).toBe(false)
    expect(text(result)).toContain('write ran')
  })

  it('runs a non-key read and grep through the executor untouched', async () => {
    const { ctx } = await setup()
    const readResult = await call(ctx, 'read', { file_path: '.env' })
    expect(readResult.isError).toBe(false)
    expect(text(readResult)).toContain('read ran')
    const grepResult = await call(ctx, 'grep', { pattern: 'TOKEN' })
    expect(grepResult.isError).toBe(false)
    expect(text(grepResult)).toContain('grep ran')
  })

  it('runs a sensitive write through the executor when sensitivePaths is false', async () => {
    const { ctx } = await setup({ sensitivePaths: false })
    const result = await call(ctx, 'write', { file_path: '.env' })
    expect(result.isError).toBe(false)
    expect(text(result)).toContain('write ran')
  })

  it('runs a sensitive bash through the executor when sensitivePaths is false', async () => {
    const { ctx } = await setup({ sensitivePaths: false })
    const result = await call(ctx, 'bash', { command: 'cat ~/.ssh/id_rsa' })
    expect(result.isError).toBe(false)
    expect(text(result)).toContain('bash ran')
  })

  it('runs a read of an SSH key through the executor when sensitivePaths is false', async () => {
    const { ctx } = await setup({ sensitivePaths: false })
    const result = await call(ctx, 'read', { file_path: '~/.ssh/id_rsa' })
    expect(result.isError).toBe(false)
    expect(text(result)).toContain('read ran')
  })
})

describe('disposal (HMR safety)', () => {
  it('removes the pre-execute listener when the plugin fiber disposes', async () => {
    const { ctx, fiber } = await setup()
    const guarded = await call(ctx, 'write', { file_path: '.env' })
    expect(guarded.isError).toBe(true)
    await fiber.dispose()
    const result = await call(ctx, 'write', { file_path: '.env' })
    expect(result.isError).toBe(false)
    expect(text(result)).toContain('write ran')
  })
})

describe('dsh-guard-sensitive-paths real-load-path guard', () => {
  it('has no default export and keeps name/inject through unwrapExports', () => {
    expect('default' in sensitivePaths).toBe(false)
    const loader = Object.create(Loader.prototype) as Loader
    const unwrapped = loader.unwrapExports(sensitivePaths) as Record<string, unknown>
    expect(unwrapped).toBe(sensitivePaths)
    expect(unwrapped.name).toBe('sensitive-paths')
    expect(unwrapped.inject).toEqual(['tools'])
    expect(typeof unwrapped.apply).toBe('function')
  })

  it('boots over ctx.tools through the unwrapped module and asks for a sensitive write', async () => {
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    ctx.tools.register(dummyTool('write', { file_path: { type: 'string' } }))
    const loader = Object.create(Loader.prototype) as Loader
    const unwrapped = loader.unwrapExports(sensitivePaths) as Parameters<Context['plugin']>[0]
    const fiber = await ctx.plugin(unwrapped, { sensitivePaths: true })
    const result = await ctx.tools.execute({
      signal: testToolSignal,
      callId: ToolCallId('c1'),
      name: 'write',
      arguments: { file_path: '.env' },
    })
    expect(result.isError).toBe(true)
    expect(text(result)).toContain('write targets the sensitive path .env')
    await fiber.dispose()
  })
})
