#!/usr/bin/env bun

import { readFileSync } from 'node:fs';
import { MAX_TIMEOUT_SEC } from './limits.ts';
import { buildEnvelope, printError, printJson, printPretty } from './output.ts';
import { buildDeployOpContext } from './recipes.ts';
import { type ExecuteDeps, executeOp, getOp, listOps } from './registry.ts';
import { runSetup } from './setup.ts';
import { buildDbOpContext } from './targets.ts';
import { runSupervisor } from './tunnel.ts';
import type { ArgSpec, Envelope, OpContext, OpSpec } from './types.ts';

const VERSION = '0.3.0';

/** Flags that never take a value: `parseArgv` must not let them swallow the next token
 *  (`--yes r1` is a flag plus a positional), and `mapArgsToCtx` reads them as booleans.
 *  `ArgSpec` carries no type field, so this is the CLI's own small lookup — every other
 *  flag is a string value. */
const BOOLEAN_FLAG_NAMES = new Set(['yes', 'dry-run', 'keep-session', 'pretty', 'help', 'all']);

const GROUPS = [...new Set(listOps().map((op) => op.group))];

/** First-positional convention per group — most groups take an ssh alias, `db`/`deploy`
 *  resolve a named target/recipe instead (see targets.ts/recipes.ts). */
const GROUP_FIRST_POSITIONAL_NOTE: Record<string, string> = {
  hosts:
    'First positional (except `list`, and optional for `disconnect`): <alias> — the ssh alias from ~/.ssh/config.',
  db: 'First positional (except `list`): <target> — a pg-target name declared in targets.toml.',
  deploy: 'First positional: <recipe> — a deploy recipe name (see recipes.md).',
  tunnel:
    'First positional (open only): <alias>. `list` takes no positional; `close` takes <id> (from `tunnel open`) instead of an alias.',
};
const DEFAULT_FIRST_POSITIONAL_NOTE =
  'First positional: <alias> — the ssh alias configured in ~/.ssh/config.';

const GLOBAL_FLAGS = [
  '--yes              confirm a mutating op (required — sshepherd never prompts interactively)',
  '--dry-run          deploy run: print the resolved plan, execute nothing',
  `--timeout <sec>    any op: seconds the remote command may run (1-${MAX_TIMEOUT_SEC}; each op has its own default)`,
  '--pretty           render a human table/key-value view instead of JSON',
  '--reveal <keys>    files cat: comma-separated env keys to unmask',
  '--from <path>      config put: local file to read + base64-encode (instead of --content-base64)',
  '--version, -v      print the sshepherd version',
];

class UsageError extends Error {}

// -- argv parsing (mirrors anywrite's src/cli.ts parseFlags) --------------------------------
// Exported so `setup.ts` reuses the same parsing instead of reinventing it for its own,
// parallel dispatch path.

export type FlagMap = Map<string, string[]>;

export function parseArgv(tokens: string[]): { positionals: string[]; flags: FlagMap } {
  const positionals: string[] = [];
  const flags: FlagMap = new Map();
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token === undefined) {
      continue;
    }
    if (token === '--') {
      positionals.push(...tokens.slice(index + 1));
      break;
    }
    if (token.startsWith('--')) {
      const name = token.slice(2);
      const next = tokens[index + 1];
      let value = 'true';
      if (!BOOLEAN_FLAG_NAMES.has(name) && next !== undefined && !next.startsWith('--')) {
        value = next;
        index++;
      }
      const existing = flags.get(name);
      if (existing) {
        existing.push(value);
      } else {
        flags.set(name, [value]);
      }
    } else {
      positionals.push(token);
    }
  }
  return { positionals, flags };
}

export function getFlag(flags: FlagMap, name: string): string | undefined {
  return flags.get(name)?.[0];
}

export function hasFlag(flags: FlagMap, name: string): boolean {
  return flags.has(name);
}

// -- OpContext construction ------------------------------------------------------------------

/** Maps CLI positionals/flags onto one `OpSpec`'s `ArgSpec[]`, in declared order — the
 *  same mapping the drift test's registry data drives the `--help` output from. */
function mapArgsToCtx(
  op: OpSpec,
  positionals: string[],
  flags: FlagMap,
): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  let posIndex = 0;
  for (const argSpec of op.args) {
    if (argSpec.kind === 'positional') {
      const value = positionals[posIndex];
      posIndex++;
      if (value === undefined) {
        if (argSpec.required) {
          throw new UsageError(`missing required positional argument '${argSpec.name}'`);
        }
        continue;
      }
      args[argSpec.name] = value;
    } else {
      const raw = getFlag(flags, argSpec.name);
      if (raw === undefined) {
        if (argSpec.required) {
          throw new UsageError(`missing required flag --${argSpec.name}`);
        }
        continue;
      }
      args[argSpec.name] = BOOLEAN_FLAG_NAMES.has(argSpec.name) ? raw !== 'false' : raw;
    }
  }
  return args;
}

/**
 * Resolves one `OpContext` per group's first-positional convention: `db`/`deploy` route
 * through `buildDbOpContext`/`buildDeployOpContext` (Phase 3/5, previously unwired) so a
 * pg-target or recipe name never bypasses those resolvers; `hosts list`/`db list` run
 * host-local with no alias; every other group treats the first positional as the ssh alias.
 */
function buildOpContext(
  group: string,
  action: string,
  op: OpSpec,
  positionals: string[],
  flags: FlagMap,
): OpContext {
  if (group === 'hosts' && action === 'list') {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
  if (group === 'hosts' && action === 'disconnect') {
    const args = mapArgsToCtx(op, positionals, flags);
    return { alias: typeof args.alias === 'string' ? args.alias : '', args };
  }
  if (group === 'db' && action === 'list') {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
  if (group === 'tunnel' && (action === 'list' || action === 'close')) {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
  if (group === 'db') {
    const args = mapArgsToCtx(op, positionals, flags);
    const targetName = args.target;
    if (typeof targetName !== 'string') {
      throw new UsageError("missing required positional argument 'target'");
    }
    return buildDbOpContext(targetName, args);
  }
  if (group === 'deploy') {
    const args = mapArgsToCtx(op, positionals, flags);
    const recipeName = args.recipe;
    if (typeof recipeName !== 'string') {
      throw new UsageError("missing required positional argument 'recipe'");
    }
    return buildDeployOpContext(recipeName, args);
  }
  const [alias, ...rest] = positionals;
  if (alias === undefined) {
    throw new UsageError("missing required positional argument 'alias'");
  }
  return { alias, args: mapArgsToCtx(op, rest, flags) };
}

/** `config put`'s `content-base64` arg is meant to be produced by the CLI, not typed by
 *  hand — `--from <local path>` reads + base64-encodes the file into that flag before the
 *  generic mapper runs, so the required-flag check in `mapArgsToCtx` sees it as supplied. */
function applyConfigPutFromFlag(group: string, action: string, flags: FlagMap): void {
  if (group !== 'config' || action !== 'put') {
    return;
  }
  const fromPath = getFlag(flags, 'from');
  if (fromPath === undefined) {
    return;
  }
  let contentBase64: string;
  try {
    contentBase64 = readFileSync(fromPath).toString('base64');
  } catch {
    throw new UsageError(`config put: local file '${fromPath}' not found or unreadable`);
  }
  flags.set('content-base64', [contentBase64]);
}

// -- help text, generated from the registry --------------------------------------------------

function formatArgLine(argSpec: ArgSpec): string {
  const marker = argSpec.required ? 'required' : 'optional';
  const label = argSpec.kind === 'positional' ? `<${argSpec.name}>` : `--${argSpec.name}`;
  return `    ${label} (${marker}) — ${argSpec.description}`;
}

function formatActionHelp(op: OpSpec): string {
  const lines = [
    `${op.group} ${op.name}  [${op.mutating ? 'mutating' : 'read-only'}]`,
    `  ${op.summary}`,
  ];
  for (const argSpec of op.args) {
    lines.push(formatArgLine(argSpec));
  }
  return lines.join('\n');
}

function formatTopHelp(): string {
  return [
    'sshepherd <group> <action> [positionals...] [--flag value]',
    '',
    'Groups:',
    ...GROUPS.map((group) => `  ${group}`),
    '  setup             human-only — writes local config, see `sshepherd setup --help`',
    '',
    'Run `sshepherd <group> --help` to see actions + args for a group.',
    'Run `sshepherd <group> <action> --help` to see one action.',
    '',
    'Global flags:',
    ...GLOBAL_FLAGS.map((line) => `  ${line}`),
  ].join('\n');
}

function formatGroupHelp(group: string): string {
  const ops = listOps().filter((op) => op.group === group);
  if (ops.length === 0) {
    throw new UsageError(`unknown group "${group}". Groups: ${GROUPS.join(', ')}`);
  }
  const note = GROUP_FIRST_POSITIONAL_NOTE[group] ?? DEFAULT_FIRST_POSITIONAL_NOTE;
  const lines = [`sshepherd ${group} <action> [args] [flags]`, '', note, '', 'Actions:'];
  for (const op of ops) {
    lines.push('', formatActionHelp(op));
  }
  return lines.join('\n');
}

// -- dispatch ---------------------------------------------------------------------------------

/** Reads the global `--timeout <sec>`: an integer in 1..MAX_TIMEOUT_SEC, else a string
 *  describing what was wrong (the caller wraps it in an `INVALID_ARGS` envelope). */
function parseTimeoutFlag(flags: FlagMap): { sec?: number; problem?: string } {
  const raw = getFlag(flags, 'timeout');
  if (raw === undefined) {
    return {};
  }
  const sec = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(sec) || sec < 1 || sec > MAX_TIMEOUT_SEC) {
    return { problem: `--timeout must be a whole number of seconds from 1 to ${MAX_TIMEOUT_SEC}` };
  }
  return { sec };
}

export async function run(argv: string[], baseDeps: ExecuteDeps = {}): Promise<void> {
  const [first, ...rest] = argv;
  if (first === undefined || first === '--help' || first === '-h') {
    process.stdout.write(`${formatTopHelp()}\n`);
    return;
  }
  if (first === '--version' || first === '-v') {
    process.stdout.write(`sshepherd ${VERSION}\n`);
    return;
  }

  if (first === 'tunnel' && rest[0] === '__supervise') {
    const [, id, durationSecRaw, command, ...commandArgs] = rest;
    if (id === undefined || durationSecRaw === undefined || command === undefined) {
      throw new UsageError('tunnel __supervise: missing id/duration/command');
    }
    const durationSec = Number(durationSecRaw);
    if (!Number.isFinite(durationSec) || durationSec <= 0) {
      throw new UsageError('tunnel __supervise: duration must be a positive number');
    }
    const exitCode = await runSupervisor({ command, args: commandArgs, durationSec });
    process.exitCode = exitCode;
    return;
  }

  if (first === 'setup') {
    await runSetup(rest);
    return;
  }

  const group = first;
  if (!GROUPS.includes(group)) {
    throw new UsageError(`unknown group "${group}". Groups: ${GROUPS.join(', ')}`);
  }

  const [actionOrHelp, ...tail] = rest;
  if (actionOrHelp === undefined || actionOrHelp === '--help' || actionOrHelp === '-h') {
    process.stdout.write(`${formatGroupHelp(group)}\n`);
    return;
  }

  const action = actionOrHelp;
  const op = getOp(group, action);
  if (!op) {
    throw new UsageError(
      `unknown action "${action}" for group "${group}".\n\n${formatGroupHelp(group)}`,
    );
  }

  const { positionals, flags } = parseArgv(tail);
  if (hasFlag(flags, 'help')) {
    process.stdout.write(`${formatActionHelp(op)}\n`);
    return;
  }

  applyConfigPutFromFlag(group, action, flags);
  const ctx = buildOpContext(group, action, op, positionals, flags);
  const timeout = parseTimeoutFlag(flags);
  if (timeout.problem !== undefined) {
    const envelope: Envelope<null> = buildEnvelope({
      alias: ctx.alias,
      command: `${group} ${action}`,
      startedAtMs: Date.now(),
      data: null,
      error: { code: 'INVALID_ARGS', message: timeout.problem },
    });
    printJson(envelope);
    process.exitCode = 2;
    return;
  }

  const deps: ExecuteDeps = { ...baseDeps, yes: hasFlag(flags, 'yes'), timeoutSec: timeout.sec };
  const envelope = await executeOp(op, ctx, deps);
  if (hasFlag(flags, 'pretty')) {
    printPretty(envelope);
  } else {
    printJson(envelope);
  }
  process.exitCode = envelope.ok ? 0 : 1;
}

async function main(): Promise<void> {
  try {
    await run(process.argv.slice(2));
  } catch (err) {
    if (err instanceof Error) {
      printError(err.message);
      process.exitCode = 2;
      return;
    }
    throw err;
  }
}

if (import.meta.main) {
  main();
}
