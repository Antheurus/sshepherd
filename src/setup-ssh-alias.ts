import { existsSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { auditMutating, confirmGate } from './audit.ts';
import { listHostAliases } from './parsers/ssh-config.ts';
import {
  appendBlock,
  joinLines,
  readTextOrEmpty,
  splitLines,
  writeTextSecure,
} from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';

const DEFAULT_PORT = 22;

export interface RegisterOptions {
  host: string;
  user: string;
  port?: number;
  overwrite?: boolean;
  yes: boolean;
}

export interface RegisterData {
  alias: string;
  host: string;
  user: string;
  port: number;
}

export interface KeygenOptions {
  yes: boolean;
}

export interface KeygenData {
  alias: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

export interface RemoveOptions {
  yes: boolean;
}

export interface RemoveData {
  alias: string;
  configRemoved: boolean;
  keyRemoved: boolean;
}

/** Overridable via `SSHEPHERD_SSH_CONFIG_PATH` (or an explicit path param) for tests — mirrors
 *  targets.ts's `SSHEPHERD_TARGETS_PATH` override. Purely additive: the real default
 *  (`~/.ssh/config`) is unchanged when the env var is unset. */
export function defaultSshConfigPath(): string {
  const override = process.env.SSHEPHERD_SSH_CONFIG_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.ssh', 'config');
}

function markerLine(alias: string): string {
  return `# sshepherd-managed: ${alias}`;
}

function keyPathFor(alias: string, configPath: string): string {
  return join(dirname(configPath), `sshepherd_${alias}_ed25519`);
}

function buildStanzaLines(alias: string, host: string, user: string, port: number): string[] {
  const lines = [markerLine(alias), `Host ${alias}`, `    HostName ${host}`, `    User ${user}`];
  if (port !== DEFAULT_PORT) {
    lines.push(`    Port ${port}`);
  }
  return lines;
}

type FindStanzaResult =
  | { kind: 'not_found' }
  | { kind: 'mismatch' }
  | { kind: 'found'; startIndex: number; endIndex: number };

/**
 * Locates the managed stanza for `alias`: the marker comment line, immediately followed by
 * `Host <alias>`, followed by contiguous indented property lines. `mismatch` (marker present
 * but the next line isn't the expected `Host <alias>`) is distinct from `not_found` so callers
 * can refuse loudly instead of guessing at a stanza that doesn't match the shape this module
 * itself writes — see plan.md Phase 2 "remove must be conservative".
 */
function findManagedStanza(lines: string[], alias: string): FindStanzaResult {
  const marker = markerLine(alias);
  const markerIndex = lines.findIndex((line) => line.trim() === marker);
  if (markerIndex === -1) {
    return { kind: 'not_found' };
  }

  const hostLineIndex = markerIndex + 1;
  if (lines[hostLineIndex]?.trim() !== `Host ${alias}`) {
    return { kind: 'mismatch' };
  }

  let endIndex = hostLineIndex;
  for (let i = hostLineIndex + 1; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^[ \t]+\S/.test(line)) {
      endIndex = i;
      continue;
    }
    break;
  }

  return { kind: 'found', startIndex: markerIndex, endIndex };
}

/** Removes a found stanza plus one adjacent blank separator line, so removal is the exact
 *  inverse of `appendStanza` rather than leaving a growing gap of blank lines behind. Prefers
 *  the leading separator (the common case); when the stanza is the first thing in the file
 *  (no leading separator to strip), it strips the trailing one instead so no orphan blank
 *  line is left at the top of the file. */
function removeStanzaLines(
  lines: string[],
  stanza: { startIndex: number; endIndex: number },
): string[] {
  let removeStart = stanza.startIndex;
  let removeEnd = stanza.endIndex;
  if (removeStart > 0 && lines[removeStart - 1] === '') {
    removeStart -= 1;
  } else if (lines[removeEnd + 1] === '') {
    removeEnd += 1;
  }
  return [...lines.slice(0, removeStart), ...lines.slice(removeEnd + 1)];
}

function upsertIdentityFile(
  lines: string[],
  stanza: { startIndex: number; endIndex: number },
  keyPath: string,
): string[] {
  const identityLine = `    IdentityFile ${keyPath}`;
  const block = lines.slice(stanza.startIndex, stanza.endIndex + 1);
  const identityIndex = block.findIndex((line) => line.trim().startsWith('IdentityFile '));
  const newBlock =
    identityIndex === -1
      ? [...block, identityLine]
      : block.map((line, i) => (i === identityIndex ? identityLine : line));
  return [...lines.slice(0, stanza.startIndex), ...newBlock, ...lines.slice(stanza.endIndex + 1)];
}

/**
 * Appends a `# sshepherd-managed: <alias>` stanza to `configPath`. Refuses with `ALIAS_EXISTS`
 * for any pre-existing alias of the same name (hand-written or setup-managed) unless
 * `--overwrite` is passed — and even then, `--overwrite` only ever replaces a stanza this
 * module itself wrote (a clean, verifiable remove-then-append); a hand-written entry with the
 * same alias name is never auto-removed, since there is no safe way to know its exact
 * boundaries without risking deleting content sshepherd didn't write.
 */
export function register(
  alias: string,
  options: RegisterOptions,
  configPath: string = defaultSshConfigPath(),
): SetupResult<RegisterData> {
  const command = 'setup ssh-alias register';
  const port = options.port ?? DEFAULT_PORT;
  const argsSummary = {
    host: options.host,
    user: options.user,
    port: String(port),
    overwrite: options.overwrite ?? false,
  };

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'register requires --yes' },
    });
  }

  const existingAliases = listHostAliases(configPath);
  const alreadyExists = existingAliases.includes(alias);

  let lines = splitLines(readTextOrEmpty(configPath));

  if (alreadyExists) {
    if (!options.overwrite) {
      auditMutating({ alias, command, argsSummary, outcome: 'error' });
      return buildSetupResult({
        command,
        error: {
          code: 'ALIAS_EXISTS',
          message: `alias '${alias}' already exists in ${configPath}; pass --overwrite to replace a setup-managed entry`,
        },
      });
    }
    const found = findManagedStanza(lines, alias);
    if (found.kind !== 'found') {
      auditMutating({ alias, command, argsSummary, outcome: 'error' });
      return buildSetupResult({
        command,
        error: {
          code: 'ALIAS_EXISTS',
          message: `alias '${alias}' exists as a hand-written ~/.ssh/config entry; sshepherd will not overwrite entries it didn't write`,
        },
      });
    }
    lines = removeStanzaLines(lines, found);
  }

  const stanzaLines = buildStanzaLines(alias, options.host, options.user, port);
  const newText = appendBlock(joinLines(lines), stanzaLines.join('\n'));
  writeTextSecure(configPath, newText);

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: { alias, host: options.host, user: options.user, port },
  });
}

/**
 * Generates a passphrase-less ed25519 keypair at `~/.ssh/sshepherd_<alias>_ed25519` (same
 * directory as `configPath`) and rewrites the managed stanza's `IdentityFile` in place. Refuses
 * with `ALIAS_NOT_FOUND` if `alias` has no managed stanza — public-key installation on the
 * remote is out of scope; the human installs it their own way.
 */
export async function keygen(
  alias: string,
  options: KeygenOptions,
  configPath: string = defaultSshConfigPath(),
): Promise<SetupResult<KeygenData>> {
  const command = 'setup ssh-alias keygen';
  const argsSummary = {};

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'keygen requires --yes' },
    });
  }

  const lines = splitLines(readTextOrEmpty(configPath));
  const found = findManagedStanza(lines, alias);
  if (found.kind === 'not_found') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'ALIAS_NOT_FOUND',
        message: `alias '${alias}' is not registered via setup ssh-alias register`,
      },
    });
  }
  if (found.kind === 'mismatch') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'PARSE_MISMATCH',
        message: `alias '${alias}' has a sshepherd-managed marker that doesn't match the expected stanza shape; refusing to guess`,
      },
    });
  }

  const keyPath = keyPathFor(alias, configPath);
  const proc = Bun.spawn(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', keyPath], {
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'ignore',
  });
  const exitCode = await proc.exited;

  if (exitCode !== 0) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'KEYGEN_FAILED',
        message: `ssh-keygen failed while generating a key for alias '${alias}'`,
      },
    });
  }

  const newLines = upsertIdentityFile(lines, found, keyPath);
  writeTextSecure(configPath, joinLines(newLines));

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: { alias, privateKeyPath: keyPath, publicKeyPath: `${keyPath}.pub` },
  });
}

/**
 * Removes only the managed stanza for `alias` (a hand-written `Host` stanza with the same name
 * survives untouched) and, if a matching `sshepherd_<alias>_ed25519` keypair exists, deletes it
 * too. Refuses loudly (`ALIAS_NOT_FOUND`/`PARSE_MISMATCH`) rather than guess at a stanza that
 * doesn't match exactly what this module writes.
 */
export async function remove(
  alias: string,
  options: RemoveOptions,
  configPath: string = defaultSshConfigPath(),
): Promise<SetupResult<RemoveData>> {
  const command = 'setup ssh-alias remove';
  const argsSummary = {};

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'remove requires --yes' },
    });
  }

  const lines = splitLines(readTextOrEmpty(configPath));
  const found = findManagedStanza(lines, alias);
  if (found.kind === 'not_found') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'ALIAS_NOT_FOUND',
        message: `alias '${alias}' is not registered via setup ssh-alias register`,
      },
    });
  }
  if (found.kind === 'mismatch') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'PARSE_MISMATCH',
        message: `alias '${alias}' has a sshepherd-managed marker that doesn't match the expected stanza shape; refusing to guess`,
      },
    });
  }

  const newLines = removeStanzaLines(lines, found);
  writeTextSecure(configPath, joinLines(newLines));

  const keyPath = keyPathFor(alias, configPath);
  const pubKeyPath = `${keyPath}.pub`;
  let keyRemoved = false;
  if (existsSync(keyPath)) {
    unlinkSync(keyPath);
    keyRemoved = true;
  }
  if (existsSync(pubKeyPath)) {
    unlinkSync(pubKeyPath);
  }

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({ command, data: { alias, configRemoved: true, keyRemoved } });
}
