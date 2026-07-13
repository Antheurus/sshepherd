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
import {
  defaultInstallServerDeps,
  type InstallOutcome,
  type InstallServerDeps,
  type InstallTarget,
  runInstallServer,
} from './setup-ssh-alias-install-server.ts';
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

export interface InstallOptions {
  yes: boolean;
}

export interface InstallData {
  alias: string;
  host: string;
  user: string;
  port: number;
  /** Only ever present when the already-trusted pre-check short-circuited the whole
   *  password-form flow — omitted entirely (not just `undefined`) on a normal password
   *  install, so the existing success shape is unchanged for that path. */
  method?: 'already_trusted';
}

export interface ListData {
  aliases: string[];
}

export interface StatusData {
  alias: string;
  host: string;
  user: string;
  port: number;
  hasKey: boolean;
  managed: true;
}

export interface UpdateOptions {
  host?: string;
  user?: string;
  port?: number;
  yes: boolean;
}

export interface UpdateData {
  alias: string;
  host: string;
  user: string;
  port: number;
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

/** Shared with `list`'s marker scan so the prefix used to write a stanza and the prefix used to
 *  enumerate them can never drift apart. */
const MANAGED_MARKER_PREFIX = '# sshepherd-managed: ';

function markerLine(alias: string): string {
  return `${MANAGED_MARKER_PREFIX}${alias}`;
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

/**
 * Rewrites (or appends, if absent) a single `    <property> <value>` line inside the located
 * managed stanza — the general form `upsertIdentityFile` used to hand-roll for `IdentityFile`
 * alone. Shared by `keygen` (IdentityFile) and `update` (HostName/User/Port) so the "find the
 * property line, replace it in place, else append" rule lives in exactly one place.
 */
function upsertStanzaProperty(
  lines: string[],
  stanza: { startIndex: number; endIndex: number },
  property: string,
  value: string,
): string[] {
  const propertyLine = `    ${property} ${value}`;
  const block = lines.slice(stanza.startIndex, stanza.endIndex + 1);
  const propertyIndex = block.findIndex((line) => line.trim().startsWith(`${property} `));
  const newBlock =
    propertyIndex === -1
      ? [...block, propertyLine]
      : block.map((line, i) => (i === propertyIndex ? propertyLine : line));
  return [...lines.slice(0, stanza.startIndex), ...newBlock, ...lines.slice(stanza.endIndex + 1)];
}

function upsertIdentityFile(
  lines: string[],
  stanza: { startIndex: number; endIndex: number },
  keyPath: string,
): string[] {
  return upsertStanzaProperty(lines, stanza, 'IdentityFile', keyPath);
}

function stanzaPropertyValue(block: string[], property: string): string | undefined {
  const line = block.find((entry) => entry.trim().startsWith(`${property} `));
  return line
    ?.trim()
    .slice(property.length + 1)
    .trim();
}

/** Reads the `install`-relevant fields (`HostName`/`User`/`Port`/`IdentityFile`) straight out
 *  of the already-located managed stanza — the same block `upsertIdentityFile` rewrites —
 *  rather than re-parsing the whole file with a second pass. Returns `undefined` when the
 *  stanza has no `IdentityFile` yet (i.e. `keygen` hasn't run), since `install` has nothing
 *  to install in that case. */
function stanzaInstallTarget(
  lines: string[],
  stanza: { startIndex: number; endIndex: number },
): { host: string; user: string; port: number; publicKeyPath: string } | undefined {
  const block = lines.slice(stanza.startIndex, stanza.endIndex + 1);
  const host = stanzaPropertyValue(block, 'HostName');
  const user = stanzaPropertyValue(block, 'User');
  const portRaw = stanzaPropertyValue(block, 'Port');
  const identityFile = stanzaPropertyValue(block, 'IdentityFile');

  if (!host || !user || !identityFile) {
    return undefined;
  }

  return {
    host,
    user,
    port: portRaw ? Number(portRaw) : DEFAULT_PORT,
    publicKeyPath: `${identityFile}.pub`,
  };
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

/**
 * Installs the alias's already-generated public key onto the real remote via a one-shot
 * local browser form (`setup-ssh-alias-install-server.ts`): the CLI/agent triggers and
 * waits, a human types the password into the form, and the password never reaches this
 * function, the CLI's stdout, the audit log, or the returned `SetupResult` — only
 * `runInstallServer`'s typed `InstallOutcome` crosses back over. Refuses with
 * `ALIAS_NOT_FOUND`/`PARSE_MISMATCH` the same way `keygen`/`remove` do, and with
 * `INSTALL_FAILED` when `keygen` hasn't been run yet (no public key to install).
 *
 * Before ever opening the browser form, two cheap pre-checks run in order: first a raw-socket
 * Tailscale banner peek (fast — a password/key probe against a Tailscale-SSH-fronted target
 * hangs instead of failing, so this must run first to give an accurate diagnosis instead of
 * eating the second check's own timeout), then a non-interactive already-trusted probe with
 * zero new credentials. Either short-circuit skips `runInstallServer` entirely — no server
 * opened, no password ever requested.
 */
export async function install(
  alias: string,
  options: InstallOptions,
  configPath: string = defaultSshConfigPath(),
  serverDeps: Partial<InstallServerDeps> = {},
): Promise<SetupResult<InstallData>> {
  const command = 'setup ssh-alias install';
  const argsSummary = {};

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'install requires --yes' },
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

  const connection = stanzaInstallTarget(lines, found);
  if (!connection) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'INSTALL_FAILED',
        message: `alias '${alias}' has no generated key yet; run 'setup ssh-alias keygen ${alias}' first`,
      },
    });
  }

  const target: InstallTarget = { alias, ...connection };
  const deps: InstallServerDeps = { ...defaultInstallServerDeps(), ...serverDeps };

  let outcome: InstallOutcome;
  if (await deps.peekBanner(target)) {
    outcome = { kind: 'tailscale_detected' };
  } else if (await deps.probeReachable(target)) {
    outcome = { kind: 'already_trusted' };
  } else {
    outcome = await runInstallServer(target, serverDeps);
  }

  if (outcome.kind === 'tailscale_detected') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'TAILSCALE_SSH_DETECTED',
        message: `alias '${alias}' is fronted by Tailscale SSH, which does not use authorized_keys — install cannot place a key here; the target must already be authorized via Tailscale's own ACL/identity, or reached over a non-Tailscale network path`,
      },
    });
  }
  if (outcome.kind === 'already_trusted') {
    auditMutating({ alias, command, argsSummary, outcome: 'ok' });
    return buildSetupResult({
      command,
      data: {
        alias,
        host: connection.host,
        user: connection.user,
        port: connection.port,
        method: 'already_trusted',
      },
    });
  }
  if (outcome.kind === 'sshpass_not_found') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'SSHPASS_NOT_FOUND',
        message:
          "sshpass is not installed; install it (macOS: 'brew install sshpass', Debian/Ubuntu: 'apt install sshpass') and retry",
      },
    });
  }
  if (outcome.kind === 'timed_out') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'INSTALL_TIMED_OUT',
        message: `no password was submitted for alias '${alias}' before the form timed out`,
      },
    });
  }
  if (outcome.kind === 'ssh_failed') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'INSTALL_FAILED',
        message: `ssh exited with code ${outcome.exitCode} while installing the key for alias '${alias}' (likely a wrong password)`,
      },
    });
  }
  if (outcome.kind === 'key_ssh_failed') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'INSTALL_FAILED',
        message: `ssh exited with code ${outcome.exitCode} while installing the key for alias '${alias}' — check the pasted key and try again`,
      },
    });
  }
  if (outcome.kind === 'invalid_private_key') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'INVALID_PRIVATE_KEY',
        message: 'the pasted text does not look like a valid private key',
      },
    });
  }
  if (outcome.kind === 'passphrase_protected_key') {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'PASSPHRASE_PROTECTED_KEY_UNSUPPORTED',
        message:
          "the pasted key is passphrase-protected, which sshepherd's install cannot supply non-interactively; use an unencrypted key or the password method instead",
      },
    });
  }

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: { alias, host: connection.host, user: connection.user, port: connection.port },
  });
}

/**
 * Enumerates every sshepherd-managed alias by name only, via a fresh scan of `configPath` for
 * `# sshepherd-managed: <name>` marker lines. Deliberately not a loop over `findManagedStanza`
 * (which locates one alias at a time) nor a reuse of `listHostAliases` (which enumerates every
 * `Host` entry, including hand-written ones sshepherd didn't write) — this is name-only and
 * sshepherd-managed-only by design. Non-mutating: no `confirmGate`/`auditMutating`, no `--yes`,
 * same `mutating: false` precedent as `hosts test`.
 */
export function list(configPath: string = defaultSshConfigPath()): SetupResult<ListData> {
  const command = 'setup ssh-alias list';
  const lines = splitLines(readTextOrEmpty(configPath));
  const aliases = lines
    .map((line) => line.trim())
    .filter((line) => line.startsWith(MANAGED_MARKER_PREFIX))
    .map((line) => line.slice(MANAGED_MARKER_PREFIX.length));

  return buildSetupResult({ command, data: { aliases } });
}

/**
 * Reports one alias's full local state (host/user/port/hasKey) — a deliberate, user-approved
 * exception to `list`'s name-only rule, since the caller already supplied host/user/port to
 * `register` in the first place. Stays local/config-only: no live reachability check (that's
 * `hosts test <alias>`). `hasKey` requires BOTH an `IdentityFile` line in the stanza AND both key
 * files actually existing on disk, since a stanza can reference a path whose files were manually
 * deleted. Refuses with `ALIAS_NOT_FOUND`/`PARSE_MISMATCH` the same way `keygen`/`remove` do.
 * Non-mutating: no `confirmGate`/`auditMutating`, no `--yes`.
 */
export function status(
  alias: string,
  configPath: string = defaultSshConfigPath(),
): SetupResult<StatusData> {
  const command = 'setup ssh-alias status';

  const lines = splitLines(readTextOrEmpty(configPath));
  const found = findManagedStanza(lines, alias);
  if (found.kind === 'not_found') {
    return buildSetupResult({
      command,
      error: {
        code: 'ALIAS_NOT_FOUND',
        message: `alias '${alias}' is not registered via setup ssh-alias register`,
      },
    });
  }
  if (found.kind === 'mismatch') {
    return buildSetupResult({
      command,
      error: {
        code: 'PARSE_MISMATCH',
        message: `alias '${alias}' has a sshepherd-managed marker that doesn't match the expected stanza shape; refusing to guess`,
      },
    });
  }

  const block = lines.slice(found.startIndex, found.endIndex + 1);
  const host = stanzaPropertyValue(block, 'HostName');
  const user = stanzaPropertyValue(block, 'User');
  if (!host || !user) {
    return buildSetupResult({
      command,
      error: {
        code: 'PARSE_MISMATCH',
        message: `alias '${alias}' has a sshepherd-managed marker that doesn't match the expected stanza shape; refusing to guess`,
      },
    });
  }

  const portRaw = stanzaPropertyValue(block, 'Port');
  const port = portRaw ? Number(portRaw) : DEFAULT_PORT;
  const identityFile = stanzaPropertyValue(block, 'IdentityFile');
  const hasKey =
    identityFile !== undefined && existsSync(identityFile) && existsSync(`${identityFile}.pub`);

  return buildSetupResult({
    command,
    data: { alias, host, user, port, hasKey, managed: true },
  });
}

/**
 * Rewrites HostName/User/Port in place on an already-registered alias's managed stanza — the
 * generated key (`IdentityFile`) and everything else in the stanza is left completely untouched,
 * and `update` never regenerates or reinstalls a key; that stays a separate, explicit
 * `keygen`/`install` step. At least one of `host`/`user`/`port` is required, enforced at the CLI
 * layer (`runSshAliasAction`) as `INVALID_ARGS`, mirroring how `register` validates its own
 * required flags. Refuses with `ALIAS_NOT_FOUND`/`PARSE_MISMATCH` the same way
 * `keygen`/`remove`/`install` do.
 */
export function update(
  alias: string,
  options: UpdateOptions,
  configPath: string = defaultSshConfigPath(),
): SetupResult<UpdateData> {
  const command = 'setup ssh-alias update';
  const argsSummary: Record<string, string | boolean> = {};
  if (options.host !== undefined) {
    argsSummary.host = options.host;
  }
  if (options.user !== undefined) {
    argsSummary.user = options.user;
  }
  if (options.port !== undefined) {
    argsSummary.port = String(options.port);
  }

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'update requires --yes' },
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

  let newLines = lines;
  let stanza: { startIndex: number; endIndex: number } = found;
  const edits: Array<[string, string | undefined]> = [
    ['HostName', options.host],
    ['User', options.user],
    ['Port', options.port === undefined ? undefined : String(options.port)],
  ];
  for (const [property, value] of edits) {
    if (value === undefined) {
      continue;
    }
    newLines = upsertStanzaProperty(newLines, stanza, property, value);
    const refound = findManagedStanza(newLines, alias);
    if (refound.kind === 'found') {
      stanza = refound;
    }
  }
  writeTextSecure(configPath, joinLines(newLines));

  const block = newLines.slice(stanza.startIndex, stanza.endIndex + 1);
  const host = stanzaPropertyValue(block, 'HostName');
  const user = stanzaPropertyValue(block, 'User');
  if (!host || !user) {
    auditMutating({ alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: {
        code: 'PARSE_MISMATCH',
        message: `alias '${alias}' has a sshepherd-managed marker that doesn't match the expected stanza shape; refusing to guess`,
      },
    });
  }
  const portRaw = stanzaPropertyValue(block, 'Port');
  const port = portRaw ? Number(portRaw) : DEFAULT_PORT;

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: { alias, host, user, port },
  });
}
