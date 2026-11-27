import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { auditMutating, confirmGate } from './audit.ts';
import { ADOPT_ENV_MAX_FILE_BYTES, ADOPT_ENV_MAX_HOSTS } from './limits.ts';
import { executeOp, getOp } from './registry.ts';
import {
  defaultSshConfigPath,
  install,
  keygen,
  keyPathFor,
  register,
  status,
} from './setup-ssh-alias.ts';
import {
  defaultInstallServerDeps,
  type InstallServerDeps,
  type InstallTarget,
} from './setup-ssh-alias-install-server.ts';
import {
  buildSetupResult,
  type SetupErrorCode,
  type SetupErrorInput,
  type SetupResult,
} from './setup-types.ts';
import type { Envelope } from './types.ts';

/**
 * One-command onboarding: `setup host add` (register, keygen, host key, install form, hosts test)
 * and `setup ssh-alias adopt-env` (the same chain for every `SSH_*` host group in a project's
 * `.env`, installing the key with the credential the `.env` already holds). Lives outside
 * `setup-ssh-alias*.ts` because it runs `hosts test` and `hosts trust` through `executeOp`, the
 * path that keeps their profile gate, strict host-key checking, scrubbing and audit row; those
 * files never import the registry.
 */

/** What the onboarding needs from `hosts test` / `hosts trust`: the verdict and the op's error code,
 *  never its output. */
export interface HostCheck {
  ok: boolean;
  code: string | null;
  message: string;
}

export interface HostKeyFingerprint {
  type: string;
  fingerprint: string;
}

export interface OnboardDeps {
  hostsTest: (alias: string) => Promise<HostCheck>;
  hostsTrust: (alias: string, fingerprint: string) => Promise<HostCheck>;
  hostKeyFingerprints: (alias: string) => Promise<HostKeyFingerprint[]>;
  /** Install-form seams (`setup ssh-alias install` reads the same ones). */
  server: Partial<InstallServerDeps>;
}

async function runHostsOp(
  name: 'test' | 'trust',
  alias: string,
  args: Record<string, string | boolean>,
  yes: boolean,
): Promise<Envelope<unknown>> {
  const op = getOp('hosts', name);
  if (op === undefined) {
    throw new Error(`registry: hosts ${name} is missing`);
  }
  return executeOp(op, { alias, args }, { yes });
}

function checkOf(envelope: Envelope<unknown>): HostCheck {
  if (envelope.error !== null) {
    return { ok: false, code: envelope.error.code, message: envelope.error.message };
  }
  return { ok: true, code: null, message: '' };
}

export function defaultOnboardDeps(): OnboardDeps {
  return {
    hostsTest: async (alias) => {
      const envelope = await runHostsOp('test', alias, {}, false);
      const check = checkOf(envelope);
      const reachable = (envelope.data as { reachable?: boolean } | null)?.reachable === true;
      return check.ok && !reachable
        ? { ok: false, code: 'HOSTS_TEST_FAILED', message: 'the echo did not come back' }
        : check;
    },
    hostsTrust: async (alias, fingerprint) =>
      checkOf(await runHostsOp('trust', alias, { fingerprint }, true)),
    hostKeyFingerprints: async (alias) => {
      const envelope = await runHostsOp('trust', alias, { 'dry-run': true }, false);
      const data = envelope.data as { fingerprints?: HostKeyFingerprint[] } | null;
      return data?.fingerprints ?? [];
    },
    server: {},
  };
}

/** A pre-install `hosts test` that fails only on authentication proves the host key is trusted: the
 *  key exchange passed under strict checking and only the not-yet-installed key was refused. */
function hostKeyTrusted(check: HostCheck): boolean {
  return check.ok || check.code === 'AUTH_FAILED';
}

const HOST_KEY_CODES: ReadonlySet<string> = new Set([
  'HOST_KEY_UNKNOWN',
  'HOST_KEY_CHANGED',
  'HOST_KEY_FINGERPRINT_MISMATCH',
]);

function setupCodeOf(code: string | null): SetupErrorCode {
  if (code !== null && HOST_KEY_CODES.has(code)) {
    return code as SetupErrorCode;
  }
  return code === 'VALIDATION_ERROR' ? 'VALIDATION_ERROR' : 'REMOTE_FAILED';
}

export interface HostAddOptions {
  host?: string;
  user?: string;
  port?: number;
  fingerprint?: string;
  yes: boolean;
}

export interface HostAddData {
  alias: string;
  steps: string[];
  /** Only when the host key is not trusted yet: what the host presents, for a human to confirm. */
  fingerprints?: HostKeyFingerprint[];
  next?: string;
}

/**
 * `setup host add <alias> --host --user [--port] [--fingerprint] --yes`: registers the alias (or
 * reuses a managed one with the same values), generates its key, makes sure the host key is
 * trusted (already in known_hosts, or recorded through `hosts trust` with the `--fingerprint` a
 * human confirmed; never accept-new), opens the one-shot install form a human types the password
 * into, and ends with `hosts test`. Each step is idempotent, so a run stopped at the host key
 * continues where it stopped when run again with `--fingerprint`.
 */
export async function hostAdd(
  alias: string,
  options: HostAddOptions,
  configPath: string = defaultSshConfigPath(),
  deps: OnboardDeps = defaultOnboardDeps(),
): Promise<SetupResult<HostAddData>> {
  const command = 'setup host add';
  const argsSummary: Record<string, string | boolean> = {
    host: options.host ?? '',
    user: options.user ?? '',
    port: options.port === undefined ? '' : String(options.port),
    fingerprint: options.fingerprint ?? '',
  };
  const steps: string[] = [];
  const stop = (
    error: SetupErrorInput,
    extra: Partial<HostAddData> = {},
  ): SetupResult<HostAddData> => {
    auditMutating({ alias, command, argsSummary, outcome: 'error', errorCode: error.code });
    return buildSetupResult({ command, data: { alias, steps, ...extra }, error });
  };

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'host add requires --yes' },
    });
  }

  const existing = status(alias, configPath);
  if (existing.data !== null) {
    const current = existing.data;
    const differs =
      (options.host !== undefined && options.host !== current.host) ||
      (options.user !== undefined && options.user !== current.user) ||
      (options.port !== undefined && options.port !== current.port);
    if (differs) {
      return stop({
        code: 'ALIAS_EXISTS',
        message: `alias '${alias}' is already registered with other connection values; change them with setup ssh-alias update first`,
        next: `sshepherd setup ssh-alias update ${alias} --yes`,
      });
    }
    steps.push('register already done');
  } else if (existing.error?.code === 'PARSE_MISMATCH') {
    return stop(existing.error);
  } else {
    if (options.host === undefined || options.user === undefined) {
      return stop({
        code: 'INVALID_ARGS',
        message: `${command}: --host and --user are required for an alias that is not registered yet`,
      });
    }
    const registered = register(
      alias,
      { host: options.host, user: options.user, port: options.port, yes: true },
      configPath,
    );
    if (registered.error !== null) {
      return stop(registered.error);
    }
    steps.push('register ok');
  }

  if (status(alias, configPath).data?.hasKey === true) {
    steps.push('keygen already done');
  } else {
    const generated = await keygen(alias, { yes: true }, configPath);
    if (generated.error !== null) {
      return stop(generated.error);
    }
    steps.push('keygen ok');
  }

  const before = await deps.hostsTest(alias);
  if (hostKeyTrusted(before)) {
    steps.push('host-key already trusted');
  } else if (before.code !== null && HOST_KEY_CODES.has(before.code)) {
    if (options.fingerprint === undefined) {
      return stop(
        {
          code: setupCodeOf(before.code),
          message: `${command}: the host key of '${alias}' is not trusted yet (${before.code}); nothing was installed`,
          next: `sshepherd setup host add ${alias} --fingerprint <SHA256:...> --yes`,
        },
        { fingerprints: await deps.hostKeyFingerprints(alias) },
      );
    }
    const trusted = await deps.hostsTrust(alias, options.fingerprint);
    if (!trusted.ok) {
      return stop(
        {
          code: setupCodeOf(trusted.code),
          message: `${command}: hosts trust: ${trusted.code}: ${trusted.message}`,
          next: `sshepherd hosts trust ${alias} --dry-run`,
        },
        { fingerprints: await deps.hostKeyFingerprints(alias) },
      );
    }
    steps.push('hosts trust ok');
  } else {
    return stop({
      code: 'REMOTE_FAILED',
      message: `${command}: hosts test: ${before.code}: ${before.message}`,
      next: `sshepherd hosts test ${alias} --diagnose`,
    });
  }

  const installed = await install(
    alias,
    { yes: true, strictHostKey: true },
    configPath,
    deps.server,
  );
  if (installed.error !== null) {
    return stop(installed.error);
  }
  steps.push(
    installed.data?.method === 'already_trusted' ? 'install already_trusted' : 'install ok',
  );

  const after = await deps.hostsTest(alias);
  if (!after.ok) {
    return stop({
      code: 'REMOTE_FAILED',
      message: `${command}: hosts test after install: ${after.code}: ${after.message}`,
      next: `sshepherd hosts test ${alias} --diagnose`,
    });
  }
  steps.push('hosts test ok');

  auditMutating({ alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: {
      alias,
      steps,
      next: `sshepherd setup files-allowlist scaffold ${alias} --paths <remote dir> --yes`,
    },
  });
}

// -- adopt-env --------------------------------------------------------------------------------

/** Reads a `.env` the way dotenv loaders do: `[export ]KEY=value`, `#` comments, CRLF, single or
 *  double quotes (a double-quoted value may span lines and carry `\n` escapes, as an inline PEM key
 *  does), an unquoted value cut at ` #`. The last assignment of a key wins. */
export function parseDotenv(text: string): Map<string, string> {
  const values = new Map<string, string>();
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index++) {
    const line = (lines[index] ?? '').trim().replace(/^export\s+/, '');
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (match === null) {
      continue;
    }
    const key = match[1] ?? '';
    let value = match[2] ?? '';
    const quote = value[0];
    if (quote === '"' || quote === "'") {
      let body = value.slice(1);
      while (!body.includes(quote) && index + 1 < lines.length) {
        index += 1;
        body += `\n${lines[index] ?? ''}`;
      }
      const end = body.indexOf(quote);
      value = end === -1 ? body : body.slice(0, end);
      if (quote === '"') {
        value = value.replace(/\\n/g, '\n');
      }
    } else {
      value = value.replace(/\s+#.*$/, '').trim();
    }
    values.set(key, value);
  }
  return values;
}

const SSH_KEY_PATTERN =
  /^(?:([A-Za-z0-9_]*?)_)?SSH_(HOST|HOSTNAME|USER|USERNAME|PORT|PASSWORD|PASS|PRIVATE_KEY)$/i;

const FIELD_OF: Record<string, keyof SshGroupFields> = {
  HOST: 'host',
  HOSTNAME: 'host',
  USER: 'user',
  USERNAME: 'user',
  PORT: 'port',
  PASSWORD: 'password',
  PASS: 'password',
  PRIVATE_KEY: 'privateKey',
};

interface SshGroupFields {
  host?: string;
  user?: string;
  port?: string;
  password?: string;
  privateKey?: string;
}

export interface SshGroup {
  /** The key prefix before `SSH_` (`BILLING` for `BILLING_SSH_HOST`), upper-case; '' for none. */
  prefix: string;
  fields: SshGroupFields;
}

/** Every `<PREFIX>_SSH_*` / `SSH_*` group in the `.env` that names a host, in file order. */
export function sshGroups(values: Map<string, string>): SshGroup[] {
  const groups = new Map<string, SshGroupFields>();
  for (const [key, value] of values) {
    const match = SSH_KEY_PATTERN.exec(key);
    if (match === null || value.length === 0) {
      continue;
    }
    const prefix = (match[1] ?? '').toUpperCase();
    const field = FIELD_OF[(match[2] ?? '').toUpperCase()];
    if (field === undefined) {
      continue;
    }
    const fields = groups.get(prefix) ?? {};
    fields[field] = value;
    groups.set(prefix, fields);
  }
  return [...groups.entries()]
    .filter(([, fields]) => fields.host !== undefined)
    .map(([prefix, fields]) => ({ prefix, fields }));
}

function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** `<project dir name>` for `SSH_*`, `<project dir name>-<prefix>` for `<PREFIX>_SSH_*`. */
export function adoptedAliasName(projectDir: string, prefix: string): string {
  const project = slug(basename(resolve(projectDir))) || 'project';
  return prefix.length === 0 ? project : `${project}-${slug(prefix)}`;
}

function keyName(prefix: string, field: string): string {
  return prefix.length === 0 ? `SSH_${field}` : `${prefix}_SSH_${field}`;
}

export interface AdoptedHost {
  alias: string;
  key_installed: boolean;
  /** Only when `key_installed` is false: the code of the step that stopped it. */
  reason?: string;
  next?: string;
}

async function adoptOne(
  alias: string,
  group: SshGroup,
  configPath: string,
  deps: OnboardDeps,
): Promise<AdoptedHost> {
  const { host, user, password, privateKey } = group.fields;
  const port = group.fields.port === undefined ? 22 : Number(group.fields.port);
  const missing = [
    user === undefined ? keyName(group.prefix, 'USER') : null,
    password === undefined && privateKey === undefined
      ? `${keyName(group.prefix, 'PASSWORD')} or ${keyName(group.prefix, 'PRIVATE_KEY')}`
      : null,
    Number.isInteger(port) && port > 0 && port < 65_536 ? null : keyName(group.prefix, 'PORT'),
  ].filter((name): name is string => name !== null);
  const notInstalled = (reason: string, next: string): AdoptedHost => ({
    alias,
    key_installed: false,
    reason,
    next,
  });
  if (host === undefined || user === undefined || missing.length > 0) {
    return notInstalled(
      'INCOMPLETE',
      `set ${missing.join(', ')} in the project's .env, then run adopt-env again`,
    );
  }

  const existing = status(alias, configPath);
  if (existing.data !== null) {
    const current = existing.data;
    if (current.host !== host || current.user !== user || current.port !== port) {
      return notInstalled(
        'ALIAS_EXISTS',
        `sshepherd setup ssh-alias update ${alias} --yes (it is registered with other values)`,
      );
    }
  } else {
    const registered = register(alias, { host, user, port, yes: true }, configPath);
    if (registered.error !== null) {
      return notInstalled(
        registered.error.code,
        registered.error.next ?? 'sshepherd setup ssh-alias list',
      );
    }
  }
  if (status(alias, configPath).data?.hasKey !== true) {
    const generated = await keygen(alias, { yes: true }, configPath);
    if (generated.error !== null) {
      return notInstalled(generated.error.code, `sshepherd setup ssh-alias keygen ${alias} --yes`);
    }
  }

  const server: InstallServerDeps = { ...defaultInstallServerDeps(), ...deps.server };
  const target: InstallTarget = {
    alias,
    host,
    user,
    port,
    publicKeyPath: `${keyPathFor(alias, configPath)}.pub`,
    sshConfigPath: configPath,
  };
  if (await server.peekBanner(target)) {
    return notInstalled('TAILSCALE_SSH_DETECTED', 'connect through Tailscale SSH without a key');
  }
  const before = await deps.hostsTest(alias);
  if (before.ok) {
    return { alias, key_installed: true };
  }
  if (!hostKeyTrusted(before)) {
    const code = before.code ?? 'REMOTE_FAILED';
    return notInstalled(
      code,
      HOST_KEY_CODES.has(code)
        ? `sshepherd hosts trust ${alias} --dry-run, then --fingerprint <SHA256:...> --yes once a human confirmed it, then adopt-env again`
        : `sshepherd hosts test ${alias} --diagnose`,
    );
  }

  if (privateKey !== undefined) {
    // A `.env` value loses the PEM's final newline, without which ssh-keygen rejects the key.
    const keyText = privateKey.endsWith('\n') ? privateKey : `${privateKey}\n`;
    const outcome = await server.spawnInstallWithKey(keyText, target);
    if (outcome.kind === 'invalid_private_key') {
      return notInstalled('INVALID_PRIVATE_KEY', `check ${keyName(group.prefix, 'PRIVATE_KEY')}`);
    }
    if (outcome.kind === 'passphrase_protected_key') {
      return notInstalled(
        'PASSPHRASE_PROTECTED_KEY_UNSUPPORTED',
        `sshepherd setup ssh-alias install ${alias} --yes (a human uses the password)`,
      );
    }
    if (outcome.kind !== 'installed') {
      return notInstalled('INSTALL_FAILED', `sshepherd setup ssh-alias install ${alias} --yes`);
    }
  } else if (password !== undefined) {
    if (server.which('sshpass') === null) {
      return notInstalled('SSHPASS_NOT_FOUND', 'install sshpass, then run adopt-env again');
    }
    const outcome = await server.spawnInstall(password, target);
    if (outcome.timedOut || outcome.code !== 0) {
      return notInstalled(
        'INSTALL_FAILED',
        `sshepherd setup ssh-alias install ${alias} --yes (the .env password was refused)`,
      );
    }
  }

  const after = await deps.hostsTest(alias);
  return after.ok
    ? { alias, key_installed: true }
    : notInstalled(after.code ?? 'HOSTS_TEST_FAILED', `sshepherd hosts test ${alias} --diagnose`);
}

/**
 * `setup ssh-alias adopt-env <project-dir> --yes`: for every host group (`SSH_HOST`,
 * `<PREFIX>_SSH_HOST` with its `_USER`, `_PORT`, `_PASSWORD` or `_PRIVATE_KEY`) in that project's
 * `.env`, registers an alias, generates its key and installs it with the credential the `.env`
 * holds, in-process (the password goes to sshpass on stdin, a key to a 0600 temp file removed
 * after). The host key must already be trusted; one that is not is reported, never accepted. The
 * result is `[{alias, key_installed}]` only: no value from the `.env` reaches the output or the
 * audit log.
 */
export async function adoptEnv(
  projectDir: string,
  options: { yes: boolean },
  configPath: string = defaultSshConfigPath(),
  deps: OnboardDeps = defaultOnboardDeps(),
): Promise<SetupResult<AdoptedHost[]>> {
  const command = 'setup ssh-alias adopt-env';
  const projectAlias = adoptedAliasName(projectDir, '');
  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias: projectAlias, command, argsSummary: {}, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'adopt-env requires --yes' },
    });
  }
  const invalid = (message: string): SetupResult<AdoptedHost[]> => {
    auditMutating({
      alias: projectAlias,
      command,
      argsSummary: {},
      outcome: 'error',
      errorCode: 'VALIDATION_ERROR',
    });
    return buildSetupResult({ command, error: { code: 'VALIDATION_ERROR', message } });
  };

  const envPath = join(projectDir, '.env');
  if (!existsSync(envPath) || !statSync(envPath).isFile()) {
    return invalid(`${command}: the project directory has no .env file`);
  }
  if (statSync(envPath).size > ADOPT_ENV_MAX_FILE_BYTES) {
    return invalid(
      `${command}: the project's .env is larger than ${ADOPT_ENV_MAX_FILE_BYTES} bytes`,
    );
  }
  const groups = sshGroups(parseDotenv(readFileSync(envPath, 'utf8')));
  if (groups.length === 0) {
    return invalid(`${command}: the project's .env has no SSH_HOST or <PREFIX>_SSH_HOST key`);
  }
  if (groups.length > ADOPT_ENV_MAX_HOSTS) {
    return invalid(
      `${command}: the project's .env names ${groups.length} hosts; adopt-env takes at most ${ADOPT_ENV_MAX_HOSTS} per run`,
    );
  }

  const adopted: AdoptedHost[] = [];
  for (const group of groups) {
    const alias = adoptedAliasName(projectDir, group.prefix);
    const result = await adoptOne(alias, group, configPath, deps);
    auditMutating({
      alias,
      command,
      argsSummary: {},
      outcome: result.key_installed ? 'ok' : 'error',
      errorCode: result.reason,
    });
    adopted.push(result);
  }
  return buildSetupResult({ command, data: adopted });
}
