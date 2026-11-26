import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  arg,
  DEFAULT_TIMEOUT_SEC,
  FILE_CAT_MAX_BYTES,
  FILE_TIMEOUT_SEC,
  optStr,
  reqStr,
} from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { parseTomlFile } from '../toml-parse.ts';
import { type AllowlistPolicy, type OpContext, OpError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

interface ConfigAllowlist {
  [alias: string]: string[];
}

/**
 * `scope` picks both the env override key (`SSHEPHERD_CONFIG_ALLOWLIST_PATH` /
 * `SSHEPHERD_FILES_ALLOWLIST_PATH`) and the default filename (`<scope>-allowlist.toml`) —
 * one function instead of a copy per scope, per coding-standard.md rule 5/17.
 */
function defaultPathAllowlistPath(scope: 'config' | 'files'): string {
  const envKey =
    scope === 'config' ? 'SSHEPHERD_CONFIG_ALLOWLIST_PATH' : 'SSHEPHERD_FILES_ALLOWLIST_PATH';
  const override = process.env[envKey];
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', `${scope}-allowlist.toml`);
}

export function defaultConfigAllowlistPath(): string {
  return defaultPathAllowlistPath('config');
}

export function defaultFilesAllowlistPath(): string {
  return defaultPathAllowlistPath('files');
}

/** Missing file yields an empty allowlist (mirrors targets.ts's missing-config behavior) — every path refused until declared. */
export function loadPathAllowlist(
  scope: 'config' | 'files',
  path: string = defaultPathAllowlistPath(scope),
): ConfigAllowlist {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return {};
  }
  const parsed = parseTomlFile(
    text,
    `${scope}-allowlist.toml`,
    `Fix the line named in ${scope}-allowlist.toml (SSHEPHERD_${scope.toUpperCase()}_ALLOWLIST_PATH, else ~/.config/sshepherd/${scope}-allowlist.toml), then run the command again.`,
  );
  const allowlist: ConfigAllowlist = {};
  for (const [alias, raw] of Object.entries(parsed)) {
    const record = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
    const paths = Array.isArray(record.paths) ? record.paths : [];
    allowlist[alias] = paths.filter((p): p is string => typeof p === 'string');
  }
  return allowlist;
}

export function loadConfigAllowlist(path: string = defaultConfigAllowlistPath()): ConfigAllowlist {
  return loadPathAllowlist('config', path);
}

export function loadFilesAllowlist(path: string = defaultFilesAllowlistPath()): ConfigAllowlist {
  return loadPathAllowlist('files', path);
}

/** Local refusal, before ssh — a path not declared for this alias never reaches the remote.
 *  Shared by both `config` and `files` ops; which scope's allowlist file to check comes from
 *  the op's declarative `allowlist` policy, not a per-op call site (see `executeOp`). */
export function assertPathAllowed(scope: 'config' | 'files', ctx: OpContext, path: string): void {
  const allowlist = loadPathAllowlist(scope);
  const allowed = allowlist[ctx.alias] ?? [];
  if (!allowed.includes(path)) {
    throw new OpError(
      'VALIDATION_ERROR',
      `${scope} path '${path}' is not on the allowlist for alias '${ctx.alias}'`,
      {
        hint: `A human declares allowed paths with setup ${scope}-allowlist scaffold; the agent never widens its own allowlist.`,
      },
    );
  }
}

interface RevealAllowlist {
  [alias: string]: string[];
}

export function defaultRevealAllowlistPath(): string {
  const override = process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', 'reveal-allowlist.toml');
}

/** Missing file yields an empty allowlist — every `--reveal` key refused until declared,
 *  same fail-closed rule as `loadPathAllowlist`. */
export function loadRevealAllowlist(path: string = defaultRevealAllowlistPath()): RevealAllowlist {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return {};
  }
  const parsed = parseTomlFile(
    text,
    'reveal-allowlist.toml',
    'Fix the line named in reveal-allowlist.toml (SSHEPHERD_REVEAL_ALLOWLIST_PATH, else ~/.config/sshepherd/reveal-allowlist.toml), then run the command again.',
  );
  const allowlist: RevealAllowlist = {};
  for (const [alias, raw] of Object.entries(parsed)) {
    const record = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
    const keys = Array.isArray(record.keys) ? record.keys : [];
    allowlist[alias] = keys.filter((k): k is string => typeof k === 'string');
  }
  return allowlist;
}

/** Hardcoded, non-overridable — checked before the per-alias reveal-allowlist, so a key
 *  matching one of these patterns can never be revealed even if it was mistakenly added to
 *  reveal-allowlist.toml. Case-insensitive substring/suffix match against the key name only
 *  (never the value, which `files cat` never sees unmasked until this check passes). */
export const REVEAL_DENYLIST_PATTERNS: RegExp[] = [
  /PASSWORD/i,
  /PASSWD/i,
  /SECRET/i,
  /TOKEN/i,
  /PRIVATE[_-]?KEY/i,
  /CREDENTIAL/i,
  /API[_-]?KEY/i,
  /_KEY$/i,
  /_PASS$/i,
];

/** Local refusal, before ssh — every requested `--reveal` key must clear the hardcoded
 *  denylist first, then be declared on the alias's reveal-allowlist.toml entry. */
export function assertRevealKeysAllowed(ctx: OpContext, keys: Set<string>): void {
  const allowlist = loadRevealAllowlist();
  const allowedForAlias = new Set(allowlist[ctx.alias] ?? []);
  for (const key of keys) {
    if (REVEAL_DENYLIST_PATTERNS.some((pattern) => pattern.test(key))) {
      throw new OpError(
        'VALIDATION_ERROR',
        `reveal key '${key}' matches a hard-denied secret pattern and can never be revealed`,
      );
    }
    if (!allowedForAlias.has(key)) {
      throw new OpError(
        'VALIDATION_ERROR',
        `reveal key '${key}' is not on the reveal-allowlist for alias '${ctx.alias}'`,
      );
    }
  }
}

/** The one place an `OpSpec.allowlist` policy is enforced — called from `executeOp` before
 *  `buildRemote` runs, so no op implements its own allowlist check (coding-standard.md rule
 *  17). Throws the same way the old per-op `assertConfigPathAllowed` calls did; the CLI's
 *  top-level `main()` catch converts the throw into a printed error + exit code 2. */
export function enforceAllowlist(policies: AllowlistPolicy[] | undefined, ctx: OpContext): void {
  for (const policy of policies ?? []) {
    if (policy.kind === 'path') {
      assertPathAllowed(policy.scope, ctx, reqStr(ctx, policy.argName));
      continue;
    }
    const keys = new Set(
      optStr(ctx, policy.argName, '')
        .split(',')
        .map((key) => key.trim())
        .filter((key) => key.length > 0),
    );
    assertRevealKeysAllowed(ctx, keys);
  }
}

interface ConfigGetResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  content: string | null;
}

const configGet: OpSpec<ConfigGetResult> = {
  group: 'config',
  name: 'get',
  summary: 'Read an allowlisted remote config file (size-guarded).',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
  ],
  mutating: false,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'config', argName: 'path' }],
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const script = [
      `p=${shq(path)}`,
      'if [ ! -f "$p" ]; then echo __NOT_FOUND__; exit 0; fi',
      'sz=$(wc -c < "$p")',
      `if [ "$sz" -gt ${FILE_CAT_MAX_BYTES} ]; then echo "__TOO_LARGE__:$sz"; else cat "$p"; fi`,
    ].join('; ');
    return shellJoin(['sh', '-c', script]);
  },
  shape: (parsed) => {
    const text = parsed as string;
    const trimmed = text.trim();
    if (trimmed === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, content: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(trimmed);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        content: null,
      };
    }
    return {
      found: true,
      truncated: false,
      size_bytes: Buffer.byteLength(text, 'utf8'),
      content: text,
    };
  },
};

function buildConfigValidateCommand(path: string): string {
  if (/nginx/i.test(path)) {
    return shellJoin(['nginx', '-t']);
  }
  if (/sshd_config/i.test(path)) {
    return shellJoin(['sshd', '-t']);
  }
  if (/caddy/i.test(path)) {
    return shellJoin(['caddy', 'validate', '--config', path]);
  }
  if (/(docker-)?compose\.ya?ml$/i.test(path)) {
    return shellJoin(['docker', 'compose', '-f', path, 'config', '-q']);
  }
  throw new OpError('VALIDATION_ERROR', `config validate: no known validator for path '${path}'`);
}

const configValidate: OpSpec<{ valid: boolean }> = {
  group: 'config',
  name: 'validate',
  summary:
    'Syntax-check an allowlisted config file (nginx -t / sshd -t / caddy validate / compose config -q).',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
  ],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'config', argName: 'path' }],
  buildRemote: (ctx) => buildConfigValidateCommand(reqStr(ctx, 'path')),
  shape: () => ({ valid: true }),
};

/** Backs up the existing file to `<path>.bak-<UTCdate>` BEFORE the write, in the same remote script. */
function buildConfigPutScript(path: string, contentBase64: string): string {
  const script = [
    `p=${shq(path)}`,
    'if [ -f "$p" ]; then cp "$p" "$p.bak-$(date -u +%Y%m%dT%H%M%SZ)"; fi',
    `printf '%s' ${shq(contentBase64)} | base64 -d > "$p"`,
  ].join('; ');
  return shellJoin(['sh', '-c', script]);
}

const configPut: OpSpec<{ written: boolean }> = {
  group: 'config',
  name: 'put',
  summary:
    'Write an allowlisted remote config file — backs up the existing file (.bak-<UTCdate>) before overwriting.',
  args: [
    arg('path', 'positional', true, 'Remote file path — must be declared in the alias allowlist.'),
    arg(
      'content-base64',
      'flag',
      true,
      'Base64-encoded content to write (CLI reads the local --from file and encodes it).',
    ),
  ],
  mutating: true,
  timeoutSec: FILE_TIMEOUT_SEC,
  output: 'raw',
  allowlist: [{ kind: 'path', scope: 'config', argName: 'path' }],
  buildRemote: (ctx) => {
    const path = reqStr(ctx, 'path');
    const contentBase64 = reqStr(ctx, 'content-base64');
    return buildConfigPutScript(path, contentBase64);
  },
  shape: () => ({ written: true }),
};

function buildConfigReloadCommand(service: string): string {
  if (service === 'nginx') {
    return shellJoin(['nginx', '-s', 'reload']);
  }
  return shellJoin(['systemctl', 'reload', service]);
}

const configReload: OpSpec<{ reloaded: boolean }> = {
  group: 'config',
  name: 'reload',
  summary: 'Reload a service after a config change (systemctl reload / nginx -s reload).',
  args: [arg('service', 'positional', true, 'Service name (e.g. nginx, sshd).')],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildConfigReloadCommand(reqStr(ctx, 'service')),
  shape: () => ({ reloaded: true }),
};

export const configOps = [configGet, configValidate, configPut, configReload] as OpSpec[];
