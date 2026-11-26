import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  arg,
  DEFAULT_TIMEOUT_SEC,
  FILE_CAT_MAX_BYTES,
  FILE_TIMEOUT_SEC,
  optStr,
  optStrOrNull,
  reqStr,
} from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { isEnvFile, maskEnvContent, REVEAL_DENYLIST_PATTERNS } from '../scrub.ts';
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

/** The allowlisted entry `path` sits under (never `/`), once `..` segments are refused outright:
 *  a `..` could walk out of the root after the prefix check passed. */
function underAllowedEntry(allowed: string[], path: string): boolean {
  if (path.split('/').includes('..')) {
    return false;
  }
  const trimmed = path.length > 1 ? path.replace(/\/+$/, '') : path;
  return allowed.some((entry) => {
    const root = entry.length > 1 ? entry.replace(/\/+$/, '') : entry;
    return root !== '/' && (trimmed === root || trimmed.startsWith(`${root}/`));
  });
}

/** Local refusal, before ssh — a path not declared for this alias never reaches the remote.
 *  Shared by both `config` and `files` ops; which scope's allowlist file to check comes from
 *  the op's declarative `allowlist` policy, not a per-op call site (see `executeOp`). `within`
 *  accepts a path under a declared entry as well as the entry itself. */
export function assertPathAllowed(
  scope: 'config' | 'files',
  ctx: OpContext,
  path: string,
  within = false,
): void {
  const allowlist = loadPathAllowlist(scope);
  const allowed = allowlist[ctx.alias] ?? [];
  if (!(within ? underAllowedEntry(allowed, path) : allowed.includes(path))) {
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

const REVEAL_ALLOWLIST_HINT =
  'Fix the line named in reveal-allowlist.toml (SSHEPHERD_REVEAL_ALLOWLIST_PATH, else ~/.config/sshepherd/reveal-allowlist.toml), then run the command again.';

function readRevealAllowlistFile(path: string): Record<string, unknown> {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return {};
  }
  return parseTomlFile(text, 'reveal-allowlist.toml', REVEAL_ALLOWLIST_HINT);
}

/** Missing file yields an empty allowlist — every `--reveal` key refused until declared,
 *  same fail-closed rule as `loadPathAllowlist`. */
export function loadRevealAllowlist(path: string = defaultRevealAllowlistPath()): RevealAllowlist {
  const parsed = readRevealAllowlistFile(path);
  const allowlist: RevealAllowlist = {};
  for (const [alias, raw] of Object.entries(parsed)) {
    const record = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
    const keys = Array.isArray(record.keys) ? record.keys : [];
    allowlist[alias] = keys.filter((k): k is string => typeof k === 'string');
  }
  return allowlist;
}

export { REVEAL_DENYLIST_PATTERNS };

/** The `[<alias>.scrub]` table of reveal-allowlist.toml, empty when absent. */
function aliasScrubTable(alias: string, path: string): Record<string, unknown> {
  const parsed = readRevealAllowlistFile(path);
  const aliasTable =
    typeof parsed[alias] === 'object' && parsed[alias] !== null ? parsed[alias] : {};
  const scrubTable = (aliasTable as Record<string, unknown>).scrub;
  return typeof scrubTable === 'object' && scrubTable !== null
    ? (scrubTable as Record<string, unknown>)
    : {};
}

/** `[<alias>.scrub] reveal_addresses = true` keeps that alias's IP literals visible (no `<ip-N>`);
 *  its own hostname, user and port stay masked whatever this says. Anything but a boolean is refused
 *  without echoing the value. */
export function loadRevealAddresses(
  alias: string,
  path: string = defaultRevealAllowlistPath(),
): boolean {
  const value = aliasScrubTable(alias, path).reveal_addresses;
  if (value === undefined) {
    return false;
  }
  if (typeof value !== 'boolean') {
    throw new OpError(
      'CONFIG_PARSE_ERROR',
      `reveal-allowlist.toml: [${alias}.scrub] reveal_addresses must be true or false`,
      { hint: REVEAL_ALLOWLIST_HINT },
    );
  }
  return value;
}

/** An alias's own extra scrub patterns, from `[<alias>.scrub] extra_patterns = ["regex", ...]`
 *  in reveal-allowlist.toml — the per-alias file that already says what is secret for it. Every
 *  match is masked in that alias's output. A pattern that does not compile is refused by index,
 *  never echoed: a human may have typed a literal secret as the pattern. */
export function loadScrubExtraPatterns(
  alias: string,
  path: string = defaultRevealAllowlistPath(),
): RegExp[] {
  const record = aliasScrubTable(alias, path);
  const sources = Array.isArray(record.extra_patterns) ? record.extra_patterns : [];
  return sources
    .filter((source): source is string => typeof source === 'string')
    .map((source, index) => {
      try {
        return new RegExp(source, 'g');
      } catch {
        throw new OpError(
          'CONFIG_PARSE_ERROR',
          `reveal-allowlist.toml: [${alias}.scrub] extra_patterns[${index}] is not a valid regular expression`,
          { hint: REVEAL_ALLOWLIST_HINT },
        );
      }
    });
}

/** The comma-separated key list a `--reveal`-style arg carries, trimmed, empties dropped. */
export function revealKeysOf(ctx: OpContext, argName: string): Set<string> {
  return new Set(
    optStr(ctx, argName, '')
      .split(',')
      .map((key) => key.trim())
      .filter((key) => key.length > 0),
  );
}

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
      if (policy.optional && optStrOrNull(ctx, policy.argName) === null) {
        continue;
      }
      assertPathAllowed(policy.scope, ctx, reqStr(ctx, policy.argName), policy.within === true);
      continue;
    }
    assertRevealKeysAllowed(ctx, revealKeysOf(ctx, policy.argName));
  }
}

interface ConfigGetResult {
  found: boolean;
  truncated: boolean;
  size_bytes: number | null;
  masked: boolean;
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
  exposes: 'content',
  exposeStderr: false,
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
  shape: (parsed, ctx) => {
    const text = parsed as string;
    const trimmed = text.trim();
    if (trimmed === '__NOT_FOUND__') {
      return { found: false, truncated: false, size_bytes: null, masked: false, content: null };
    }
    const tooLarge = /^__TOO_LARGE__:(\d+)/.exec(trimmed);
    if (tooLarge) {
      const size = tooLarge[1];
      return {
        found: true,
        truncated: true,
        size_bytes: size !== undefined ? Number.parseInt(size, 10) : null,
        masked: false,
        content: null,
      };
    }
    const shouldMask = isEnvFile(reqStr(ctx, 'path'));
    return {
      found: true,
      truncated: false,
      size_bytes: Buffer.byteLength(text, 'utf8'),
      masked: shouldMask,
      content: shouldMask ? maskEnvContent(text, new Set()) : text,
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
  exposes: 'none',
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
  exposes: 'none',
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
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildConfigReloadCommand(reqStr(ctx, 'service')),
  shape: () => ({ reloaded: true }),
};

export const configOps = [configGet, configValidate, configPut, configReload] as OpSpec[];
