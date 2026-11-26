import { arg, DEFAULT_TIMEOUT_SEC, optBool } from '../op-args.ts';
import { parseAuthorizedKeysLine, parseFingerprintLine } from '../parsers/authorized-keys.ts';
import { parseFail2banStatus } from '../parsers/fail2ban.ts';
import { splitSections } from '../parsers/sections.ts';
import { parseSs } from '../parsers/ss.ts';
import { parseSshdDirectives } from '../parsers/sshd-directives.ts';
import { shellJoin, shq } from '../quote.ts';
import type { OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// security
// ---------------------------------------------------------------------------

/** Directives that cannot self-lockout an already-authenticated session — applied unconditionally. */
const HARDEN_SAFE_DIRECTIVES: Array<[string, string]> = [
  ['X11Forwarding', 'no'],
  ['PermitEmptyPasswords', 'no'],
  ['MaxAuthTries', '4'],
  ['ClientAliveInterval', '300'],
  ['ClientAliveCountMax', '2'],
];

/** Directives that CAN self-lockout (disabling the current session's own auth method) — refused
 *  unless `--keep-session` is explicitly turned off (server-pattern.md §D no-self-lockout rule). */
const HARDEN_RISKY_DIRECTIVES: Array<[string, string]> = [
  ['PermitRootLogin', 'no'],
  ['PasswordAuthentication', 'no'],
];

function buildHardenScript(keepSession: boolean): string {
  const cfg = '/etc/ssh/sshd_config';
  const directives = keepSession
    ? HARDEN_SAFE_DIRECTIVES
    : [...HARDEN_SAFE_DIRECTIVES, ...HARDEN_RISKY_DIRECTIVES];
  const steps = [`cp ${cfg} ${cfg}.bak-$(date -u +%Y%m%dT%H%M%SZ)`];
  for (const [key, value] of directives) {
    steps.push(`sed -i '/^${key} /d' ${cfg}`);
    steps.push(`echo ${shq(`${key} ${value}`)} >> ${cfg}`);
  }
  steps.push('sshd -t');
  steps.push('systemctl reload sshd || service ssh reload');
  return shellJoin(['sh', '-c', steps.join(' && ')]);
}

const securityHarden: OpSpec<{ applied: string[]; keep_session: boolean }> = {
  group: 'security',
  name: 'harden',
  summary:
    'Backs up sshd_config, applies lockout-safe hardening directives, validates (sshd -t), reloads. ' +
    '--keep-session defaults true and refuses PermitRootLogin/PasswordAuthentication changes unless explicitly turned off.',
  args: [
    arg(
      'keep-session',
      'flag',
      false,
      'Default true. Pass false to also apply lockout-risky directives (PermitRootLogin no, PasswordAuthentication no).',
    ),
  ],
  mutating: true,
  exposes: 'none',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: (ctx) => buildHardenScript(optBool(ctx, 'keep-session', true)),
  shape: (_parsed, ctx) => {
    const keepSession = optBool(ctx, 'keep-session', true);
    const directives = keepSession
      ? HARDEN_SAFE_DIRECTIVES
      : [...HARDEN_SAFE_DIRECTIVES, ...HARDEN_RISKY_DIRECTIVES];
    return {
      applied: directives.map(([key, value]) => `${key} ${value}`),
      keep_session: keepSession,
    };
  },
};

// security (read-only)

/** Every directive `security harden` can apply IS the posture this reports on — one
 *  source of truth for "recommended", so harden and its read-only counterpart can never
 *  silently disagree on what "hardened" means. */
const SSH_AUDIT_DIRECTIVES: Array<[string, string]> = [
  ...HARDEN_SAFE_DIRECTIVES,
  ...HARDEN_RISKY_DIRECTIVES,
];

function isDirectiveOk(value: string | null, recommended: string): boolean {
  if (value === null) {
    return false;
  }
  const recommendedNumber = Number.parseInt(recommended, 10);
  if (!Number.isNaN(recommendedNumber)) {
    const valueNumber = Number.parseInt(value, 10);
    return !Number.isNaN(valueNumber) && valueNumber > 0 && valueNumber <= recommendedNumber;
  }
  return value.toLowerCase() === recommended.toLowerCase();
}

/** `sshd -T` (effective config, requires root) with a same-round-trip fallback to reading
 *  `/etc/ssh/sshd_config` directly when that fails — only when BOTH sources fail does the
 *  script exit non-zero, which `transport.run` classifies as a clean `COMMAND_FAILED`. */
function buildSshAuditScript(): string {
  return [
    'if command -v sshd >/dev/null 2>&1 && out=$(sshd -T 2>/dev/null); then printf \'%s\' "$out";',
    'elif out=$(cat /etc/ssh/sshd_config 2>/dev/null); then printf \'%s\' "$out";',
    'else exit 1; fi',
  ].join(' ');
}

interface SshAuditDirectiveResult {
  directive: string;
  value: string | null;
  recommended: string;
  ok: boolean;
}

const securitySshAudit: OpSpec<{ directives: SshAuditDirectiveResult[] }> = {
  group: 'security',
  name: 'ssh-audit',
  summary:
    'Effective sshd hardening posture per directive (sshd -T, degrades to reading sshd_config) — ' +
    'the read-only counterpart to security harden, sharing its recommended values.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => shellJoin(['sh', '-c', buildSshAuditScript()]),
  shape: (parsed) => {
    const effective = parseSshdDirectives(parsed as string);
    return {
      directives: SSH_AUDIT_DIRECTIVES.map(([directive, recommended]) => {
        const value = effective[directive.toLowerCase()] ?? null;
        return { directive, value, recommended, ok: isDirectiveOk(value, recommended) };
      }),
    };
  },
};

interface SecurityListenerEntry {
  proto: 'tcp';
  local_addr: string;
  port: number;
  process: string | null;
  pid: number | null;
}

const securityListeners: OpSpec<{ listening: SecurityListenerEntry[] }> = {
  group: 'security',
  name: 'listeners',
  summary:
    'Listening TCP sockets + owning process — the attack surface (same ss -H -tlnp data as check ports, security-group framing, same parser).',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => shellJoin(['ss', '-H', '-tlnp']),
  shape: (parsed) => ({
    listening: parseSs(parsed as string).map((entry) => ({
      proto: entry.proto,
      local_addr: entry.local_address,
      port: entry.local_port,
      process: entry.process,
      pid: entry.pid,
    })),
  }),
};

/** Bundles the raw `authorized_keys` file with a remote `ssh-keygen -lf` fingerprint pass
 *  over that same file, in one round trip — the two outputs are line-order-aligned (both
 *  skip blank/comment lines the same way) so `shape` never needs the key blob itself to
 *  correlate a fingerprint with its options/comment. */
function buildAuthorizedKeysScript(): string {
  return [
    'p="$HOME/.ssh/authorized_keys"',
    'if [ ! -f "$p" ]; then exit 0; fi',
    'echo __RAW__',
    'cat "$p"',
    'echo __FP__',
    'ssh-keygen -lf "$p" 2>/dev/null || true',
  ].join('; ');
}

interface AuthorizedKeyResult {
  type: string;
  fingerprint: string | null;
  comment: string | null;
  options: string | null;
}

const securityAuthorizedKeys: OpSpec<{ found: boolean; keys: AuthorizedKeyResult[] }> = {
  group: 'security',
  name: 'authorized-keys',
  summary:
    "Enumerates the connecting user's authorized_keys entries as {type, fingerprint, comment, options} — " +
    'fingerprints only, never the raw key blob.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: { parse: splitSections },
  buildRemote: () => shellJoin(['sh', '-c', buildAuthorizedKeysScript()]),
  shape: (parsed) => {
    const sections = parsed as Record<string, string>;
    if (sections.RAW === undefined) {
      return { found: false, keys: [] };
    }
    const rawLines = sections.RAW.split('\n').filter(
      (line) => line.trim().length > 0 && !line.trim().startsWith('#'),
    );
    const fingerprintLines = (sections.FP ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const keys = rawLines.map((line, index) => {
      const parsedLine = parseAuthorizedKeysLine(line);
      const fingerprintLine = fingerprintLines[index];
      return {
        type: parsedLine?.type ?? 'unknown',
        fingerprint: fingerprintLine !== undefined ? parseFingerprintLine(fingerprintLine) : null,
        comment: parsedLine?.comment ?? null,
        options: parsedLine?.options ?? null,
      };
    });
    return { found: true, keys };
  },
};

/** No native JSON flag for fail2ban-client — bundles the jail list with each jail's
 *  status in one round trip, marker-delimited like `check overview`'s sections. */
function buildFail2banScript(): string {
  return [
    'if ! command -v fail2ban-client >/dev/null 2>&1; then echo __UNAVAILABLE__; exit 0; fi',
    "jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ')",
    'for j in $jails; do echo "__JAIL__:$j"; fail2ban-client status "$j" 2>/dev/null; done',
  ].join('; ');
}

const securityFail2ban: OpSpec<ReturnType<typeof parseFail2banStatus>> = {
  group: 'security',
  name: 'fail2ban',
  summary:
    'fail2ban jail status + banned IP counts per jail — degrades to {available:false} when fail2ban-client is absent.',
  args: [],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => shellJoin(['sh', '-c', buildFail2banScript()]),
  shape: (parsed) => parseFail2banStatus(parsed as string),
};

export const securityOps = [
  securityHarden,
  securitySshAudit,
  securityListeners,
  securityAuthorizedKeys,
  securityFail2ban,
] as OpSpec[];
