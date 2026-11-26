import { lookup } from 'node:dns/promises';
import { connect, isIP } from 'node:net';
import {
  CONNECT_TIMEOUT_SEC,
  DIAGNOSE_SSH_TIMEOUT_SEC,
  DIAGNOSE_STAGE_TIMEOUT_SEC,
} from './limits.ts';
import {
  classify,
  defaultRunner,
  resolveAlias,
  STRICT_HOST_KEY_ARGS,
  type TransportDeps,
} from './transport.ts';
import { OpError } from './types.ts';

export const DIAGNOSE_STAGES = ['dns', 'tcp', 'banner', 'auth', 'echo'] as const;
export type DiagnoseStageName = (typeof DIAGNOSE_STAGES)[number];

export interface DiagnoseStage {
  stage: DiagnoseStageName;
  verdict: 'ok' | 'fail' | 'skipped';
  /** Wall time of the stage; null when it did not run. */
  ms: number | null;
  /** A fixed sentence: it never carries the host name, address or port. */
  detail: string;
}

export interface DiagnoseResult {
  reachable: boolean;
  stages: DiagnoseStage[];
  failed_at: DiagnoseStageName | null;
  /** The most likely reason, from the stage that failed; null when every stage passed. */
  likely_cause: string | null;
}

const ECHO_TOKEN = 'sshepherd-ok';
const STAGE_MS = DIAGNOSE_STAGE_TIMEOUT_SEC * 1_000;
const SSH_BANNER = 'SSH-';
const SSH_CONFIG_PROBE_MS = 5_000;

const LIKELY_CAUSE: Record<DiagnoseStageName, string> = {
  dns: 'name-not-resolved',
  tcp: 'host-down-or-port-closed',
  banner: 'sshd-hung-or-not-ssh',
  auth: 'auth-rejected-or-login-hung',
  echo: 'remote-command-failed',
};

interface HostTarget {
  host: string;
  port: number;
  proxied: boolean;
}

function field(sshG: string, name: string): string | undefined {
  return new RegExp(`^${name}\\s+(\\S+)`, 'im').exec(sshG)?.[1];
}

function targetOf(sshG: string): HostTarget {
  const port = Number.parseInt(field(sshG, 'port') ?? '22', 10);
  const none = (value: string | undefined) => value === undefined || value === 'none';
  return {
    host: field(sshG, 'hostname') ?? '',
    port: Number.isNaN(port) ? 22 : port,
    proxied: !none(field(sshG, 'proxyjump')) || !none(field(sshG, 'proxycommand')),
  };
}

function stage(
  name: DiagnoseStageName,
  verdict: DiagnoseStage['verdict'],
  detail: string,
  startedMs?: number,
  endedMs: number = Date.now(),
): DiagnoseStage {
  return {
    stage: name,
    verdict,
    ms: startedMs === undefined ? null : endedMs - startedMs,
    detail,
  };
}

function skipped(name: DiagnoseStageName, why: string): DiagnoseStage {
  return stage(name, 'skipped', why);
}

async function dnsStage(host: string): Promise<{ result: DiagnoseStage; address: string | null }> {
  const started = Date.now();
  if (isIP(host) !== 0) {
    return {
      result: stage('dns', 'skipped', 'the alias names an address, not a name', started),
      address: host,
    };
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('dns timeout')), STAGE_MS);
    });
    const found = await Promise.race([lookup(host), timeout]);
    return { result: stage('dns', 'ok', 'the name resolves', started), address: found.address };
  } catch (err) {
    const timedOut = err instanceof Error && err.message === 'dns timeout';
    const detail = timedOut
      ? `no answer from the resolver within ${DIAGNOSE_STAGE_TIMEOUT_SEC} s`
      : 'the name does not resolve (typo in HostName, or the resolver or VPN is down)';
    return { result: stage('dns', 'fail', detail, started), address: null };
  } finally {
    clearTimeout(timer);
  }
}

/** Opens one TCP connection and reads what the server sends first: the tcp and banner stages are
 *  two views of that one connection. */
function tcpAndBanner(address: string, port: number): Promise<[DiagnoseStage, DiagnoseStage]> {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = connect({ host: address, port });
    let settled = false;
    let bannerStarted = started;
    let connectedAt: number | null = null;
    const finish = (tcp: DiagnoseStage, banner: DiagnoseStage): void => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve([tcp, banner]);
      }
    };
    const failTcp = (detail: string): void =>
      finish(
        stage('tcp', 'fail', detail, started),
        skipped('banner', 'the connection never opened'),
      );
    socket.setTimeout(STAGE_MS);
    socket.once('timeout', () => {
      if (connectedAt === null) {
        failTcp(
          `no answer within ${DIAGNOSE_STAGE_TIMEOUT_SEC} s: the host is down, or a firewall drops the ssh port`,
        );
        return;
      }
      finish(
        stage('tcp', 'ok', 'the port accepted the connection', started, connectedAt),
        stage(
          'banner',
          'fail',
          `connected, but sshd sent no banner within ${DIAGNOSE_STAGE_TIMEOUT_SEC} s: sshd is hung or the connection is being held`,
          bannerStarted,
        ),
      );
    });
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') {
        failTcp('connection refused: the host is up but nothing listens on the ssh port');
      } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
        failTcp('no route to the host');
      } else {
        failTcp(`the connection failed (${err.code ?? 'error'})`);
      }
    });
    socket.once('connect', () => {
      connectedAt = Date.now();
      bannerStarted = connectedAt;
    });
    socket.once('data', (chunk: Buffer) => {
      const tcp = stage('tcp', 'ok', 'the port accepted the connection', started, bannerStarted);
      finish(
        tcp,
        chunk.toString('latin1').startsWith(SSH_BANNER)
          ? stage('banner', 'ok', 'sshd answered with its banner', bannerStarted)
          : stage(
              'banner',
              'fail',
              'the port answers, but not with an ssh banner: another service',
              bannerStarted,
            ),
      );
    });
  });
}

/** One batch-mode ssh login that bypasses any reused ControlMaster, so a stale master cannot make a
 *  healthy host look dead (or the reverse): the auth stage is the login, the echo stage the command. */
async function loginStages(
  alias: string,
  deps: TransportDeps,
): Promise<[DiagnoseStage, DiagnoseStage]> {
  const started = Date.now();
  const outcome = await deps.runner(
    [
      ...STRICT_HOST_KEY_ARGS,
      '-o',
      'BatchMode=yes',
      '-o',
      'ControlMaster=no',
      '-o',
      'ControlPath=none',
      '-o',
      `ConnectTimeout=${CONNECT_TIMEOUT_SEC}`,
      '-o',
      'LogLevel=ERROR',
      alias,
      '--',
      'echo',
      ECHO_TOKEN,
    ],
    DIAGNOSE_SSH_TIMEOUT_SEC * 1_000,
  );
  const echoSkipped = skipped('echo', 'the login did not complete');
  if (outcome.timedOut) {
    return [
      stage(
        'auth',
        'fail',
        `the login did not finish within ${DIAGNOSE_SSH_TIMEOUT_SEC} s: key exchange or authentication hung (a Tailscale SSH check-mode approval pending looks exactly like this)`,
        started,
      ),
      echoSkipped,
    ];
  }
  const error = classify({
    code: outcome.code,
    stdout: outcome.stdout,
    transportStderr: outcome.code === 255 ? outcome.stderr : '',
    commandStderr: outcome.code === 255 ? '' : outcome.stderr,
    timedOut: false,
  });
  if (outcome.code === 255) {
    const detail =
      error?.code === 'AUTH_FAILED'
        ? 'the server rejected every key offered (wrong key, or the user is not allowed)'
        : error?.code === 'HOST_KEY_CHANGED' || error?.code === 'HOST_KEY_UNKNOWN'
          ? `host key refused (${error.code}): see hosts trust`
          : 'ssh could not complete the login (transport error)';
    return [stage('auth', 'fail', detail, started), echoSkipped];
  }
  const auth = stage('auth', 'ok', 'the login was accepted', started);
  if (outcome.code === 0 && outcome.stdout.trim() === ECHO_TOKEN) {
    return [auth, stage('echo', 'ok', 'a remote command ran and answered', started)];
  }
  return [
    auth,
    stage(
      'echo',
      'fail',
      outcome.code === 0
        ? 'the remote command ran but its answer was not the expected one'
        : `the remote command exited ${outcome.code}`,
      started,
    ),
  ];
}

/** `hosts test --diagnose`: the five stages a connection passes through, each with a verdict, so
 *  a hang is placed at one of them instead of reading as a bare timeout. Names, addresses and
 *  ports of the host are used here and never returned. */
export async function diagnoseHost(
  alias: string,
  transport: TransportDeps | undefined,
): Promise<DiagnoseResult> {
  const deps = transport ?? { runner: defaultRunner };
  const { error } = await resolveAlias(alias, deps);
  if (error) {
    throw new OpError(error.code, error.message, {
      hint: error.hint,
      next: error.next,
      did_you_mean: error.did_you_mean,
    });
  }
  const sshG = await deps.runner(['-G', alias], SSH_CONFIG_PROBE_MS);
  const target = targetOf(sshG.stdout);
  const stages: DiagnoseStage[] = [];

  if (target.proxied) {
    stages.push(
      skipped('dns', 'the alias goes through a proxy; the login stage covers the whole path'),
      skipped('tcp', 'the alias goes through a proxy'),
      skipped('banner', 'the alias goes through a proxy'),
    );
  } else {
    const dnsResult = await dnsStage(target.host);
    stages.push(dnsResult.result);
    if (dnsResult.address === null) {
      stages.push(
        skipped('tcp', 'the name did not resolve'),
        skipped('banner', 'the name did not resolve'),
      );
    } else {
      stages.push(...(await tcpAndBanner(dnsResult.address, target.port)));
    }
  }

  const networkFailed = stages.find((entry) => entry.verdict === 'fail');
  if (networkFailed) {
    stages.push(
      skipped('auth', `the ${networkFailed.stage} stage failed`),
      skipped('echo', `the ${networkFailed.stage} stage failed`),
    );
  } else {
    stages.push(...(await loginStages(alias, deps)));
  }

  const failed = stages.find((entry) => entry.verdict === 'fail');
  return {
    reachable: failed === undefined,
    stages,
    failed_at: failed?.stage ?? null,
    likely_cause: failed ? LIKELY_CAUSE[failed.stage] : null,
  };
}
