import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diagnoseHost } from '../hosts-diagnose.ts';
import { executeOp, getOp } from '../registry.ts';
import { type SpawnOutcome, type SshRunner, socketPath } from '../transport.ts';
import { OpError } from '../types.ts';

type Server = { stop: (closeActive?: boolean) => void };
const servers: Server[] = [];

function serve(onOpen: (socket: { write: (data: string) => unknown }) => void): number {
  const server = Bun.listen({
    hostname: '127.0.0.1',
    port: 0,
    socket: { open: onOpen, data() {} },
  });
  servers.push(server);
  return server.port;
}

// The ControlMaster socket directory is a throwaway one (under /tmp: a socket path must stay under
// 100 characters), so no real master on this machine is seen.
const runtimeBefore = process.env.XDG_RUNTIME_DIR;
beforeAll(() => {
  process.env.XDG_RUNTIME_DIR = mkdtempSync('/tmp/sshepherd-diag-run-');
});

afterAll(() => {
  for (const server of servers) {
    server.stop(true);
  }
  if (runtimeBefore === undefined) {
    delete process.env.XDG_RUNTIME_DIR;
  } else {
    process.env.XDG_RUNTIME_DIR = runtimeBefore;
  }
});

const outcome = (over: Partial<SpawnOutcome>): SpawnOutcome => ({
  code: 0,
  stdout: '',
  stderr: '',
  timedOut: false,
  ...over,
});

/** `ssh -G` answers with `config`; the login (the only call with `echo` in it) answers with `login`. */
function runnerFor(config: string, login: SpawnOutcome): SshRunner {
  return async (args) => (args.includes('echo') ? login : outcome({ stdout: config }));
}

const configOf = (port: number, extra = ''): string =>
  `hostname 127.0.0.1\nport ${port}\nproxyjump none\nproxycommand none\n${extra}`;

const OK_LOGIN = outcome({ stdout: 'sshepherd-ok\n' });

async function verdicts(config: string, login: SpawnOutcome) {
  const result = await diagnoseHost('web', { runner: runnerFor(config, login) });
  return {
    result,
    byStage: Object.fromEntries(result.stages.map((entry) => [entry.stage, entry.verdict])),
  };
}

describe('hosts test --diagnose', () => {
  test('a healthy host with no master open passes all six stages, in order', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const { result, byStage } = await verdicts(configOf(port), OK_LOGIN);
    expect(result.stages.map((entry) => entry.stage)).toEqual([
      'master',
      'dns',
      'tcp',
      'banner',
      'auth',
      'echo',
    ]);
    expect(byStage).toEqual({
      master: 'skipped',
      dns: 'skipped',
      tcp: 'ok',
      banner: 'ok',
      auth: 'ok',
      echo: 'ok',
    });
    expect({ reachable: result.reachable, failed_at: result.failed_at }).toEqual({
      reachable: true,
      failed_at: null,
    });
  });

  test('a closed port fails at tcp and skips every later stage', async () => {
    const closed = Bun.listen({ hostname: '127.0.0.1', port: 0, socket: { data() {} } });
    const port = closed.port;
    closed.stop(true);
    const { result, byStage } = await verdicts(configOf(port), OK_LOGIN);
    expect(byStage).toEqual({
      master: 'skipped',
      dns: 'skipped',
      tcp: 'fail',
      banner: 'skipped',
      auth: 'skipped',
      echo: 'skipped',
    });
    expect(result.failed_at).toBe('tcp');
    expect(result.likely_cause).toBe('host-down-or-port-closed');
  });

  test('a port that answers with something other than an ssh banner fails at banner', async () => {
    const port = serve((socket) => socket.write('HTTP/1.1 400 Bad Request\r\n'));
    const { result } = await verdicts(configOf(port), OK_LOGIN);
    expect(result.failed_at).toBe('banner');
    expect(result.stages.find((entry) => entry.stage === 'banner')?.detail).toContain(
      'not with an ssh banner',
    );
  });

  test('a port that accepts and then says nothing is a banner hang, not a bare timeout', async () => {
    const port = serve(() => {});
    const { result } = await verdicts(configOf(port), OK_LOGIN);
    expect(result.failed_at).toBe('banner');
    expect(result.likely_cause).toBe('sshd-hung-or-not-ssh');
    expect(result.stages.find((entry) => entry.stage === 'tcp')?.verdict).toBe('ok');
    expect(result.stages.find((entry) => entry.stage === 'banner')?.ms).toBeGreaterThanOrEqual(
      4_900,
    );
  }, 15_000);

  test('a name that does not resolve fails at dns', async () => {
    const config = 'hostname no-such-host.invalid\nport 22\nproxyjump none\nproxycommand none\n';
    const { result, byStage } = await verdicts(config, OK_LOGIN);
    expect(byStage.dns).toBe('fail');
    expect(result.likely_cause).toBe('name-not-resolved');
    expect(byStage.tcp).toBe('skipped');
  });

  test('a rejected key fails at auth and the echo is not attempted', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const denied = outcome({ code: 255, stderr: 'user@host: Permission denied (publickey).' });
    const { result, byStage } = await verdicts(configOf(port), denied);
    expect({ auth: byStage.auth, echo: byStage.echo }).toEqual({ auth: 'fail', echo: 'skipped' });
    expect(result.likely_cause).toBe('auth-rejected-or-login-hung');
  });

  test('a login that never finishes is reported as an auth hang naming the Tailscale approval', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const { result } = await verdicts(configOf(port), outcome({ code: 143, timedOut: true }));
    const auth = result.stages.find((entry) => entry.stage === 'auth');
    expect(auth?.verdict).toBe('fail');
    expect(auth?.detail).toContain('Tailscale');
  });

  test('a login that works but whose command fails fails at echo only', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const { byStage } = await verdicts(configOf(port), outcome({ code: 126 }));
    expect({ auth: byStage.auth, echo: byStage.echo }).toEqual({ auth: 'ok', echo: 'fail' });
  });

  test('an alias behind a proxy skips the network stages and still runs the login', async () => {
    const config = 'hostname 127.0.0.1\nport 22\nproxyjump bastion\nproxycommand none\n';
    const { byStage } = await verdicts(config, OK_LOGIN);
    expect(byStage).toEqual({
      master: 'skipped',
      dns: 'skipped',
      tcp: 'skipped',
      banner: 'skipped',
      auth: 'ok',
      echo: 'ok',
    });
  });

  test('the result never carries the host name, address or port', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const { result } = await verdicts(configOf(port), OK_LOGIN);
    const text = JSON.stringify(result);
    expect(text.includes('127.0.0.1')).toBe(false);
    expect(text.includes(String(port))).toBe(false);
  });

  test('an alias ssh config does not know is UNKNOWN_ALIAS, with no probe run', async () => {
    const empty = join(mkdtempSync(join(tmpdir(), 'sshepherd-diag-')), 'config');
    writeFileSync(empty, '');
    const runner: SshRunner = async () => outcome({ code: 1 });
    const error = await diagnoseHost('nowhere', { runner, sshConfigPath: empty }).catch(
      (err: unknown) => err,
    );
    expect(error).toBeInstanceOf(OpError);
    expect((error as OpError).code).toBe('UNKNOWN_ALIAS');
  });

  test('through the op: --diagnose returns the stage list as data, and plain hosts test is unchanged', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const hostsTest = getOp('hosts', 'test');
    if (!hostsTest) {
      throw new Error('hosts test missing');
    }
    const diagnosed = await executeOp(
      hostsTest,
      { alias: 'web', args: { diagnose: true } },
      { transport: { runner: runnerFor(configOf(port), OK_LOGIN) } },
    );
    expect(diagnosed.ok).toBe(true);
    expect((diagnosed.data as { stages: unknown[] }).stages).toHaveLength(6);

    const calls: string[][] = [];
    const plain = await executeOp(
      hostsTest,
      { alias: 'web', args: {} },
      {
        transport: {
          runner: async (args) => {
            calls.push(args);
            return outcome({
              stdout: args.includes('timeout') ? 'sshepherd-ok\n' : 'HostName 10.0.0.9\n',
            });
          },
        },
      },
    );
    expect(plain.data).toEqual({ reachable: true });
  });
});

describe('hosts test --diagnose — the ControlMaster stage (control-master-stale)', () => {
  /** A socket file for `alias` in the throwaway runtime dir: the stage only probes a master that exists. */
  function openMaster(alias: string): void {
    const sock = socketPath(alias);
    mkdirSync(join(sock, '..'), { recursive: true });
    writeFileSync(sock, '');
  }

  /** `-O check` answers `check`; a command through the master (ControlMaster=no) answers `viaMaster`. */
  function masterRunner(
    port: number,
    check: SpawnOutcome,
    viaMaster: SpawnOutcome = OK_LOGIN,
  ): SshRunner {
    return async (args) => {
      if (args.includes('-O')) {
        return check;
      }
      if (args.includes('ControlMaster=no') && !args.includes('ControlPath=none')) {
        return viaMaster;
      }
      return args.includes('echo') ? OK_LOGIN : outcome({ stdout: configOf(port) });
    };
  }

  test('a master whose ssh -O check hangs fails first, as control-master-stale, and the host stages still run', async () => {
    openMaster('frozen');
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const seen: number[] = [];
    const runner = masterRunner(port, outcome({ code: -1, timedOut: true }));
    const result = await diagnoseHost('frozen', {
      runner: async (args, ms, options) => {
        if (args.includes('-O')) {
          seen.push(ms);
        }
        return runner(args, ms, options);
      },
    });
    const byStage = Object.fromEntries(result.stages.map((entry) => [entry.stage, entry.verdict]));
    expect(byStage).toEqual({
      master: 'fail',
      dns: 'skipped',
      tcp: 'ok',
      banner: 'ok',
      auth: 'ok',
      echo: 'ok',
    });
    expect({ failed_at: result.failed_at, likely_cause: result.likely_cause }).toEqual({
      failed_at: 'master',
      likely_cause: 'control-master-stale',
    });
    expect(result.stages[0]?.detail).toContain('hosts disconnect frozen');
    expect(seen).toEqual([3_000]);
  });

  test('a master that answers check but cannot carry a command is stale', async () => {
    openMaster('deadlink');
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const result = await diagnoseHost('deadlink', {
      runner: masterRunner(port, outcome({}), outcome({ code: -1, timedOut: true })),
    });
    expect(result.stages[0]?.verdict).toBe('fail');
    expect(result.stages[0]?.detail).toContain('stale');
    expect(result.likely_cause).toBe('control-master-stale');
  });

  test('a live master passes; a socket left by an exited master is not a fault', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    openMaster('livemaster');
    const live = await diagnoseHost('livemaster', { runner: masterRunner(port, outcome({})) });
    expect({ verdict: live.stages[0]?.verdict, reachable: live.reachable }).toEqual({
      verdict: 'ok',
      reachable: true,
    });
    openMaster('exited');
    const refused = outcome({ code: 255, stderr: 'Control socket connect(x): Connection refused' });
    const exited = await diagnoseHost('exited', { runner: masterRunner(port, refused) });
    expect({ verdict: exited.stages[0]?.verdict, reachable: exited.reachable }).toEqual({
      verdict: 'ok',
      reachable: true,
    });
  });

  test('a login held behind a Tailscale SSH check banner is named tailscale-check-approval-pending', async () => {
    const port = serve((socket) => socket.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const held = outcome({
      code: -1,
      timedOut: true,
      stderr:
        '# Tailscale SSH requires an additional check.\n# To authenticate, visit: https://login.tailscale.com/a/0000\n',
    });
    const { result } = await verdicts(configOf(port), held);
    expect({ failed_at: result.failed_at, likely_cause: result.likely_cause }).toEqual({
      failed_at: 'auth',
      likely_cause: 'tailscale-check-approval-pending',
    });
    expect(JSON.stringify(result)).not.toContain('login.tailscale.com');
  });
});
