import { describe, expect, test } from 'bun:test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { install, keygen, register } from '../setup-ssh-alias.ts';
import {
  buildSshpassArgs,
  DEFAULT_INSTALL_TIMEOUT_MS,
  type InstallServerDeps,
  type InstallTarget,
  runInstallServer,
  type ServeLikeFn,
  type ServeLikeOptions,
} from '../setup-ssh-alias-install-server.ts';

function tempConfigPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-install-server-test-'));
  return join(dir, 'config');
}

const TARGET: InstallTarget = {
  alias: 'myserver',
  host: '1.2.3.4',
  user: 'deploy',
  port: 22,
  publicKeyPath: '/tmp/does-not-need-to-exist.pub',
};

/** Captures the `fetch` handler + hostname/port a fake `serve` was invoked with, and
 *  records whether `stop()` was called — the same test-seam pattern `registry.test.ts`'s
 *  `scriptedRunner` uses for `SshRunner`, applied to `ServeLikeFn`. `state` is returned as
 *  the same mutable object `stop()` writes into, so callers read it AFTER awaiting (a
 *  destructured value would only snapshot `stopped` at call time, before `stop()` runs). */
function fakeServe(): {
  serve: ServeLikeFn;
  calls: ServeLikeOptions[];
  state: { stopped: boolean };
} {
  const calls: ServeLikeOptions[] = [];
  const state = { stopped: false };
  const serve: ServeLikeFn = (options) => {
    calls.push(options);
    return {
      port: 54321,
      stop: () => {
        state.stopped = true;
      },
    };
  };
  return { serve, calls, state };
}

/** Simulates a human submitting the form the instant it's served — fires the POST against
 *  the captured `fetch` handler asynchronously, so `runInstallServer`'s timeout race never
 *  wins. Used by tests that need `install()` to reach `spawnInstall`, as opposed to
 *  `fakeInstallDeps()`'s own default `serve`, which deliberately never submits (needed by
 *  the abandoned-form/timeout test). */
function submittingServe(password: string, token = 'tok'): ServeLikeFn {
  return (options) => {
    queueMicrotask(() => {
      const form = new FormData();
      form.set('password', password);
      void options.fetch(
        new Request(`http://127.0.0.1:1/${token}/submit`, { method: 'POST', body: form }),
      );
    });
    return { port: 1, stop: () => {} };
  };
}

function baseDeps(overrides: Partial<InstallServerDeps> = {}): Partial<InstallServerDeps> {
  return {
    which: () => '/opt/homebrew/bin/sshpass',
    announceUrl: () => {},
    randomToken: () => 'fixed-token',
    ...overrides,
  };
}

describe('buildSshpassArgs', () => {
  test('pipes the password via stdin (-f /dev/stdin) and never embeds a password in argv', () => {
    const args = buildSshpassArgs(TARGET, 'echo hi');

    expect(args[0]).toBe('sshpass');
    expect(args.slice(1, 3)).toEqual(['-f', '/dev/stdin']);
    expect(args).toContain('ssh');
    expect(args).toContain(`${TARGET.user}@${TARGET.host}`);
    expect(args).toContain('echo hi');
    // The function signature itself takes no password argument, so there is structurally
    // no way for a password to land in this array — asserted here for good measure.
    expect(args.join(' ')).not.toMatch(/password/i);
  });

  test('passes --port and a connect timeout', () => {
    const args = buildSshpassArgs({ ...TARGET, port: 2222 }, 'true');

    expect(args).toContain('-p');
    expect(args).toContain('2222');
    expect(args.some((arg) => arg.startsWith('ConnectTimeout='))).toBe(true);
  });
});

describe('runInstallServer', () => {
  test('checks sshpass up front; missing sshpass returns sshpass_not_found and starts no server', async () => {
    const { serve, calls } = fakeServe();

    const outcome = await runInstallServer(TARGET, {
      ...baseDeps({ which: () => null }),
      serve,
    });

    expect(outcome).toEqual({ kind: 'sshpass_not_found' });
    expect(calls).toHaveLength(0);
  });

  test('binds 127.0.0.1 only, never 0.0.0.0', async () => {
    const { serve, calls } = fakeServe();

    await runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5 }),
      serve,
    });

    expect(calls[0]?.hostname).toBe('127.0.0.1');
  });

  test('announces a URL containing the ephemeral port and the random token', async () => {
    const { serve } = fakeServe();
    let announced: string | undefined;

    await runInstallServer(TARGET, {
      ...baseDeps({
        timeoutMs: 5,
        randomToken: () => 'tok123',
        announceUrl: (url) => {
          announced = url;
        },
      }),
      serve,
    });

    expect(announced).toBe('http://127.0.0.1:54321/tok123');
  });

  test('a request with a wrong token gets 404, not 403', async () => {
    const { serve } = fakeServe();
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return serve(options);
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5 }),
      serve: capturingServe,
    });

    const response = await capturedFetch?.(new Request('http://127.0.0.1:54321/wrong-token'));
    expect(response?.status).toBe(404);

    await resultPromise;
  });

  test('a request with no token at all gets 404', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5 }),
      serve: capturingServe,
    });

    const response = await capturedFetch?.(new Request('http://127.0.0.1:1/'));
    expect(response?.status).toBe(404);

    await resultPromise;
  });

  test('GET with the correct token serves the password form', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5, randomToken: () => 'tok' }),
      serve: capturingServe,
    });

    const requestUrl = 'http://127.0.0.1:1/tok';
    const response = await capturedFetch?.(new Request(requestUrl));
    expect(response?.status).toBe(200);
    const body = await response?.text();
    expect(body).toContain('<form');
    expect(body).toContain(TARGET.alias);

    // Regression guard: a relative `action` (e.g. action="submit") resolves against the
    // page URL per browser semantics, and `/tok` (no trailing slash) resolves "submit" to
    // `/submit` — dropping the token entirely and 404ing on real submission. Resolve the
    // form's actual action the same way a browser does, don't just grep for a substring.
    const actionMatch = body?.match(/action="([^"]+)"/);
    expect(actionMatch?.[1]).toBeTruthy();
    const resolvedSubmitUrl = new URL(actionMatch?.[1] ?? '', requestUrl);
    expect(resolvedSubmitUrl.pathname).toBe('/tok/submit');

    await resultPromise;
  });

  test('an abandoned form times out cleanly and stops the server, no hang', async () => {
    const { serve, state } = fakeServe();

    const outcome = await runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 10 }),
      serve,
    });

    expect(outcome).toEqual({ kind: 'timed_out' });
    expect(state.stopped).toBe(true);
  });

  test('default timeout is 3 minutes', () => {
    expect(DEFAULT_INSTALL_TIMEOUT_MS).toBe(3 * 60 * 1_000);
  });

  test('a submitted password is handed to spawnInstall via stdin argument, never returned in the outcome', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    let receivedPassword: string | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 60_000 }),
      serve: capturingServe,
      spawnInstall: async (password) => {
        receivedPassword = password;
        return { code: 0, timedOut: false };
      },
    });

    const form = new FormData();
    form.set('password', 'super-secret-password');
    const response = await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    expect(response?.status).toBe(200);
    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'installed' });
    expect(receivedPassword).toBe('super-secret-password');
    expect(JSON.stringify(outcome)).not.toContain('super-secret-password');
  });

  test('a failed ssh auth maps to ssh_failed with the real exit code, not a crash', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 60_000 }),
      serve: capturingServe,
      spawnInstall: async () => ({ code: 5, timedOut: false }),
    });

    const form = new FormData();
    form.set('password', 'wrong-password');
    await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'ssh_failed', exitCode: 5 });
  });
});

describe('install (setup-ssh-alias.ts)', () => {
  function fakeInstallDeps(overrides: Partial<InstallServerDeps> = {}): Partial<InstallServerDeps> {
    return {
      which: () => '/opt/homebrew/bin/sshpass',
      serve: () => ({ port: 1, stop: () => {} }),
      announceUrl: () => {},
      randomToken: () => 'tok',
      timeoutMs: 10,
      spawnInstall: async () => ({ code: 0, timedOut: false }),
      ...overrides,
    };
  }

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no server started', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    let serveCalled = false;
    const result = await install(
      'myserver',
      { yes: false },
      configPath,
      fakeInstallDeps({
        serve: () => {
          serveCalled = true;
          return { port: 1, stop: () => {} };
        },
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(serveCalled).toBe(false);
  });

  test('fails with ALIAS_NOT_FOUND for an unregistered alias', async () => {
    const configPath = tempConfigPath();

    const result = await install('myserver', { yes: true }, configPath, fakeInstallDeps());

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_NOT_FOUND');
  });

  test('fails with INSTALL_FAILED when keygen has not been run yet (no public key to install)', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = await install('myserver', { yes: true }, configPath, fakeInstallDeps());

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('INSTALL_FAILED');
  });

  test('fails with SSHPASS_NOT_FOUND when sshpass is missing', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({ which: () => null }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('SSHPASS_NOT_FOUND');
  }, 15_000);

  test('fails with INSTALL_TIMED_OUT when the form is abandoned', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({ timeoutMs: 5 }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('INSTALL_TIMED_OUT');
  }, 15_000);

  test('fails with INSTALL_FAILED (real exit code in the message) on a wrong-password ssh exit', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        serve: submittingServe('wrong-password'),
        spawnInstall: async () => ({ code: 5, timedOut: false }),
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('INSTALL_FAILED');
    expect(result.error?.message).toContain('5');
  }, 15_000);

  test('succeeds end-to-end with injected fakes: data carries host/user/port, never a password', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '9.9.9.9', user: 'deploy', port: 2222, yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({ serve: submittingServe('correct-password') }),
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'myserver', host: '9.9.9.9', user: 'deploy', port: 2222 });
    expect(JSON.stringify(result)).not.toMatch(/password/i);
  }, 15_000);
});
