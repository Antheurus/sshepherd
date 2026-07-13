import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { install, keygen, register } from '../setup-ssh-alias.ts';
import {
  buildSshpassArgs,
  DEFAULT_INSTALL_TIMEOUT_MS,
  defaultSpawnInstallWithKey,
  type InstallServerDeps,
  type InstallTarget,
  runInstallServer,
  type ServeLikeFn,
  type ServeLikeOptions,
  type SpawnInstallOutcome,
} from '../setup-ssh-alias-install-server.ts';

function tempConfigPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-install-server-test-'));
  return join(dir, 'config');
}

/** Real, locally-generated (never a production key), unencrypted ed25519 private key — used
 *  as the test fixture for the "valid pasted key" path. Generated once via
 *  `ssh-keygen -t ed25519 -N '' -f valid_key -C sshepherd-test-fixture`. */
const VALID_TEST_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBWQpAFuTVou1QKF3YJTpsAaCa9TqVdOmHv8ryMVZ8yLAAAAKCwny4NsJ8u
DQAAAAtzc2gtZWQyNTUxOQAAACBWQpAFuTVou1QKF3YJTpsAaCa9TqVdOmHv8ryMVZ8yLA
AAAECga8T1ga5p/F73lxf9NfGMByubqbUBHGKl2FVLyRlm3VZCkAW5NWi7VAoXdglOmwBo
Jr1OpV06Ye/yvIxVnzIsAAAAFnNzaGVwaGVyZC10ZXN0LWZpeHR1cmUBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
`;

/** A distinctive substring pulled from `VALID_TEST_KEY`'s own base64 body — used to grep
 *  serialized outcomes/results for accidental key-content leakage, the same
 *  "grep for the secret-carrying variable name" discipline the password test applies to
 *  `'super-secret-password'`. */
const VALID_TEST_KEY_SNIPPET = 'MVZ8yLAAAAKCwny4NsJ8u';

/** Real, locally-generated (never a production key), passphrase-protected ed25519 private
 *  key — used as the test fixture for the "rejected: passphrase-protected" path. Generated
 *  once via `ssh-keygen -t ed25519 -N 'testpassphrase123' -f passphrase_key`. */
const PASSPHRASE_TEST_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAwk8qFZR
jpiql2SG9+Vs7pAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHZJV1XBlzj/RmCu
npgo8gIZ9Q//FBcf6/Uel9W2pOdjAAAAoObyoWXdSZ23+t01SdDoCcG3FIrjk/ExhI/NfY
dAQ8jiIpmgSGGFy2Xy4Qclx1RxF2Gu/Rdg9lUv9XM4UnwQNOxaEfGJx1xwAtwtSLIXlvru
xJwC1kjI9x3tIRg5XhvFD2n8nHsITmIP0uUmvmopDQPrUMkN6bJfY0gjk5d562O8xqyFQM
JUpOQOSRcrjxw6x08JMpww/8miywa3JpM91nE=
-----END OPENSSH PRIVATE KEY-----
`;

/** Deliberately not a private key at all — exercises the `invalid_private_key` path. */
const GARBAGE_TEXT = 'this is not a private key, just some pasted garbage text';

/** Extracts the temp key path a fake `SshKeySpawnFn` was invoked with (`-i <path>`), so tests
 *  can assert the temp *directory* (`dirname(path)`) is gone after `defaultSpawnInstallWithKey`
 *  returns, without `defaultSpawnInstallWithKey` itself having to leak that path in its
 *  return value. */
function keyPathFromArgs(args: string[]): string {
  const iIndex = args.indexOf('-i');
  const keyPath = args[iIndex + 1];
  if (keyPath === undefined) {
    throw new Error('fake ssh spawn: -i not found in args');
  }
  return keyPath;
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

  test('GET form includes a method toggle and a private-key textarea alongside the password field', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5, randomToken: () => 'tok' }),
      serve: capturingServe,
    });

    const response = await capturedFetch?.(new Request('http://127.0.0.1:1/tok'));
    const body = await response?.text();

    expect(body).toContain('name="method"');
    expect(body).toContain('value="password"');
    expect(body).toContain('value="key"');
    expect(body).toContain('<textarea name="private_key"');
    expect(body).toContain('input[type=password],textarea');

    await resultPromise;
  });

  test('a submitted private key is handed to spawnInstallWithKey, never returned in the outcome', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    let receivedKeyText: string | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 60_000 }),
      serve: capturingServe,
      spawnInstallWithKey: async (privateKeyText) => {
        receivedKeyText = privateKeyText;
        return { kind: 'installed' };
      },
    });

    const form = new FormData();
    form.set('method', 'key');
    form.set('private_key', VALID_TEST_KEY);
    const response = await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    expect(response?.status).toBe(200);
    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'installed' });
    expect(receivedKeyText).toBe(VALID_TEST_KEY);
    expect(JSON.stringify(outcome)).not.toContain(VALID_TEST_KEY_SNIPPET);
  });

  test('an empty pasted key is rejected with 400, spawnInstallWithKey never called', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    let spawnCalled = false;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 5 }),
      serve: capturingServe,
      spawnInstallWithKey: async () => {
        spawnCalled = true;
        return { kind: 'installed' };
      },
    });

    const form = new FormData();
    form.set('method', 'key');
    form.set('private_key', '   ');
    const response = await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    expect(response?.status).toBe(400);
    expect(spawnCalled).toBe(false);

    // The 400 rejection never calls `settle`, so the server falls through to its own
    // abandoned-form timeout (5ms here) — awaited so the test doesn't leave a dangling timer.
    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'timed_out' });
  });

  test('a passphrase-protected pasted key maps to passphrase_protected_key', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 60_000 }),
      serve: capturingServe,
      spawnInstallWithKey: async () => ({ kind: 'passphrase_protected_key' }),
    });

    const form = new FormData();
    form.set('method', 'key');
    form.set('private_key', PASSPHRASE_TEST_KEY);
    const response = await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    expect(response?.status).toBe(400);
    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'passphrase_protected_key' });
  });

  test('unparseable pasted text maps to invalid_private_key', async () => {
    let capturedFetch: ServeLikeOptions['fetch'] | undefined;
    const capturingServe: ServeLikeFn = (options) => {
      capturedFetch = options.fetch;
      return { port: 1, stop: () => {} };
    };

    const resultPromise = runInstallServer(TARGET, {
      ...baseDeps({ timeoutMs: 60_000 }),
      serve: capturingServe,
      spawnInstallWithKey: async () => ({ kind: 'invalid_private_key' }),
    });

    const form = new FormData();
    form.set('method', 'key');
    form.set('private_key', GARBAGE_TEXT);
    const response = await capturedFetch?.(
      new Request('http://127.0.0.1:1/fixed-token/submit', { method: 'POST', body: form }),
    );

    expect(response?.status).toBe(400);
    const outcome = await resultPromise;
    expect(outcome).toEqual({ kind: 'invalid_private_key' });
  });
});

describe('defaultSpawnInstallWithKey (real temp-file + ssh-keygen preflight)', () => {
  test('a valid unencrypted key installs successfully and removes the temp dir afterward', async () => {
    let capturedKeyPath: string | undefined;
    const fakeRunSsh = async (args: string[]): Promise<SpawnInstallOutcome> => {
      capturedKeyPath = keyPathFromArgs(args);
      return { code: 0, timedOut: false };
    };

    const outcome = await defaultSpawnInstallWithKey(VALID_TEST_KEY, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'installed' });
    expect(capturedKeyPath).toBeDefined();
    expect(existsSync(dirname(capturedKeyPath as string))).toBe(false);
  });

  test('a failed ssh spawn maps to ssh_failed with the real exit code and still removes the temp dir', async () => {
    let capturedKeyPath: string | undefined;
    const fakeRunSsh = async (args: string[]): Promise<SpawnInstallOutcome> => {
      capturedKeyPath = keyPathFromArgs(args);
      return { code: 5, timedOut: false };
    };

    const outcome = await defaultSpawnInstallWithKey(VALID_TEST_KEY, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'ssh_failed', exitCode: 5 });
    expect(capturedKeyPath).toBeDefined();
    expect(existsSync(dirname(capturedKeyPath as string))).toBe(false);
  });

  test('a timed-out ssh spawn maps to ssh_failed (exitCode -1), not the form-abandon timed_out kind', async () => {
    const fakeRunSsh = async (): Promise<SpawnInstallOutcome> => ({ code: -1, timedOut: true });

    const outcome = await defaultSpawnInstallWithKey(VALID_TEST_KEY, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'ssh_failed', exitCode: -1 });
  });

  test('a passphrase-protected key is rejected before ever spawning ssh, temp dir removed', async () => {
    let sshSpawned = false;
    const fakeRunSsh = async (): Promise<SpawnInstallOutcome> => {
      sshSpawned = true;
      return { code: 0, timedOut: false };
    };

    const outcome = await defaultSpawnInstallWithKey(PASSPHRASE_TEST_KEY, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'passphrase_protected_key' });
    expect(sshSpawned).toBe(false);
  });

  test('text that does not parse as a private key at all is rejected before ever spawning ssh', async () => {
    let sshSpawned = false;
    const fakeRunSsh = async (): Promise<SpawnInstallOutcome> => {
      sshSpawned = true;
      return { code: 0, timedOut: false };
    };

    const outcome = await defaultSpawnInstallWithKey(GARBAGE_TEXT, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'invalid_private_key' });
    expect(sshSpawned).toBe(false);
  });

  test('a CRLF-corrupted paste of a valid key is normalized before the ssh-keygen preflight sees it', async () => {
    const crlfKey = VALID_TEST_KEY.replace(/\n/g, '\r\n');
    const fakeRunSsh = async (): Promise<SpawnInstallOutcome> => ({ code: 0, timedOut: false });

    const outcome = await defaultSpawnInstallWithKey(crlfKey, TARGET, fakeRunSsh);

    expect(outcome).toEqual({ kind: 'installed' });
  });

  test('the key content never appears in the serialized outcome', async () => {
    const fakeRunSsh = async (): Promise<SpawnInstallOutcome> => ({ code: 0, timedOut: false });

    const outcome = await defaultSpawnInstallWithKey(VALID_TEST_KEY, TARGET, fakeRunSsh);

    expect(JSON.stringify(outcome)).not.toContain(VALID_TEST_KEY_SNIPPET);
  });
});

describe('install (setup-ssh-alias.ts)', () => {
  function fakeInstallDeps(overrides: Partial<InstallServerDeps> = {}): Partial<InstallServerDeps> {
    return {
      which: () => '/opt/homebrew/bin/sshpass',
      // Neither pre-check fires by default, so the existing tests below keep exercising
      // the exact password-form flow they were written against.
      peekBanner: async () => false,
      probeReachable: async () => false,
      serve: () => ({ port: 1, stop: () => {} }),
      announceUrl: () => {},
      randomToken: () => 'tok',
      timeoutMs: 10,
      spawnInstall: async () => ({ code: 0, timedOut: false }),
      spawnInstallWithKey: async () => ({ kind: 'installed' }),
      ...overrides,
    };
  }

  /** Simulates a human choosing the private-key method and pasting `privateKeyText` the
   *  instant the form is served — mirrors `submittingServe`, applied to the `key` method. */
  function submittingKeyServe(privateKeyText: string, token = 'tok'): ServeLikeFn {
    return (options) => {
      queueMicrotask(() => {
        const form = new FormData();
        form.set('method', 'key');
        form.set('private_key', privateKeyText);
        void options.fetch(
          new Request(`http://127.0.0.1:1/${token}/submit`, { method: 'POST', body: form }),
        );
      });
      return { port: 1, stop: () => {} };
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

  test('fails with TAILSCALE_SSH_DETECTED when the banner peek detects Tailscale, no server opened', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    let serveCalled = false;
    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        peekBanner: async () => true,
        serve: () => {
          serveCalled = true;
          return { port: 1, stop: () => {} };
        },
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('TAILSCALE_SSH_DETECTED');
    expect(result.error?.message).toContain('myserver');
    expect(serveCalled).toBe(false);
  });

  test('succeeds immediately (already_trusted) when the reachability probe succeeds, no server opened', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '9.9.9.9', user: 'deploy', port: 2222, yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    let serveCalled = false;
    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        probeReachable: async () => true,
        serve: () => {
          serveCalled = true;
          return { port: 1, stop: () => {} };
        },
      }),
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      alias: 'myserver',
      host: '9.9.9.9',
      user: 'deploy',
      port: 2222,
      method: 'already_trusted',
    });
    expect(serveCalled).toBe(false);
  });

  test('the Tailscale check runs before the already-trusted probe, no server opened either way', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    let probeReachableCalled = false;
    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        peekBanner: async () => true,
        probeReachable: async () => {
          probeReachableCalled = true;
          return true;
        },
      }),
    );

    expect(result.error?.code).toBe('TAILSCALE_SSH_DETECTED');
    expect(probeReachableCalled).toBe(false);
  });

  test('succeeds end-to-end via the pasted-key method: data carries host/user/port, never the key content', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '9.9.9.9', user: 'deploy', port: 2222, yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    let receivedKeyText: string | undefined;
    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        serve: submittingKeyServe(VALID_TEST_KEY),
        spawnInstallWithKey: async (privateKeyText) => {
          receivedKeyText = privateKeyText;
          return { kind: 'installed' };
        },
      }),
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'myserver', host: '9.9.9.9', user: 'deploy', port: 2222 });
    expect(receivedKeyText).toBe(VALID_TEST_KEY);
    expect(JSON.stringify(result)).not.toContain(VALID_TEST_KEY_SNIPPET);
  }, 15_000);

  test('fails with INVALID_PRIVATE_KEY when the pasted text does not parse as a private key', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        serve: submittingKeyServe(GARBAGE_TEXT),
        spawnInstallWithKey: async () => ({ kind: 'invalid_private_key' }),
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('INVALID_PRIVATE_KEY');
    expect(JSON.stringify(result)).not.toContain(GARBAGE_TEXT);
  }, 15_000);

  test('fails with PASSPHRASE_PROTECTED_KEY_UNSUPPORTED when the pasted key needs a passphrase', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        serve: submittingKeyServe(PASSPHRASE_TEST_KEY),
        spawnInstallWithKey: async () => ({ kind: 'passphrase_protected_key' }),
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('PASSPHRASE_PROTECTED_KEY_UNSUPPORTED');
    expect(JSON.stringify(result)).not.toContain('BEGIN OPENSSH PRIVATE KEY');
  }, 15_000);

  test('fails with INSTALL_FAILED on a pasted-key ssh_failed outcome, never leaking key content', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);

    const result = await install(
      'myserver',
      { yes: true },
      configPath,
      fakeInstallDeps({
        serve: submittingKeyServe(VALID_TEST_KEY),
        spawnInstallWithKey: async () => ({ kind: 'ssh_failed', exitCode: 5 }),
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('INSTALL_FAILED');
    expect(JSON.stringify(result)).not.toContain(VALID_TEST_KEY_SNIPPET);
  }, 15_000);
});
