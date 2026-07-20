# SSH Tunnel / Port-Forwarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `tunnel` op group (`open`/`list`/`close`) to `sshepherd` covering local, remote, and
dynamic (SOCKS) SSH port forwarding — each tunnel runs detached in the background, self-expires via an
internal timer (no external `timeout` binary, no standing sshepherd daemon), and stays zero-knowledge
(never echoes the alias's own `HostName`/`User`/`Port`).

**Architecture:** A new `src/tunnel.ts` module owns tunnel state (`~/.local/state/sshepherd/tunnels/
<id>.json`) and the spawn/kill mechanics. Because every existing op assumes a blocking, one-shot `ssh
<alias> <command>` round-trip (`transport.ts`) and a tunnel deliberately never exits on its own, `tunnel
open` spawns a **detached self-supervising subprocess** — a second invocation of the `sshepherd` binary
itself in a hidden `tunnel __supervise` mode — which spawns the real `ssh -N -L/-R/-D ...` as its own
child (inheriting its process group), holds a `setTimeout` for the requested duration, and kills its ssh
child when that fires. `closeTunnel` kills the whole group (supervisor + ssh) by sending the signal to
the **negative** PID. `listTunnels` opportunistically prunes dead/expired entries on every read. The
three new ops plug into the existing `OpSpec`/registry/CLI machinery via `runLocal` (host-local, no ssh
round-trip needed for the CLI call itself) plus one small additive change to `executeOp` so a `runLocal`
op can return a structured, agent-facing validation error instead of only ever succeeding.

**Tech Stack:** TypeScript, Bun (`Bun.listen` for synchronous free-port discovery, `Bun.spawn` for
detached process spawning), `bun:test`, existing `sshepherd` registry/CLI/audit machinery.

---

## Design deviations from the spec (found while planning — both narrow, both correctness fixes)

1. **No external `timeout` binary.** `docs/superpowers/specs/2026-07-20-ssh-tunnel-design.md` proposed
   wrapping the ssh invocation with the `timeout` command. GNU `timeout` isn't reliably present on macOS
   (BSD userland ships no equivalent by default) — using it would break tunnel expiry on the darwin
   release targets this project ships for. Replaced with a **self-supervising subprocess**: the compiled
   `sshepherd` binary re-invokes itself in a hidden mode that owns the `setTimeout` in JS instead of
   shelling out to a platform-specific binary. No user-facing behavior changes (`--duration` still means
   the same thing); this only changes the internal mechanism.
2. **`TUNNEL_NOT_FOUND` is not an error code.** The spec listed it under "New error codes," but also
   described `close` on an unknown id as "treated as a no-op success, not a hard error." Implemented as
   `TunnelCloseResult { id, closed: boolean }` — `closed: false` on an already-gone id, still `ok: true`
   at the envelope level. No `TUNNEL_NOT_FOUND` code exists; keeps the error-code list to genuine failures
   (`VALIDATION_ERROR`, `TUNNEL_PORT_TAKEN`, `TUNNEL_SPAWN_FAILED`).

---

## File Structure

- **Modify `src/types.ts`** — add 3 `SshErrorCode` members + a new `OpRunLocalError` class.
- **Modify `src/transport.ts`** — add matching `ERROR_MESSAGES` entries (required for
  `Record<SshErrorCode, string>` to stay total).
- **Modify `src/registry.ts`** — one additive try/catch in `executeOp`; 3 new `OpSpec` consts
  (`tunnelOpen`/`tunnelList`/`tunnelClose`) appended to `REGISTRY`.
- **Create `src/tunnel.ts`** — all tunnel state/spawn/kill logic. One file: the whole concern (state I/O,
  port-finding, spawn, supervisor, list, close) is small enough (~200 lines) that splitting it further
  would fragment one readable flow, matching how `targets.ts` is a single file for its whole concern.
- **Modify `src/cli.ts`** — intercept the hidden `tunnel __supervise` entrypoint before normal dispatch;
  add `tunnel list`/`tunnel close` to the host-local (`alias: ''`) special-case in `buildOpContext`; add a
  `tunnel` entry to `GROUP_FIRST_POSITIONAL_NOTE`.
- **Create `src/__tests__/tunnel.test.ts`** — unit tests for the new module.
- **Modify `src/__tests__/registry.test.ts`** — registry-level tests for the 3 new ops.
- **Modify `SKILL.md`** — document the `tunnel` group (Quick reference table, zero-knowledge model note,
  action count).
- **Modify `scripts/smoke.sh`** — add a live tunnel smoke step (open → curl through it → close), matching
  the existing BUILT-BUT-NOT-RUN precedent for anything needing a real Docker/sshd fixture.

---

### Task 1: Error plumbing — `OpRunLocalError` + new `SshErrorCode`s

**Files:**
- Modify: `src/types.ts`
- Modify: `src/transport.ts`
- Test: `src/__tests__/setup-types.test.ts` (existing file — add a case for the new class)

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/setup-types.test.ts`:

```typescript
import { OpRunLocalError } from '../types.ts';

test('OpRunLocalError carries a code and a dynamic message', () => {
  const err = new OpRunLocalError('VALIDATION_ERROR', "--remote is required for kind 'local'");
  expect(err).toBeInstanceOf(Error);
  expect(err.name).toBe('OpRunLocalError');
  expect(err.code).toBe('VALIDATION_ERROR');
  expect(err.message).toBe("--remote is required for kind 'local'");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/setup-types.test.ts`
Expected: FAIL — `OpRunLocalError` is not exported from `../types.ts`.

- [ ] **Step 3: Add the new error codes and the class to `src/types.ts`**

Find the `SshErrorCode` union:

```typescript
export type SshErrorCode =
  | 'UNKNOWN_ALIAS'
  | 'CONNECT_TIMEOUT'
  | 'AUTH_FAILED'
  | 'HOST_KEY_MISMATCH'
  | 'SSH_TRANSPORT_ERROR'
  | 'COMMAND_FAILED'
  | 'COMMAND_TIMEOUT'
  | 'CONFIRMATION_REQUIRED';
```

Replace with:

```typescript
export type SshErrorCode =
  | 'UNKNOWN_ALIAS'
  | 'CONNECT_TIMEOUT'
  | 'AUTH_FAILED'
  | 'HOST_KEY_MISMATCH'
  | 'SSH_TRANSPORT_ERROR'
  | 'COMMAND_FAILED'
  | 'COMMAND_TIMEOUT'
  | 'CONFIRMATION_REQUIRED'
  | 'VALIDATION_ERROR'
  | 'TUNNEL_PORT_TAKEN'
  | 'TUNNEL_SPAWN_FAILED';
```

Then, after the `ErrorInfo` interface, add:

```typescript
/**
 * Thrown by an `OpSpec.runLocal` implementation that needs to fail with a structured,
 * agent-facing error instead of always succeeding — `executeOp` catches this specifically and
 * builds the `ErrorInfo` from `code`/`message` directly (bypassing the static `ERROR_MESSAGES`
 * lookup `errorInfo()` uses for transport-originated errors, since a `runLocal` validation
 * message carries no ssh-stderr leak risk and is more useful to the caller when specific).
 */
export class OpRunLocalError extends Error {
  constructor(
    public readonly code: SshErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'OpRunLocalError';
  }
}
```

- [ ] **Step 4: Add matching `ERROR_MESSAGES` entries in `src/transport.ts`**

Find `const ERROR_MESSAGES: Record<SshErrorCode, string> = {` and add three entries (TypeScript will
refuse to compile without them, since the record type is total over `SshErrorCode`):

```typescript
  VALIDATION_ERROR: 'invalid arguments',
  TUNNEL_PORT_TAKEN: 'the selected local port is already in use',
  TUNNEL_SPAWN_FAILED: 'failed to start the tunnel process',
```

(These fallback strings are never actually read on the `OpRunLocalError` path — Task 2's catch block
uses the thrown error's own `message` — but the `Record<SshErrorCode, string>` type requires every code
to have an entry regardless of whether `errorInfo()` is ever called with it.)

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test src/__tests__/setup-types.test.ts`
Expected: PASS

- [ ] **Step 6: Typecheck the whole project**

Run: `bun run typecheck` (or `tsc --noEmit` if that's the project's actual script name — check
`package.json`'s `scripts` block first)
Expected: EXIT 0 (confirms `ERROR_MESSAGES`'s `Record<SshErrorCode, string>` is still total)

- [ ] **Step 7: Commit**

```bash
git add src/types.ts src/transport.ts src/__tests__/setup-types.test.ts
git commit -m "feat(tunnel): add OpRunLocalError and tunnel-related SshErrorCodes"
```

---

### Task 2: Wire `OpRunLocalError` into `executeOp`

**Files:**
- Modify: `src/registry.ts:2313-2372` (the `executeOp` function)
- Test: `src/__tests__/registry.test.ts`

This is the one shared-dispatch-path change every other task depends on — done and tested in isolation,
using a throwaway fake op, before any real tunnel op exists.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/registry.test.ts` (mirrors the file's existing pattern of building a minimal fake
`OpSpec` inline to test `executeOp` in isolation — grep the file for an existing `const fakeOp` or
similar if one already exists, and match its shape):

```typescript
import { OpRunLocalError } from '../types.ts';

test('executeOp converts a thrown OpRunLocalError into a structured Envelope error', async () => {
  const throwingOp: OpSpec<null> = {
    group: 'test',
    name: 'throws',
    summary: 'test-only op that always throws OpRunLocalError',
    args: [],
    mutating: false,
    timeoutSec: 5,
    output: 'raw',
    buildRemote: () => null,
    shape: () => null,
    runLocal: () => {
      throw new OpRunLocalError('VALIDATION_ERROR', 'kind must be one of local/remote/dynamic');
    },
  };

  const envelope = await executeOp(throwingOp, { alias: '', args: {} }, {});

  expect(envelope.ok).toBe(false);
  expect(envelope.error?.code).toBe('VALIDATION_ERROR');
  expect(envelope.error?.message).toBe('kind must be one of local/remote/dynamic');
  expect(envelope.data).toBeNull();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/registry.test.ts -t "OpRunLocalError"`
Expected: FAIL — the thrown error propagates uncaught out of `executeOp` instead of becoming an
`Envelope`.

- [ ] **Step 3: Wrap the `runLocal` call in `executeOp`**

In `src/registry.ts`, find this block inside `executeOp` (around line 2337-2350):

```typescript
  if (remoteCmd === null) {
    if (!op.runLocal) {
      throw new Error(
        `registry: op '${command}' has no buildRemote output and no runLocal fallback`,
      );
    }
    const sshConfigPath = deps.sshConfigPath ?? join(homedir(), '.ssh', 'config');
    const data = op.runLocal(ctx, sshConfigPath);
    const envelope = buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'ok');
    }
    return envelope;
  }
```

Replace with:

```typescript
  if (remoteCmd === null) {
    if (!op.runLocal) {
      throw new Error(
        `registry: op '${command}' has no buildRemote output and no runLocal fallback`,
      );
    }
    const sshConfigPath = deps.sshConfigPath ?? join(homedir(), '.ssh', 'config');
    let data: unknown;
    try {
      data = op.runLocal(ctx, sshConfigPath);
    } catch (err) {
      if (err instanceof OpRunLocalError) {
        if (requiresConfirm) {
          auditFor(deps, ctx.alias, command, ctx, 'error');
        }
        return buildEnvelope({
          alias: ctx.alias,
          command,
          startedAtMs,
          data: null,
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
    const envelope = buildEnvelope({ alias: ctx.alias, command, startedAtMs, data, error: null });
    if (requiresConfirm) {
      auditFor(deps, ctx.alias, command, ctx, 'ok');
    }
    return envelope;
  }
```

Add `OpRunLocalError` to the existing `import type { ... } from './types.ts'`-style import at the top of
`src/registry.ts` (check the exact existing import line for `types.ts` and add it there — `OpRunLocalError`
is a class, not a type-only export, so it must be a value import, not `import type`).

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/registry.test.ts -t "OpRunLocalError"`
Expected: PASS

- [ ] **Step 5: Run the full existing test suite to confirm no regression**

Run: `bun test`
Expected: PASS — every pre-existing `runLocal` op (`hosts list`, `db list`) still succeeds normally since
they never throw `OpRunLocalError`; the new `try`/`catch` only changes behavior for that one error type.

- [ ] **Step 6: Commit**

```bash
git add src/registry.ts src/__tests__/registry.test.ts
git commit -m "feat(tunnel): executeOp converts OpRunLocalError into a structured Envelope error"
```

---

### Task 3: `src/tunnel.ts` — types + state file I/O

**Files:**
- Create: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

- [ ] **Step 1: Write the failing test**

Create `src/__tests__/tunnel.test.ts`:

```typescript
import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defaultTunnelStateDir, readTunnelRecordFile, writeTunnelRecord } from '../tunnel.ts';

function tempStateDir(): string {
  return mkdtempSync(join(tmpdir(), 'sshepherd-tunnel-test-'));
}

describe('defaultTunnelStateDir', () => {
  test('honors SSHEPHERD_TUNNEL_STATE_DIR override', () => {
    const original = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    process.env.SSHEPHERD_TUNNEL_STATE_DIR = '/tmp/example-override';
    expect(defaultTunnelStateDir()).toBe('/tmp/example-override');
    if (original === undefined) {
      delete process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    } else {
      process.env.SSHEPHERD_TUNNEL_STATE_DIR = original;
    }
  });
});

describe('writeTunnelRecord / readTunnelRecordFile', () => {
  test('round-trips a record through disk with 0600 permissions', () => {
    const dir = tempStateDir();
    const record = {
      id: 't-test1',
      alias: 'example-alias',
      kind: 'local' as const,
      localPort: 54321,
      remoteTarget: 'localhost:5432',
      localTarget: null,
      pid: 999999,
      openedAt: '2026-07-20T10:00:00.000Z',
      expiresAt: '2026-07-20T11:00:00.000Z',
    };
    const path = join(dir, `${record.id}.json`);
    writeTunnelRecord(path, record);

    const mode = require('node:fs').statSync(path).mode & 0o777;
    expect(mode).toBe(0o600);

    const roundTripped = readTunnelRecordFile(path);
    expect(roundTripped).toEqual(record);
  });

  test('readTunnelRecordFile returns null for a missing file', () => {
    const dir = tempStateDir();
    expect(readTunnelRecordFile(join(dir, 'does-not-exist.json'))).toBeNull();
  });

  test('readTunnelRecordFile returns null for malformed JSON', () => {
    const dir = tempStateDir();
    const path = join(dir, 'broken.json');
    require('node:fs').writeFileSync(path, 'not json{{{');
    expect(readTunnelRecordFile(path)).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts`
Expected: FAIL — `../tunnel.ts` does not exist yet.

- [ ] **Step 3: Create `src/tunnel.ts` with the state/types layer**

```typescript
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export type TunnelKind = 'local' | 'remote' | 'dynamic';

export interface TunnelRecord {
  id: string;
  alias: string;
  kind: TunnelKind;
  /** Auto-assigned local port for kind=local/dynamic; null for kind=remote. */
  localPort: number | null;
  /** kind=local: the "host:port" being forwarded to. kind=remote: the bind spec on the
   *  alias's side. null for kind=dynamic (a SOCKS proxy has no single target). */
  remoteTarget: string | null;
  /** kind=remote only: "host:port" on the operator's machine being exposed. null otherwise. */
  localTarget: string | null;
  /** PID of the detached supervisor process (the process-GROUP leader) — NOT ssh's own PID. */
  pid: number;
  openedAt: string;
  expiresAt: string;
}

/** Overridable via `SSHEPHERD_TUNNEL_STATE_DIR` for tests — mirrors `targets.ts`'s
 *  `SSHEPHERD_TARGETS_PATH` override. */
export function defaultTunnelStateDir(): string {
  const override = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.local', 'state', 'sshepherd', 'tunnels');
}

function tunnelRecordPath(dir: string, id: string): string {
  return join(dir, `${id}.json`);
}

/** Writes a tunnel state file at 0600, creating the parent dir (0700) if missing. */
export function writeTunnelRecord(path: string, record: TunnelRecord): void {
  mkdirSync(join(path, '..'), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
}

/** Returns `null` for a missing or malformed state file — a tunnel state dir behaves like
 *  `targets.ts`'s "missing file yields empty" tolerance, never throws on a bad read. */
export function readTunnelRecordFile(path: string): TunnelRecord | null {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(text) as TunnelRecord;
  } catch {
    return null;
  }
}

export { tunnelRecordPath };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): state file types and read/write helpers"
```

---

### Task 4: `findFreePort`

**Files:**
- Modify: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/tunnel.test.ts`:

```typescript
import { createServer } from 'node:net';
import { findFreePort } from '../tunnel.ts';

describe('findFreePort', () => {
  test('returns a port that is immediately bindable again', async () => {
    const port = findFreePort();
    expect(port).toBeGreaterThan(0);
    expect(port).toBeLessThan(65536);

    // Prove it's actually free by binding a real listener on it.
    await new Promise<void>((resolve, reject) => {
      const server = createServer();
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => {
        server.close(() => resolve());
      });
    });
  });

  test('two consecutive calls return different ports', () => {
    const a = findFreePort();
    const b = findFreePort();
    expect(a).not.toBe(b);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts -t "findFreePort"`
Expected: FAIL — `findFreePort` is not exported yet.

- [ ] **Step 3: Implement `findFreePort` using `Bun.listen`**

Add to `src/tunnel.ts` (verified against `node_modules/bun-types/bun.d.ts`: `Bun.listen` is
**synchronous** — it returns a `TCPSocketListener` directly, not a `Promise`, and its `socket` handler
object has every field optional, so `{}` type-checks):

```typescript
/** Binds an ephemeral local TCP listener, reads back the OS-assigned port, releases it
 *  immediately. There is a small window between release and ssh's own bind where another
 *  process could take the port — `openTunnel` surfaces `TUNNEL_PORT_TAKEN` if that happens,
 *  rather than pretending this race can be closed entirely on localhost. */
export function findFreePort(): number {
  const listener = Bun.listen({
    hostname: '127.0.0.1',
    port: 0,
    socket: {},
  });
  const port = listener.port;
  listener.stop(true);
  return port;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts -t "findFreePort"`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): findFreePort via synchronous Bun.listen"
```

---

### Task 5: Arg validation + ssh invocation builder

**Files:**
- Modify: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/tunnel.test.ts`:

```typescript
import { OpRunLocalError } from '../types.ts';
import { buildSshArgs, DEFAULT_DURATION_SEC, MAX_DURATION_SEC, MIN_DURATION_SEC, validateOpenParams } from '../tunnel.ts';

describe('validateOpenParams', () => {
  test('accepts a valid local-kind request', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'local', remote: 'localhost:5432', durationSec: 60 }),
    ).not.toThrow();
  });

  test('rejects an unknown kind', () => {
    expect(() =>
      // @ts-expect-error deliberately invalid kind for the test
      validateOpenParams({ alias: 'a', kind: 'bogus', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects local kind missing --remote', () => {
    expect(() => validateOpenParams({ alias: 'a', kind: 'local', durationSec: 60 })).toThrow(
      OpRunLocalError,
    );
  });

  test('rejects remote kind missing --local', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'remote', remote: '0.0.0.0:8080', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects dynamic kind carrying a --local flag', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', local: 'localhost:3000', durationSec: 60 }),
    ).toThrow(OpRunLocalError);
  });

  test('rejects a duration outside [MIN, MAX]', () => {
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', durationSec: MIN_DURATION_SEC - 1 }),
    ).toThrow(OpRunLocalError);
    expect(() =>
      validateOpenParams({ alias: 'a', kind: 'dynamic', durationSec: MAX_DURATION_SEC + 1 }),
    ).toThrow(OpRunLocalError);
  });
});

describe('buildSshArgs', () => {
  test('local kind', () => {
    expect(
      buildSshArgs({ alias: 'web-01', kind: 'local', remote: 'localhost:5432', durationSec: 60 }, 54321),
    ).toEqual(['-N', '-L', '54321:localhost:5432', 'web-01']);
  });

  test('dynamic kind', () => {
    expect(buildSshArgs({ alias: 'web-01', kind: 'dynamic', durationSec: 60 }, 1080)).toEqual([
      '-N',
      '-D',
      '1080',
      'web-01',
    ]);
  });

  test('remote kind', () => {
    expect(
      buildSshArgs(
        { alias: 'web-01', kind: 'remote', remote: '0.0.0.0:8080', local: 'localhost:3000', durationSec: 60 },
        null,
      ),
    ).toEqual(['-N', '-R', '0.0.0.0:8080:localhost:3000', 'web-01']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts -t "validateOpenParams|buildSshArgs"`
Expected: FAIL — neither function exists yet.

- [ ] **Step 3: Implement in `src/tunnel.ts`**

```typescript
import { OpRunLocalError } from './types.ts';

export const DEFAULT_DURATION_SEC = 3600;
export const MIN_DURATION_SEC = 30;
export const MAX_DURATION_SEC = 86_400;

export interface OpenTunnelParams {
  alias: string;
  kind: TunnelKind;
  remote?: string;
  local?: string;
  durationSec: number;
}

export function validateOpenParams(params: OpenTunnelParams): void {
  if (params.kind !== 'local' && params.kind !== 'remote' && params.kind !== 'dynamic') {
    throw new OpRunLocalError(
      'VALIDATION_ERROR',
      `kind must be 'local', 'remote', or 'dynamic', got '${params.kind}'`,
    );
  }
  if ((params.kind === 'local' || params.kind === 'remote') && !params.remote) {
    throw new OpRunLocalError('VALIDATION_ERROR', `--remote is required for kind '${params.kind}'`);
  }
  if (params.kind === 'remote' && !params.local) {
    throw new OpRunLocalError('VALIDATION_ERROR', "--local is required for kind 'remote'");
  }
  if ((params.kind === 'local' || params.kind === 'dynamic') && params.local) {
    throw new OpRunLocalError('VALIDATION_ERROR', `--local is not valid for kind '${params.kind}'`);
  }
  if (params.durationSec < MIN_DURATION_SEC || params.durationSec > MAX_DURATION_SEC) {
    throw new OpRunLocalError(
      'VALIDATION_ERROR',
      `--duration must be between ${MIN_DURATION_SEC} and ${MAX_DURATION_SEC} seconds`,
    );
  }
}

/** `localPort` is the auto-assigned port from `findFreePort()` for kind=local/dynamic, `null`
 *  for kind=remote (the local side there is `params.local`, an agent-supplied string, not a
 *  port sshepherd allocates). */
export function buildSshArgs(params: OpenTunnelParams, localPort: number | null): string[] {
  if (params.kind === 'local') {
    return ['-N', '-L', `${localPort}:${params.remote}`, params.alias];
  }
  if (params.kind === 'dynamic') {
    return ['-N', '-D', String(localPort), params.alias];
  }
  return ['-N', '-R', `${params.remote}:${params.local}`, params.alias];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts -t "validateOpenParams|buildSshArgs"`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): arg validation and ssh invocation builder"
```

---

### Task 6: Self-invocation + supervisor entrypoint

**Files:**
- Modify: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/tunnel.test.ts`:

```typescript
import { resolveSelfInvocation, runSupervisor } from '../tunnel.ts';

describe('resolveSelfInvocation', () => {
  test('dev mode (argv[1] ends with cli.ts) re-invokes bun + the script path', () => {
    const original = process.argv;
    process.argv = [original[0] ?? 'bun', '/repo/src/cli.ts', 'tunnel', 'open'];
    try {
      expect(resolveSelfInvocation()).toEqual([process.argv[0], '/repo/src/cli.ts']);
    } finally {
      process.argv = original;
    }
  });

  test('compiled-binary mode (argv[1] does not end with cli.ts) re-invokes execPath alone', () => {
    const original = process.argv;
    process.argv = ['/usr/local/bin/sshepherd', 'tunnel', 'open'];
    try {
      expect(resolveSelfInvocation()).toEqual([process.execPath]);
    } finally {
      process.argv = original;
    }
  });
});

describe('runSupervisor', () => {
  test('spawns the given command, kills it once durationSec elapses, and resolves', async () => {
    // Use a real, harmless long-running command (`sleep 5`) standing in for `ssh -N ...` — the
    // supervisor doesn't know or care what it's supervising, only that it must die on schedule.
    const start = Date.now();
    const exitCode = await runSupervisor({
      command: 'sleep',
      args: ['5'],
      durationSec: 1,
    });
    const elapsedMs = Date.now() - start;
    // Killed by the 1s timer, long before `sleep 5` would exit on its own.
    expect(elapsedMs).toBeLessThan(4000);
    expect(exitCode).not.toBe(0);
  });

  test('resolves with the real exit code when the command finishes before the deadline', async () => {
    const exitCode = await runSupervisor({ command: 'true', args: [], durationSec: 10 });
    expect(exitCode).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts -t "resolveSelfInvocation|runSupervisor"`
Expected: FAIL — neither function exists yet.

- [ ] **Step 3: Implement in `src/tunnel.ts`**

```typescript
/** Dev mode (`bun src/cli.ts ...`) needs `[bun, /path/to/cli.ts]` to re-invoke correctly —
 *  `process.execPath` alone would just be the `bun` binary, which can't be run with no script
 *  argument the way this needs. A compiled standalone binary (`dist/sshepherd`, the real
 *  distribution artifact) has no separate script path in `process.argv[1]`, so `process.execPath`
 *  alone IS the correct full re-invocation. */
export function resolveSelfInvocation(): string[] {
  const scriptArg = process.argv[1];
  if (scriptArg && scriptArg.endsWith('cli.ts')) {
    return [process.execPath, scriptArg];
  }
  return [process.execPath];
}

export interface RunSupervisorParams {
  command: string;
  args: string[];
  durationSec: number;
}

/** Runs as the hidden `sshepherd tunnel __supervise` entrypoint (wired in `cli.ts`). Spawns the
 *  real command (ssh) as its OWN child — inheriting this process's group, which `openTunnel`
 *  makes a NEW group via `detached: true` when it spawns the supervisor itself — holds a JS
 *  timer for `durationSec`, and kills the child directly (no process-group trick needed here;
 *  this process has a direct handle to its own child) if the timer fires first. */
export async function runSupervisor(params: RunSupervisorParams): Promise<number> {
  const proc = Bun.spawn([params.command, ...params.args], {
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  const timer = setTimeout(() => {
    proc.kill('SIGKILL');
  }, params.durationSec * 1000);
  const exitCode = await proc.exited;
  clearTimeout(timer);
  return exitCode;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts -t "resolveSelfInvocation|runSupervisor"`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): self-invocation resolver and supervisor entrypoint"
```

---

### Task 7: `openTunnel`

**Files:**
- Modify: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

`openTunnel` ties Tasks 3-6 together. It takes an injectable `spawnSupervisor` dependency (mirroring the
existing `TransportDeps`/`InstallServerDeps` DI pattern elsewhere in this codebase) so unit tests never
spawn a real detached process or touch real ssh.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/tunnel.test.ts`:

```typescript
import { openTunnel } from '../tunnel.ts';

describe('openTunnel', () => {
  function withTempStateDir<T>(fn: () => T): T {
    const dir = tempStateDir();
    const original = process.env.SSHEPHERD_TUNNEL_STATE_DIR;
    process.env.SSHEPHERD_TUNNEL_STATE_DIR = dir;
    try {
      return fn();
    } finally {
      if (original === undefined) {
        delete process.env.SSHEPHERD_TUNNEL_STATE_DIR;
      } else {
        process.env.SSHEPHERD_TUNNEL_STATE_DIR = original;
      }
    }
  }

  test('local kind: assigns a port, spawns via the injected fn, writes a state record', () => {
    withTempStateDir(() => {
      const record = openTunnel(
        { alias: 'web-01', kind: 'local', remote: 'localhost:5432', durationSec: 120 },
        { spawnSupervisor: () => ({ pid: 424242 }) },
      );

      expect(record.alias).toBe('web-01');
      expect(record.kind).toBe('local');
      expect(record.localPort).toBeGreaterThan(0);
      expect(record.remoteTarget).toBe('localhost:5432');
      expect(record.localTarget).toBeNull();
      expect(record.pid).toBe(424242);

      const onDisk = readTunnelRecordFile(tunnelRecordPath(defaultTunnelStateDir(), record.id));
      expect(onDisk).toEqual(record);
    });
  });

  test('remote kind: no localPort assigned, records localTarget', () => {
    withTempStateDir(() => {
      const record = openTunnel(
        { alias: 'web-01', kind: 'remote', remote: '0.0.0.0:8080', local: 'localhost:3000', durationSec: 120 },
        { spawnSupervisor: () => ({ pid: 424242 }) },
      );
      expect(record.localPort).toBeNull();
      expect(record.remoteTarget).toBe('0.0.0.0:8080');
      expect(record.localTarget).toBe('localhost:3000');
    });
  });

  test('propagates validation errors before ever calling spawnSupervisor', () => {
    withTempStateDir(() => {
      let spawnCalled = false;
      expect(() =>
        openTunnel(
          { alias: 'web-01', kind: 'local', durationSec: 120 },
          { spawnSupervisor: () => { spawnCalled = true; return { pid: 1 }; } },
        ),
      ).toThrow(OpRunLocalError);
      expect(spawnCalled).toBe(false);
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts -t "openTunnel"`
Expected: FAIL — `openTunnel` is not exported yet.

- [ ] **Step 3: Implement in `src/tunnel.ts`**

```typescript
import { randomUUID } from 'node:crypto';

export interface SpawnSupervisorResult {
  pid: number;
}

export interface OpenTunnelDeps {
  spawnSupervisor?: (id: string, durationSec: number, sshArgs: string[]) => SpawnSupervisorResult;
}

/** The real (production) spawn path — a detached re-invocation of this same binary in
 *  `tunnel __supervise` mode. `detached: true` makes the supervisor the leader of a NEW process
 *  group; the ssh child it spawns from inside `runSupervisor` inherits that same group (default
 *  POSIX fork/exec behavior for a non-detached child), which is what lets `closeTunnel` kill
 *  both with one negative-PID signal. */
function defaultSpawnSupervisor(id: string, durationSec: number, sshArgs: string[]): SpawnSupervisorResult {
  const [bin, ...selfArgs] = resolveSelfInvocation();
  const proc = Bun.spawn([bin, ...selfArgs, 'tunnel', '__supervise', id, String(durationSec), 'ssh', ...sshArgs], {
    stdio: ['ignore', 'ignore', 'ignore'],
    detached: true,
  });
  proc.unref();
  return { pid: proc.pid };
}

export function openTunnel(params: OpenTunnelParams, deps: OpenTunnelDeps = {}): TunnelRecord {
  validateOpenParams(params);

  const id = `t-${randomUUID()}`;
  const localPort = params.kind === 'local' || params.kind === 'dynamic' ? findFreePort() : null;
  const sshArgs = buildSshArgs(params, localPort);

  const spawn = deps.spawnSupervisor ?? defaultSpawnSupervisor;
  const { pid } = spawn(id, params.durationSec, sshArgs);

  const now = Date.now();
  const record: TunnelRecord = {
    id,
    alias: params.alias,
    kind: params.kind,
    localPort,
    remoteTarget: params.kind === 'dynamic' ? null : (params.remote ?? null),
    localTarget: params.kind === 'remote' ? (params.local ?? null) : null,
    pid,
    openedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + params.durationSec * 1000).toISOString(),
  };

  writeTunnelRecord(tunnelRecordPath(defaultTunnelStateDir(), id), record);
  return record;
}
```

Also add `import { randomUUID } from 'node:crypto';` at the top of `src/tunnel.ts` alongside the other
`node:*` imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts -t "openTunnel"`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): openTunnel ties validation, port-finding, and spawn together"
```

---

### Task 8: `listTunnels` + `closeTunnel`

**Files:**
- Modify: `src/tunnel.ts`
- Test: `src/__tests__/tunnel.test.ts`

Uses a **real** short-lived subprocess (`sleep 100 &`-style) as the PID under test so liveness/kill logic
is exercised against genuine OS behavior, not a mock — the same "use a real subprocess, not a fake" bar
`setup-ssh-alias-install-server.test.ts` already holds itself to.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/tunnel.test.ts`:

```typescript
import { closeTunnel, listTunnels } from '../tunnel.ts';

describe('listTunnels / closeTunnel', () => {
  function spawnRealGroupLeader(): number {
    // A real detached process, its own group leader — stands in for a real supervisor PID
    // without actually re-invoking the sshepherd binary from inside a unit test.
    const proc = Bun.spawn(['sleep', '30'], { stdio: ['ignore', 'ignore', 'ignore'], detached: true });
    proc.unref();
    return proc.pid;
  }

  test('listTunnels returns an active, non-expired record with remainingSec', () => {
    withTempStateDir(() => {
      const pid = spawnRealGroupLeader();
      const record = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        { spawnSupervisor: () => ({ pid }) },
      );

      const active = listTunnels();
      expect(active).toHaveLength(1);
      expect(active[0]?.id).toBe(record.id);
      expect(active[0]?.remainingSec).toBeGreaterThan(0);
      expect(active[0]?.remainingSec).toBeLessThanOrEqual(120);

      closeTunnel(record.id); // cleanup: kill the real sleep process
    });
  });

  test('listTunnels prunes a record whose PID is dead', () => {
    withTempStateDir(() => {
      const proc = Bun.spawn(['true'], { stdio: ['ignore', 'ignore', 'ignore'] });
      const deadPid = proc.pid;
      // Deliberately not awaited via a state-check loop — `true` exits almost instantly, and
      // listTunnels' own kill-0 check tolerates a PID that's already gone.
      const record = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        { spawnSupervisor: () => ({ pid: deadPid }) },
      );

      // Give the short-lived process a moment to actually exit before asserting it's pruned.
      const path = tunnelRecordPath(defaultTunnelStateDir(), record.id);
      let active = listTunnels();
      // Retry briefly — `true` is fast but not synchronous from this test's perspective.
      for (let i = 0; i < 20 && active.length > 0; i++) {
        active = listTunnels();
      }
      expect(active).toHaveLength(0);
      expect(readTunnelRecordFile(path)).toBeNull();
    });
  });

  test('closeTunnel kills a real process group and removes the state file', () => {
    withTempStateDir(() => {
      const pid = spawnRealGroupLeader();
      const record = openTunnel(
        { alias: 'web-01', kind: 'dynamic', durationSec: 120 },
        { spawnSupervisor: () => ({ pid }) },
      );

      const result = closeTunnel(record.id);
      expect(result).toEqual({ id: record.id, closed: true });
      expect(readTunnelRecordFile(tunnelRecordPath(defaultTunnelStateDir(), record.id))).toBeNull();

      // Confirm the real process is actually gone, not just the state file.
      expect(() => process.kill(pid, 0)).toThrow();
    });
  });

  test('closeTunnel on an unknown id is idempotent (closed: false, no throw)', () => {
    withTempStateDir(() => {
      expect(closeTunnel('t-does-not-exist')).toEqual({ id: 't-does-not-exist', closed: false });
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/tunnel.test.ts -t "listTunnels|closeTunnel"`
Expected: FAIL — neither function exists yet.

- [ ] **Step 3: Implement in `src/tunnel.ts`**

```typescript
export interface TunnelListEntry extends TunnelRecord {
  remainingSec: number;
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Kills the WHOLE process group (supervisor + its ssh child) via the negative PID — killing
 *  only the supervisor's own PID would leave ssh running as an orphan, since a `timeout`-style
 *  wrapper dying does not propagate to its own child by default. Silently no-ops if the group
 *  is already gone. */
function killProcessGroup(pid: number): void {
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // already dead
  }
}

export function listTunnels(): TunnelListEntry[] {
  const dir = defaultTunnelStateDir();
  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    return [];
  }

  const now = Date.now();
  const entries: TunnelListEntry[] = [];
  for (const file of files) {
    if (!file.endsWith('.json')) {
      continue;
    }
    const path = join(dir, file);
    const record = readTunnelRecordFile(path);
    if (record === null) {
      continue;
    }
    const alive = isPidAlive(record.pid);
    const expiresAtMs = Date.parse(record.expiresAt);
    if (!alive || now >= expiresAtMs) {
      if (alive) {
        // Past expiry but the supervisor's own timer hasn't fired yet — force-clean rather
        // than report a stale entry as active.
        killProcessGroup(record.pid);
      }
      rmSync(path, { force: true });
      continue;
    }
    entries.push({ ...record, remainingSec: Math.max(0, Math.round((expiresAtMs - now) / 1000)) });
  }
  return entries;
}

export interface TunnelCloseResult {
  id: string;
  closed: boolean;
}

/** Idempotent: closing an id with no matching state file is a success (`closed: false`), not
 *  an error — the same "remove is a no-op on an already-gone target" precedent used elsewhere
 *  in this codebase. */
export function closeTunnel(id: string): TunnelCloseResult {
  const path = tunnelRecordPath(defaultTunnelStateDir(), id);
  const record = readTunnelRecordFile(path);
  if (record === null) {
    return { id, closed: false };
  }
  killProcessGroup(record.pid);
  rmSync(path, { force: true });
  return { id, closed: true };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/tunnel.test.ts -t "listTunnels|closeTunnel"`
Expected: PASS (5 tests)

- [ ] **Step 5: Run the whole `tunnel.test.ts` file together**

Run: `bun test src/__tests__/tunnel.test.ts`
Expected: PASS (all tests from Tasks 3-8)

- [ ] **Step 6: Commit**

```bash
git add src/tunnel.ts src/__tests__/tunnel.test.ts
git commit -m "feat(tunnel): listTunnels pruning and closeTunnel process-group kill"
```

---

### Task 9: Registry ops + CLI wiring

**Files:**
- Modify: `src/registry.ts`
- Modify: `src/cli.ts`

- [ ] **Step 1: Import `tunnel.ts` into `registry.ts`**

Add near the other local imports at the top of `src/registry.ts`:

```typescript
import {
  closeTunnel,
  DEFAULT_DURATION_SEC,
  listTunnels,
  MAX_DURATION_SEC,
  openTunnel,
  type TunnelKind,
} from './tunnel.ts';
```

- [ ] **Step 2: Add the 3 `OpSpec` consts**

Add this block right before the `// registry + executor` section comment (i.e., right before
`const REGISTRY: OpSpec[] = [`):

```typescript
// ---------------------------------------------------------------------------
// tunnel
// ---------------------------------------------------------------------------

interface TunnelOpenResult {
  id: string;
  alias: string;
  kind: TunnelKind;
  localPort: number | null;
  remoteTarget: string | null;
  localTarget: string | null;
  expiresAt: string;
}

const tunnelOpen: OpSpec<TunnelOpenResult> = {
  group: 'tunnel',
  name: 'open',
  summary: 'Open a local/remote/dynamic SSH port forward that self-closes after --duration.',
  args: [
    arg('kind', 'flag', true, "Forward kind: 'local', 'remote', or 'dynamic'."),
    arg(
      'remote',
      'flag',
      false,
      "Required for kind=local (forward target 'host:port') and kind=remote (bind spec 'host:port' on the alias's own network).",
    ),
    arg(
      'local',
      'flag',
      false,
      "Required for kind=remote only: 'host:port' on the operator's machine being exposed.",
    ),
    arg(
      'duration',
      'flag',
      false,
      `Tunnel lifetime in seconds before it self-closes (default ${DEFAULT_DURATION_SEC}, max ${MAX_DURATION_SEC}).`,
    ),
  ],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelOpenResult,
  runLocal: (ctx) => {
    const kind = ctx.args.kind as TunnelKind;
    const durationSec =
      typeof ctx.args.duration === 'string' ? Number(ctx.args.duration) : DEFAULT_DURATION_SEC;
    const record = openTunnel({
      alias: ctx.alias,
      kind,
      remote: typeof ctx.args.remote === 'string' ? ctx.args.remote : undefined,
      local: typeof ctx.args.local === 'string' ? ctx.args.local : undefined,
      durationSec,
    });
    return {
      id: record.id,
      alias: record.alias,
      kind: record.kind,
      localPort: record.localPort,
      remoteTarget: record.remoteTarget,
      localTarget: record.localTarget,
      expiresAt: record.expiresAt,
    };
  },
};

interface TunnelListResult {
  tunnels: ReturnType<typeof listTunnels>;
}

const tunnelList: OpSpec<TunnelListResult> = {
  group: 'tunnel',
  name: 'list',
  summary: 'List this operator’s active tunnels (alias, kind, port, remaining lifetime).',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelListResult,
  runLocal: () => ({ tunnels: listTunnels() }),
};

interface TunnelCloseResultShape {
  id: string;
  closed: boolean;
}

const tunnelClose: OpSpec<TunnelCloseResultShape> = {
  group: 'tunnel',
  name: 'close',
  summary: 'Close an open tunnel by id (idempotent — an already-gone id still succeeds).',
  args: [arg('id', 'positional', true, "Tunnel id, as returned by 'tunnel open'.")],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelCloseResultShape,
  runLocal: (ctx) => closeTunnel(ctx.args.id as string),
};
```

- [ ] **Step 3: Append the 3 new ops to `REGISTRY`**

Find the `const REGISTRY: OpSpec[] = [` array (ends with `securityFail2ban,\n] as OpSpec[];`) and add the
3 new consts right before the closing bracket:

```typescript
  securityFail2ban,
  tunnelOpen,
  tunnelList,
  tunnelClose,
] as OpSpec[];
```

- [ ] **Step 4: Wire the hidden `tunnel __supervise` entrypoint in `src/cli.ts`**

Add the import at the top of `src/cli.ts`:

```typescript
import { runSupervisor } from './tunnel.ts';
```

In the `run()` function, right after the existing `--version`/`--help` handling and BEFORE the `if
(first === 'setup')` check, add:

```typescript
  if (first === 'tunnel' && rest[0] === '__supervise') {
    const [, id, durationSecRaw, command, ...commandArgs] = rest;
    if (id === undefined || durationSecRaw === undefined || command === undefined) {
      throw new UsageError('tunnel __supervise: missing id/duration/command');
    }
    const durationSec = Number(durationSecRaw);
    if (!Number.isFinite(durationSec) || durationSec <= 0) {
      throw new UsageError('tunnel __supervise: duration must be a positive number');
    }
    const exitCode = await runSupervisor({ command, args: commandArgs, durationSec });
    process.exitCode = exitCode;
    return;
  }
```

(`__supervise` is intentionally NOT registered as a real `OpSpec`/group — it has no `Envelope`, no
`--yes` gate, and is never meant to be invoked by an agent directly; it only exists as a target for
`tunnel.ts`'s own `defaultSpawnSupervisor` to re-invoke.)

- [ ] **Step 5: Special-case `tunnel list`/`tunnel close` as host-local (no alias) in `buildOpContext`**

Find this block in `src/cli.ts`:

```typescript
  if (group === 'hosts' && action === 'list') {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
  if (group === 'db' && action === 'list') {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
```

Add right after it:

```typescript
  if (group === 'tunnel' && (action === 'list' || action === 'close')) {
    return { alias: '', args: mapArgsToCtx(op, positionals, flags) };
  }
```

(`tunnel open`'s first positional stays the alias, going through the existing generic fallback at the
bottom of `buildOpContext` — unchanged.)

- [ ] **Step 6: Add a `tunnel` entry to `GROUP_FIRST_POSITIONAL_NOTE`**

Find `GROUP_FIRST_POSITIONAL_NOTE` near the top of `src/cli.ts` and add:

```typescript
  tunnel:
    'First positional (open only): <alias>. `list` takes no positional; `close` takes <id> (from `tunnel open`) instead of an alias.',
```

- [ ] **Step 7: Typecheck**

Run: `bun run typecheck` (or the project's actual typecheck script — verify the exact name in
`package.json` first)
Expected: EXIT 0

- [ ] **Step 8: Manual smoke of the CLI wiring (no real ssh target needed for this step)**

Run: `bun src/cli.ts tunnel open --help`
Expected: prints the `open` action's args (kind/remote/local/duration), matching `formatActionHelp`'s
existing output shape for every other op.

Run: `bun src/cli.ts tunnel list`
Expected: `{"ok":true,...,"data":{"tunnels":[]}}` (no tunnels open yet) — confirms the host-local
`alias:''` path and `runLocal` wiring both work end-to-end through the real CLI, not just unit tests.

- [ ] **Step 9: Commit**

```bash
git add src/registry.ts src/cli.ts
git commit -m "feat(tunnel): register tunnel open/list/close ops and CLI wiring"
```

---

### Task 10: Registry-level tests for the 3 new ops

**Files:**
- Modify: `src/__tests__/registry.test.ts`

Mirrors the file's existing per-op test shape (grep the file for `describe('hosts list'` or similar to
match the exact existing style before writing these — arg validation, mutating gate, envelope shape).

- [ ] **Step 1: Write the tests**

Add to `src/__tests__/registry.test.ts`:

```typescript
describe('tunnel open', () => {
  test('refuses without --yes (mutating gate)', async () => {
    const op = getOp('tunnel', 'open');
    if (!op) throw new Error('tunnel open not registered');
    const envelope = await executeOp(
      op,
      { alias: 'web-01', args: { kind: 'dynamic', duration: '60' } },
      { yes: false },
    );
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
  });

  test('returns VALIDATION_ERROR for an unknown kind, even with --yes', async () => {
    const op = getOp('tunnel', 'open');
    if (!op) throw new Error('tunnel open not registered');
    const envelope = await executeOp(
      op,
      { alias: 'web-01', args: { kind: 'bogus', duration: '60' } },
      { yes: true },
    );
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
  });

  test('envelope never carries HostName/User/Port fields for the alias', async () => {
    const op = getOp('tunnel', 'open');
    if (!op) throw new Error('tunnel open not registered');
    const envelope = await executeOp(
      op,
      { alias: 'web-01', args: { kind: 'dynamic', duration: '60' } },
      { yes: true },
    );
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain('HostName');
    expect(serialized).not.toContain('IdentityFile');
    // Cleanup: close whatever this actually opened.
    if (envelope.ok && envelope.data && typeof envelope.data === 'object' && 'id' in envelope.data) {
      const closeOp = getOp('tunnel', 'close');
      if (closeOp) {
        await executeOp(closeOp, { alias: '', args: { id: (envelope.data as { id: string }).id } }, { yes: true });
      }
    }
  });
});

describe('tunnel close', () => {
  test('refuses without --yes (mutating gate)', async () => {
    const op = getOp('tunnel', 'close');
    if (!op) throw new Error('tunnel close not registered');
    const envelope = await executeOp(op, { alias: '', args: { id: 't-whatever' } }, { yes: false });
    expect(envelope.ok).toBe(false);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
  });

  test('closing an unknown id still succeeds (idempotent)', async () => {
    const op = getOp('tunnel', 'close');
    if (!op) throw new Error('tunnel close not registered');
    const envelope = await executeOp(op, { alias: '', args: { id: 't-does-not-exist' } }, { yes: true });
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({ id: 't-does-not-exist', closed: false });
  });
});

describe('tunnel list', () => {
  test('is non-mutating (no --yes needed) and returns an empty array by default', async () => {
    const op = getOp('tunnel', 'list');
    if (!op) throw new Error('tunnel list not registered');
    const envelope = await executeOp(op, { alias: '', args: {} }, {});
    expect(envelope.ok).toBe(true);
    expect(envelope.data).toEqual({ tunnels: [] });
  });
});
```

(These tests will actually spawn a real detached supervisor process via `openTunnel`'s default,
production `spawnSupervisor` path for the "envelope never carries..." test — that's intentional, it's
exercising the real end-to-end wiring once, not just the injectable-dependency unit tests from Task 7.
Point `SSHEPHERD_TUNNEL_STATE_DIR` at a temp dir for this test file the same way `tunnel.test.ts` does,
so it never touches the real `~/.local/state/sshepherd/tunnels/`.)

- [ ] **Step 2: Run the new tests**

Run: `bun test src/__tests__/registry.test.ts -t "tunnel"`
Expected: PASS (6 tests)

- [ ] **Step 3: Run the full suite**

Run: `bun test`
Expected: PASS, 0 fail — confirms Task 2's `executeOp` change and the 3 new ops don't regress any of the
existing 160+ tests.

- [ ] **Step 4: Commit**

```bash
git add src/__tests__/registry.test.ts
git commit -m "test(tunnel): registry-level coverage for open/list/close"
```

---

### Task 11: Docs + live smoke step

**Files:**
- Modify: `SKILL.md`
- Modify: `scripts/smoke.sh`

- [ ] **Step 1: Update `SKILL.md`**

- In the "Quick reference — 9 registry-driven groups (52 ops)" heading, update the group/op counts to
  reflect the new `tunnel` group and 3 new ops (grep for the exact current numbers first — they're
  data-driven off `listOps()`/`SETUP_SUB_GROUPS` per `skill-doc.test.ts`, so get the real count from
  running `bun test src/__tests__/skill-doc.test.ts` and reading its failure diff rather than guessing).
- Add a `tunnel` row to the "Command shape" positional-convention table:
  `| \`tunnel list\` | *(none — host-local)* | — |` alongside the existing `hosts list`/`db list` row,
  and note `tunnel close` takes `<id>`, not an alias.
- Add 3 example lines near the other `sshepherd <group> <action>` examples:
  ```
  sshepherd tunnel open web-01 --kind local --remote localhost:5432 --duration 1800 --yes
  sshepherd tunnel list
  sshepherd tunnel close t-a1b2c3d4 --yes
  ```
- In "The zero-knowledge model" section, add one line after the existing `hosts list`/`setup ssh-alias
  list` bullet: "`tunnel open`'s `--remote`/`--local` flags are the forward target/exposed service as
  seen from the alias's own network (almost always `localhost:<port>`) — not the alias's own connection
  identity; the response never carries `HostName`/`User`/`Port` regardless."

- [ ] **Step 2: Run `skill-doc.test.ts` to confirm the doc matches the real registry**

Run: `bun test src/__tests__/skill-doc.test.ts`
Expected: PASS — if it fails, its diff names the exact count/text mismatch; fix `SKILL.md` accordingly
rather than the test.

- [ ] **Step 3: Add a live tunnel smoke step to `scripts/smoke.sh`**

Read `scripts/smoke.sh` first to match its exact existing style (it already drives the disposable sshd
fixture from `scripts/sshd-fixture/` for other groups — mirror that setup/teardown shape). Add a step
that: opens a `local` tunnel from the fixture to a port the fixture's sshd box listens on, curls through
the forwarded local port to confirm a real response, then closes the tunnel and confirms the local port
is released (a second curl to the same port fails to connect). Mark it clearly in a comment as requiring
Docker, matching the file's existing `just smoke` precedent — this step is written but not run as part of
this plan (no Docker host available in this environment); it becomes part of `just smoke`'s existing
BUILT-BUT-NOT-RUN status until the user runs it for real.

- [ ] **Step 4: Commit**

```bash
git add SKILL.md scripts/smoke.sh
git commit -m "docs(tunnel): document the tunnel group, add a live smoke step"
```

---

## Self-Review

**Spec coverage:** `open`/`list`/`close` (Task 9), local/remote/dynamic kinds (Task 5), auto-assigned
local port (Task 4), self-expiry (Task 6, revised from `timeout` to a self-supervising subprocess —
documented in the Deviations section above), zero-knowledge boundary (Task 10's dedicated test + Task 11
doc line), mutating gate + audit (Task 9's `mutating: true`, exercised in Task 10), state file location
`~/.local/state/sshepherd/tunnels/` (Task 3), error codes (Task 1). Every spec section has a task.

**Placeholder scan:** No TBD/TODO. The one intentionally-deferred item (Task 11 Step 3's live smoke run)
is explicit about WHY it's deferred (no Docker host in this environment) and WHAT running it later
requires — matching the project's own existing `just smoke` precedent, not a vague "add tests later."

**Type consistency:** `TunnelRecord`/`TunnelKind`/`OpenTunnelParams`/`TunnelCloseResult` are defined once
in `src/tunnel.ts` (Tasks 3/5/8) and imported, never redeclared, everywhere else (Task 7's `openTunnel`,
Task 9's registry ops, Task 10's tests). `OpRunLocalError` (Task 1) is the single error-signaling
mechanism used by every validation failure across `validateOpenParams` (Task 5) — no second error
convention introduced.
