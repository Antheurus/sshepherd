import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_PARTIAL_STDOUT_CHARS } from '../limits.ts';
import { executeOp, getOp } from '../registry.ts';
import { scrubText } from '../scrub.ts';
import { scaffold } from '../setup-config-allowlist.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

// Re-audit of Block 8 fix C1 (6685bc0). Red tests here are findings.

const SSH_G = 'hostname srv-01.example.net\nuser opsuser\nport 2222\n';
const DEMO_RECIPE_PATH = join(import.meta.dir, 'fixtures', 'deploy.demo.toml');
const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });
const canary = ['canary', 'a08c', 'window', '5521'].join('-');

let scratch = '';
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'sshepherd-a08c-'));
});
afterAll(() => {
  if (existsSync(join(scratch, 'locked'))) {
    chmodSync(join(scratch, 'locked'), 0o700);
  }
  rmSync(scratch, { recursive: true, force: true });
});

function timedOutRunner(stdout: string): SshRunner {
  return async (args) => {
    if (args[0] === '-G') {
      return ok(SSH_G);
    }
    if (args.includes('-O')) {
      return ok('');
    }
    return { code: 124, stdout, stderr: '', timedOut: true };
  };
}

async function deployRun(runner: SshRunner) {
  const op = getOp('deploy', 'run');
  if (!op) {
    throw new Error('deploy run missing');
  }
  process.env.SSHEPHERD_RECIPE_PATH = DEMO_RECIPE_PATH;
  try {
    return await executeOp(
      op,
      { alias: 'lms-server', args: { recipe: 'demo' } },
      { transport: { runner }, yes: true, auditLogPath: join(scratch, 'deploy-audit.jsonl') },
    );
  } finally {
    delete process.env.SSHEPHERD_RECIPE_PATH;
  }
}

describe('a08c NEW-1 — D-env: partial_stdout is cut before the env-block pass sees the block', () => {
  const block = ['APP_NAME=shop', `SPACED = ${canary}`, 'DB_HOST=db', 'LOG_LEVEL=debug'];
  const firstTwo = `${block[0]}\n${block[1]}\n`;
  const fillerLine = `${'compiling module '.repeat(5)}\n`;
  const fillerLen = MAX_PARTIAL_STDOUT_CHARS - firstTwo.length - 3;
  const filler = `${fillerLine.repeat(Math.ceil(fillerLen / fillerLine.length)).slice(0, fillerLen - 1)}\n`;

  test('control: the same block near the start of a timed-out run -> 0 hits', async () => {
    const env = await deployRun(timedOutRunner(`start\n${block.join('\n')}\n${filler}`));
    expect({ code: env.error?.code, hits: JSON.stringify(env).split(canary).length - 1 }).toEqual({
      code: 'COMMAND_TIMEOUT',
      hits: 0,
    });
  });

  test('block straddling the MAX_PARTIAL_STDOUT_CHARS cut -> 0 hits in partial_stdout', async () => {
    const env = await deployRun(timedOutRunner(`${filler}${block.join('\n')}\nstill running\n`));
    expect({ code: env.error?.code, hits: JSON.stringify(env).split(canary).length - 1 }).toEqual({
      code: 'COMMAND_TIMEOUT',
      hits: 0,
    });
  });
});

describe('a08c NEW-2 — D-audit: setup actions still fail with INTERNAL_ERROR on an unwritable log', () => {
  const stateBefore = process.env.SSHEPHERD_STATE_DIR;
  beforeAll(() => {
    const locked = join(scratch, 'locked');
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    process.env.SSHEPHERD_STATE_DIR = locked;
  });
  afterAll(() => {
    process.env.SSHEPHERD_STATE_DIR = stateBefore;
  });

  test('setup config-allowlist scaffold --yes writes the file and returns ok + AUDIT_UNWRITABLE', () => {
    const target = join(scratch, 'config-allowlist.toml');
    let outcome: unknown;
    try {
      outcome = scaffold('edge-box', { paths: ['/srv/app'], yes: true }, target);
    } catch (err) {
      outcome = { threw: err instanceof Error ? err.name : String(err) };
    }
    const result = outcome as {
      ok?: boolean;
      warnings?: { code: string }[];
      threw?: string;
    };
    expect({
      written: existsSync(target),
      threw: result.threw,
      ok: result.ok,
      warning: result.warnings?.[0]?.code,
    }).toEqual({ written: true, threw: undefined, ok: true, warning: 'AUDIT_UNWRITABLE' });
  });
});

describe('a08c NEW-3 — N3 class: a verifier before an ellipsis or `.=`/`./` stays raw', () => {
  test.each([
    'md5c6b5b1f3c95b4c3e1b6b9c1c2f0c8d4a',
    '$argon2id$v=19$m=65536,t=2,p=1$xnRRApYS1VdXvixvu029zYSEvReVF/g0TTHnEOBpKfY$z0TQTvCCvrCLLh3pSOs/0CyBo/kC7+3U1m5/GVW0yt4',
  ])('stored verifier was %s... then', (h) => {
    expect(scrubText(`stored verifier was ${h}... then`).value).not.toContain(h.slice(-12));
  });
});
