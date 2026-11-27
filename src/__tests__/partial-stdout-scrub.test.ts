import { describe, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { executeOp, getOp } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

function runnerFor(last: SpawnOutcome): SshRunner {
  const outcomes: SpawnOutcome[] = [
    { code: 0, stdout: 'HostName 10.0.0.9\n', stderr: '', timedOut: false },
    { code: 0, stdout: '', stderr: '', timedOut: false },
    last,
  ];
  let index = 0;
  return async () => {
    const outcome = outcomes[Math.min(index, outcomes.length - 1)] as SpawnOutcome;
    index += 1;
    return outcome;
  };
}

/** Full-width 64-column body lines and a short last one, as a private key's PEM body prints them;
 *  random per run, so no key-shaped literal sits in the repo. */
function keyBodyLines(): string[] {
  const body = randomBytes(1_190).toString('base64').replace(/=+$/, '');
  const lines: string[] = [];
  for (let start = 0; start < body.length; start += 64) {
    lines.push(body.slice(start, start + 64));
  }
  return lines;
}

describe('a timed-out logs window: partial_stdout gets the key-body masking its normal stdout gets', () => {
  test('body lines with both PEM markers outside the window never come back', async () => {
    const op = getOp('logs', 'docker');
    if (!op) {
      throw new Error('logs docker op missing');
    }
    const body = keyBodyLines();
    const stdout = [
      '2026-11-27T10:00:00.000000000Z starting worker',
      ...body.map((line) => `2026-11-27T10:00:01.000000000Z ${line}`),
      '2026-11-27T10:00:02.000000000Z worker ready',
      '',
    ].join('\n');

    const envelope = await executeOp(
      op,
      { alias: 'logs-host', args: { container: 'app' } },
      {
        transport: {
          runner: runnerFor({ code: 124, stdout, stderr: '', timedOut: false }),
        },
      },
    );

    expect(envelope.error?.code).toBe('COMMAND_TIMEOUT');
    const partial = (envelope.data as { partial_stdout?: string } | null)?.partial_stdout ?? '';
    expect(partial).toContain('worker ready');
    for (const line of body) {
      expect(partial.includes(line)).toBe(false);
    }
  });
});
