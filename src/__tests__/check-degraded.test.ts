import { describe, expect, test } from 'bun:test';
import { computeDeadEndRisk } from '../parsers/verdict.ts';
import { executeOp, getOp } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';

const ok = (stdout: string): SpawnOutcome => ({ code: 0, stdout, stderr: '', timedOut: false });
const canned =
  (stdout: string): SshRunner =>
  async (args) =>
    args[0] === '-G' ? ok('hostname srv-01.example.net\n') : ok(args.includes('-O') ? '' : stdout);

async function drive(group: string, name: string, stdout: string, args = {}) {
  const op = getOp(group, name);
  if (!op) {
    throw new Error(`${group} ${name} missing`);
  }
  return executeOp(op, { alias: 'edge-box', args }, { transport: { runner: canned(stdout) } });
}

const DF_OK = [
  '__DF__',
  'Filesystem     1B-blocks       Used   Available Capacity Mounted on',
  '/dev/sda1    21467271168 8589934592 11824550912       43% /',
  '__DF_RC__',
  '0',
];
const FREE_OK = [
  '__FREE__',
  '               total        used        free      shared  buff/cache   available',
  'Mem:      8000000000  2000000000  4000000000    10000000  2000000000  5800000000',
  'Swap:     1000000000           0  1000000000',
  '__FREE_RC__',
  '0',
];
const UPTIME_OK = [
  '__UPTIME__',
  '14:32:05 up 10 days,  3:14,  2 users,  load average: 0.15, 0.22, 0.18',
  '__UPTIME_RC__',
  '0',
];

describe('check — a degraded section carries no reading, and only a deciding one makes the verdict unknown', () => {
  test('overview with nproc missing: nproc is null, not 0, and the verdict is still false', async () => {
    const stdout = [
      '__NPROC__',
      '__NPROC_RC__',
      '127',
      ...FREE_OK,
      ...DF_OK,
      ...UPTIME_OK,
      '__PSI__',
    ];
    const data = (await drive('check', 'overview', stdout.join('\n'))).data as {
      nproc: number | null;
      degraded: string[];
      dead_end_risk: boolean | null;
    };
    expect(data).toMatchObject({ nproc: null, degraded: ['nproc'], dead_end_risk: false });
  });

  test('check mem with free missing: mem is null and the verdict unknown', async () => {
    const data = (
      await drive('check', 'mem', ['__FREE__', '__FREE_RC__', '127', '__PSI__'].join('\n'))
    ).data as { mem: unknown; dead_end_risk: boolean | null };
    expect({ mem: data.mem, dead_end_risk: data.dead_end_risk }).toEqual({
      mem: null,
      dead_end_risk: null,
    });
  });

  test('the verdict: a known risk wins, an undecided deciding section is null, the rest is false', () => {
    const risk = (diskUsePercents: number[], memSomeAvg10: number | null, degraded: string[]) =>
      computeDeadEndRisk({ diskUsePercents, memSomeAvg10, degraded });
    expect([
      risk([95], null, ['mem']),
      risk([40], 25, ['disk']),
      risk([40], null, ['mem']),
      risk([], null, ['disk']),
      risk([40], null, ['nproc', 'uptime', 'inodes', 'top_du']),
      risk([40], 2, []),
    ]).toEqual([true, true, null, null, false, false]);
  });
});

describe('logs compose — project_dir is a files-allowlist path', () => {
  test('an undeclared project directory is refused before any remote command', async () => {
    const calls: string[][] = [];
    const op = getOp('logs', 'compose');
    if (!op) {
      throw new Error('logs compose missing');
    }
    const envelope = await executeOp(
      op,
      { alias: 'edge-box', args: { project_dir: '/srv/undeclared' } },
      {
        transport: {
          runner: async (args) => {
            calls.push(args);
            return ok(args[0] === '-G' ? 'hostname srv-01.example.net\n' : '');
          },
        },
      },
    );
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(calls.filter((args) => args[0] !== '-G')).toEqual([]);
  });
});
