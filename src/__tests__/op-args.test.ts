import { describe, expect, test } from 'bun:test';
import { assertOpPositionals, assertPositional } from '../op-args.ts';
import { executeOp, listOps } from '../registry.ts';
import type { SpawnOutcome, SshRunner } from '../transport.ts';
import { OpError, type OpSpec } from '../types.ts';

const OK_OUTCOME: SpawnOutcome = { code: 0, stdout: '', stderr: '', timedOut: false };

function spyRunner(): { runner: SshRunner; calls: string[][] } {
  const calls: string[][] = [];
  const runner: SshRunner = async (args) => {
    calls.push(args);
    return OK_OUTCOME;
  };
  return { runner, calls };
}

const NAME_POSITIONALS = ['container', 'unit', 'service', 'stream', 'id'];
const PATH_POSITIONALS = ['path', 'remote_path', 'local_path', 'file'];

function opsWithPositional(name: string): OpSpec[] {
  return listOps().filter((op) =>
    op.args.some((spec) => spec.kind === 'positional' && spec.name === name),
  );
}

describe('assertPositional', () => {
  test('a leading dash is refused for every kind of name and path argument', () => {
    for (const name of [...NAME_POSITIONALS, ...PATH_POSITIONALS, 'alias']) {
      for (const value of ['-f', '--x', '-oProxyCommand=evil']) {
        expect(() => assertPositional(name, value)).toThrow(OpError);
      }
    }
  });

  test('ordinary container, unit and path values pass', () => {
    expect(() => assertPositional('container', 'app_web-1')).not.toThrow();
    expect(() => assertPositional('unit', 'user@1000.service')).not.toThrow();
    expect(() => assertPositional('path', '/srv/my app/.env')).not.toThrow();
    expect(() => assertPositional('alias', 'web-01')).not.toThrow();
  });

  test('shell and control characters are outside the allowed set', () => {
    for (const value of ['a;b', 'a b', '$(id)', 'a\nb', 'a`b`']) {
      expect(() => assertPositional('container', value)).toThrow(OpError);
    }
    for (const value of ['/etc/a\nb', '/etc/a\rb', '/etc/a\0b']) {
      expect(() => assertPositional('path', value)).toThrow(OpError);
    }
  });

  test('a path takes any other character: shellJoin quotes it', () => {
    for (const value of [
      '/var/www/My Site (1)/x.txt',
      '/srv/café/a',
      '/srv/a#b/c',
      '/srv/[x]/c',
      "/srv/it's/a;b",
    ]) {
      expect(() => assertPositional('path', value)).not.toThrow();
    }
  });

  test('free-text positionals such as sql are not checked: psql reads them as the value of -c', () => {
    const queryOp = listOps().find((o) => o.group === 'db' && o.name === 'query');
    if (!queryOp) {
      throw new Error('db query op missing');
    }
    expect(() =>
      assertOpPositionals(queryOp, {
        alias: 'web-01',
        args: { target: 'main', sql: '-- note\nSELECT 1' },
      }),
    ).not.toThrow();
  });
});

describe('executeOp refuses an option-shaped positional before any runner call', () => {
  const nameOps = NAME_POSITIONALS.flatMap((name) =>
    opsWithPositional(name).map((op) => ({ op, name })),
  );
  const pathOps = PATH_POSITIONALS.flatMap((name) =>
    opsWithPositional(name).map((op) => ({ op, name })),
  );

  test('the registry has container, unit and path positionals to cover', () => {
    expect(nameOps.length).toBeGreaterThan(0);
    expect(pathOps.length).toBeGreaterThan(0);
  });

  for (const { op, name } of [...nameOps, ...pathOps]) {
    for (const value of ['-f', '--x']) {
      test(`${op.group} ${op.name}: ${name}=${value} -> INVALID_ARGS, runner calls 0`, async () => {
        const { runner, calls } = spyRunner();
        const args: Record<string, string | boolean> = {};
        for (const spec of op.args) {
          if (spec.required) {
            args[spec.name] = 'ok';
          }
        }
        args[name] = value;
        const envelope = await executeOp(
          op,
          { alias: 'web-01', args },
          { transport: { runner }, yes: true, auditLogPath: '/dev/null' },
        );
        expect(envelope.ok).toBe(false);
        expect(envelope.error?.code).toBe('INVALID_ARGS');
        expect(envelope.error?.hint.length).toBeGreaterThan(0);
        expect(calls.length).toBe(0);
      });
    }
  }

  test('an alias that starts with a dash is refused too', async () => {
    const op = listOps().find((o) => o.group === 'hosts' && o.name === 'test');
    if (!op) {
      throw new Error('hosts test op missing');
    }
    const { runner, calls } = spyRunner();
    const envelope = await executeOp(
      op,
      { alias: '-oProxyCommand=evil', args: {} },
      { transport: { runner } },
    );
    expect(envelope.error?.code).toBe('INVALID_ARGS');
    expect(calls.length).toBe(0);
  });
});

describe('remote tools that support it get `--` before the positional', () => {
  const CASES: Array<[string, string, Record<string, string>, string]> = [
    ['services', 'inspect', { container: 'web' }, "'--' 'web'"],
    ['services', 'restart', { container: 'web' }, "'--' 'web'"],
    ['services', 'systemctl-restart', { unit: 'nginx.service' }, "'--' 'nginx.service'"],
    ['files', 'ls', { path: '/srv/app' }, "'--' '/srv/app'"],
    ['files', 'tail', { path: '/srv/app/log' }, "'--' '/srv/app/log'"],
    ['files', 'disk-usage', { path: '/srv/app' }, "'--' '/srv/app'"],
  ];
  for (const [group, name, args, expected] of CASES) {
    test(`${group} ${name}`, () => {
      const op = listOps().find((o) => o.group === group && o.name === name);
      expect(op?.buildRemote({ alias: 'web-01', args })).toContain(expected);
    });
  }
});
