import { beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeOp, getOp } from '../registry.ts';
import type { SshRunner } from '../transport.ts';
import type { OpSpec } from '../types.ts';

const ALIAS = 'trust-host';
const KNOWN_NAME = '[10.0.0.9]:2222';

let dir = '';
let knownHosts = '';
let hostKey = '';
let hostKeyFingerprint = '';
let impostorKey = '';

function sshKeygen(...args: string[]): string {
  const proc = Bun.spawnSync(['ssh-keygen', ...args], { stdout: 'pipe', stderr: 'pipe' });
  return proc.stdout.toString();
}

function makeKey(name: string): string {
  const path = join(dir, name);
  sshKeygen('-q', '-t', 'ed25519', '-N', '', '-f', path);
  return readFileSync(`${path}.pub`, 'utf8').split(' ').slice(0, 2).join(' ');
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sshepherd-hosts-trust-'));
  knownHosts = join(dir, 'known_hosts');
  writeFileSync(join(dir, 'ssh_config'), `Host ${ALIAS}\n  HostName 10.0.0.9\n`);
  hostKey = makeKey('host_key');
  impostorKey = makeKey('impostor_key');
  hostKeyFingerprint = sshKeygen('-lf', join(dir, 'host_key.pub')).split(' ')[1] ?? '';
});

interface Scripted {
  runner: SshRunner;
  calls: string[][];
}

/** `-G` answers with a temp known_hosts (never the user's); the key-fetch call writes the host
 *  key into whatever scratch file it was handed, the way ssh does, then fails authentication. */
function scriptedHost(hashKnownHosts = false): Scripted {
  const calls: string[][] = [];
  const runner: SshRunner = async (args) => {
    calls.push(args);
    if (args[0] === '-G') {
      const stdout = `hostname 10.0.0.9\nport 2222\nuserknownhostsfile ${knownHosts} ${knownHosts}2\nhashknownhosts ${hashKnownHosts ? 'yes' : 'no'}\n`;
      return { code: 0, stdout, stderr: '', timedOut: false };
    }
    const scratch = args.find((arg) => arg.startsWith('UserKnownHostsFile='))?.split('=')[1];
    if (scratch !== undefined) {
      writeFileSync(scratch, `${KNOWN_NAME} ${hostKey}\n`);
    }
    return { code: 255, stdout: '', stderr: 'Permission denied (publickey).', timedOut: false };
  };
  return { runner, calls };
}

function trustOp(): OpSpec {
  const op = getOp('hosts', 'trust');
  if (!op) {
    throw new Error('hosts trust op missing');
  }
  return op;
}

async function trust(args: Record<string, string | boolean>, host: Scripted, yes = true) {
  return executeOp(
    trustOp(),
    { alias: ALIAS, args },
    {
      transport: { runner: host.runner },
      sshConfigPath: join(dir, 'ssh_config'),
      yes,
      auditLogPath: join(dir, 'audit.jsonl'),
    },
  );
}

describe('hosts trust', () => {
  test('--dry-run shows the presented fingerprint (the same one ssh-keygen -l prints) and writes nothing', async () => {
    writeFileSync(knownHosts, '');
    const envelope = await trust({ 'dry-run': true }, scriptedHost(), false);
    expect(envelope.error).toBeNull();
    expect(envelope.data).toEqual({
      fingerprints: [{ type: 'ssh-ed25519', fingerprint: hostKeyFingerprint }],
      written: false,
      replaced_entries: 0,
    });
    expect(readFileSync(knownHosts, 'utf8')).toBe('');
    expect(JSON.stringify(envelope)).not.toContain('10.0.0.9');
  });

  test('the key fetch records only into a scratch file, offers no authentication and skips the ControlMaster', async () => {
    const host = scriptedHost();
    await trust({ 'dry-run': true }, host, false);
    const fetch = host.calls.find((args) => args.includes('PreferredAuthentications=none'));
    expect(fetch).toBeDefined();
    const joined = (fetch ?? []).join(' ');
    expect(joined).toContain('ControlPath=none');
    expect(joined).toContain('GlobalKnownHostsFile=/dev/null');
    expect(joined).not.toContain(`UserKnownHostsFile=${knownHosts}`);
    const scratch = (fetch ?? [])
      .find((arg) => arg.startsWith('UserKnownHostsFile='))
      ?.split('=')[1];
    expect(scratch !== undefined && existsSync(scratch)).toBe(false);
  });

  test('without --yes (and without --dry-run) it is refused before any ssh call', async () => {
    const host = scriptedHost();
    const envelope = await trust({ fingerprint: hostKeyFingerprint }, host, false);
    expect(envelope.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(host.calls).toHaveLength(0);
  });

  test('--yes without --fingerprint is refused and writes nothing', async () => {
    writeFileSync(knownHosts, '');
    const envelope = await trust({}, scriptedHost());
    expect(envelope.error?.code).toBe('VALIDATION_ERROR');
    expect(envelope.error?.next).toBe(`sshepherd hosts trust ${ALIAS} --dry-run`);
    expect(readFileSync(knownHosts, 'utf8')).toBe('');
  });

  test('a fingerprint the host does not present is HOST_KEY_CHANGED and writes nothing', async () => {
    writeFileSync(knownHosts, '');
    const wrong = sshKeygen('-lf', join(dir, 'impostor_key.pub')).split(' ')[1] ?? '';
    const envelope = await trust({ fingerprint: wrong }, scriptedHost());
    expect(envelope.error?.code).toBe('HOST_KEY_CHANGED');
    expect(envelope.error?.message).toContain(hostKeyFingerprint);
    expect(readFileSync(knownHosts, 'utf8')).toBe('');
  });

  test('the matching fingerprint records the key, replacing only this host stale entries (plain and hashed)', async () => {
    const otherHost = `other.example ${impostorKey}`;
    const marker = `@cert-authority *.example ${impostorKey}`;
    writeFileSync(knownHosts, `${otherHost}\n${KNOWN_NAME} ${impostorKey}\n${marker}\n`);
    sshKeygen('-H', '-f', knownHosts);
    writeFileSync(knownHosts, `${readFileSync(knownHosts, 'utf8')}${KNOWN_NAME} ${impostorKey}\n`);

    const envelope = await trust({ fingerprint: hostKeyFingerprint }, scriptedHost());
    expect(envelope.error).toBeNull();
    expect(envelope.data).toMatchObject({ written: true, replaced_entries: 2 });
    const text = readFileSync(knownHosts, 'utf8');
    expect(text).toContain(marker);
    expect(text.endsWith(`${KNOWN_NAME} ${hostKey}\n`)).toBe(true);
    expect(sshKeygen('-F', KNOWN_NAME, '-f', knownHosts)).toContain(hostKey.split(' ')[1] ?? '?');
    expect(sshKeygen('-F', KNOWN_NAME, '-f', knownHosts)).not.toContain(
      impostorKey.split(' ')[1] ?? '?',
    );
    expect(sshKeygen('-F', 'other.example', '-f', knownHosts)).toContain(
      impostorKey.split(' ')[1] ?? '?',
    );
  });

  test('HashKnownHosts yes: the recorded name is hashed and ssh-keygen -F still finds it', async () => {
    writeFileSync(knownHosts, '');
    const envelope = await trust({ fingerprint: hostKeyFingerprint }, scriptedHost(true));
    expect(envelope.error).toBeNull();
    const text = readFileSync(knownHosts, 'utf8');
    expect(text.startsWith('|1|')).toBe(true);
    expect(text).not.toContain('10.0.0.9');
    expect(sshKeygen('-F', KNOWN_NAME, '-f', knownHosts)).toContain(hostKey.split(' ')[1] ?? '?');
  });

  test('a mutating trust writes one audit row', async () => {
    const auditPath = join(dir, 'audit.jsonl');
    writeFileSync(auditPath, '');
    await trust({ fingerprint: hostKeyFingerprint }, scriptedHost());
    const rows = readFileSync(auditPath, 'utf8').trim().split('\n');
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0] ?? '{}')).toMatchObject({ command: 'hosts trust', outcome: 'ok' });
  });
});
