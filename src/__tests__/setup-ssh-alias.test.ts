import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { listHostAliases } from '../parsers/ssh-config.ts';
import { keygen, register, remove } from '../setup-ssh-alias.ts';

function tempConfigPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sshepherd-ssh-alias-test-'));
  return join(dir, 'config');
}

describe('register', () => {
  test('appends a marked stanza with Host/HostName/User/Port', () => {
    const configPath = tempConfigPath();
    const result = register(
      'myserver',
      { host: '1.2.3.4', user: 'deploy', port: 2222, yes: true },
      configPath,
    );

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'myserver', host: '1.2.3.4', user: 'deploy', port: 2222 });

    const lines = readFileSync(configPath, 'utf8').split('\n');
    expect(lines[0]).toBe('# sshepherd-managed: myserver');
    expect(lines[1]).toBe('Host myserver');
    expect(lines[2]).toBe('    HostName 1.2.3.4');
    expect(lines[3]).toBe('    User deploy');
    expect(lines[4]).toBe('    Port 2222');
  });

  test('omits the Port line when port is the default 22', () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const text = readFileSync(configPath, 'utf8');
    expect(text).not.toContain('Port');
  });

  test('fails with ALIAS_EXISTS for a hand-written alias of the same name, no --overwrite', () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      ['Host myserver', '    HostName 9.9.9.9', '    User root', ''].join('\n'),
    );

    const result = register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_EXISTS');
    expect(readFileSync(configPath, 'utf8')).toContain('9.9.9.9');
  });

  test('fails with ALIAS_EXISTS for a hand-written alias even WITH --overwrite (never touches unmanaged entries)', () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      ['Host myserver', '    HostName 9.9.9.9', '    User root', ''].join('\n'),
    );

    const result = register(
      'myserver',
      { host: '1.2.3.4', user: 'deploy', overwrite: true, yes: true },
      configPath,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_EXISTS');
    expect(readFileSync(configPath, 'utf8')).toContain('9.9.9.9');
  });

  test('fails with ALIAS_EXISTS for a setup-managed alias without --overwrite', () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = register('myserver', { host: '5.6.7.8', user: 'ops', yes: true }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_EXISTS');
  });

  test('--overwrite cleanly replaces a setup-managed alias', () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = register(
      'myserver',
      { host: '5.6.7.8', user: 'ops', overwrite: true, yes: true },
      configPath,
    );

    expect(result.ok).toBe(true);
    const text = readFileSync(configPath, 'utf8');
    expect(text).toContain('5.6.7.8');
    expect(text).not.toContain('1.2.3.4');
    expect((text.match(/# sshepherd-managed: myserver/g) ?? []).length).toBe(1);
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no file touched', () => {
    const configPath = tempConfigPath();
    const result = register(
      'myserver',
      { host: '1.2.3.4', user: 'deploy', yes: false },
      configPath,
    );

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(existsSync(configPath)).toBe(false);
  });

  test('hosts list (real listHostAliases) enumerates a setup-registered alias', () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    expect(listHostAliases(configPath)).toEqual(['myserver']);
  });

  test('a setup-registered alias coexists with a pre-existing hand-written alias in hosts list', () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      ['Host handwritten', '    HostName 9.9.9.9', '    User root', ''].join('\n'),
    );
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    expect(listHostAliases(configPath).sort()).toEqual(['handwritten', 'myserver']);
  });
});

describe('keygen', () => {
  test('fails with ALIAS_NOT_FOUND on an unregistered alias, no file written', async () => {
    const configPath = tempConfigPath();

    const result = await keygen('myserver', { yes: true }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_NOT_FOUND');
    expect(existsSync(configPath)).toBe(false);
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = await keygen('myserver', { yes: false }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
  });

  test('creates a passphrase-less ed25519 keypair and updates IdentityFile in place', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = await keygen('myserver', { yes: true }, configPath);

    expect(result.ok).toBe(true);
    const expectedKeyPath = join(join(configPath, '..'), 'sshepherd_myserver_ed25519');
    expect(result.data).toEqual({
      alias: 'myserver',
      privateKeyPath: expectedKeyPath,
      publicKeyPath: `${expectedKeyPath}.pub`,
    });
    expect(existsSync(expectedKeyPath)).toBe(true);
    expect(existsSync(`${expectedKeyPath}.pub`)).toBe(true);

    const privateKey = readFileSync(expectedKeyPath, 'utf8');
    expect(privateKey).toContain('PRIVATE KEY');
    expect(privateKey).not.toContain('ENCRYPTED');

    const text = readFileSync(configPath, 'utf8');
    expect(text).toContain(`    IdentityFile ${expectedKeyPath}`);
  }, 15_000);
});

describe('remove', () => {
  test('fails with ALIAS_NOT_FOUND when no managed stanza exists', async () => {
    const configPath = tempConfigPath();

    const result = await remove('myserver', { yes: true }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('ALIAS_NOT_FOUND');
  });

  test('fails with CONFIRMATION_REQUIRED when --yes is omitted, no file touched', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    const before = readFileSync(configPath, 'utf8');

    const result = await remove('myserver', { yes: false }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('CONFIRMATION_REQUIRED');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  });

  test('removes only the managed stanza; a hand-written stanza with the same name survives', async () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      ['Host myserver', '    HostName 9.9.9.9', '    User root', ''].join('\n'),
    );
    register('otheralias', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);

    const result = await remove('otheralias', { yes: true }, configPath);

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'otheralias', configRemoved: true, keyRemoved: false });
    const text = readFileSync(configPath, 'utf8');
    expect(text).toContain('Host myserver');
    expect(text).toContain('9.9.9.9');
    expect(text).not.toContain('otheralias');
  });

  test('deletes the matching generated keypair when one exists', async () => {
    const configPath = tempConfigPath();
    register('myserver', { host: '1.2.3.4', user: 'deploy', yes: true }, configPath);
    await keygen('myserver', { yes: true }, configPath);
    const keyPath = join(join(configPath, '..'), 'sshepherd_myserver_ed25519');
    expect(existsSync(keyPath)).toBe(true);

    const result = await remove('myserver', { yes: true }, configPath);

    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ alias: 'myserver', configRemoved: true, keyRemoved: true });
    expect(existsSync(keyPath)).toBe(false);
    expect(existsSync(`${keyPath}.pub`)).toBe(false);
    expect(listHostAliases(configPath)).toEqual([]);
  }, 15_000);

  test('fails with PARSE_MISMATCH rather than guessing when the marker is malformed', async () => {
    const configPath = tempConfigPath();
    writeFileSync(
      configPath,
      ['# sshepherd-managed: myserver', 'Host something-else', '    HostName 1.2.3.4', ''].join(
        '\n',
      ),
    );
    const before = readFileSync(configPath, 'utf8');

    const result = await remove('myserver', { yes: true }, configPath);

    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('PARSE_MISMATCH');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  });
});
