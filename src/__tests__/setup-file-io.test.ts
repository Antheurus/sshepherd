import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendBlock, readTextOrEmpty, writeTextSecure } from '../setup-file-io.ts';

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'sshepherd-file-io-test-'));
}

describe('readTextOrEmpty', () => {
  test('returns an empty string when the file does not exist', () => {
    const path = join(tempDir(), 'missing.txt');

    expect(readTextOrEmpty(path)).toBe('');
  });

  test('returns the file contents when the file exists', () => {
    const path = join(tempDir(), 'existing.txt');
    writeFileSync(path, 'hello world\n');

    expect(readTextOrEmpty(path)).toBe('hello world\n');
  });
});

describe('writeTextSecure', () => {
  test('creates the parent directory at mode 0o700 and the file at mode 0o600', () => {
    const dir = tempDir();
    const parent = join(dir, 'nested');
    const path = join(parent, 'file.txt');

    writeTextSecure(path, 'content');

    expect(existsSync(path)).toBe(true);
    expect(statSync(parent).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test('overwrites existing content', () => {
    const dir = tempDir();
    const path = join(dir, 'file.txt');
    writeTextSecure(path, 'first');

    writeTextSecure(path, 'second');

    expect(readFileSync(path, 'utf8')).toBe('second');
  });
});

describe('appendBlock', () => {
  test('returns the new block as-is (plus a trailing newline) when existing content is empty', () => {
    expect(appendBlock('', 'a\nb')).toBe('a\nb\n');
  });

  test('appends with exactly one blank-line separator when existing content is non-empty', () => {
    expect(appendBlock('a\nb\n', 'c\nd')).toBe('a\nb\n\nc\nd\n');
  });

  test('strips trailing whitespace off existing content before separating', () => {
    expect(appendBlock('a\nb\n\n\n', 'c')).toBe('a\nb\n\nc\n');
  });
});
