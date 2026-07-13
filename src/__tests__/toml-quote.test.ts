import { describe, expect, test } from 'bun:test';
import { tomlQuote } from '../toml-quote.ts';

describe('tomlQuote', () => {
  test('wraps a plain value in double quotes with no escaping needed', () => {
    expect(tomlQuote('hello')).toBe('"hello"');
  });

  test('escapes an embedded double quote', () => {
    expect(tomlQuote('my"alias')).toBe('"my\\"alias"');
  });

  test('escapes an embedded backslash', () => {
    expect(tomlQuote('C:\\path')).toBe('"C:\\\\path"');
  });

  test('escapes both a quote and a backslash in the same value', () => {
    expect(tomlQuote('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  test('round-trips a double-quote-containing value through the real Bun.TOML.parse', () => {
    const value = 'my"alias';
    const toml = `alias = ${tomlQuote(value)}\n`;

    const parsed = Bun.TOML.parse(toml) as Record<string, unknown>;

    expect(parsed.alias).toBe(value);
  });

  test('round-trips a backslash-containing value through the real Bun.TOML.parse', () => {
    const value = 'C:\\Users\\deploy';
    const toml = `workdir = ${tomlQuote(value)}\n`;

    const parsed = Bun.TOML.parse(toml) as Record<string, unknown>;

    expect(parsed.workdir).toBe(value);
  });

  test('round-trips a value containing both a quote and a backslash', () => {
    const value = 'weird\\"value';
    const toml = `alias = ${tomlQuote(value)}\n`;

    const parsed = Bun.TOML.parse(toml) as Record<string, unknown>;

    expect(parsed.alias).toBe(value);
  });
});
