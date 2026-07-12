import { describe, expect, test } from 'bun:test';
import { shellJoin, shq } from '../quote.ts';

describe('shq', () => {
  test('wraps a plain value in single quotes', () => {
    expect(shq('hello')).toBe("'hello'");
  });

  test("escapes an embedded single quote as '\\''", () => {
    expect(shq("a'b")).toBe("'a'\\''b'");
  });

  test('blocks command injection via a `;` separator', () => {
    const quoted = shq('; rm -rf /');
    // The whole payload must be inside one quoted token — no unescaped `;` outside quotes
    // that a remote shell could interpret as a command separator.
    expect(quoted).toBe("'; rm -rf /'");
    expect(quoted.startsWith("'")).toBe(true);
    expect(quoted.endsWith("'")).toBe(true);
  });

  test('blocks injection via an embedded single quote plus a follow-on command', () => {
    const quoted = shq("' ; rm -rf / #");
    // Naive `'${value}'` wrapping would let this break out after the first quote;
    // shq must escape the embedded quote so the whole thing stays one literal argument.
    expect(quoted).toBe("''\\'' ; rm -rf / #'");
  });
});

describe('shellJoin', () => {
  test('quotes every part and joins with spaces', () => {
    expect(shellJoin(['docker', 'logs', "a'b"])).toBe("'docker' 'logs' 'a'\\''b'");
  });
});
