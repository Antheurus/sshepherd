/**
 * Escapes and quotes a string for use as a TOML basic string literal (`"..."`). Every
 * user-supplied value interpolated into a generated TOML file by `setup`'s scaffolders must
 * go through this — an unescaped `"` or `\` in an alias/user/path corrupts the surrounding
 * table line (e.g. `alias = "my"alias"`), which then throws an unhandled TOML parse error on
 * the next `db list`/`deploy run`/etc. read of that file. Mirrors `shq` in `quote.ts`: takes
 * the raw value, returns the fully quoted+escaped literal ready to interpolate directly.
 *
 * TOML basic strings require `"` and `\` to be escaped, plus every control character except
 * tab (which TOML allows literally); tab is intentionally left unescaped rather than emitted
 * as `\t`, working around a Bun.TOML.parse bug where `\t` is misparsed as `\f`.
 */
export function tomlQuote(value: string): string {
  let escaped = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    switch (char) {
      case '\\':
        escaped += '\\\\';
        break;
      case '"':
        escaped += '\\"';
        break;
      case '\n':
        escaped += '\\n';
        break;
      case '\r':
        escaped += '\\r';
        break;
      case '\b':
        escaped += '\\b';
        break;
      case '\f':
        escaped += '\\f';
        break;
      default:
        // Tab (0x09) is allowed literally in a TOML basic string; every other control
        // character (0x00-0x08, 0x0a-0x1f, 0x7f) must be escaped or it would break the
        // single-line basic string.
        escaped +=
          (code <= 0x1f && code !== 0x09) || code === 0x7f
            ? `\\u${code.toString(16).padStart(4, '0')}`
            : char;
    }
  }
  return `"${escaped}"`;
}
