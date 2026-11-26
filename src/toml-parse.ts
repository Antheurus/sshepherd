import { OpError } from './types.ts';

/** Bun's TOML parser throws a BuildMessage, not an Error: its `message` and `position.line`
 *  name the problem; `position.lineText` is never copied, since a config line can hold a secret.
 *  `label` names the file kind in the message ("targets.toml", "files-allowlist.toml", "recipe 'x'"). */
export function parseTomlFile(text: string, label: string, hint: string): Record<string, unknown> {
  try {
    return Bun.TOML.parse(text) as Record<string, unknown>;
  } catch (err) {
    const record = typeof err === 'object' && err !== null ? (err as Record<string, unknown>) : {};
    const reason = typeof record.message === 'string' ? record.message : 'invalid TOML';
    const position =
      typeof record.position === 'object' && record.position !== null
        ? (record.position as Record<string, unknown>)
        : {};
    const line = typeof position.line === 'number' ? ` at line ${position.line}` : '';
    throw new OpError('CONFIG_PARSE_ERROR', `${label} is not valid TOML${line}: ${reason}`, {
      hint,
    });
  }
}
