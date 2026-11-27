import { OpError } from './types.ts';

/**
 * The single remote-shell quoting function. Every value interpolated into a remote
 * command string must go through `shq` — this is the only defense against a value
 * (a filename, an arg, a query) breaking out of its argument boundary on the remote
 * shell.
 */
export function shq(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function shellJoin(parts: string[]): string {
  return parts.map(shq).join(' ');
}

/** `shellJoin` for an argv that must reach the remote program exactly as written (`exec`): a NUL
 *  cannot cross a command line — the program would see that element cut short — so it is refused
 *  instead of silently truncated. */
export function shellJoinExact(parts: string[]): string {
  if (parts.some((part) => part.includes('\0'))) {
    throw new OpError(
      'INVALID_ARGS',
      'an argv element contains a NUL, which no command line carries',
      {
        hint: 'Remove the NUL character from the value or the definition.',
      },
    );
  }
  return shellJoin(parts);
}
