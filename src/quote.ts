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
