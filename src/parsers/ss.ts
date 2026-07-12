/**
 * Parses `ss -H -tlnp` (`-H` suppresses the header; `-tlnp` = TCP, listening, numeric,
 * with process). `ss -j` (native JSON) is not available on every iproute2 build still in
 * the field, so this hand-written parser is the portable choice (documented in
 * registry.ts next to the `check ports` op).
 * Example line: `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))`
 */
export interface ListeningPort {
  proto: 'tcp';
  local_address: string;
  local_port: number;
  process: string | null;
  pid: number | null;
}

const PROCESS_PATTERN = /users:\(\("([^"]+)",pid=(\d+)/;

/** Splits `"0.0.0.0:22"` / `"[::]:22"` on the LAST colon — IPv6 addresses contain colons. */
function splitAddressPort(value: string): { address: string; port: number } | null {
  const lastColon = value.lastIndexOf(':');
  if (lastColon === -1) {
    return null;
  }
  const address = value.slice(0, lastColon);
  const port = Number.parseInt(value.slice(lastColon + 1), 10);
  if (Number.isNaN(port)) {
    return null;
  }
  return { address, port };
}

export function parseSs(stdout: string): ListeningPort[] {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const ports: ListeningPort[] = [];

  for (const line of lines) {
    const fields = line.split(/\s+/);
    const localAddressField = fields[3];
    if (fields[0] !== 'LISTEN' || localAddressField === undefined) {
      continue;
    }
    const localAddressPort = splitAddressPort(localAddressField);
    if (!localAddressPort) {
      continue;
    }
    const processMatch = PROCESS_PATTERN.exec(line);
    const process = processMatch?.[1] ?? null;
    const pid = processMatch?.[2] !== undefined ? Number.parseInt(processMatch[2], 10) : null;
    ports.push({
      proto: 'tcp',
      local_address: localAddressPort.address,
      local_port: localAddressPort.port,
      process,
      pid,
    });
  }

  return ports;
}
