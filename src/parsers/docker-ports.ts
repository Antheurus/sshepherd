/**
 * Docker port mappings, structured — never the raw `"0.0.0.0:8080->80/tcp"` string (see
 * research.md §response envelope). Two source shapes exist depending on which docker
 * subcommand produced the data:
 *  - `docker inspect`'s `NetworkSettings.Ports` is already a JSON object
 *    (`{ "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }] | null }`) — parsed by
 *    `parseInspectPorts`.
 *  - `docker ps` / `docker compose ps` text-shaped `Ports` fields (comma-separated
 *    `"0.0.0.0:8080->80/tcp"` entries) — parsed by `parsePortMappingString`.
 */
export interface PortMapping {
  host_ip: string | null;
  host_port: number | null;
  container_port: number;
  proto: string;
}

function splitContainerPortProto(spec: string): { container_port: number; proto: string } | null {
  const [portRaw, proto] = spec.split('/');
  if (portRaw === undefined || proto === undefined) {
    return null;
  }
  const containerPort = Number.parseInt(portRaw, 10);
  if (Number.isNaN(containerPort)) {
    return null;
  }
  return { container_port: containerPort, proto };
}

export function parseInspectPorts(ports: unknown): PortMapping[] {
  if (typeof ports !== 'object' || ports === null) {
    return [];
  }
  const mappings: PortMapping[] = [];

  for (const [spec, bindings] of Object.entries(ports as Record<string, unknown>)) {
    const parsedSpec = splitContainerPortProto(spec);
    if (!parsedSpec) {
      continue;
    }
    if (!Array.isArray(bindings) || bindings.length === 0) {
      mappings.push({ host_ip: null, host_port: null, ...parsedSpec });
      continue;
    }
    for (const binding of bindings) {
      if (typeof binding !== 'object' || binding === null) {
        continue;
      }
      const record = binding as Record<string, unknown>;
      const hostIp = typeof record.HostIp === 'string' ? record.HostIp : null;
      const hostPortRaw =
        typeof record.HostPort === 'string' ? Number.parseInt(record.HostPort, 10) : Number.NaN;
      mappings.push({
        host_ip: hostIp,
        host_port: Number.isNaN(hostPortRaw) ? null : hostPortRaw,
        ...parsedSpec,
      });
    }
  }

  return mappings;
}

const PORT_MAPPING_STRING_PATTERN = /^(?:([\d.a-fA-F:]+):)?(\d+)->(\d+)\/(\w+)$/;

export function parsePortMappingString(raw: string): PortMapping[] {
  if (raw.trim().length === 0) {
    return [];
  }
  const mappings: PortMapping[] = [];

  for (const entry of raw.split(',').map((part) => part.trim())) {
    const match = PORT_MAPPING_STRING_PATTERN.exec(entry);
    if (!match) {
      continue;
    }
    const [, hostIp, hostPort, containerPort, proto] = match;
    if (hostPort === undefined || containerPort === undefined || proto === undefined) {
      continue;
    }
    mappings.push({
      host_ip: hostIp ?? null,
      host_port: Number.parseInt(hostPort, 10),
      container_port: Number.parseInt(containerPort, 10),
      proto,
    });
  }

  return mappings;
}
