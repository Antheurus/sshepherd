/**
 * Parses the marker-delimited `fail2ban-client status` bundle `security fail2ban`
 * (registry.ts) builds on the remote: `__UNAVAILABLE__` as the whole output when the
 * binary is missing, else one `__JAIL__:<name>` marker per jail followed by that jail's
 * `fail2ban-client status <jail>` text block. No native JSON flag exists for
 * fail2ban-client, so this is a hand-written parser (same convention as ss.ts/sysctl.ts).
 */
export interface Fail2banJailStatus {
  jail: string;
  currently_banned: number | null;
  total_banned: number | null;
  banned_ips: string[];
}

export interface Fail2banResult {
  available: boolean;
  reason: string | null;
  jails: Fail2banJailStatus[];
}

const JAIL_MARKER = /^__JAIL__:(.+)$/;

function parseJailBlock(jail: string, lines: string[]): Fail2banJailStatus {
  let currentlyBanned: number | null = null;
  let totalBanned: number | null = null;
  let bannedIps: string[] = [];

  for (const line of lines) {
    const currently = /Currently banned:\s*(\d+)/.exec(line);
    if (currently?.[1] !== undefined) {
      currentlyBanned = Number.parseInt(currently[1], 10);
      continue;
    }
    const total = /Total banned:\s*(\d+)/.exec(line);
    if (total?.[1] !== undefined) {
      totalBanned = Number.parseInt(total[1], 10);
      continue;
    }
    const ips = /Banned IP list:\s*(.*)$/.exec(line);
    if (ips?.[1] !== undefined) {
      bannedIps = ips[1]
        .trim()
        .split(/\s+/)
        .filter((ip) => ip.length > 0);
    }
  }

  return {
    jail,
    currently_banned: currentlyBanned,
    total_banned: totalBanned,
    banned_ips: bannedIps,
  };
}

export function parseFail2banStatus(stdout: string): Fail2banResult {
  const lines = stdout.split('\n').map((line) => line.trim());
  if (lines[0] === '__UNAVAILABLE__') {
    return { available: false, reason: 'fail2ban-client not installed', jails: [] };
  }

  const jails: Fail2banJailStatus[] = [];
  let currentJail: string | null = null;
  let buffer: string[] = [];

  const flush = (): void => {
    if (currentJail !== null) {
      jails.push(parseJailBlock(currentJail, buffer));
    }
    buffer = [];
  };

  for (const line of lines) {
    const marker = JAIL_MARKER.exec(line);
    if (marker) {
      flush();
      currentJail = marker[1] ?? null;
      continue;
    }
    if (currentJail !== null) {
      buffer.push(line);
    }
  }
  flush();

  return { available: true, reason: null, jails };
}
