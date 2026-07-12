/**
 * Docker's human-readable size strings (`docker stats`, `docker system df`) use IEC
 * binary units (KiB/MiB/GiB/TiB) with a `go-units`-style single-letter fallback (K/M/G).
 * This is the one place that converts those strings back to bytes so every caller
 * (services stats today, anything else later) shares one conversion table.
 */
const UNIT_MULTIPLIERS: Record<string, number> = {
  B: 1,
  KB: 1000,
  KIB: 1024,
  K: 1024,
  MB: 1000 ** 2,
  MIB: 1024 ** 2,
  M: 1024 ** 2,
  GB: 1000 ** 3,
  GIB: 1024 ** 3,
  G: 1024 ** 3,
  TB: 1000 ** 4,
  TIB: 1024 ** 4,
  T: 1024 ** 4,
};

/** Parses `"20.5MiB"` / `"1.945GB"` / `"512B"` into an integer byte count. */
export function parseHumanBytes(value: string): number | null {
  const trimmed = value.trim();
  const match = /^([\d.]+)\s*([A-Za-z]+)?$/.exec(trimmed);
  if (!match) {
    return null;
  }
  const amount = Number.parseFloat(match[1] ?? '');
  if (Number.isNaN(amount)) {
    return null;
  }
  const unitToken = (match[2] ?? 'B').toUpperCase();
  const multiplier = UNIT_MULTIPLIERS[unitToken];
  if (multiplier === undefined) {
    return null;
  }
  return Math.round(amount * multiplier);
}

/** Parses `"20.5MiB / 1.945GiB"` into `{ used_bytes, limit_bytes }`. */
export function parseHumanBytesPair(value: string): {
  used_bytes: number | null;
  limit_bytes: number | null;
} {
  const [usedRaw, limitRaw] = value.split('/').map((part) => part.trim());
  return {
    used_bytes: usedRaw !== undefined ? parseHumanBytes(usedRaw) : null,
    limit_bytes: limitRaw !== undefined ? parseHumanBytes(limitRaw) : null,
  };
}

/** Parses a trailing-`%` string (`"12.34%"`) into a number, or null if unparseable. */
export function parsePercent(value: string): number | null {
  const match = /^([\d.]+)%$/.exec(value.trim());
  if (!match) {
    return null;
  }
  const parsed = Number.parseFloat(match[1] ?? '');
  return Number.isNaN(parsed) ? null : parsed;
}
