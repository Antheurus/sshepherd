/**
 * Parses `cat /proc/pressure/memory` (Linux PSI, kernel 4.20+). No native JSON flag
 * exists — hand-written parser. Format:
 * `some avg10=0.00 avg60=0.00 avg300=0.00 total=0` / `full avg10=... avg60=... avg300=... total=...`
 * Returns `null` when the file is empty/unavailable (older kernels, some containers).
 */
export interface PsiSnapshot {
  some_avg10: number;
  some_avg60: number;
  some_avg300: number;
  full_avg10: number;
  full_avg60: number;
  full_avg300: number;
}

function parseRow(line: string): { avg10: number; avg60: number; avg300: number } | null {
  const avg10 = /avg10=([\d.]+)/.exec(line)?.[1];
  const avg60 = /avg60=([\d.]+)/.exec(line)?.[1];
  const avg300 = /avg300=([\d.]+)/.exec(line)?.[1];
  if (avg10 === undefined || avg60 === undefined || avg300 === undefined) {
    return null;
  }
  return {
    avg10: Number.parseFloat(avg10),
    avg60: Number.parseFloat(avg60),
    avg300: Number.parseFloat(avg300),
  };
}

export function parsePsi(stdout: string): PsiSnapshot | null {
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const someLine = lines.find((line) => line.startsWith('some '));
  const fullLine = lines.find((line) => line.startsWith('full '));
  if (!someLine || !fullLine) {
    return null;
  }
  const some = parseRow(someLine);
  const full = parseRow(fullLine);
  if (!some || !full) {
    return null;
  }
  return {
    some_avg10: some.avg10,
    some_avg60: some.avg60,
    some_avg300: some.avg300,
    full_avg10: full.avg10,
    full_avg60: full.avg60,
    full_avg300: full.avg300,
  };
}
