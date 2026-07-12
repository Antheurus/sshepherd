import { parseSysctl } from './sysctl.ts';

/**
 * Parses `systemctl show <unit> --property=...` (`Key=Value` per line, no spaces around
 * `=`). Deliberately NOT `systemctl show -o json`: that JSON output flag is inconsistent
 * across systemd versions still deployed in the field (e.g. Ubuntu 20.04 ships systemd
 * 245, which predates it), while `--property=`-scoped key/value output is guaranteed on
 * every systemd release. Reuses `parseSysctl`'s `key = value` / `key=value` line splitter
 * — same shape, different command.
 */
export interface SystemctlStatus {
  active_state: string | null;
  sub_state: string | null;
  load_state: string | null;
  unit_file_state: string | null;
  main_pid: number | null;
  n_restarts: number | null;
  result: string | null;
}

export function parseSystemctlShow(stdout: string): SystemctlStatus {
  const fields = parseSysctl(stdout);
  const mainPid = fields.MainPID !== undefined ? Number.parseInt(fields.MainPID, 10) : Number.NaN;
  const nRestarts =
    fields.NRestarts !== undefined ? Number.parseInt(fields.NRestarts, 10) : Number.NaN;

  return {
    active_state: fields.ActiveState ?? null,
    sub_state: fields.SubState ?? null,
    load_state: fields.LoadState ?? null,
    unit_file_state: fields.UnitFileState ?? null,
    main_pid: Number.isNaN(mainPid) ? null : mainPid,
    n_restarts: Number.isNaN(nRestarts) ? null : nRestarts,
    result: fields.Result ?? null,
  };
}
