import { arg, DEFAULT_TIMEOUT_SEC } from '../op-args.ts';
import {
  closeTunnel,
  DEFAULT_DURATION_SEC,
  listTunnels,
  MAX_DURATION_SEC,
  openTunnel,
  type TunnelKind,
} from '../tunnel.ts';
import { OpRunLocalError, type OpSpec } from '../types.ts';

// ---------------------------------------------------------------------------
// tunnel
// ---------------------------------------------------------------------------

interface TunnelOpenResult {
  id: string;
  alias: string;
  kind: TunnelKind;
  localPort: number | null;
  remoteTarget: string | null;
  localTarget: string | null;
  expiresAt: string;
}

const tunnelOpen: OpSpec<TunnelOpenResult> = {
  group: 'tunnel',
  name: 'open',
  summary: 'Open a local/remote/dynamic SSH port forward that self-closes after --duration.',
  args: [
    arg('kind', 'flag', true, "Forward kind: 'local', 'remote', or 'dynamic'."),
    arg(
      'remote',
      'flag',
      false,
      "Required for kind=local (forward target 'host:port') and kind=remote (bind spec 'host:port' on the alias's own network).",
    ),
    arg(
      'local',
      'flag',
      false,
      "Required for kind=remote only: 'host:port' on the operator's machine being exposed.",
    ),
    arg(
      'duration',
      'flag',
      false,
      `Tunnel lifetime in seconds before it self-closes (default ${DEFAULT_DURATION_SEC}, max ${MAX_DURATION_SEC}).`,
    ),
  ],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelOpenResult,
  runLocal: (ctx, sshConfigPath) => {
    const kind = ctx.args.kind as TunnelKind;
    const durationSec =
      typeof ctx.args.duration === 'string' ? Number(ctx.args.duration) : DEFAULT_DURATION_SEC;
    // A non-numeric --duration parses to NaN, which slips past validateOpenParams's
    // range check (every comparison against NaN is false) and only surfaces as a cryptic
    // `RangeError: Invalid Date` after openTunnel has already spawned the supervisor.
    if (!Number.isFinite(durationSec)) {
      throw new OpRunLocalError(
        'VALIDATION_ERROR',
        `--duration must be a number, got '${ctx.args.duration}'`,
      );
    }
    const record = openTunnel(
      {
        alias: ctx.alias,
        kind,
        remote: typeof ctx.args.remote === 'string' ? ctx.args.remote : undefined,
        local: typeof ctx.args.local === 'string' ? ctx.args.local : undefined,
        durationSec,
      },
      sshConfigPath,
    );
    return {
      id: record.id,
      alias: record.alias,
      kind: record.kind,
      localPort: record.localPort,
      remoteTarget: record.remoteTarget,
      localTarget: record.localTarget,
      expiresAt: record.expiresAt,
    };
  },
};

interface TunnelListResult {
  tunnels: ReturnType<typeof listTunnels>;
}

const tunnelList: OpSpec<TunnelListResult> = {
  group: 'tunnel',
  name: 'list',
  summary:
    'List this operator’s active tunnels (alias, kind, port, remaining lifetime). NOTE: this op is host-local but NOT side-effect-free — it prunes dead tunnel records and force-kills any tunnel past its expiry, per tunnel.ts’s listTunnels() doc comment.',
  args: [],
  mutating: false,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelListResult,
  runLocal: () => ({ tunnels: listTunnels() }),
};

interface TunnelCloseResultShape {
  id: string;
  closed: boolean;
}

const tunnelClose: OpSpec<TunnelCloseResultShape> = {
  group: 'tunnel',
  name: 'close',
  summary: 'Close an open tunnel by id (idempotent — an already-gone id still succeeds).',
  args: [arg('id', 'positional', true, "Tunnel id, as returned by 'tunnel open'.")],
  mutating: true,
  timeoutSec: DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  shape: (parsed) => parsed as TunnelCloseResultShape,
  runLocal: (ctx) => closeTunnel(ctx.args.id as string),
};

export const tunnelOps = [tunnelOpen, tunnelList, tunnelClose] as OpSpec[];
