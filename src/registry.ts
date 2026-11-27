import { auditOps } from './ops/audit.ts';
import { checkOps } from './ops/check.ts';
import { configOps } from './ops/config.ts';
import { dbOps } from './ops/db.ts';
import { deployOps } from './ops/deploy.ts';
import { envOps } from './ops/env.ts';
import { filesOps } from './ops/files.ts';
import { hostsOps } from './ops/hosts.ts';
import { logsOps } from './ops/logs.ts';
import { securityOps } from './ops/security.ts';
import { servicesOps } from './ops/services.ts';
import { tunnelOps } from './ops/tunnel.ts';
import type { OpSpec } from './types.ts';

const REGISTRY: OpSpec[] = [
  ...hostsOps,
  ...checkOps,
  ...logsOps,
  ...servicesOps,
  ...filesOps,
  ...envOps,
  ...configOps,
  ...dbOps,
  ...deployOps,
  ...securityOps,
  ...tunnelOps,
  ...auditOps,
];

export function getOp(group: string, name: string): OpSpec | undefined {
  return REGISTRY.find((op) => op.group === group && op.name === name);
}

export function listOps(): OpSpec[] {
  return REGISTRY;
}

export { type ExecuteDeps, executeOp } from './execute.ts';
// Re-exported for parser unit tests and future CLI --help rendering.
// Re-exported for setup config-allowlist/files-allowlist/reveal-allowlist scaffolding and
// their round-trip tests (mirrors targets.ts's exported loadTargets/defaultTargetsPath —
// see setup-config-allowlist.ts, setup-files-allowlist.ts, setup-reveal-allowlist.ts).
export {
  assertPathAllowed,
  assertRevealKeysAllowed,
  defaultConfigAllowlistPath,
  defaultFilesAllowlistPath,
  defaultRevealAllowlistPath,
  enforceAllowlist,
  loadConfigAllowlist,
  loadFilesAllowlist,
  loadPathAllowlist,
  loadRevealAllowlist,
  REVEAL_DENYLIST_PATTERNS,
} from './ops/config.ts';
export { runDoctor, runDoctorHosts } from './ops/doctor.ts';
export { parseHumanBytes } from './parsers/bytes.ts';
