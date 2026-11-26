import { createHash } from 'node:crypto';
import pkg from '../package.json' with { type: 'json' };
import { listOps } from './registry.ts';

export interface BuildStamp {
  sha: string;
  time: string;
  registry: string;
}

/** Injected by `scripts/release.sh` through `bun build --define`; absent in dev and CI builds. */
declare const SSHEPHERD_BUILD_STAMP: BuildStamp | undefined;

export const VERSION: string = pkg.version;

/** First 12 hex chars of sha256 over the sorted `group/name` list — changes exactly when an op is added, removed or renamed. */
export function registryHash(): string {
  const names = listOps()
    .map((op) => `${op.group}/${op.name}`)
    .sort();
  return createHash('sha256').update(names.join('\n')).digest('hex').slice(0, 12);
}

export function versionLine(): string {
  if (typeof SSHEPHERD_BUILD_STAMP === 'undefined') {
    return `sshepherd ${VERSION} (dev, registry ${registryHash()})`;
  }
  const { sha, time, registry } = SSHEPHERD_BUILD_STAMP;
  return `sshepherd ${VERSION} (${sha}, ${time}, registry ${registry})`;
}
