import { HEAVY_NICE_LEVEL } from './limits.ts';
import { shellJoin } from './quote.ts';

/** Runs `$1` under `nice` and, where the host allows it, `ionice -c3`. Each tool is probed first:
 *  busybox may lack `ionice`, and a container without the capability refuses `ionice` outright,
 *  which would otherwise fail the whole command instead of just running it un-niced. */
const NICE_SCRIPT = [
  'cmd="$1"',
  'if command -v nice >/dev/null 2>&1; then',
  '  if command -v ionice >/dev/null 2>&1 && ionice -c3 true >/dev/null 2>&1; then',
  `    exec nice -n ${HEAVY_NICE_LEVEL} ionice -c3 sh -c "$cmd"`,
  '  fi',
  `  exec nice -n ${HEAVY_NICE_LEVEL} sh -c "$cmd"`,
  'fi',
  'exec sh -c "$cmd"',
].join('\n');

/** Wraps a remote command line so it runs at low CPU and I/O priority; exit status and output are
 *  the command's own. Every `check *` and `logs *` op builds its command through this. */
export function niced(command: string): string {
  return shellJoin(['sh', '-c', NICE_SCRIPT, 'sh', command]);
}
