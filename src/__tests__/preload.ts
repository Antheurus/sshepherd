import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Every test run writes its audit rows into a throwaway state dir, never the real log.
process.env.SSHEPHERD_STATE_DIR = mkdtempSync(join(tmpdir(), 'sshepherd-test-state-'));
