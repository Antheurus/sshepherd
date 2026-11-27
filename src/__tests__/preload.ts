import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Every test run writes its audit rows and reads its allowlists from a throwaway directory,
// never the machine's real log or ~/.config/sshepherd. The allowlist files are not created: a
// missing file is an empty allowlist, and a test that needs one points its own path at a file.
const isolated = mkdtempSync(join(tmpdir(), 'sshepherd-test-state-'));
process.env.SSHEPHERD_STATE_DIR = isolated;
process.env.SSHEPHERD_REVEAL_ALLOWLIST_PATH = join(isolated, 'reveal-allowlist.toml');
process.env.SSHEPHERD_FILES_ALLOWLIST_PATH = join(isolated, 'files-allowlist.toml');
process.env.SSHEPHERD_CONFIG_ALLOWLIST_PATH = join(isolated, 'config-allowlist.toml');
process.env.SSHEPHERD_EXEC_DIR = join(isolated, 'exec');
