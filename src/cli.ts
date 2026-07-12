const VERSION = '0.1.0';

const arg = Bun.argv[2];

if (arg === '--version' || arg === '-v') {
  console.log(`sshepherd ${VERSION}`);
} else {
  console.log(`sshepherd ${VERSION} — zero-knowledge SSH server-ops CLI (scaffold)`);
}
