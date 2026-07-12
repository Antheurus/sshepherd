/**
 * Parses one `authorized_keys`-format line into its options/type/comment, WITHOUT ever
 * returning the key-data blob itself — `security authorized-keys` (registry.ts) pairs
 * this with a remote `ssh-keygen -lf` fingerprint computed on the same file, index-aligned
 * line by line, so the raw public key never needs to leave the parsed structure.
 * Line shape: `[options] keytype base64key [comment]` (RFC 4716 / sshd AUTHORIZED_KEYS FILE FORMAT).
 */
const KEY_TYPE_PATTERN =
  /^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/;

export interface AuthorizedKeysLine {
  options: string | null;
  type: string;
  comment: string | null;
}

export function parseAuthorizedKeysLine(line: string): AuthorizedKeysLine | null {
  const trimmed = line.trim();
  if (trimmed.length === 0 || trimmed.startsWith('#')) {
    return null;
  }
  const tokens = trimmed.split(/\s+/);
  const typeIndex = tokens.findIndex((token) => KEY_TYPE_PATTERN.test(token));
  if (typeIndex === -1) {
    return null;
  }
  const options = typeIndex > 0 ? tokens.slice(0, typeIndex).join(' ') : null;
  const type = tokens[typeIndex] ?? '';
  const comment = tokens.slice(typeIndex + 2).join(' ');
  return { options, type, comment: comment.length > 0 ? comment : null };
}

/** Extracts the `SHA256:...` token from one `ssh-keygen -lf` output line. */
export function parseFingerprintLine(line: string): string | null {
  const match = /(SHA256:\S+)/.exec(line);
  return match?.[1] ?? null;
}
