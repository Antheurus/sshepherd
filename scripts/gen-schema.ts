import { mkdirSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateSchemas } from '../src/schema.ts';

const ROOT = join(import.meta.dir, '..');
const OUT_DIR = join(ROOT, 'docs', 'schema');
const FIXTURE_DIRS = ['debian', 'alpine'].map((variant) =>
  join(ROOT, 'src', '__tests__', 'fixtures', 'live', variant),
);

const files = generateSchemas(FIXTURE_DIRS);
mkdirSync(OUT_DIR, { recursive: true });
for (const [name, text] of files) {
  writeFileSync(join(OUT_DIR, name), text);
}
for (const name of readdirSync(OUT_DIR)) {
  if (name.endsWith('.json') && !files.has(name)) {
    unlinkSync(join(OUT_DIR, name));
  }
}
console.log(`gen-schema: wrote ${files.size} files to ${OUT_DIR}`);
