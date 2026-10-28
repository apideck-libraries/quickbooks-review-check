import fs from 'node:fs';
import path from 'node:path';
import { classifyFile, isSkippedDir, scanFiles, MAX_BYTES } from './scan-core.js';

export { LINE_RULES, scanFiles } from './scan-core.js';

function walk(dir, root, files) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!isSkippedDir(e.name)) walk(full, root, files);
    } else if (e.isFile()) {
      const kind = classifyFile(e.name);
      if (kind) files.push({ full, rel: path.relative(root, full), kind });
    }
  }
}

export function scanSource(root, opts = {}) {
  const abs = path.resolve(root);
  const found = [];
  walk(abs, abs, found);
  const files = [];
  for (const f of found) {
    try {
      if (fs.statSync(f.full).size > MAX_BYTES) continue;
      files.push({ rel: f.rel, kind: f.kind, text: fs.readFileSync(f.full, 'utf8') });
    } catch {
      // unreadable file; skip
    }
  }
  return { root: abs, ...scanFiles(files, opts) };
}
