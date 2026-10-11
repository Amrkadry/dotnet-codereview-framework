'use strict';
// One-shot: add author headers to every script/data file, idempotent.
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
const TAG = 'Author: Amr Kadry (github.com/Amrkadry)';

function walk(dir, exts, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (/node_modules|\.git|\.tools-bin|\.moraa-review|Scratch/.test(e.name)) continue;
      walk(p, exts, out);
    } else if (exts.includes(path.extname(e.name).toLowerCase())) out.push(p);
  }
  return out;
}

let tagged = 0, skipped = 0;
for (const f of walk(ROOT, ['.js', '.ps1', '.sh'])) {
  const rel = path.relative(ROOT, f).replace(/\\/g, '/');
  let s = fs.readFileSync(f, 'utf8');
  if (s.includes(TAG)) { skipped++; continue; }
  const nl = s.includes('\r\n') ? '\r\n' : '\n';
  const header = `// dotnet-codereview-framework — ${rel}${nl}// ${TAG} · MIT License${nl}`;
  if (s.startsWith('#!')) {
    // keep shebang first
    const nlPos = s.indexOf('\n');
    s = s.slice(0, nlPos + 1) + header + s.slice(nlPos + 1);
  } else {
    s = header + s;
  }
  fs.writeFileSync(f, s);
  tagged++;
}
console.log(`tagged ${tagged} script files, skipped ${skipped} already-tagged`);

// catalog JSONs: author key first
for (const f of fs.readdirSync(path.join(ROOT, 'catalog')).filter(x => x.endsWith('.json'))) {
  const p = path.join(ROOT, 'catalog', f);
  const raw = fs.readFileSync(p, 'utf8');
  if (raw.includes('"author"')) { skipped++; continue; }
  const obj = JSON.parse(raw);
  const withAuthor = { author: 'Amr Kadry (github.com/Amrkadry)', ...obj };
  fs.writeFileSync(p, JSON.stringify(withAuthor, null, 1) + '\n');
  tagged++;
}
console.log(`done: ${tagged} tagged, ${skipped} skipped`);
