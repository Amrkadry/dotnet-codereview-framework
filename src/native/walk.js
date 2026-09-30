'use strict';
/**
 * File walking + snippet reading for the native engine.
 *
 * THE SKIP LIST IS PART OF THE RESULT, NOT A HIDDEN BEHAVIOUR. A reviewer reading a native
 * report must be able to see which directories were never examined, because "no findings in
 * Tests/" is only trustworthy if you know Tests/ was skipped on purpose. Every walk records
 * what it skipped and that record is surfaced in the RunResult notes.
 *
 * Skips are deliberately narrow: build output (obj/, bin/), restored packages, dependency and
 * test trees, generated migrations and editor state. Nothing else is skipped — a finding missed
 * because a directory was silently filtered is worse than a slower walk.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = [
  'bin', 'obj', 'packages', 'node_modules', 'Tests', 'tests', 'test', 'Migrations',
  '.git', '.vs', '.idea', '.svn', '.moraa-review', '.moraa-tmp', '.sonarqube', 'TestResults'
];

const MAX_FILES = 20000;
const MAX_BYTES = 2 * 1024 * 1024; // per file read guard

/** What a walk saw. `skippedDirs` is reported verbatim in engine output. */
function walk(root, extensions) {
  const files = [];
  const skippedDirs = [];
  const ext = new Set(extensions.map(e => e.toLowerCase()));
  let truncated = false;

  const visit = dir => {
    if (truncated || files.length >= MAX_FILES) { truncated = files.length >= MAX_FILES; return; }
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { skippedDirs.push(path.relative(root, dir) + ' (unreadable)'); return; }
    for (const e of entries) {
      if (truncated) break;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.includes(e.name.toLowerCase()) || SKIP_DIRS.includes(e.name)) {
          skippedDirs.push(path.relative(root, full).replace(/\\/g, '/') + '/');
          continue;
        }
        visit(full);
      } else if (ext.has(path.extname(e.name).toLowerCase())) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { continue; }
        if (size > 0 && size <= MAX_BYTES) files.push(full);
        else if (size > MAX_BYTES) skippedDirs.push(path.relative(root, full) + ' (over 2 MB)');
      }
    }
  };
  visit(root);
  return { files, skippedDirs, truncated };
}

/** Read a file as numbered lines. Returns null when unreadable (caller decides honesty). */
function readLines(absPath) {
  try {
    return fs.readFileSync(absPath, 'utf8').split(/\r?\n/);
  } catch { return null; }
}

/**
 * A code window around a match: the finding's evidence MUST quote the real file, so the
 * snippet is always cut from the same lines array that produced the match.
 */
function snippet(lines, line, radius = 2) {
  const from = Math.max(1, line - radius);
  const to = Math.min(lines.length, line + radius);
  return lines.slice(from - 1, to).join('\n');
}

module.exports = { walk, readLines, snippet, SKIP_DIRS, MAX_FILES, MAX_BYTES };
