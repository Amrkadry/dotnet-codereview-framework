'use strict';
/**
 * PR/diff mode: which files did this branch actually introduce changes to?
 *
 * WHY THREE DOTS: `A...B` diffs from the MERGE BASE of A and B to B, so it shows only what the
 * PR branch introduced on top of where it diverged. `A..B` diffs the two tips directly, so it
 * ALSO surfaces changes made on the base branch since divergence — as if the PR had made them,
 * producing findings the PR author did not cause and cannot fix. Three-dot is the PR-review
 * semantic and is the default; two-dot stays available (moraa review --diff-two-dot) for the
 * genuinely different question "what changed between these two exact trees".
 *
 *   main ----X--------M        (someone else fixed a leak on main after the branch point)
 *             \------F  HEAD   (the PR: touched b.txt only)
 *
 *   git diff --name-only main...HEAD  ->  b.txt          (what the PR did — the default)
 *   git diff --name-only main..HEAD   ->  a.txt, b.txt   (main's fix leaks in as if the PR did it)
 *
 * The unit test in tests/diff.test.js builds exactly this repo and pins both behaviours.
 */

const { execFileSync } = require('child_process');

/**
 * One normalisation shared by everything that compares finding locations against changed-file
 * sets: backslashes -> forward slashes (Windows-native tool output), strip a leading ./,
 * lowercase (Windows paths are case-insensitive and tools disagree about case).
 * Deliberately identical to `norm` in src/correlate/merge.js.
 */
function normalisePath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
}

/**
 * The git arguments that select the diff, returned literally so tests can pin the three-dot
 * default WITHOUT running git. These are appended after `git diff --name-only`.
 * @returns {string[]} e.g. ['main...HEAD'] (merge base) or ['main..HEAD'] (two-dot)
 */
function resolveDiffRange(base, mergeBase) {
  return [mergeBase ? `${base}...HEAD` : `${base}..HEAD`];
}

/**
 * Repo-relative, normalised paths that differ between the merge base of <base> and HEAD.
 * @param {string} base a git ref the changed files are measured against (e.g. origin/main)
 * @param {{cwd?: string, mergeBase?: boolean}} opts cwd defaults to process.cwd();
 *        mergeBase defaults to true (three-dot, see the file header)
 * @returns {Set<string>} normalised repo-relative paths
 * @throws Error with an actionable message when cwd is not a git repository, the base ref is
 *         unknown, or git is not installed.
 */
function changedFiles(base, opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const mergeBase = opts.mergeBase !== false;
  const range = resolveDiffRange(base, mergeBase);

  let out;
  try {
    out = execFileSync('git', ['diff', '--name-only', ...range], { cwd, encoding: 'utf8' });
  } catch (e) {
    const err = e || {};
    const stderr = String(err.stderr || '');
    // Distinguish by what git actually said, not by guessing. Order matters: "not a git
    // repository" is definitive, then an unresolvable ref, then a missing binary.
    if (/not a git repository/i.test(stderr) || /not a git repository/i.test(String(err.message))) {
      throw new Error(`--diff requires a git repository: ${cwd} is not one`);
    }
    if (/unknown revision|ambiguous argument|bad revision/i.test(stderr)) {
      throw new Error(`--diff base ref not found: ${base}. ` +
        'Fetch it first (in CI: actions/checkout with fetch-depth: 0).');
    }
    if (err.code === 'ENOENT') {
      throw new Error('--diff requires git on PATH');
    }
    throw new Error(`git diff ${range.join(' ')} failed in ${cwd}: ` +
      (stderr.trim() || err.message || 'unknown git error'));
  }

  return new Set(out.split('\n').map(s => s.trim()).filter(Boolean).map(normalisePath));
}

module.exports = { changedFiles, resolveDiffRange, normalisePath };
