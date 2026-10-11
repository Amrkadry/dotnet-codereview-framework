// dotnet-codereview-framework — tests/diff.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Unit and end-to-end tests for PR/diff mode (src/diff/*, bin/moraa.js --diff).
 *
 * Three-dot vs two-dot is pinned against a REAL throwaway git repo, not a mock: main moves
 * after the branch point, and the assertions prove that `main...HEAD` (the default) reports
 * only what the branch introduced while `main..HEAD` also reports the unrelated main-side
 * change. The CLI test runs the full review pipeline over a synthetic .NET project inside a
 * git repo and checks the filtered report, the diff summary block, and the --fail-on-new gate.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { changedFiles, resolveDiffRange, normalisePath } = require('../src/diff/changed-files');
const { partitionFindings, DIFF_RELATION } = require('../src/diff/filter');
const { finding } = require('./helpers/finding');

const root = path.resolve(__dirname, '..');

// Everything git-dependent is skipped (not failed) when git is not installed.
let gitOk = true;
try { execFileSync('git', ['--version'], { stdio: 'pipe' }); } catch { gitOk = false; }

const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });

// ------------------------------------------------------------------ range construction
describe('resolveDiffRange: the argv form, pinned without running git', () => {
  test('mergeBase true (the default) produces the three-dot range', () => {
    const argv = resolveDiffRange('main', true);
    assert.ok(argv.includes('main...HEAD'), `expected main...HEAD in ${JSON.stringify(argv)}`);
  });

  test('mergeBase false produces the two-dot range', () => {
    const argv = resolveDiffRange('main', false);
    assert.ok(argv.includes('main..HEAD'), `expected main..HEAD in ${JSON.stringify(argv)}`);
    assert.ok(!argv.includes('main...HEAD'), 'two-dot mode must not regress to three dots');
  });
});

describe('normalisePath', () => {
  test('backslashes, leading ./ and case are all normalised', () => {
    assert.equal(normalisePath('Src\\Foo.cs'), 'src/foo.cs');
    assert.equal(normalisePath('./App/Readme.cs'), 'app/readme.cs');
    assert.equal(normalisePath(''), '');
    assert.equal(normalisePath(null), '');
  });
});

// ------------------------------------------------------------------ a real git repo
let repo;        // the unit-level repo from the task scenario
let scratch;     // non-repo dir for the error-path test

before(() => {
  repo = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-diff-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-diff-nonrepo-'));
  if (!gitOk) return;

  git(repo, 'init', '-b', 'main');
  git(repo, 'config', 'user.email', 'test@example.com');
  git(repo, 'config', 'user.name', 'moraa test');
  fs.writeFileSync(path.join(repo, 'a.txt'), 'base a\n');
  fs.writeFileSync(path.join(repo, 'b.txt'), 'base b\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '-m', 'base');

  // The PR branch changes ONLY b.txt...
  git(repo, 'checkout', '-b', 'feature');
  fs.writeFileSync(path.join(repo, 'b.txt'), 'changed on feature\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '-m', 'feature change');

  // ...while main moves on INDEPENDENTLY, changing a.txt after the branch point.
  git(repo, 'checkout', 'main');
  fs.writeFileSync(path.join(repo, 'a.txt'), 'changed on main\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '-m', 'main moved on');

  git(repo, 'checkout', 'feature');
});

after(() => {
  fs.rmSync(repo, { recursive: true, force: true });
  fs.rmSync(scratch, { recursive: true, force: true });
});

describe('changedFiles against a real repo: three-dot is the PR semantic', () => {
  test('merge-base (default) sees ONLY what the branch introduced', t => {
    if (!gitOk) return t.skip('git not available');
    const changed = changedFiles('main', { cwd: repo, mergeBase: true });
    assert.ok(changed.has('b.txt'), `the PR changed b.txt, got: ${[...changed].join(', ')}`);
    assert.ok(!changed.has('a.txt'),
      'a.txt changed on MAIN after divergence; three-dot must not blame the PR for it');
  });

  test('two-dot also reports the main-side change — the exact reason it is not the default', t => {
    if (!gitOk) return t.skip('git not available');
    const changed = changedFiles('main', { cwd: repo, mergeBase: false });
    assert.ok(changed.has('b.txt'), 'the branch change must still appear');
    assert.ok(changed.has('a.txt'),
      'two-dot diffs the tips directly, so main\'s a.txt change surfaces as if the PR made it');
  });
});

describe('changedFiles error paths', () => {
  test('a directory that is not a git repository produces an actionable message', t => {
    if (!gitOk) return t.skip('git not available');
    // The mandated message is exactly "--diff requires a git repository: <cwd> is not one";
    // pin its actionable core (the spec's /not a git repository/i regex cannot match that
    // exact string, since the phrase it looks for is not a substring of the message).
    assert.throws(() => changedFiles('main', { cwd: scratch }),
      /--diff requires a git repository: .* is not one/);
  });

  test('an unknown base ref tells the user to fetch it first', t => {
    if (!gitOk) return t.skip('git not available');
    assert.throws(() => changedFiles('no-such-ref-exists', { cwd: repo }),
      /not found/i);
  });
});

// ------------------------------------------------------------------ partitioning
describe('partitionFindings', () => {
  const changed = new Set(['app/changed.cs', 'src/foo.cs']);

  test('primary findings land in inDiff, untouched ones in outOfDiff', () => {
    const primary = finding({ title: 'on a changed file', location: { file: 'App/Changed.cs', startLine: 5 } });
    const outside = finding({ title: 'on an unchanged file', location: { file: 'App/Untouched.cs', startLine: 7 } });
    const p = partitionFindings([primary, outside], changed, {});

    assert.equal(p.inDiff.length, 1);
    assert.equal(p.inDiff[0], primary, 'the SAME object must come back, not a copy');
    assert.equal(p.inDiff[0].diffRelation, DIFF_RELATION.PRIMARY);
    assert.equal(p.outOfDiff.length, 1);
    assert.equal(p.outOfDiff[0].diffRelation, DIFF_RELATION.OUTSIDE);
    assert.equal(p.contextual.length, 0);
  });

  test('a finding whose additionalLocations touch a changed file is contextual by default', () => {
    const ctx = finding({
      title: 'sink here, source on a changed file',
      location: { file: 'App/Sink.cs', startLine: 1,
        additionalLocations: [{ file: 'App/unchanged.cs', startLine: 2 },
                              { file: 'src\\Foo.cs', startLine: 9 }] }
    });
    const p = partitionFindings([ctx], changed, { context: false });
    assert.equal(p.inDiff.length, 0, 'without --diff-context a contextual finding must not gate');
    assert.equal(p.contextual.length, 1);
    assert.equal(p.contextual[0].diffRelation, DIFF_RELATION.CONTEXT);
  });

  test('--diff-context moves the contextual finding into inDiff', () => {
    const ctx = finding({
      location: { file: 'App/Sink.cs', startLine: 1,
        additionalLocations: [{ file: 'SRC/FOO.CS', startLine: 9 }] }
    });
    const p = partitionFindings([ctx], changed, { context: true });
    assert.equal(p.inDiff.length, 1);
    assert.equal(p.inDiff[0].diffRelation, DIFF_RELATION.CONTEXT);
    assert.equal(p.contextual.length, 0, 'buckets are disjoint: the finding moved, not duplicated');
  });

  test('path normalisation matches Src\\Foo.cs against src/foo.cs', () => {
    const f = finding({ location: { file: 'Src\\Foo.cs', startLine: 3 } });
    const p = partitionFindings([f], new Set(['src/foo.cs']), {});
    assert.equal(p.inDiff.length, 1, 'Windows-native separators and case must not hide a change');
  });

  test('buckets are disjoint, sum to the input, preserve order, and never mutate changedSet', () => {
    const input = [
      finding({ title: 'f1-out', location: { file: 'x.cs' } }),
      finding({ title: 'f2-in',  location: { file: 'APP/CHANGED.CS' } }),
      finding({ title: 'f3-out', location: { file: 'y.cs' } }),
      finding({ title: 'f4-in',  location: { file: 'SRC/FOO.cs' } })
    ];
    const changedBefore = [...changed].sort();
    const p = partitionFindings(input, changed, { context: false });

    assert.deepEqual(p.inDiff.map(f => f.title), ['f2-in', 'f4-in'], 'input order preserved');
    assert.deepEqual(p.outOfDiff.map(f => f.title), ['f1-out', 'f3-out']);
    assert.equal(p.inDiff.length + p.contextual.length + p.outOfDiff.length, input.length);
    assert.deepEqual([...changed].sort(), changedBefore, 'changedSet must not be mutated');
  });
});

// ------------------------------------------------------------------ end-to-end CLI
describe('CLI end-to-end: moraa review --diff on a synthetic .NET project', () => {
  // Deliberately the selfcheck.js project shape: legacy non-SDK web app + packages.config,
  // which discovery alone finds findings on (csproj and sln), with no external tool required.
  const SLN = 'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "App\\App.csproj", "{1}"\nEndProject\n';
  const CSPROJ = '<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>' +
    '<Import Project="$(VSToolsPath)\\WebApplications\\Microsoft.WebApplication.targets" /></Project>';
  const PKG = '<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="11.0.1" /></packages>';

  let e2e;       // temp git repo holding the synthetic project
  const moraa = (args, opts = {}) =>
    execFileSync(process.execPath, [path.join(root, 'bin/moraa.js'), ...args],
      Object.assign({ cwd: root, encoding: 'utf8', stdio: 'pipe' }, opts));

  before(function () {
    if (!gitOk) this.skip();
    e2e = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-diff-e2e-'));
    git(e2e, 'init', '-b', 'main');
    git(e2e, 'config', 'user.email', 'test@example.com');
    git(e2e, 'config', 'user.name', 'moraa test');
    fs.mkdirSync(path.join(e2e, 'App'), { recursive: true });
    fs.writeFileSync(path.join(e2e, 'App.sln'), SLN);
    fs.writeFileSync(path.join(e2e, 'App', 'App.csproj'), CSPROJ);
    fs.writeFileSync(path.join(e2e, 'App', 'packages.config'), PKG);
    git(e2e, 'add', '.');
    git(e2e, 'commit', '-m', 'base');

    // The PR: branch off main and touch exactly one file — App.csproj, which discovery
    // findings are located on (dependency capability + lockfile findings).
    git(e2e, 'checkout', '-b', 'pr');
    fs.writeFileSync(path.join(e2e, 'App', 'App.csproj'),
      CSPROJ.replace('</PropertyGroup>', '<LangVersion>7.3</LangVersion></PropertyGroup>'));
    git(e2e, 'add', '.');
    git(e2e, 'commit', '-m', 'pr: touch App.csproj');
  });

  after(() => { if (e2e) fs.rmSync(e2e, { recursive: true, force: true }); });

  test('full run then diff run: exit 0, summary.diff populated, findings are a subset', () => {
    if (!gitOk) return;

    // Unfiltered reference run — the diff run's findings must be a subset of these.
    moraa(['review', e2e, '--out', '.moraa-review-full']);
    const full = JSON.parse(fs.readFileSync(path.join(e2e, '.moraa-review-full', 'data', 'report.json'), 'utf8'));
    assert.ok(full.findings.length > 0, 'the synthetic project must produce findings at all');

    // Diff run.
    const out = moraa(['review', e2e, '--diff', 'main', '--out', '.moraa-review']);
    const rep = JSON.parse(fs.readFileSync(path.join(e2e, '.moraa-review', 'data', 'report.json'), 'utf8'));

    assert.ok(out.includes('diff base main'), 'the console must print the diff summary');
    assert.equal(rep.summary.diff.base, 'main');
    assert.equal(rep.summary.diff.range, 'main...HEAD', 'three-dot must be the default');
    assert.equal(rep.summary.diff.mergeBase, true);
    assert.equal(rep.summary.diff.changedFiles, 1, 'exactly App.csproj changed on the branch');
    assert.equal(rep.summary.diff.context, false);
    assert.equal(rep.summary.diff.inDiff + rep.summary.diff.contextual + rep.summary.diff.outOfDiff,
      full.findings.length, 'the three buckets must partition the unfiltered finding set');

    const key = f => `${f.title}|${(f.location && f.location.file) || ''}`;
    const fullKeys = new Set(full.findings.map(key));
    const diffKeys = rep.findings.map(key);
    assert.ok(diffKeys.length > 0, 'App.csproj carries discovery findings, so the diff set is non-empty');
    for (const k of diffKeys) {
      assert.ok(fullKeys.has(k), `diff-mode finding "${k}" must exist in the unfiltered report`);
    }
    assert.ok(diffKeys.length < full.findings.length,
      'findings located on App.sln (untouched) must have been filtered out');
    assert.ok(rep.findings.every(f => normalisePath(f.location.file) === 'app/app.csproj'),
      'every reported finding must live on a changed file');
  });

  test('--fail-on-new LOW exits 1 because a LOW-or-worse finding is in the diff set', () => {
    if (!gitOk) return;
    let err = null;
    try {
      moraa(['review', e2e, '--diff', 'main', '--fail-on-new', 'LOW', '--out', '.moraa-review-gate']);
    } catch (e) { err = e; }
    assert.ok(err, 'the gate must have failed the run');
    assert.equal(err.status, 1, `expected exit 1, got ${err.status}`);
    assert.match(String(err.stderr), /at or above LOW in the diff set/);
  });

  test('--diff with no argument is a usage error, not base ref "true"', () => {
    let err = null;
    try { moraa(['review', e2e, '--diff']); } catch (e) { err = e; }
    assert.ok(err, 'a bare --diff must fail');
    assert.equal(err.status, 2);
    assert.match(String(err.stderr), /--diff requires a base ref/);
  });
});
