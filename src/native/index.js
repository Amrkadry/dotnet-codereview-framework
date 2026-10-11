// dotnet-codereview-framework — src/native/index.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * THE NATIVE ENGINE — the framework's own analyzer. Real findings with NO scanner and NO AI
 * installed, in pure Node standard library.
 *
 * Coverage model (this is the engine's contract with the .NET test-case catalog):
 *   - Every catalog case applicable to the project's stack is ACCOUNTED FOR in the result:
 *       * decided by an implemented check that ran          -> coverage record 'checked'
 *         (with a finding when the check matched)
 *       * not mechanically decidable / no implemented check -> one `manual-review` INFO finding
 *         carrying the case's own checklist question.
 *   - Nothing is silently dropped: "covered" and "undecided" are both visible, so the report
 *     never implies a clean bill where nobody looked. That is what "standalone" means here:
 *     zero tools installed still yields a 279-case-accounted-for review.
 *
 * False-positive discipline:
 *   - comments are stripped before code checks match (dead code is not a finding);
 *   - Tests/, obj/, bin/, packages/, node_modules/, Migrations/ (and editor/build dirs) are
 *     SKIPPED, and the skip list is written into the RunResult notes so the reviewer can see it;
 *   - bare regex matches are confidence POSSIBLE and their findings say so in plain language.
 *
 * Shape: adapter contract (id/name/kind/stacks/detect/run/parse) + `analyze()` as the single
 * entry function, mirroring src/supplychain. A directory with no .NET surface returns
 * NOT_APPLICABLE with zero findings — never an exception.
 */

const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');
const { walk, readLines, SKIP_DIRS } = require('./walk');
const { finding, manualReview, TOOL } = require('./finding');
const WEB_CHECKS = require('./checks/web-config').CHECKS;
const MEMBERSHIP_CHECKS = require('./checks/web-membership').CHECKS;
const CS_CHECKS = require('./checks/csharp').CHECKS;
const LEGACY_CHECKS = require('./checks/legacy-csharp').CHECKS;
const HARDENING_CHECKS = require('./checks/hardening-csharp').CHECKS;
const MANIFEST_CHECKS = require('./checks/manifests').CHECKS;
const STARTUP = require('./checks/startup');

const ID = 'native';
const VERSION = '1.0.0';
const ANALYSED_EXTS = ['.cs', '.vb', '.config', '.json', '.csproj', '.vbproj', '.fsproj',
  '.asax', '.aspx', '.cshtml', '.vbhtml', '.master'];
// `currentCheck` lets each check's emit() attribute coverage to the check currently running
// (module-level because the check runners receive only a per-file ctx).
let currentCheck = null;

const catalogDir = path.join(__dirname, '..', '..', 'catalog');
function loadCatalog() {
  const tests = [];
  try {
    for (const f of fs.readdirSync(catalogDir).filter(x => x.endsWith('.json')).sort()) {
      const c = JSON.parse(fs.readFileSync(path.join(catalogDir, f), 'utf8'));
      tests.push(...(c.tests || []));
    }
  } catch { /* catalog missing: coverage honesty degrades, engine still runs */ }
  return tests;
}

function applicable(caseDef, stack) {
  return caseDef.stack === 'both' || caseDef.stack === stack ||
    stack === 'unknown' || stack === 'mixed';
}

/** Does this directory look like a .NET application at all? */
function hasNetSurface(root, files) {
  if (files.some(f => /\.(cs|csproj|vbproj|fsproj)$/i.test(f))) return true;
  let entries = [];
  try { entries = fs.readdirSync(root); } catch { return false; }
  return entries.some(e =>
    /^(web|app)\.(\w+\.)?config$/i.test(e) || /^appsettings(\.\w+)?\.json$/i.test(e) ||
    /^(global\.asax|packages\.config|.*\.sln)$/i.test(e));
}

/**
 * THE entry function.
 * @param {string} sourcePath directory to analyse (never mutated)
 * @param {object} [options] { outPath, stack, log, noManualReview }
 * @returns {Promise<RunResult>} contract-valid; never rejects
 */
async function analyze(sourcePath, options = {}) {
  const started = Date.now();
  const root = path.resolve(String(sourcePath || '.'));
  const log = options.log || (() => {});
  const command = 'internal: native engine — ' +
    'XML config + C# + manifest heuristics driven by the 279-case .NET catalog ' +
    '(no external tool, no network, no AI)';

  try {
    if (!fs.existsSync(root)) {
      return C.failed(ID, `source path not found: ${root}`,
        { command, durationMs: Date.now() - started });
    }
    const { files, skippedDirs, truncated } = walk(root,
      ['.cs', '.vb', '.config', '.json', '.csproj', '.vbproj', '.fsproj',
        '.asax', '.aspx', '.cshtml', '.vbhtml', '.master']);
    const stack = options.stack || detectStack(root);

    if (!hasNetSurface(root, files)) {
      return {
        status: 'NOT_APPLICABLE', tool: ID, version: VERSION, command, exitCode: 0,
        durationMs: Date.now() - started, findings: [],
        notes: 'No .NET source or configuration surface under ' + root +
          ' (no .cs/.csproj, no Web.config/appsettings). Nothing to analyse natively.',
        limitations: 'This is NOT a clean result — no .NET surface exists here to examine.'
      };
    }

    const findings = [];
    const emit = f => findings.push(f);
    const checkedCases = new Set();
    const emitChecked = (check, f) => { check.caseIds.forEach(id => checkedCases.add(id)); emit(f); };

    // ---- XML configuration checks (Web.config / app.config shaped)
    const xmlFiles = files.filter(f => /\.(config)$/i.test(f));
    // appsettings*.json ride the same config-check registry but only for the checks that
    // declare themselves applicable (the JSON check self-filters on the file name).
    const jsonConfigFiles = files.filter(f => /^appsettings(\.\w+)?\.json$/i.test(path.basename(f)));
    for (const file of [...xmlFiles, ...jsonConfigFiles]) {
      const lines = readLines(file);
      if (!lines) continue;
      const isJson = /\.json$/i.test(file);
      const ctx = {
        relPath: path.relative(root, file).replace(/\\/g, '/'),
        text: lines.join('\n'), lines, emit: f => emitChecked(currentCheck, f)
      };
      for (const check of WEB_CHECKS) {
        if (isJson && check.id !== 'web-appsettings-secret') continue;
        if (!isJson && check.id === 'web-appsettings-secret') continue;
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
      for (const check of MEMBERSHIP_CHECKS) {
        if (isJson && check.id !== 'web-appsettings-secret') continue;
        if (!isJson && check.id === 'web-appsettings-secret') continue;
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
    }
    currentCheck = null;

    // ---- C# source checks
    const csFiles = files.filter(f => /\.(cs|vb)$/i.test(f));

    // Authorisation posture is a PROJECT fact, not a per-file one: whether a controller is
    // protected depends on a global filter registered in some other file entirely, and
    // whether CSRF is even reachable depends on the application using ambient cookie
    // credentials rather than bearer tokens. A per-file check cannot see either, so both are
    // established once here and handed to the controller checks, which would otherwise have
    // to guess -- and would guess wrong in both directions.
    const authz = { globalFilter: null, cookieAuth: false, tokenAuth: false };
    const GLOBAL_FILTER = [
      /Filters\s*\.\s*Add\s*\(\s*new\s+Authorize/i,
      /\bAuthorizeFilter\b/i,
      /\.RequireAuthorization\s*\(/i,
      /FallbackPolicy\s*=/i,
      /options\s*\.\s*Filters\s*\.\s*Add\s*<\s*Authorize/i
    ];
    const COOKIE_AUTH = /AddCookie\s*\(|CookieAuthentication|FormsAuthentication|UseCookieAuthentication/i;
    const TOKEN_AUTH = /OAuthAuthorizationServerOptions|AddJwtBearer|UseJwtBearerAuthentication|OAuthBearerAuthentication|UseOAuthBearerTokens/i;
    for (const file of csFiles) {
      const lines = readLines(file);
      if (!lines) continue;
      const text = lines.join('\n');
      if (!authz.globalFilter && GLOBAL_FILTER.some(re => re.test(text))) {
        authz.globalFilter = path.relative(root, file).replace(/\\/g, '/');
      }
      if (COOKIE_AUTH.test(text)) authz.cookieAuth = true;
      if (TOKEN_AUTH.test(text)) authz.tokenAuth = true;
    }

    for (const file of csFiles) {
      const lines = readLines(file);
      if (!lines) continue;
      const ctx = {
        relPath: path.relative(root, file).replace(/\\/g, '/'),
        text: lines.join('\n'), lines, emit: f => emitChecked(currentCheck, f),
        project: { stack, authz }
      };
      for (const check of CS_CHECKS) {
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
      for (const check of LEGACY_CHECKS) {
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
      for (const check of HARDENING_CHECKS) {
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
    }
    currentCheck = null;

    // ---- manifest checks
    const manifestFiles = files.filter(f => /\.(csproj|vbproj|fsproj)$/i.test(f));
    for (const file of manifestFiles) {
      const lines = readLines(file);
      if (!lines) continue;
      const ctx = {
        relPath: path.relative(root, file).replace(/\\/g, '/'),
        text: lines.join('\n'), lines, emit: f => emitChecked(currentCheck, f)
      };
      for (const check of MANIFEST_CHECKS) {
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
    }
    currentCheck = null;

    // ---- startup (project-level pipeline facts)
    for (const file of STARTUP.startupFiles(files)) {
      const lines = readLines(file);
      if (!lines) continue;
      const ctx = {
        relPath: path.relative(root, file).replace(/\\/g, '/'),
        text: lines.join('\n'), lines, emit: f => emitChecked(currentCheck, f), project: { stack }
      };
      for (const check of STARTUP.CHECKS) {
        currentCheck = check;
        try { check.run(ctx); } catch (e) { log(`      native: check ${check.id} failed on ${ctx.relPath}: ${e.message}`); }
      }
    }
    currentCheck = null;

    // ---- project-level: lockfile presence (O-003) when manifests exist
    const hasPackages = files.some(f => /(^|[/\\])packages\.config$/i.test(f)) || manifestFiles.length;
    const hasLock = files.some(f => /packages\.lock\.json$/i.test(f));
    if (hasPackages && !hasLock) {
      const anchor = manifestFiles[0] || files.find(f => /packages\.config$/i.test(f));
      const rel = anchor ? path.relative(root, anchor).replace(/\\/g, '/') : '(project)';
      emit(finding({
        check: 'native-no-lockfile', caseIds: ['O-003'], confidence: 'CONFIRMED', severity: 'MEDIUM',
        category: 'dependency', cwe: ['CWE-1357'], language: 'xml',
        title: 'No packages.lock.json — dependency resolution is not reproducible',
        file: rel, startLine: 1,
        snippet: '(project-level check: no packages.lock.json found alongside the package manifests)',
        problem: 'The project declares package dependencies but commits no lockfile, so restore ' +
          'resolves versions at build time from the configured feeds.',
        impact: 'Two builds of the same commit can differ; a malicious or broken package version ' +
          'published after the manifest was written is silently adopted. Reviewing dependencies ' +
          'against a manifest-only state cannot say what would actually be compiled in.',
        recommendation: 'Enable <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>, ' +
          'commit packages.lock.json, and pass --locked-mode to restore in CI.'
      }));
      checkedCases.add('O-003');
    }

    // ---- coverage: account for EVERY applicable catalog case
    const catalog = loadCatalog();
    const manual = [];
    const coverage = [];
    let applicableCount = 0;
    for (const cse of catalog) {
      if (!applicable(cse, stack)) {
        coverage.push({ caseId: cse.id, stack: cse.stack, outcome: 'not-applicable', tool: TOOL });
        continue;
      }
      applicableCount++;
      if (checkedCases.has(cse.id)) {
        coverage.push({ caseId: cse.id, stack: cse.stack, outcome: 'checked', tool: TOOL });
      } else {
        coverage.push({ caseId: cse.id, stack: cse.stack, outcome: 'manual-review', tool: TOOL });
        if (!options.noManualReview) manual.push(manualReview(cse, stack));
      }
    }
    findings.push(...manual);

    const sevCount = s => findings.filter(f => f.severity === s).length;
    const notes =
      `Native engine analysed ${csFiles.length} source, ${xmlFiles.length} config and ` +
      `${manifestFiles.length} manifest file(s) against the catalog: ` +
      `${applicableCount} case(s) applicable to stack "${stack}" — ` +
      `${checkedCases.size} decided by implemented checks (${findings.filter(f => f.severity !== 'INFO').length} ` +
      `finding(s) emitted), ${applicableCount - checkedCases.size} left as explicit manual-review ` +
      'items carrying their checklist questions. Skipped directories: ' +
      (skippedDirs.length ? skippedDirs.slice(0, 12).join(', ') + (skippedDirs.length > 12 ? ` … (${skippedDirs.length} total)` : '') : 'none') +
      (truncated ? '. FILE LIMIT REACHED — results cover the first ' + files.length + ' files only.' : '.') +
      ' Manual-review items are INFO severity by design: they are undecided questions, not defects.';

    return {
      status: 'EXECUTED', tool: ID, version: VERSION, command, exitCode: 0,
      durationMs: Date.now() - started, findings,
      catalogCoverage: coverage,
      rawPath: undefined,
      notes,
      limitations: 'Heuristic static analysis: POSSIBLE-confidence findings are leads to read, not ' +
        'verdicts; dataflow across files, compiled behaviour and runtime configuration are not ' +
        'modelled. A manual-review item means NOBODY looked — it is not a pass.'
    };
  } catch (e) {
    return C.failed(ID, `native engine failed internally: ${String(e && e.message || e).slice(0, 300)}`,
      { command, durationMs: Date.now() - started });
  }
}

/** Cheap stack detection without the full discover pass (kept dependency-light). */
function detectStack(root) {
  let sdks = 0, old = 0;
  const scan = (dir, depth) => {
    if (depth > 6) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.includes(e.name)) scan(full, depth + 1); continue; }
      if (/\.(csproj|vbproj|fsproj)$/i.test(e.name)) {
        try {
          const t = fs.readFileSync(full, 'utf8');
          if (/<Project\s+Sdk=/i.test(t)) sdks++; else old++;
        } catch { /* unreadable project counts as neither */ }
      }
    }
  };
  scan(root, 0);
  if (!sdks && !old) return 'unknown';
  if (sdks && old) return 'mixed';
  return sdks ? 'core' : 'framework';
}

// adapter contract surface — registered like any adapter, needs no external tool

/** Pure-ish parse(): turn stored raw output {findings:[...]} back into findings. */
function parse(raw) {
  if (!raw) return [];
  const doc = typeof raw === 'string' ? (() => { try { return JSON.parse(raw); } catch { return null; } })() : raw;
  if (!doc || !Array.isArray(doc.findings)) return [];
  return doc.findings;
}

module.exports = {
  id: ID,
  name: 'Native engine (built-in, zero-install)',
  kind: 'sast',
  stacks: ['framework', 'core', 'both'],

  detect: async () => ({ available: true, version: VERSION, reason: 'Built into the framework: pure Node, no external tool.' }),
  run: async ctx => analyze(ctx.sourcePath, {
    outPath: ctx.outPath, log: ctx.log,
    stack: (ctx.project && ctx.project.stack) || undefined,
    noManualReview: ctx.config && ctx.config.native && ctx.config.native.noManualReview
  }),
  parse,

  analyze,
  VERSION
};
