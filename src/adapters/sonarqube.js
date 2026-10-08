// dotnet-codereview-framework — src/adapters/sonarqube.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * SonarQube adapter — reads issues and security hotspots from the Web API.
 *
 * TWO IMPORTANT .NET FACTS this adapter encodes:
 *
 * 1. On .NET Framework, Sonar analysis REQUIRES the MSBuild scanner
 *    (SonarScanner.MSBuild.exe begin -> msbuild -> end). The plain CLI scanner analyses no C# at
 *    all, so a "successful" CLI scan of a .NET Framework solution is a silent false clean.
 *    This adapter therefore reads results rather than pretending to produce them, and says so.
 *
 * 2. Sonar analyses COMPILED code. It never reads Web.config or appsettings.json, so configuration
 *    is a structural blind spot — recorded in `limitations` so a reader does not mistake Sonar's
 *    silence on config for a clean config.
 *
 * Offline mode: if the server is unreachable but a previous scan left
 * `.sonarqube/out/0/Issues.json` in the source tree, that raw analyser output is parsed instead.
 * That is genuinely useful — it is how a review proceeds when the server is down.
 *
 * Auth: SONAR_TOKEN from the environment only (never config, never argv).
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const C = require('../core/adapter-contract');

const ID = 'sonarqube';

// Sonar issue types -> canonical categories.
const TYPE_CATEGORY = {
  VULNERABILITY: 'security',
  SECURITY_HOTSPOT: 'security',
  BUG: 'reliability',
  CODE_SMELL: 'code-quality'
};

function get(urlStr, token, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json' };
    if (token) headers.authorization = 'Basic ' + Buffer.from(token + ':').toString('base64');
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', headers
    }, res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 30000, () => req.destroy(new Error('SonarQube request timed out')));
    req.end();
  });
}

function cfgOf(ctx) {
  const c = (ctx.config.tools && ctx.config.tools[ID]) || {};
  const env = ctx.env || process.env;
  return {
    hostUrl: (env.SONAR_HOST_URL || c.hostUrl || 'http://localhost:9000').replace(/\/+$/, ''),
    projectKey: c.projectKey || env.SONAR_PROJECT_KEY || null,
    token: env.SONAR_TOKEN || null,
    pageSize: Math.min(Number(c.pageSize) || 500, 500),
    maxPages: Number(c.maxPages) || 20,
    offlineIssuesPath: c.offlineIssuesPath || '.sonarqube/out/0/Issues.json'
  };
}

/** Walk up from the source looking for a previous analyser export (newest run dir wins). */
function findOfflineExport(sourcePath) {
  const rel = c => c.offlineIssuesPath || '.sonarqube/out/0/Issues.json';
  let d = path.resolve(sourcePath);
  for (let i = 0; i < 4 && path.dirname(d) !== d; i++) {
    d = path.dirname(d);
    const outDir = path.join(d, '.sonarqube', 'out');
    try {
      for (const run of fs.readdirSync(outDir).sort().reverse()) {
        const f = path.join(outDir, run, 'Issues.json');
        if (fs.existsSync(f)) return f;
      }
    } catch { /* not this level */ }
  }
  return null;
}

async function detect(ctx) {
  const c = cfgOf(ctx);
  const legacyOffline = path.join(ctx.sourcePath, c.offlineIssuesPath);
  const offline = fs.existsSync(legacyOffline) ? legacyOffline : (findOfflineExport(ctx.sourcePath) || legacyOffline);

  if (!c.projectKey) {
    if (!fs.existsSync(offline)) {
      return {
        available: false,
        reason: 'No SonarQube projectKey configured and no previous analyser output on disk.',
        command: 'set tools.sonarqube.projectKey in moraa.config.json, and SONAR_TOKEN in the environment'
      };
    }
    // Latent-bug fix: this branch must declare offline mode, or run() falls through
    // to the server path and fails against a null project key.
    return {
      available: true, version: 'offline', mode: 'offline',
      reason: 'No projectKey configured, but a previous analyser run was found on disk; offline mode will be used.',
      command: 'set tools.sonarqube.projectKey in moraa.config.json, and SONAR_TOKEN in the environment'
    };
  }
  try {
    const r = await get(`${c.hostUrl}/api/system/status`, c.token, 8000);
    if (r.statusCode === 200) {
      let v = '';
      try { v = JSON.parse(r.body).version || ''; } catch { /* ignore */ }
      return { available: true, version: v || 'reachable', mode: 'server' };
    }
    throw new Error('HTTP ' + r.statusCode);
  } catch (e) {
    if (fs.existsSync(offline)) {
      return { available: true, version: 'offline', mode: 'offline',
        reason: `Server unreachable (${e.message}); falling back to analyser output on disk.` };
    }
    return {
      available: false,
      reason: `SonarQube at ${c.hostUrl} is unreachable (${e.message}) and no previous analyser ` +
        'output exists on disk, so no Sonar results are available.',
      command: 'docker start sonarqube   # then re-run the MSBuild scanner (begin/build/end)'
    };
  }
}

async function run(ctx) {
  const d = await detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);

  const c = cfgOf(ctx);
  const started = Date.now();
  fs.mkdirSync(path.join(ctx.outPath, 'raw'), { recursive: true });

  // ---------------- offline mode: parse analyser output left on disk ----------------
  if (d.mode === 'offline') {
    const legacySrc = path.join(ctx.sourcePath, c.offlineIssuesPath);
    const src = fs.existsSync(legacySrc) ? legacySrc : (findOfflineExport(ctx.sourcePath) || legacySrc);
    const rawPath = path.join(ctx.outPath, 'raw', 'sonarqube-offline.json');
    let raw = '';
    try { raw = fs.readFileSync(src, 'utf8'); fs.writeFileSync(rawPath, raw); }
    catch (e) { return C.failed(ID, 'Could not read offline analyser output: ' + e.message); }

    const findings = parse(raw, ctx);
    return {
      status: 'EXECUTED', tool: ID, version: 'offline',
      command: `read ${c.offlineIssuesPath} (server unreachable)`,
      exitCode: 0, durationMs: Date.now() - started, rawPath, findings,
      notes: `Offline mode: parsed ${findings.length} issue(s) from a previous analyser run. ` +
        'The server was not reachable, so this reflects the last scan, not the current code.',
      limitations: 'Sonar analyses COMPILED code and never reads Web.config or appsettings.json, so ' +
        'configuration defects are outside its reach entirely. Offline results may also be stale ' +
        'relative to the working tree.'
    };
  }

  // ---------------- server mode ----------------
  const all = [];
  const pages = [];
  for (const type of ['VULNERABILITY', 'BUG', 'CODE_SMELL']) {
    for (let p = 1; p <= c.maxPages; p++) {
      const url = `${c.hostUrl}/api/issues/search?componentKeys=${encodeURIComponent(c.projectKey)}` +
        `&types=${type}&ps=${c.pageSize}&p=${p}&resolved=false`;
      let r;
      try { r = await get(url, c.token, 30000); }
      catch (e) { return C.failed(ID, `Sonar API request failed: ${e.message}`, { durationMs: Date.now() - started }); }
      if (r.statusCode === 401 || r.statusCode === 403) {
        return C.failed(ID, `Sonar API returned ${r.statusCode}: SONAR_TOKEN is missing or lacks Browse permission.`,
          { exitCode: r.statusCode });
      }
      if (r.statusCode !== 200) {
        return C.failed(ID, `Sonar API returned HTTP ${r.statusCode}`, { exitCode: r.statusCode });
      }
      let doc;
      try { doc = JSON.parse(r.body); } catch { return C.failed(ID, 'Sonar API returned invalid JSON'); }
      pages.push(doc);
      all.push(...(doc.issues || []));
      const total = Number(doc.total || 0);
      if (p * c.pageSize >= total) break;
    }
  }

  // Security hotspots live on a separate endpoint.
  try {
    const hr = await get(`${c.hostUrl}/api/hotspots/search?projectKey=${encodeURIComponent(c.projectKey)}&ps=500`,
      c.token, 30000);
    if (hr.statusCode === 200) {
      const hd = JSON.parse(hr.body);
      pages.push(hd);
      (hd.hotspots || []).forEach(h => all.push(Object.assign({ type: 'SECURITY_HOTSPOT' }, h)));
    }
  } catch { /* hotspots are best-effort; absence is not a failure */ }

  const rawPath = path.join(ctx.outPath, 'raw', 'sonarqube.json');
  const raw = JSON.stringify({ issues: all, _pages: pages.length }, null, 2);
  fs.writeFileSync(rawPath, raw);

  const findings = parse(raw, ctx);
  return {
    status: 'EXECUTED', tool: ID, version: d.version,
    command: `GET ${c.hostUrl}/api/issues/search?componentKeys=${c.projectKey} (+ /api/hotspots/search)`,
    exitCode: 0, durationMs: Date.now() - started, rawPath, findings,
    notes: `Fetched ${all.length} unresolved issue(s) and hotspot(s) for project ${c.projectKey}.`,
    limitations: 'Sonar analyses COMPILED code: it never reads Web.config or appsettings.json, so ' +
      'configuration is a structural blind spot. On .NET Framework it also produces no C# analysis ' +
      'at all unless the MSBuild scanner (begin/build/end) was used, so verify how the scan was run ' +
      'before trusting a low issue count.'
  };
}

/** Pure. Accepts either the shape this adapter writes, or a raw Issues.json from the analyser. */
function parse(raw, ctx) {
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || typeof doc !== 'object') return [];

  // Server shape: {issues:[...]}. Analyser-on-disk shape: {Issues:[...]} with PascalCase.
  // Roslyn-analyser exports are SARIF: {runs:[{results:[...]}]} — flatten to issue-likes.
  let issues = Array.isArray(doc.issues) ? doc.issues
    : Array.isArray(doc.Issues) ? doc.Issues
      : Array.isArray(doc) ? doc : null;
  if (!issues && Array.isArray(doc.runs)) {
    issues = [];
    for (const run of doc.runs) {
      for (const r of (run.results || [])) {
        if (!r || typeof r !== 'object') continue;
        let uri = '', line;
        for (const loc of (r.locations || [])) {
          const phys = loc.physicalLocation || loc.resultFile || {};
          uri = (phys.artifactLocation && phys.artifactLocation.uri) || phys.uri || '';
          line = (phys.region && phys.region.startLine) || line;
          if (uri) break;
        }
        try { uri = decodeURIComponent(String(uri).replace(/\\/g, '/')); } catch { uri = String(uri).replace(/\\/g, '/'); }
        for (const pfx of ['file:///', 'file:']) {
          if (uri.toLowerCase().startsWith(pfx)) uri = uri.slice(pfx.length);
        }
        const root = ctx && ctx.sourcePath ? path.resolve(ctx.sourcePath).replace(/\\/g, '/').toLowerCase() + '/' : null;
        if (root && uri.toLowerCase().startsWith(root)) uri = uri.slice(root.length);
        issues.push({
          rule: r.ruleId || '',
          message: typeof r.message === 'string' ? r.message : (r.message && r.message.text) || '',
          severity: r.level === 'error' ? 'CRITICAL' : r.level === 'warning' ? 'MAJOR' : 'MINOR',
          component: 'sangeneric:' + uri,
          line,
        });
      }
    }
  }
  if (!issues) return [];

  const out = [];
  for (const i of issues) {
    if (!i || typeof i !== 'object') continue;

    // Normalise both casings.
    const ruleId = i.rule || i.RuleId || i.ruleKey || '';
    const message = i.message || i.Message || '';
    const type = i.type || i.Type || (/hotspot/i.test(i.securityCategory || '') ? 'SECURITY_HOTSPOT' : 'CODE_SMELL');
    const sev = i.severity || i.Severity || i.vulnerabilityProbability || 'MAJOR';
    const comp = i.component || i.Component || i.FileName || '';
    const line = i.line || i.Line || (i.textRange && i.textRange.startLine) ||
      (i.Location && i.Location.StartLine) || undefined;

    if (!ruleId && !message) continue;

    // Strip the Sonar project prefix from component keys: "key:path/to/File.cs"
    const file = String(comp).includes(':') ? String(comp).split(':').slice(1).join(':') : String(comp);
    const shortRule = String(ruleId).includes(':') ? String(ruleId).split(':').pop() : String(ruleId);

    out.push({
      title: (message || shortRule).slice(0, 200),
      category: TYPE_CATEGORY[type] || 'code-quality',
      subcategory: shortRule || undefined,
      severity: C.normaliseSeverity(sev, 'MEDIUM'),
      // Sonar hotspots are explicitly "review me", not confirmed defects.
      confidence: type === 'SECURITY_HOTSPOT' ? 'POSSIBLE' : 'LIKELY',
      cvss: null,   // Sonar does not emit CVSS; inventing one would be dishonest
      cwe: undefined,
      location: { file: file || '(unknown)', startLine: line },
      evidence: {
        snippet: '',
        language: 'csharp',
        toolOutput: `sonarqube rule=${ruleId} type=${type} severity=${sev}` +
          (i.effort || i.debt ? ` effort=${i.effort || i.debt}` : '')
      },
      problem: message || '',
      impact: type === 'SECURITY_HOTSPOT'
        ? 'Flagged by Sonar as a security hotspot: a construct that REQUIRES human review rather than ' +
          'a confirmed defect. Treat it as a question, not a finding, until reviewed.'
        : '',
      recommendation: `See the SonarQube rule ${shortRule} for guidance.`,
      detection: { class: 'DETERMINISTIC', rules: [{ engine: 'sonarqube', ruleId: shortRule, status: 'EXISTS' }] },
      sources: [{
        tool: ID, sourceFindingId: shortRule, status: 'REPORTED',
        note: type === 'SECURITY_HOTSPOT' ? 'security hotspot (review-required)' : undefined
      }],
      status: 'OPEN'
    });
  }
  return out;
}

module.exports = {
  id: ID, name: 'SonarQube', kind: 'quality',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse
};
