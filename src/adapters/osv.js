// dotnet-codereview-framework — src/adapters/osv.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * OSV.dev adapter — keyless known-vulnerability matching for packages.config.
 *
 * Queries https://api.osv.dev/v1/querybatch with every (id, version) pair found in
 * packages.config manifests, then fetches per-vuln details for the hits. No API key
 * exists for OSV; the only failure modes are "no manifests" (NOT_APPLICABLE) and
 * "network unreachable" (FAILED with the reason) — a clean bill is only ever returned
 * from a real HTTP 200 with zero matches.
 *
 * This complements snyk/trivy: those need accounts/tokens; OSV is the no-credentials
 * advisory source. It reads the same canonical model and correlates like any tool.
 */

const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');

const ID = 'osv';
const VERSION = '1.0.0';
const API = 'https://api.osv.dev/v1';
const MAX_DETAIL_FETCH = 40; // cap detail round-trips; querybatch already told us the ids

function postJson(url, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    const r = mod.request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, timeout: timeoutMs },
      res => {
        let buf = '';
        res.on('data', d => { buf += d; });
        res.on('end', () => resolve({ statusCode: res.statusCode, body: buf }));
      });
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.on('error', reject);
    r.write(JSON.stringify(body));
    r.end();
  });
}

function getJson(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    const r = mod.get(url, { timeout: timeoutMs }, res => {
      let buf = '';
      res.on('data', d => { buf += d; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: buf }));
    });
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.on('error', reject);
  });
}

/** Pure: parse packages.config manifests into [{file, line, id, version}]. */
function collectPackages(sourcePath) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (/^(bin|obj|packages|node_modules|\.git|\.vs|tests?|Migrations)$/i.test(e.name)) continue;
        walk(path.join(dir, e.name), depth + 1);
      } else if (e.name.toLowerCase() === 'packages.config') {
        const file = path.join(dir, e.name);
        let lines;
        try { lines = fs.readFileSync(file, 'utf8').split(/\r?\n/); } catch { continue; }
        lines.forEach((line, i) => {
          const m = line.match(/<package\s+id="([^"]+)"\s+version="([^"]+)"/);
          if (m) out.push({
            file: path.relative(sourcePath, file).replace(/\\/g, '/'),
            line: i + 1, id: m[1], version: m[2],
          });
        });
      }
    }
  };
  walk(sourcePath, 0);
  return out;
}

/** Pure: map querybatch results + details into canonical findings. */
function parse(raw, ctx) {
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || !Array.isArray(doc.packages) || !Array.isArray(doc.vulns)) return [];

  const details = {};
  for (const v of doc.vulns) details[v.id] = v;

  const out = [];
  for (const hit of doc.packages) {
    const v = details[hit.vulnId] || {};
    const sevLabel = (v.database_specific && v.database_specific.severity) || '';
    const cvssVec = (v.severity || []).find(s => /CVSS/i.test(s.type || ''));
    const fixed = [];
    for (const aff of v.affected || []) {
      for (const range of aff.ranges || []) {
        for (const ev of range.events || []) if (ev.fixed) fixed.push(ev.fixed);
      }
    }
    const summary = (v.summary || v.details || hit.vulnId || 'known vulnerability').split('\n')[0].slice(0, 300);
    out.push({
      title: `${hit.packageId} ${hit.version}: ${hit.vulnId}`,
      category: 'dependency',
      subcategory: hit.vulnId,
      severity: C.normaliseSeverity(
        sevLabel === 'CRITICAL' ? 'CRITICAL' : sevLabel === 'HIGH' ? 'HIGH' :
        sevLabel === 'LOW' ? 'LOW' : 'MEDIUM', 'MEDIUM'),
      confidence: 'CONFIRMED', // the advisory match is a database fact, not a heuristic
      cvss: null,
      cwe: (v.cwe || []).slice(0, 3),
      advisories: [hit.vulnId],
      location: { file: hit.file, startLine: hit.line },
      evidence: {
        snippet: `<package id="${hit.packageId}" version="${hit.version}" />`,
        language: 'xml',
        toolOutput: `osv.dev ${hit.vulnId}: ${summary}` +
          (fixed.length ? ` — fixed in ${fixed.slice(0, 3).join(', ')}` : ' — no fix published'),
      },
      package: { name: hit.packageId, installed: hit.version, fixed: fixed[0] || null },
      detection: { class: 'DETERMINISTIC', rules: [{ engine: ID, ruleId: hit.vulnId, status: 'EXISTS' }] },
      sources: [{ tool: ID, sourceFindingId: hit.vulnId, status: 'REPORTED' }],
      status: 'OPEN',
      problem: `${hit.packageId} ${hit.version} matches published vulnerability ${hit.vulnId}: ${summary}`,
      impact: 'Known-exploited or publicly documented vulnerabilities in dependencies are the ' +
        'cheapest attack surface an attacker can buy: the defect is documented and the exploit ' +
        'is often public.',
      attackScenario: 'Attacker looks up the dependency version (error pages, repos, artifact ' +
        'strings) and applies the public exploit for ' + hit.vulnId + '.',
      recommendation: fixed.length
        ? `Upgrade ${hit.packageId} to ${fixed.slice(0, 1)[0]} (or later). Verify no breaking API usage, then re-run the review.`
        : `No fixed version is published for ${hit.vulnId}. Isolate or replace ${hit.packageId}; apply the advisory mitigations.`,
      tests: ['O-001'],
    });
  }
  return out;
}

async function detect(ctx) {
  const pkgs = collectPackages(ctx.sourcePath);
  return {
    available: pkgs.length > 0,
    version: VERSION,
    reason: pkgs.length ? `${pkgs.length} package reference(s) in packages.config` : 'no packages.config manifests found',
    command: 'POST https://api.osv.dev/v1/querybatch',
  };
}

async function run(ctx) {
  const d = await detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);
  const started = Date.now();
  fs.mkdirSync(path.join(ctx.outPath, 'raw'), { recursive: true });

  const pkgs = collectPackages(ctx.sourcePath);
  let batchRes;
  try {
    batchRes = await postJson(API + '/querybatch',
      { queries: pkgs.map(p => ({ package: { name: p.id, ecosystem: 'NuGet' }, version: p.version })) },
      45000);
  } catch (e) {
    return C.failed(ID, `OSV.dev unreachable: ${e.message}`, { durationMs: Date.now() - started });
  }
  if (batchRes.statusCode !== 200) {
    return C.failed(ID, `OSV.dev returned HTTP ${batchRes.statusCode}`, { durationMs: Date.now() - started });
  }

  let batch;
  try { batch = JSON.parse(batchRes.body); } catch (e) {
    return C.failed(ID, 'OSV.dev returned unparseable batch output: ' + e.message);
  }

  // zip queries with results
  const hits = [];
  (batch.results || []).forEach((r, i) => {
    for (const v of ((r || {}).vulns || [])) hits.push({ pkg: pkgs[i], vulnId: v.id });
  });

  // fetch details for unique ids (capped)
  const vulns = [];
  const unique = [...new Set(hits.map(h => h.vulnId))].slice(0, MAX_DETAIL_FETCH);
  for (const vid of unique) {
    try {
      const r = await getJson(API + '/vulns/' + encodeURIComponent(vid), 30000);
      if (r.statusCode === 200) vulns.push(JSON.parse(r.body));
    } catch { /* detail loss is survivable; the id alone is actionable */ }
  }

  const raw = JSON.stringify({ packages: hits.map(h => ({
    packageId: h.pkg.id, version: h.pkg.version, file: h.pkg.file, line: h.pkg.line,
    vulnId: h.vulnId })), vulns }, null, 1);
  const rawPath = path.join(ctx.outPath, 'raw', 'osv.json');
  fs.writeFileSync(rawPath, raw);

  const findings = parse(raw, ctx);
  return {
    status: 'EXECUTED', tool: ID, version: VERSION,
    command: `POST ${API}/querybatch (${pkgs.length} packages) + ${unique.length} vuln detail fetch(es)`,
    exitCode: 0, durationMs: Date.now() - started, rawPath, findings,
    notes: `${pkgs.length} packages checked against OSV.dev; ${hits.length} vulnerable ` +
      `reference(s) across ${unique.length} distinct advisories.`,
    limitations: 'OSV covers published advisories only (no private/commercial intel); version ' +
      'matching depends on the ranges published per advisory. Transitive dependencies resolved ' +
      'at build time are not visible from packages.config alone.',
  };
}

module.exports = { id: ID, name: 'OSV.dev', kind: 'dependency', stacks: ['both'], detect, run, parse };
