'use strict';
/**
 * AI-assisted review adapter.
 *
 * WHY THIS IS A TOOL AND NOT THE PIPELINE
 * AI review complements deterministic tooling; it does not replace it. Static analysers are strong
 * on hygiene and blind to design-level access control; AI review is the reverse, and it is also
 * capable of confident, wrong reasoning. So its output is labelled `tool: 'ai-review'`, capped at
 * confidence POSSIBLE, and it never receives a CVSS score from the model. A human or a
 * deterministic rule must confirm before a finding is treated as CONFIRMED.
 *
 * KEY HANDLING — the security requirements of this adapter itself:
 *   - API keys are read ONLY from environment variables. Never from config files, never CLI args
 *     (argv is visible in process listings).
 *   - Keys are never logged, never written to raw output, never included in a finding.
 *   - The raw response written to data/raw/ is scrubbed of anything key-shaped before writing.
 *   - Source code is SENT TO A THIRD PARTY. This adapter is therefore OPT-IN: it stays
 *     NOT_APPLICABLE unless config.tools['ai-review'].enabled is explicitly true, and it prints
 *     what it is about to transmit.
 *
 * Providers (auto-detected from whichever key is present):
 *   ANTHROPIC_API_KEY  -> api.anthropic.com   /v1/messages
 *   OPENAI_API_KEY     -> api.openai.com      /v1/chat/completions
 *   ZAI_API_KEY        -> api.z.ai            (OpenAI-compatible)
 *   MORAA_AI_BASE_URL  -> override for a self-hosted OpenAI-compatible endpoint
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { URL } = require('url');
const C = require('../core/adapter-contract');

const ID = 'ai-review';

const PROVIDERS = [
  { env: 'ANTHROPIC_API_KEY', name: 'anthropic', base: 'https://api.anthropic.com', model: 'claude-sonnet-5' },
  { env: 'OPENAI_API_KEY', name: 'openai', base: 'https://api.openai.com', model: 'gpt-4o' },
  { env: 'ZAI_API_KEY', name: 'zai', base: 'https://api.z.ai/api/paas/v4', model: 'glm-5.3' }
];

/** Redact anything that looks like a credential before it is written anywhere. */
function scrub(s) {
  return String(s == null ? '' : s)
    .replace(/(sk-[A-Za-z0-9_\-]{12,})/g, 'sk-***REDACTED***')
    .replace(/(sk-ant-[A-Za-z0-9_\-]{12,})/g, 'sk-ant-***REDACTED***')
    .replace(/\b[0-9a-f]{32}\.[A-Za-z0-9]{16,}\b/g, '***REDACTED***')
    .replace(/(Bearer\s+)[A-Za-z0-9._\-]{16,}/gi, '$1***REDACTED***')
    .replace(/("?(?:api[_-]?key|authorization|x-api-key)"?\s*[:=]\s*")[^"]+(")/gi, '$1***REDACTED***$2');
}

function pickProvider(env) {
  for (const p of PROVIDERS) if (env[p.env]) return p;
  return null;
}

function detect(ctx) {
  const env = ctx.env || process.env;
  const cfg = (ctx.config && ctx.config.tools && ctx.config.tools[ID]) || {};
  if (!cfg.enabled) {
    return {
      available: false,
      reason: 'AI review is opt-in because it transmits source code to a third-party API. ' +
        'Enable with tools."ai-review".enabled = true in moraa.config.json.',
      command: 'set ANTHROPIC_API_KEY=...   (or OPENAI_API_KEY / ZAI_API_KEY)'
    };
  }
  const p = pickProvider(env);
  if (!p) {
    return {
      available: false,
      reason: 'AI review is enabled but no API key is present in the environment. Keys are read ' +
        'only from env vars, never from config files or CLI arguments.',
      command: 'set ANTHROPIC_API_KEY=...   (or OPENAI_API_KEY / ZAI_API_KEY)'
    };
  }
  return { available: true, version: `${p.name}:${cfg.model || p.model}`, provider: p };
}

/** Choose the highest-value files to review, within a budget. */
function selectFiles(ctx, cfg) {
  const maxFiles = cfg.maxFiles || 12;
  const maxBytes = cfg.maxBytesPerFile || 60000;
  // Priority: auth, authorization, config wiring, data access, then controllers.
  const PRIORITY = [
    /auth/i, /identity|login|token|jwt|principal/i, /startup|global\.asax|program\.cs/i,
    /config/i, /middleware|filter|handler/i, /repositor|dataaccess|dbcontext/i,
    /controller/i, /service/i
  ];
  const out = [];
  const walk = dir => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (/^(bin|obj|packages|node_modules|\.git|\.vs|\.moraa-review|\.sonarqube)$/i.test(e.name)) continue;
        walk(full);
      } else if (/\.(cs|config|json)$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { continue; }
        if (size > maxBytes || size === 0) continue;
        out.push(full);
      }
    }
  };
  walk(ctx.sourcePath);

  const score = f => {
    const rel = f.replace(/\\/g, '/');
    for (let i = 0; i < PRIORITY.length; i++) if (PRIORITY[i].test(rel)) return i;
    return PRIORITY.length;
  };
  return out.sort((a, b) => score(a) - score(b)).slice(0, maxFiles);
}

function postJson(urlStr, headers, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      method: 'POST',
      headers: Object.assign({
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body)
      }, headers)
    }, res => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 180000, () => { req.destroy(new Error('AI request timed out')); });
    req.write(body); req.end();
  });
}

const SYSTEM = `You are a .NET application security reviewer. You are given source files from one
application. Report ONLY defects you can point at in the supplied code.

Hard rules:
- Never invent a file path, line number or code snippet. Quote the code verbatim.
- If you are unsure a defect is real, omit it. A short accurate list beats a long speculative one.
- Do NOT report generic advice, style opinions, or anything you cannot tie to a specific line.
- Focus on what static analysers miss: missing authorization, broken access control, ownership
  checks, trust-boundary errors, unsafe configuration wiring, logic that fails open.

Reply with ONLY a JSON array, no prose, no markdown fence. Each element:
{
  "title": "short specific title",
  "file": "path exactly as given to you",
  "startLine": 123,
  "category": "security|configuration|reliability|code-quality|architecture",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cwe": ["CWE-862"],
  "snippet": "verbatim code, max 12 lines",
  "problem": "what is wrong",
  "impact": "what an attacker or a failure achieves, in this application",
  "recommendation": "concrete fix"
}
Return [] if you find nothing you can evidence.`;

async function run(ctx) {
  const d = detect(ctx);
  if (!d.available) {
    return {
      status: (ctx.config?.tools?.[ID]?.enabled) ? 'NOT_AVAILABLE' : 'NOT_APPLICABLE',
      tool: ID, findings: [], notes: d.reason,
      limitations: 'No AI-assisted review was performed. Deterministic tools do not cover ' +
        'design-level access control, so that class may be under-represented in this report.',
      remediation: d.command
    };
  }

  const cfg = (ctx.config.tools && ctx.config.tools[ID]) || {};
  const provider = d.provider;
  const model = cfg.model || provider.model;
  const files = selectFiles(ctx, cfg);
  if (!files.length) {
    return C.failed(ID, 'No reviewable source files were found under the source path.');
  }

  const bundle = files.map(f => {
    const rel = path.relative(ctx.sourcePath, f).replace(/\\/g, '/');
    let text = '';
    try { text = fs.readFileSync(f, 'utf8'); } catch { return null; }
    const numbered = text.split('\n').map((l, i) => `${i + 1}: ${l}`).join('\n');
    return `===== FILE: ${rel} =====\n${numbered}`;
  }).filter(Boolean).join('\n\n');

  // Transparency: say what is being transmitted, without transmitting anything unexpected.
  ctx.log?.(`  ai-review: sending ${files.length} file(s), ${(bundle.length / 1024).toFixed(0)} KB ` +
    `to ${provider.name} (${model}). Source code leaves this machine.`);

  const started = Date.now();
  let resp;
  try {
    if (provider.name === 'anthropic') {
      resp = await postJson(`${cfg.baseUrl || provider.base}/v1/messages`, {
        'x-api-key': (ctx.env || process.env)[provider.env],
        'anthropic-version': '2023-06-01'
      }, {
        model, max_tokens: 8000, system: SYSTEM,
        messages: [{ role: 'user', content: bundle }]
      }, cfg.timeoutMs);
    } else {
      const base = (ctx.env || process.env).MORAA_AI_BASE_URL || cfg.baseUrl || provider.base;
      resp = await postJson(`${base}/v1/chat/completions`.replace('/v4/v1/', '/v4/'), {
        authorization: `Bearer ${(ctx.env || process.env)[provider.env]}`
      }, {
        model, max_tokens: 8000,
        messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: bundle }]
      }, cfg.timeoutMs);
    }
  } catch (e) {
    return C.failed(ID, `AI request failed: ${scrub(e.message)}`, { durationMs: Date.now() - started });
  }

  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    return C.failed(ID, `AI provider returned HTTP ${resp.statusCode}: ${scrub(resp.body).slice(0, 300)}`,
      { exitCode: resp.statusCode, durationMs: Date.now() - started });
  }

  // Persist a SCRUBBED copy for auditability.
  const rawPath = path.join(ctx.outPath, 'raw', 'ai-review.json');
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });
  fs.writeFileSync(rawPath, scrub(resp.body));

  let findings;
  try { findings = parse(resp.body, ctx); } catch (e) {
    return C.failed(ID, 'AI response could not be parsed: ' + scrub(e.message), { rawPath });
  }

  return {
    status: 'EXECUTED', tool: ID, version: `${provider.name}:${model}`,
    command: `POST ${provider.base} (model=${model}, ${files.length} files)`,
    exitCode: 0, durationMs: Date.now() - started, rawPath, findings,
    notes: `AI review of ${files.length} file(s) produced ${findings.length} candidate finding(s). ` +
      'All are capped at confidence POSSIBLE and carry no CVSS: they require confirmation before ' +
      'being treated as established.',
    limitations: 'A model can be confidently wrong. Findings here are leads, not conclusions, and ' +
      'only the files listed in the command were reviewed — this is not whole-repository coverage.'
  };
}

/** Pure. Extracts the JSON array from a provider response of either shape. */
function parse(raw, ctx) {
  if (!raw) return [];
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || typeof doc !== 'object') return [];

  // Pull the assistant text out of either provider envelope.
  let text = '';
  if (Array.isArray(doc.content)) {
    text = doc.content.map(c => (c && c.text) || '').join('\n');           // anthropic
  } else if (Array.isArray(doc.choices)) {
    text = doc.choices.map(c => (c.message && c.message.content) || '').join('\n'); // openai-compatible
  } else if (Array.isArray(doc)) {
    text = JSON.stringify(doc);                                            // already the array
  } else return [];

  if (!text.trim()) return [];
  // Tolerate a fenced block or leading prose.
  const m = text.match(/\[[\s\S]*\]/);
  if (!m) return [];
  let items;
  try { items = JSON.parse(m[0]); } catch { return []; }
  if (!Array.isArray(items)) return [];

  const allowedCat = ['security', 'configuration', 'reliability', 'code-quality', 'architecture'];
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== 'object' || !it.title || !it.file) continue;
    const category = allowedCat.includes(it.category) ? it.category : 'security';
    out.push({
      title: String(it.title).slice(0, 200),
      category,
      subcategory: 'ai-review',
      severity: C.normaliseSeverity(it.severity, 'MEDIUM'),
      // Capped deliberately: a model's assertion is a lead.
      confidence: 'POSSIBLE',
      cvss: null,
      cwe: Array.isArray(it.cwe) ? it.cwe.filter(c => /^CWE-\d+$/.test(c)) : undefined,
      location: {
        file: String(it.file).replace(/\\/g, '/'),
        startLine: Number.isInteger(it.startLine) ? it.startLine : undefined
      },
      evidence: {
        snippet: String(it.snippet || '').split('\n').slice(0, 12).join('\n'),
        language: 'csharp',
        toolOutput: 'ai-review: model-proposed finding, unconfirmed'
      },
      problem: String(it.problem || ''),
      impact: String(it.impact || ''),
      recommendation: String(it.recommendation || ''),
      detection: { class: 'AI_ASSISTED', rules: [] },
      sources: [{
        tool: ID, status: 'REPORTED',
        note: 'AI-proposed; requires human or deterministic confirmation'
      }],
      status: 'UNVERIFIED',
      verification: {
        method: 'Proposed by an AI review of the file contents.',
        outcome: 'UNVERIFIED',
        openQuestion: 'Confirm against the code before acting. AI findings are leads, not conclusions.'
      }
    });
  }
  return out;
}

module.exports = {
  id: ID, name: 'AI-assisted review', kind: 'ai',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse, _scrub: scrub
};
