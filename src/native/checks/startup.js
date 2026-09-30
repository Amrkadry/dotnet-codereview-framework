'use strict';
/**
 * Native checks over application startup: Startup.cs, Program.cs, Global.asax(.cs), OWIN
 * Startup files. These decide the REQUEST PIPELINE, so project-level facts (which middleware
 * never runs) live here rather than in per-file checks.
 *
 * The absence findings (no HSTS, no security headers, no authorization middleware) are LIKELY,
 * not CONFIRMED: headers can be added at the host/CDN layer this engine cannot see. The finding
 * says exactly that, so a reviewer can confirm against the hosting layer instead of trusting
 * or dismissing the flag.
 */

const fs = require('fs');
const path = require('path');
const { finding } = require('../finding');

const STARTUP_FILES = /(?:^|[/\\])(Startup|Program|Global)\.(cs|vb)$|(?:^|[/\\])Startup\.\w+\.(?:cs|vb)$/i;

function stripComments(lines) {
  const out = [];
  let inBlock = false;
  for (const raw of lines) {
    let line = '';
    let i = 0;
    while (i < raw.length) {
      if (inBlock) {
        const end = raw.indexOf('*/', i);
        if (end < 0) { i = raw.length; continue; }
        inBlock = false; i = end + 2; continue;
      }
      const block = raw.indexOf('/*', i);
      const lineC = raw.indexOf('//', i);
      if (lineC >= 0 && (block < 0 || lineC < block)) break;
      if (block >= 0) { line += raw.slice(i, block); inBlock = true; i = block + 2; continue; }
      line += raw.slice(i); break;
    }
    out.push(line);
  }
  return out;
}

/** Each check: { id, caseIds, run(ctx) }. ctx: {relPath, text, lines, emit, project}. */
const CHECKS = [
  {
    id: 'startup-security-headers',
    caseIds: ['N-004', 'F-005'],
    run(ctx) {
      if (!/(Configure(?:Services)?|UseRouting|MapControllers|Application_Start)\s*\(/.test(ctx.text)) return;
      if (/\.UseHsts\s*\(|UseSecurityHeaders|X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|UseHsts\(/i.test(ctx.text)) return;
      const line = Math.max(1, ctx.lines.findIndex(l => /void\s+Configure|Configure\s*\(|Application_Start/.test(l)) + 1);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'MEDIUM',
        category: 'configuration', cwe: ['CWE-693'], language: 'csharp',
        title: 'Request pipeline sets no security headers and no HSTS',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines.slice(Math.max(0, line - 1), line + 4).join('\n'),
        problem: 'The pipeline configuration contains neither UseHsts/UseSecurityHeaders nor any ' +
          'explicit security-header assignment, so responses ship with browser-default behaviour.',
        impact: 'Without nosniff, CSP and frame protection, a single injection point becomes ' +
          'script execution, clickjacking or content confusion; without HSTS an initial plain-HTTP ' +
          'request is hijackable.',
        recommendation: 'Add app.UseHsts() and app.UseSecurityHeaders() (or Web.config customHeaders ' +
          'for hosted IIS) unless the edge/CDN layer demonstrably sets the full header set — verify there, then.',
        possibleNote: 'Likely: headers could be set at the reverse proxy or CDN, which source review cannot see.'
      }));
    }
  },
  {
    id: 'startup-cors',
    caseIds: ['N-001', 'N-002', 'N-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const hasAnyOrigin = stripped.some(l => /AllowAnyOrigin\s*\(/.test(l));
      const hasCred = stripped.some(l => /AllowCredentials\s*\(/.test(l));
      if (!hasAnyOrigin) return;
      const line = Math.max(1, stripped.findIndex(l => /AllowAnyOrigin\s*\(/.test(l)) + 1);
      ctx.emit(finding({
        check: this.id,
        caseIds: hasCred ? ['N-002'] : ['N-001', 'N-003'],
        confidence: 'LIKELY', severity: hasCred ? 'CRITICAL' : 'HIGH',
        category: 'security', cwe: hasCred ? ['CWE-942'] : ['CWE-346'], language: 'csharp',
        title: hasCred ? 'CORS policy allows any origin with credentials'
          : 'CORS policy allows any origin',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines.slice(Math.max(0, line - 1), line + 4).join('\n'),
        problem: 'A CORS policy built on AllowAnyOrigin is registered' +
          (hasCred ? ' together with AllowCredentials.' : '.'),
        impact: hasCred
          ? 'The intended configuration is invalid per the fetch specification; any relaxation of ' +
            'the wildcard later inherits credential-bearing cross-origin access.'
          : 'Any web origin can read this API\u2019s non-credentialed responses, which turns any ' +
            'unauthenticated data endpoint into a bulk-export endpoint for third-party scripts.',
        recommendation: 'Name exact origins in the policy (WithOrigins("https://app.example.com")) ' +
          'and keep credentials out of wildcard policies entirely.'
      }));
    }
  },
  {
    id: 'startup-dev-exception',
    caseIds: ['H-002', 'H-001'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(/\.UseDeveloperExceptionPage\s*\(/);
        if (!m) continue;
        // An env guard on the SAME line (if (env.IsDevelopment()) app.UseDeveloperExceptionPage())
        // or immediately above (3 lines) is the standard safe pattern.
        const guarded = /IsDevelopment\s*\(|if\s*\(/.test(stripped[i]) || /if\s*\(\s*\w+\.IsDevelopment/.test(stripped[Math.max(0, i - 1)]);
        if (guarded) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'HIGH',
          category: 'configuration', cwe: ['CWE-209'], language: 'csharp',
          title: 'Developer exception page registered without a visible environment guard',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 2).join('\n'),
          problem: 'UseDeveloperExceptionPage() is registered unconditionally in this branch of ' +
            'the pipeline — no IsDevelopment check is visible at the call site.',
          impact: 'In production, full exception detail — stack traces, connection strings in ' +
            'messages, internal paths — renders to end users.',
          recommendation: 'Wrap the call in if (app.Environment.IsDevelopment()) and register ' +
            'UseExceptionHandler("/error") for everything else.',
          possibleNote: 'Likely: the environment may be constrained elsewhere (WebHost.CreateDefaultBuilder ' +
            'prefixes); confirm at the host before treating production as exposed.'
        }));
      }
    }
  },
  {
    id: 'startup-authz-middleware',
    caseIds: ['B-002', 'W-012'],
    run(ctx) {
      if (!/app\s*\.\s*(?:Use|Map)/.test(ctx.text)) return;
      const stripped = stripComments(ctx.lines);
      const hasEndpoints = /MapControllers\s*\(|MapRazorPages\s*\(|Map\w+Endpoints?\s*\(|MapGet\s*\(|MapPost\s*\(/.test(ctx.text);
      if (!hasEndpoints) return;
      const hasAuthz = /UseAuthorization\s*\(|RequireAuthorization\s*\(|\[Authorize\]|FallbackPolicy|AddAuthorization/.test(ctx.text);
      const hasAuthn = /UseAuthentication\s*\(|AddAuthentication/.test(ctx.text);
      if (hasAuthz || hasAuthn) return;
      const line = Math.max(1, stripped.findIndex(l => /MapControllers|MapRazorPages|Map\w+Endpoints?\s*\(|MapGet\s*\(|MapPost\s*\(/.test(l)) + 1);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
        category: 'security', cwe: ['CWE-862'], language: 'csharp',
        title: 'No authentication or authorization anywhere in the request pipeline',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines.slice(Math.max(0, line - 1), line + 4).join('\n'),
        problem: 'Endpoints are mapped, but the pipeline never calls UseAuthentication/UseAuthorization ' +
          'and no fallback authorization policy is configured.',
        impact: 'Every endpoint is anonymous by default. Authorization then depends entirely on ' +
          'per-endpoint attributes; one forgotten [Authorize] is a public endpoint, and nothing ' +
          'catches the omission.',
        recommendation: 'Add app.UseAuthentication()/app.UseAuthorization() and set ' +
          'FallbackPolicy = RequireAuthenticatedUser so the default is deny-by-default and ' +
          '[AllowAnonymous] becomes the explicit, reviewable exception.'
      }));
    }
  }
];

/** Are any startup files present in the walked file list? Returns matched file records. */
function startupFiles(files) {
  return files.filter(f => STARTUP_FILES.test(f));
}

module.exports = { CHECKS, startupFiles, stripComments, STARTUP_FILES };
