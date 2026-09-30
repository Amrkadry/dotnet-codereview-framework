'use strict';
/**
 * Native checks over XML configuration: Web.config, app.config, machine.config-level files.
 *
 * These are the CONFIRMED layer of the native engine: the fact is literally in the file —
 * debug="true" is present, customErrors mode is "Off", a connection string embeds a password.
 * No dataflow speculation is needed, so these findings carry confidence CONFIRMED.
 *
 * REDACTION: configuration snippets routinely contain live secrets. Every snippet passes
 * through redactSecrets() before it becomes evidence, and the finding text never repeats the
 * value. The finding says a credential is present; it does not duplicate the credential into
 * the report — the report is exactly the artifact most likely to be shared.
 */

const { finding } = require('../finding');

const attr = (text, name) => {
  const m = text.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`, 'i'));
  return m ? m[1] : null;
};

/** Mask secret-looking attribute values inside a snippet, keeping position/shape readable. */
function redactSecrets(snippet) {
  return snippet
    .replace(/(password|pwd|secret|key|credential|token)(\s*=\s*)("[^"]*"|'[^']*'|[^\s;]+)/gi,
      (m, k, eq) => `${k}${eq}***REDACTED***`)
    .replace(/(connectionString\s*=\s*")([^"]*)"/gi,
      (m, pre, val) => pre + val.replace(/(password|pwd)=[^;"]+/gi, '$1=***REDACTED***') + '"');
}

const REDACTED = { redacted: true };

/** Each check: { id, caseIds, run(ctx) }. ctx: {relPath, text, lines, emit, stack}. */
const CHECKS = [
  {
    id: 'web-debug-compilation',
    caseIds: ['N-006'],
    run(ctx) {
      const m = ctx.text.match(/<compilation[^>]*\bdebug\s*=\s*"true"[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'MEDIUM',
        category: 'configuration', cwe: ['CWE-11'],
        title: 'Debug compilation enabled in Web.config',
        file: ctx.relPath, startLine: line,
        snippet: redactSecrets(ctx.lines[line - 1]),
        language: 'xml',
        problem: '<compilation debug="true"> is present in configuration, so ASP.NET compiles ' +
          'pages in debug mode regardless of the build configuration.',
        impact: 'Debug builds disable optimisations, extend execution timeouts, batch-compilation ' +
          'and symbol generation, leak file/line detail in errors, and are measurably slower ' +
          'under load. Microsoft explicitly does not support production deployments with debug=true.',
        recommendation: 'Set debug="false" (or remove the attribute — false is the default) and ' +
          'verify the deployed artefact via <deployment retail="true" /> in machine.config-level ' +
          'hardening where possible.'
      }));
    }
  },
  {
    id: 'web-custom-errors-off',
    caseIds: ['H-002', 'H-001'],
    run(ctx) {
      const m = ctx.text.match(/<customErrors[^>]*\bmode\s*=\s*"Off"[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
        category: 'configuration', cwe: ['CWE-209'],
        title: 'customErrors mode="Off" — ASP.NET error detail returns to clients',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines[line - 1],
        language: 'xml',
        problem: 'customErrors is explicitly Off, so unhandled exceptions render full ASP.NET ' +
          'error pages (yellow screens) with stack traces, source paths and framework internals.',
        impact: 'An attacker probing endpoints receives exception detail that names classes, ' +
          'queries, file paths and library versions — a map for the next exploitation step.',
        recommendation: 'Set <customErrors mode="RemoteOnly" defaultRedirect="~/error" /> and ' +
          'ensure handled error pages do not echo exception.ToString().'
      }));
    }
  },
  {
    id: 'web-machinekey',
    caseIds: ['A-015', 'T-002'],
    run(ctx) {
      const m = ctx.text.match(/<machineKey[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      const el = m[0];
      const vkey = attr(el, 'validationKey');
      const dkey = attr(el, 'decryptionKey');
      const validation = (attr(el, 'validation') || '').toUpperCase();
      const decryption = (attr(el, 'decryption') || '').toUpperCase();
      const problems = [];
      const keyish = k => k && !/AutoGenerate/i.test(k);
      if (keyish(vkey) && vkey.replace(/[^0-9A-Fa-f]/g, '').length < 64 && !vkey.includes(','))
        problems.push(`validationKey is shorter than the 64-hex-char minimum (${vkey.length} chars)`);
      if (keyish(dkey) && dkey.replace(/[^0-9A-Fa-f]/g, '').length < 48 && !dkey.includes(','))
        problems.push(`decryptionKey is shorter than the 48-hex-char minimum (${dkey.length} chars)`);
      if (validation === 'SHA1') problems.push('validation="SHA1" uses a SHA-1 HMAC');
      if (validation === 'MD5' || decryption === 'DES')
        problems.push(`weak algorithm selected: ${validation === 'MD5' ? 'MD5' : 'DES'}`);
      if (validation === '3DES') problems.push('validation="3DES" (legacy triple-DES)');
      if (!problems.length) return;
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'CRITICAL',
        category: 'security', cwe: ['CWE-321', 'CWE-326'],
        title: 'Weak machineKey material in configuration',
        file: ctx.relPath, startLine: line,
        snippet: redactSecrets(el),
        language: 'xml',
        problem: 'machineKey ' + problems.join('; ') + '. The machineKey protects ViewState, ' +
          'forms-authentication tickets and anti-forgery tokens on ASP.NET Framework.',
        impact: 'A short, weak or well-known key allows ViewState forgery — which is ' +
          'unauthenticated remote code execution on projects with unsafe ViewState ' +
          'deserialisation gadget chains — and forged authentication tickets.',
        attackScenario: 'An attacker who learns or brute-forces the machineKey signs a malicious ' +
          'ViewState payload (or a __VIEWSTATEGENERATOR-consistent postback) and the server ' +
          'deserialises it as trusted.',
        recommendation: 'Generate a strong per-environment machineKey ' +
          '(validationKey 64+ hex chars, decryptionKey 48+ hex chars, validation="HMACSHA256", ' +
          'decryption="AES"), store it outside source control, and never share it across apps.'
      }));
    }
  },
  {
    id: 'web-viewstate-mac',
    caseIds: ['J-006', 'T-001'],
    run(ctx) {
      const m = ctx.text.match(/<pages[^>]*\b(enableViewStateMac\s*=\s*"false"|viewStateEncryptionMode\s*=\s*"Never")[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'CRITICAL',
        category: 'security', cwe: ['CWE-502'],
        title: 'ViewState integrity protection disabled in <pages>',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines[line - 1],
        language: 'xml',
        problem: 'Pages configuration disables ViewState MAC validation (or encryption entirely), ' +
          'so clients can tamper with ViewState and the server will trust it.',
        impact: 'ViewState becomes an attacker-controlled deserialisation payload. Combined with ' +
          'any gadget chain in the loaded assemblies this is remote code execution without ' +
          'authentication.',
        recommendation: 'Remove the override — MAC validation is on by default for the runtime the ' +
          'project targets — and keep viewStateEncryptionMode at Auto or Always.'
      }));
    }
  },
  {
    id: 'web-request-validation',
    caseIds: ['D-004'],
    run(ctx) {
      const hits = [];
      let m;
      const re1 = /<(?:pages|httpRuntime)[^>]*\b(validateRequest\s*=\s*"false"|requestValidationMode\s*=\s*"2\.0")[^>]*>/gi;
      while ((m = re1.exec(ctx.text)) !== null) hits.push(m);
      for (const hit of hits) {
        const line = lineOf(ctx.lines, hit.index);
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
          category: 'security', cwe: ['CWE-79'],
          title: 'ASP.NET request validation disabled or downgraded',
          file: ctx.relPath, startLine: line,
          snippet: hit[0],
          language: 'xml',
          problem: hit[0].includes('requestValidationMode="2.0"')
            ? 'requestValidationMode="2.0" reverts request validation to the ASP.NET 2.0 ' +
              'page-level behaviour, silently weakening the built-in XSS tripwire.'
            : 'validateRequest="false" turns off the ASP.NET request validation that rejects ' +
              'potentially dangerous input (including markup) at the request level.',
          impact: 'Unencoded input reaches page code and output paths with one fewer safety net; ' +
            'reflected XSS depends now entirely on per-site output encoding discipline.',
          recommendation: 'Remove the downgrade. If specific endpoints must accept markup, use ' +
            'the AllowHtml attribute on the narrowest possible model property and encode on output.'
        }));
      }
    }
  },
  {
    id: 'web-trace',
    caseIds: ['N-007'],
    run(ctx) {
      const m = ctx.text.match(/<trace[^>]*\benabled\s*=\s*"true"[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
        category: 'configuration', cwe: ['CWE-489'],
        title: 'ASP.NET tracing enabled (trace.axd)',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines[line - 1],
        language: 'xml',
        problem: '<trace enabled="true"> exposes trace.axd, which lists recent requests with ' +
          'session ids, cookie contents, headers, form values and server variables.',
        impact: 'Anyone who can reach trace.axd reads other users\u2019 session cookies and any ' +
          'secret that transited a request — a complete session-hijacking primitive.',
        recommendation: 'Set enabled="false" (and requestLimit/localOnly defaults) in production; ' +
          'diagnose locally or through a correlated logging pipeline instead.'
      }));
    }
  },
  {
    id: 'web-directory-browsing',
    caseIds: ['N-009'],
    run(ctx) {
      const m = ctx.text.match(/<directoryBrowse[^>]*\benabled\s*=\s*"true"[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'MEDIUM',
        category: 'configuration', cwe: ['CWE-548'],
        title: 'Directory browsing enabled',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines[line - 1],
        language: 'xml',
        problem: '<directoryBrowse enabled="true"> lets IIS render directory listings.',
        impact: 'Attackers enumerate files that were never linked: backups, config copies, logs, ' +
          'exported data — turning reconnaissance into targeted retrieval.',
        recommendation: 'Remove the element (disabled is the default) and keep the webroot free ' +
          'of anything the app does not deliberately serve.'
      }));
    }
  },
  {
    id: 'web-forms-auth',
    caseIds: ['T-009', 'T-010', 'N-005'],
    run(ctx) {
      const m = ctx.text.match(/<forms[^>]*>/i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      const el = m[0];
      const protection = (attr(el, 'protection') || '').toUpperCase();
      const cookieless = (attr(el, 'cookieless') || '').toLowerCase();
      const requireSSL = attr(el, 'requireSSL');
      const timeout = Number(attr(el, 'timeout') || NaN);
      const problems = [];
      if (protection === 'NONE' || protection === 'ENCRYPTION' || protection === 'VALIDATION')
        problems.push(`ticket protection="${protection}" (tickets need both encryption and validation)`);
      if (cookieless === 'useuri' || cookieless === 'true')
        problems.push('cookieless="UseUri" puts the session ticket in the URL');
      if (requireSSL === 'false') problems.push('requireSSL="false" lets the auth cookie travel over plain HTTP');
      if (Number.isFinite(timeout) && timeout > 480)
        problems.push(`timeout="${timeout}" minutes keeps tickets valid far beyond working sessions`);
      if (!problems.length) return;
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
        category: 'security', cwe: ['CWE-565'],
        title: 'Forms-authentication cookie misconfiguration',
        file: ctx.relPath, startLine: line,
        snippet: redactSecrets(el),
        language: 'xml',
        problem: '<forms> authentication is configured with: ' + problems.join('; ') + '.',
        impact: 'Depending on the combination: tickets can be forged (protection), stolen off the ' +
          'URL or an unencrypted channel (cookieless/requireSSL), or reused long after a user ' +
          'walks away (timeout).',
        recommendation: 'Use protection="All" (default), requireSSL="true", cookieless="UseCookies", ' +
          'a ticket timeout matched to the application\u2019s real session policy, and slidingExpiration only where appropriate.'
      }));
    }
  },
  {
    id: 'web-cookie-flags',
    caseIds: ['N-005'],
    run(ctx) {
      let m;
      const re = /<httpCookie[^>]*>/gi;
      while ((m = re.exec(ctx.text)) !== null) {
        const el = m[0];
        if (/secure\s*=\s*"false"/i.test(el) || /httpOnlyCookies\s*=\s*"false"/i.test(el)) {
          const line = lineOf(ctx.lines, m.index);
          ctx.emit(finding({
            check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'MEDIUM',
            category: 'security', cwe: ['CWE-1004'],
            title: 'Cookie security flags explicitly disabled',
            file: ctx.relPath, startLine: line,
            snippet: el, language: 'xml',
            problem: 'A cookie is configured without (or against) Secure/HttpOnly at the site level.',
            impact: 'Cookies ride plain-HTTP requests and are readable from script after any XSS, ' +
              'including the session cookie.',
            recommendation: 'Set requireSSL and httpOnlyCookies to true in <httpCookies> and per-cookie.'
          }));
        }
      }
    }
  },
  {
    id: 'web-wcf',
    caseIds: ['V-001', 'V-002', 'V-003', 'V-004'],
    run(ctx) {
      // V-002 / V-003: service metadata + fault detail
      for (const [re, id, sev, title, problem, impact, rec] of [
        [/<serviceMetadata[^>]*\bhttpGetEnabled\s*=\s*"true"[^>]*>/i, 'V-002', 'MEDIUM',
          'WCF metadata publishing enabled',
          'serviceMetadata httpGetEnabled="true" serves the WSDL publicly.',
          'The full service contract — operations, types, policies — is enumerable by anyone, ' +
          'which is free reconnaissance for SOAP-specific attacks.',
          'Disable metadata publishing in production; expose the WSDL through a controlled channel.'],
        [/<serviceDebug[^>]*\bincludeExceptionDetailInFaults\s*=\s*"true"[^>]*>/i, 'V-003', 'HIGH',
          'WCF includeExceptionDetailInFaults enabled',
          'Fault exceptions will carry raw exception detail to SOAP clients.',
          'Stack traces, connection strings in messages and internal type names flow to the caller.',
          'Set includeExceptionDetailInFaults="false" and log the detail server-side.'],
        [/<binding[^>]*\bmode\s*=\s*"None"[^>]*>/i, 'V-001', 'CRITICAL',
          'WCF binding with security mode="None"',
          'A WCF binding transports messages with no transport or message protection.',
          'Credentials and payloads cross the network in cleartext; SOAP actions can be captured, ' +
          'read and replayed by anyone on the path.',
          'Use transport (HTTPS) or message security on every endpoint; mode="None" only behind ' +
          'an equivalent protected channel, and say so in the binding documentation.']
      ]) {
        const m = ctx.text.match(re);
        if (!m) continue;
        const line = lineOf(ctx.lines, m.index);
        ctx.emit(finding({
          check: id, caseIds: [id], confidence: 'CONFIRMED', severity: sev,
          category: 'security', cwe: id === 'V-001' ? ['CWE-319'] : id === 'V-003' ? ['CWE-209'] : ['CWE-200'],
          title, file: ctx.relPath, startLine: line,
          snippet: m[0], language: 'xml', problem,
          impact, recommendation: rec
        }));
      }
    }
  },
  {
    id: 'web-execution-limits',
    caseIds: ['N-010'],
    run(ctx) {
      const m = ctx.text.match(/<httpRuntime[^>]*\bmaxRequestLength\s*=\s*"(\d+)"[^>]*>/i);
      if (!m) return;
      const kb = Number(m[1]);
      if (!(kb > 0)) return;
      const mb = Math.round(kb / 1024);
      // Only report when the limit is large enough to matter for a DoS budget (>100 MB)
      if (mb <= 100) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'LOW',
        category: 'configuration', cwe: ['CWE-400'],
        title: `Request size limit raised to ${mb} MB in httpRuntime`,
        file: ctx.relPath, startLine: line,
        snippet: m[0], language: 'xml',
        problem: `maxRequestLength=${kb} (KB) permits very large request bodies.`,
        impact: 'Upload and parsing endpoints become cheap memory/disk exhaustion targets unless ' +
          'the application independently bounds what it buffers.',
        recommendation: 'Lower maxRequestLength to the real maximum the application accepts and ' +
          'keep requestFiltering limits consistent with it.'
      }));
    }
  },
  {
    id: 'web-connection-string',
    caseIds: ['E-001', 'M-001'],
    run(ctx) {
      let m;
      const re = /<add\s+[^>]*connectionString\s*=\s*"([^"]*)"[^>]*>/gi;
      while ((m = re.exec(ctx.text)) !== null) {
        const cs = m[1];
        const cred = cs.match(/(password|pwd)\s*=\s*([^;"\s][^;]*)/i);
        const user = /user\s+id\s*=\s*(?! integrated)/i.test(cs) || /uid\s*=\s*[^;]+/i.test(cs);
        if (!cred) continue;
        const line = lineOf(ctx.lines, m.index);
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-798'], language: 'xml',
          title: 'Database credentials in cleartext in a connection string',
          file: ctx.relPath, startLine: line,
          snippet: m[0].replace(/(password|pwd)\s*=\s*[^;"\s][^;]*/gi, '$1=***REDACTED***'),
          problem: 'A connection string embeds a username' + (user ? ' and password' : ' (and the password arrives from elsewhere in config)') +
            ' in plaintext within configuration.',
          impact: 'Anyone with repository, share, backup or artifact access holds database ' +
            'credentials; the sa/admin-shaped accounts typically grant server-wide access.',
          recommendation: 'Move credentials to the environment or a secret store and reference ' +
            'them (config builders / IIS configuration transform), rotate the exposed password, ' +
            'and drop privileged accounts for least-privilege logins.'
        }));
      }
    }
  },
  {
    id: 'web-appsettings-secret',
    caseIds: ['E-001', 'M-001'],
    run(ctx) {
      if (!/^appsettings/i.test(ctx.relPath.split('/').pop() || '')) return;
      let m;
      const re = /"(\w*(?:password|passwd|pwd|secret|apikey|api_key|token|connectionstring|connstr)\w*)"\s*:\s*"([^"]{4,})"/gi;
      while ((m = re.exec(ctx.text)) !== null) {
        const line = lineOf(ctx.lines, m.index);
        const looksReal = !/^($|{your|<|changeme|x+|placeholder|\*+|REDACTED)/i.test(m[2]);
        if (!looksReal) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-798'], language: 'json',
          title: `Credential-shaped value in appsettings: "${m[1]}"`,
          file: ctx.relPath, startLine: line,
          snippet: `"${m[1]}": "***REDACTED***"`,
          problem: 'appsettings carries a credential-shaped value in plaintext configuration.',
          impact: 'The value ships with the deployment and sits in source history; rotating it ' +
            'means touching code or config everywhere it was copied.',
          recommendation: 'Read it from the environment or a secret provider (user-secrets in dev, ' +
            'Key Vault/parameter store in production) and rotate the exposed value.',
          possibleNote: 'Confirmed: a credential-shaped literal exists at this line. Redacted from evidence.'
        }));
      }
    }
  },
  {
    id: 'web-security-headers',
    caseIds: ['N-004'],
    run(ctx) {
      if (ctx.text.includes('<customHeaders')) return; // headers may be configured — checked at project level
      if (!/<system\.webServer/i.test(ctx.text)) return;
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'MEDIUM',
        category: 'configuration', cwe: ['CWE-693'],
        title: 'No security response headers configured in Web.config',
        file: ctx.relPath, startLine: lineOf(ctx.lines, ctx.text.search(/<system\.webServer/i)),
        snippet: ctx.lines[lineOf(ctx.lines, ctx.text.search(/<system\.webServer/i)) - 1],
        language: 'xml',
        problem: 'This Web.config has a system.webServer section but no <customHeaders> block, so ' +
          'unless code adds them, responses ship without X-Content-Type-Options, X-Frame-Options, ' +
          'a Content-Security-Policy or Referrer-Policy.',
        impact: 'Browsers fall back to permissive defaults: MIME sniffing, framing/clickjacking, ' +
          'and referrer leakage all stay available to an attacker who finds one injection point.',
        recommendation: 'Add the header set under <httpProtocol><customHeaders> (or middleware for ' +
          'ASP.NET Core): X-Content-Type-Options nosniff, a CSP, frame-ancestors/frame-options, ' +
          'Referrer-Policy, and HSTS behind TLS.'
      }));
    }
  }
];

/** 1-based line number of a character offset. */
function lineOf(lines, offset) {
  let upto = 0;
  for (let i = 0; i < lines.length; i++) {
    upto += lines[i].length + 1;
    if (offset < upto) return i + 1;
  }
  return lines.length;
}

module.exports = { CHECKS, redactSecrets, lineOf, attr, REDACTED };
