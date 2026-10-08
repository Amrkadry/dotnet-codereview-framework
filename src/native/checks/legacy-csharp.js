// dotnet-codereview-framework — src/native/checks/legacy-csharp.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Legacy ASP.NET Framework / Dynamics-idiom checks — ported from a detection set
 * validated against a 42k-line enterprise ASP.NET Framework application and a
 * 26-finding manual source-code review (2026-10-08).
 *
 * Same honesty rules as checks/csharp.js:
 *   - comments stripped before matching (dead code is not a finding); string literals are
 *     PRESERVED because most of these checks look INSIDE strings (URLs, keys, attribute names);
 *   - structural facts ("this API is called here") are LIKELY; content-dependent patterns
 *     ("this parameter MIGHT be attacker-controlled") are POSSIBLE;
 *   - every case here has a matching LH-* entry in catalog/dotnet-test-cases-legacy.json.
 *
 * ctx: { relPath, text, lines, emit } — one .cs file per call.
 */

const { finding } = require('../finding');
// shared, string-aware helpers from the core C# check module
const { stripComments, windowAfter, windowBefore, clean } = require('./csharp');

const CHECKS = [
  {
    id: 'cs-ssh-hostkey', caseIds: ['LH-001'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /GiveUpSecurityAndAcceptAnySshHostKey\s*=\s*true|HostKeyReceived[\s\S]{0,80}(?:e\.CanTrust\s*=\s*false|return\s*;)/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-001'], confidence: 'LIKELY',
          severity: 'HIGH', category: 'security', cwe: ['CWE-322'], language: 'csharp',
          title: 'SSH host key verification disabled',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 3).join('\n'),
          problem: 'The SSH/SFTP client is told to accept any host key, so it cannot detect a ' +
            'rogue or impersonated server on the transfer channel.',
          impact: 'A machine on the network path impersonates the SFTP server, captures the ' +
            'credentials configured for the channel and can swap the files being transferred.',
          attackScenario: 'ARP/DNS spoofing or a compromised router answers as the SFTP host; ' +
            'the client authenticates and uploads/downloads through the attacker.',
          recommendation: 'Pin the server SSH host key fingerprint (SSH.NET: HostKeyReceived ' +
            'event comparing against a stored fingerprint) and fail closed on mismatch.'
        }));
      }
    }
  },
  {
    id: 'cs-ldap-plaintext', caseIds: ['LH-002'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /ValidateCredentials\s*\(|new\s+PrincipalContext\s*\(|new\s+DirectoryEntry\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowBefore(stripped, i + 1, 6) + ' ' + windowAfter(stripped, i + 1, 4);
        if (/SecureSocketLayer|LDAPS:\/\//i.test(win)) continue;
        const emptyGuard = /IsNullOrWhiteSpace|IsNullOrEmpty/.test(windowAfter(stripped, i + 1, 10) + windowBefore(stripped, i + 1, 10));
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-002'],
          confidence: 'LIKELY', severity: 'HIGH', category: 'security',
          cwe: ['CWE-287', 'CWE-319'], language: 'csharp',
          title: 'Directory credential validation without LDAPS',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 4).join('\n'),
          problem: 'The directory bind/validation runs without LDAPS or SecureSocketLayer in the ' +
            'surrounding context, so domain credentials transit in cleartext and the server is ' +
            'never authenticated by the client.' + (emptyGuard ? '' : ' No empty/whitespace ' +
            'credential guard was found in the same method, leaving the empty-password bind path open.'),
          impact: 'Anyone on the network path reads domain usernames and passwords from the bind ' +
            'traffic; an empty-password bind may authenticate against some directory configurations.',
          attackScenario: 'Passive capture of LDAP bind traffic (or an ARP MITM) yields working ' +
            'domain credentials for password spray and lateral movement.',
          recommendation: 'Use LDAPS (LDAP over 636 with certificate validation) or StartTLS; ' +
            'reject empty/whitespace credentials before any directory call.'
        }));
      }
    }
  },
  {
    id: 'cs-pbkdf2-iterations', caseIds: ['LH-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /new\s+Rfc2898DeriveBytes\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const call = windowAfter(stripped, i + 1, 3);
        const m = call.match(/,\s*(\d{2,9})\s*[,)]/);
        const iters = m ? parseInt(m[1], 10) : null;
        if (iters !== null && iters >= 10000) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-003'],
          confidence: 'LIKELY', severity: iters !== null ? 'HIGH' : 'MEDIUM',
          category: 'security', cwe: ['CWE-916'], language: 'csharp',
          title: iters !== null
            ? `PBKDF2 run for only ${iters} iterations`
            : 'PBKDF2 with library-default iteration count (1,000)',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 4).join('\n'),
          problem: iters !== null
            ? `The KDF work factor is ${iters} iterations — far below the OWASP baseline of 100,000+, ` +
              'so keys/verifiers derived from passwords are cheap to brute-force offline.'
            : 'Rfc2898DeriveBytes without an explicit iteration argument uses the .NET Framework ' +
              'default of 1,000 iterations — obsolete as a work factor.',
          impact: 'Password-derived material (login verifiers, encryption keys) falls to offline ' +
            'dictionary attacks once any database or traffic capture leaks.',
          attackScenario: 'Attacker exfiltrates the credential store or a captured token blob and ' +
            'cracks it at desktop-GPU speeds because the KDF cost is negligible.',
          recommendation: 'Use the overload with an explicit iteration count (>= 100,000) or move ' +
            'password hashing to ASP.NET Identity / Argon2.'
        }));
      }
    }
  },
  {
    id: 'cs-static-key-iv', caseIds: ['LH-004'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\.(?:Key|IV)\s*=\s*(?:"([^"\n]{8,64})"|Convert\.FromBase64String\s*\(\s*"([^"\n]{8,64})"|new\s+byte\s*\[[^\]]*\])/;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re);
        if (!m) continue;
        const isIV = /\.IV\s*=/.test(m[0]);
        const isByteArray = /new\s+byte\s*\[/.test(m[0]);
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-004'],
          confidence: 'LIKELY', severity: 'HIGH', category: 'security',
          cwe: [isIV ? 'CWE-329' : 'CWE-321'], language: 'csharp',
          title: isIV
            ? (isByteArray ? 'Static byte-array IV (possibly all zeros)' : 'Hard-coded IV string')
            : 'Hard-coded encryption key material',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: isIV
            ? 'A fixed IV is assigned at runtime: identical plaintexts produce identical ciphertext ' +
              'prefixes, and an all-zero IV is a well-known starting state.'
            : 'The symmetric key is embedded in the source/artifact, so every deployment shares it ' +
              'and anyone with the artifact can decrypt.',
          impact: 'Confidentiality of everything encrypted under this key/IV collapses once the ' +
            'binary, repo or config is seen by anyone outside the deployment.',
          attackScenario: 'Reverse the shipped assembly (or read the repo) to recover the key and ' +
            'decrypt captured payloads at leisure.',
          recommendation: isIV
            ? 'Generate a random IV per message (RNGCryptoServiceProvider) and prepend it to the ciphertext.'
            : 'Load keys from a managed store (DPAPI-protected config, Key Vault); rotate any value committed here.'
        }));
      }
    }
  },
  {
    id: 'cs-crm-bool-compare', caseIds: ['LH-005'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\]\s*\.\s*ToString\s*\(\s*\)\s*(?:==|!=)\s*"(?:True|False|true|false)"/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-005'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'reliability',
          cwe: ['CWE-597'], language: 'csharp',
          title: 'Attribute boolean compared as case-sensitive string',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'An attribute value is stringified with ToString() and compared to "True"/"False". ' +
            'Non-primitive attribute values (OptionSetValue, Money, AliasedValue, EntityReference) ' +
            'stringify to their wrapper type name, so the comparison silently fails.',
          impact: 'Any authorization or business branch built on this comparison misfires in a way ' +
            'that never throws — decisions silently flip depending on the runtime type.',
          attackScenario: 'No attacker needed: the defect is a decision that quietly evaluates the ' +
            'wrong way for records whose attribute arrives as a wrapper type.',
          recommendation: 'Compare typed values: entity.GetAttributeValue<bool>("...") or cast and ' +
            'compare .Value — never the stringified form.'
        }));
      }
    }
  },
  {
    id: 'cs-unguarded-appsettings', caseIds: ['LH-006'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /AppSettings\s*\[\s*"[^"]+"\s*\]\s*\.\s*(?:ToString|Trim|Split|ToUpper|ToLower|Substring|Replace)\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-006'],
          confidence: 'LIKELY', severity: 'MEDIUM', category: 'reliability',
          cwe: ['CWE-476'], language: 'csharp',
          title: 'Configuration value dereferenced without a null check',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'AppSettings[key] returns null for a missing key; the immediate method call ' +
            'throws NullReferenceException on every request that reaches this path.',
          impact: 'A missing key in one environment turns an entire feature (login, integration ' +
            'calls) into a guaranteed 500, and the flattened error hides the cause.',
          attackScenario: 'Not attacker-driven — an operational fragility: one un-deployed config ' +
            'key takes the feature down and the generic error page hides why.',
          recommendation: 'Null-check the value, fail fast at startup, or define the key in every ' +
            'deployed config transform.'
        }));
      }
    }
  },
  {
    id: 'cs-fail-open-catch', caseIds: ['LH-007'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /catch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\/[^\n]*\n\s*)*return\s+(?:0|0\.0|m|false|null)\s*;/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i] + ' ' + windowAfter(stripped, i + 1, 2))) continue;
        if (!/catch\s*(\(|\{)/.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-007'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'reliability',
          cwe: ['CWE-703'], language: 'csharp',
          title: 'Exception handler returns a fixed default value',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 4).join('\n'),
          problem: 'A catch block converts any internal failure into a fixed business value ' +
            '(0 / false / null) instead of propagating the error.',
          impact: 'Downstream logic cannot distinguish "genuinely zero" from "the system broke" — ' +
            'in decisioning/money code that means silently wrong amounts or approvals.',
          attackScenario: 'An attacker who can induce the fault path (malformed input, exhausted ' +
            'dependency) picks the outcome the catch returns.',
          recommendation: 'Let the operation fail; handle at the boundary with an explicit error ' +
            'state. Never substitute business values inside catch.'
        }));
      }
    }
  },
  {
    id: 'cs-shared-handler-state', caseIds: ['LH-008'],
    run(ctx) {
      const text = stripComments(ctx.lines).join('\n');
      if (!/class\s+\w*(Handler|Filter|Middleware|ExceptionHandler)/.test(text)) return;
      const re = /(?:private|protected|internal|public)\s+(?:static\s+)?(?!readonly\s|const\s)[\w<>\[\],.?]+\s+(\w+)\s*(?:=|;)/g;
      const fields = new Set();
      let m;
      while ((m = re.exec(text)) !== null) fields.add(m[1]);
      if (!fields.size) return;
      const outRe = /\bout\s+(\w+)\b/g;
      const written = new Set();
      let o;
      while ((o = outRe.exec(text)) !== null) if (fields.has(o[1])) written.add(o[1]);
      const assignRe = /(?:this\.)?(\w+)\s*=(?!=)/g;
      while ((o = assignRe.exec(text)) !== null) if (fields.has(o[1])) written.add(o[1]);
      if (!written.size) return;
      const lineNo = ctx.lines.findIndex(l => /class\s+\w*(Handler|Filter|Middleware|ExceptionHandler)/.test(l)) + 1;
      ctx.emit(finding({
        check: this.id, caseIds: ['LH-008'],
        confidence: 'LIKELY', severity: 'MEDIUM', category: 'reliability',
        cwe: ['CWE-488', 'CWE-362'], language: 'csharp',
        title: 'Mutable state on a per-request handler/filter component',
        file: ctx.relPath, startLine: Math.max(1, lineNo),
        snippet: ctx.lines.slice(Math.max(0, lineNo - 1), lineNo + 12).join('\n'),
        problem: `Instance fields (${[...written].slice(0, 4).join(', ')}) on a handler/filter are ` +
          'written during request processing. These components are typically instantiated once, so ' +
          'concurrent requests overwrite each other\u2019s values.',
        impact: 'Under load, audit metadata (service codes, origins, header values) from one ' +
          'request is attributed to another — corrupted audit trail and wrong per-request behavior.',
        attackScenario: 'Concurrent requests are enough; no attacker required — but an attacker ' +
          'can force the mix deliberately to pollute attribution.',
        recommendation: 'Make the component stateless: method locals or HttpContext.Items for ' +
          'per-request values; static only for immutable configuration.'
      }));
    }
  },
  {
    id: 'cs-culture-parse', caseIds: ['LH-009'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\b(?:double|decimal|int)\.Parse\s*\([^;]{0,140}?\.ToString\s*\(\s*\)/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-009'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'reliability',
          cwe: ['CWE-682'], language: 'csharp',
          title: 'Numeric Parse over culture-sensitive ToString output',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'A number is stringified with the server culture and parsed back. On a host with ' +
            'a comma-decimal locale the parsed value silently differs from the stored one.',
          impact: 'Money math (income, limits, approved amounts) computes wrong by orders of ' +
            'magnitude on some deployments, with no exception to notice.',
          attackScenario: 'No attacker needed — a locale change at deploy time corrupts every ' +
            'amount that passes through the round-trip.',
          recommendation: 'Parse the primitive directly, or pin CultureInfo.InvariantCulture on ' +
            'both ToString and Parse.'
        }));
      }
    }
  },
  {
    id: 'cs-webroot-write', caseIds: ['LH-010'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /File\.(?:WriteAllBytes|WriteAllText|WriteAllLines)\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const around = windowBefore(stripped, i + 1, 12) + ' ' + windowAfter(stripped, i + 1, 4);
        if (!/Convert\.FromBase64String/.test(around)) continue;
        if (!/BaseDirectory|MapPath|~\/|AppDomain/.test(around)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-010'],
          confidence: 'LIKELY', severity: 'HIGH', category: 'security',
          cwe: ['CWE-552'], language: 'csharp',
          title: 'Caller-supplied binary written under the application root',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 6), i + 3).join('\n'),
          problem: 'Base64 data supplied by the caller is decoded and written under the web root, ' +
            'and (in the common pattern) the absolute server path is returned in the response.',
          impact: 'Attackers plant content that the web server may serve directly, learn internal ' +
            'paths from the response, and fill the disk.',
          attackScenario: 'POST a crafted base64 payload to the upload endpoint; fetch the planted ' +
            'file back over HTTP; enumerate neighbors via the returned path.',
          recommendation: 'Store outside the webroot or in blob storage; validate content type; ' +
            'return an indirect reference (id/URL), never the filesystem path.'
        }));
      }
    }
  },
  {
    id: 'cs-filename-collision', caseIds: ['LH-011'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /File\.(?:WriteAllBytes|WriteAllText|WriteAllLines|Copy|Move)\s*\(|StreamWriter\s*\(/;
      const tsRe = /DateTime\.Now(?:\.ToString\s*\(\s*)?["':]*[yYMdHs]{6,}|DateTime\.Now:|\$\".*DateTime\.Now:/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const around = windowBefore(stripped, i + 1, 10);
        if (!tsRe.test(around)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-011'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'reliability',
          cwe: ['CWE-340', 'CWE-362'], language: 'csharp',
          title: 'Timestamp-derived filename can collide',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 6), i + 3).join('\n'),
          problem: 'The filename comes from DateTime.Now at second resolution; two operations in ' +
            'the same second target the same path and the second silently overwrites the first.',
          impact: 'Files (e.g. customer signature images on agreements) get swapped or lost without ' +
            'any error — a data-integrity defect, not just a bug.',
          attackScenario: 'Concurrent submissions suffice; an attacker can also time submissions to ' +
            'overwrite a competitor\u2019s artifact.',
          recommendation: 'Use a GUID or a sequence with existence checks; include a per-request ' +
            'unique component in the name.'
        }));
      }
    }
  },
  {
    id: 'cs-denylist-validation', caseIds: ['LH-012'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /Regex\.Replace\s*\(/;
      const deny = /<script|javascript:|eval\s*\(|onerror|alert\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const around = stripped[i] + ' ' + windowBefore(stripped, i + 1, 6) + ' ' + windowAfter(stripped, i + 1, 2);
        if (!deny.test(around)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-012'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'security',
          cwe: ['CWE-184'], language: 'csharp',
          title: 'Denylist-based input sanitization',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 4), i + 2).join('\n'),
          problem: 'Input validation is a blocklist of known-bad markup applied over encoded text. ' +
            'Denylists never cover the full syntax space, and the prior encoding changes what the ' +
            'patterns can even match — most variants pass.',
          impact: 'Stored/reflected XSS payloads that dodge the blocklist persist and execute in ' +
            'other users\u2019 browsers.',
          attackScenario: 'Variant encoding (case, entities, event handlers, broken tags) walks ' +
            'the payload past the denylist.',
          recommendation: 'Allowlist-validate at input; encode at output with the framework ' +
            'encoders (AntiXssEncoder); drop the denylist as a primary control.'
        }));
      }
    }
  },
  {
    id: 'cs-path-combine', caseIds: ['LH-013'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /Path\.Combine\s*\(/;
      const taint = /\b(?:fileName|filename|filePath|path|name|userPath|relativePath|subPath)\b/i;
      for (let i = 0; i < stripped.length; i++) {
        const line = stripped[i];
        if (!re.test(line)) continue;
        const args = windowAfter(stripped, i + 1, 2);
        if (!taint.test(args)) continue;
        if (/GetFullPath|\.\.\.|StartsWith\s*\(\s*base/i.test(args)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-013'],
          confidence: 'POSSIBLE', severity: 'MEDIUM', category: 'security',
          cwe: ['CWE-22'], language: 'csharp',
          title: 'Path.Combine with caller-influenced segment and no containment check',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 3).join('\n'),
          problem: 'A path segment with a caller-influenced name is joined to a base directory ' +
            'without canonicalization; "../" sequences (or rooted second arguments) escape the base.',
          impact: 'Arbitrary file read/write/delete under the process identity, inside or outside ' +
            'the application tree.',
          attackScenario: 'fileName = "..\\..\\web.config" reaches File.Delete/Read and removes or ' +
            'exposes files the endpoint was never meant to touch.',
          recommendation: 'Path.GetFullPath the result and verify it starts with the intended root; ' +
            'reject rooted paths and traversal sequences; allowlist filenames.'
        }));
      }
    }
  },
  {
    id: 'cs-exception-to-client', caseIds: ['LH-014'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\.(?:message|Message|error|Error|detail|Detail)\s*=\s*ex(?:ception)?\.(?:Message|ToString\s*\(\s*\))/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-014'],
          confidence: 'LIKELY', severity: 'LOW', category: 'security',
          cwe: ['CWE-209'], language: 'csharp',
          title: 'Exception details returned to API callers',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'Exception message/stack text is copied into the response object the caller sees.',
          impact: 'Internal structure — types, paths, query text, dependency names — is disclosed ' +
            'to anyone who can trigger the error.',
          attackScenario: 'Probe endpoints with malformed input and read the returned exception ' +
            'text to map the backend.',
          recommendation: 'Return a generic error identifier; keep the detail in server-side logs.'
        }));
      }
    }
  },
  {
    id: 'cs-entities-zero', caseIds: ['LH-015'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\.Entities\s*\[\s*0\s*\]/;
      let hits = 0;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        hits++;
        if (hits > 3) continue; // systemic pattern: report first few, not 150 locations
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-015'],
          confidence: 'POSSIBLE', severity: 'LOW', category: 'reliability',
          cwe: ['CWE-476'], language: 'csharp',
          title: 'First entity indexed without an empty-result guard',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: '.Entities[0] is indexed directly after a retrieval; an empty result throws ' +
            'instead of being a handled case.',
          impact: 'Record-missing scenarios surface as 500s instead of clean "not found" responses.',
          attackScenario: 'A caller referencing a deleted/foreign record triggers the unhandled ' +
            'path at will.',
          recommendation: 'Check Entities.Length / use FirstOrDefault before indexing.'
        }));
      }
    }
  },
  {
    id: 'cs-cleartext-url', caseIds: ['LH-016'],
    run(ctx) {
      // raw lines: stripComments would cut string literals at "//" (http://)
      const skip = /xmlns|schemas\.(microsoft|openxmlformats)|w3\.org|localhost|127\.0\.0\.1|tempuri|example\.com|wordnik|swagger\.io/i;
      const re = /"http:\/\/[^"\s]+"/;
      for (let i = 0; i < ctx.lines.length; i++) {
        const m = ctx.lines[i].match(re);
        if (!m || skip.test(m[0])) continue;
        // full-line comment guard: the comment-stripped copy of this line must be non-empty
        if (!stripComments([ctx.lines[i]])[0].trim()) continue;
        const rawIp = /"http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(m[0]);
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-016'],
          confidence: 'LIKELY', severity: rawIp ? 'MEDIUM' : 'LOW', category: 'security',
          cwe: ['CWE-319'], language: 'csharp',
          title: rawIp ? 'Cleartext HTTP call to a raw IP address' : 'Cleartext HTTP endpoint in code',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'Live code calls a plain-HTTP endpoint' + (rawIp
            ? ' — and the host is a bare public IP, so the channel is unencrypted and unattributable.'
            : '; traffic is readable and alterable in transit.'),
          impact: 'Credentials, tokens and payloads on this channel are exposed to anyone on the ' +
            'network path; responses can be rewritten.',
          attackScenario: 'Passive capture or an on-path MITM reads and modifies the exchange.',
          recommendation: 'Use HTTPS and reject plain-http destinations; pin or validate certificates.'
        }));
      }
    }
  },
  {
    id: 'cs-verbless-mutating', caseIds: ['LH-017'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const text = stripped.join('\n');
      if (!/\b(?:ApiController|Controller)\b/.test(text)) return;
      const sig = /(?:public|protected)\s+[\w<>\[\],.?]+\s+(Create|Delete|Update|Save|Insert|Add|Cancel|Submit|Authorize|Book|Release|Clone|Assign|Upload|Approve|Reject|Register|Remove)\w*\s*\(/g;
      const m2 = /attr/; // placeholder to keep linters quiet about unused regex
      let m;
      const names = [];
      while ((m = sig.exec(text)) !== null) {
        const upTo = text.slice(Math.max(0, m.index - 300), m.index);
        if (/\[\s*Http(?:Post|Put|Delete)/i.test(upTo)) continue;
        names.push(m[1]);
      }
      if (!names.length) return;
      const lineNo = Math.max(1, ctx.lines.findIndex(l => sig.test(l)) + 1);
      ctx.emit(finding({
        check: this.id, caseIds: ['LH-017'],
        confidence: 'POSSIBLE', severity: 'LOW', category: 'security',
        cwe: ['CWE-352'], language: 'csharp',
        title: 'Mutating actions accept any HTTP verb',
        file: ctx.relPath, startLine: lineNo,
        snippet: (names.slice(0, 6).join(', ')),
        problem: `${names.length} action(s) with mutating names (${names.slice(0, 5).join(', ')}${names.length > 5 ? ', …' : ''}) ` +
          'carry no [HttpPost]/[HttpPut]/[HttpDelete] attribute; Web API routes match all verbs.',
        impact: 'Wider CSRF and verb-tampering surface: mutation endpoints are reachable via GET ' +
          'and preflight-free requests.',
        attackScenario: 'A cross-site page (or a crafted link) drives state-changing calls through ' +
          'the verb-unconstrained route.',
        recommendation: 'Pin each mutating endpoint with [HttpPost]/[HttpPut]/[HttpDelete] and keep ' +
          'authentication + anti-forgery on.'
      }));
    }
  },
  {
    id: 'cs-token-lifetime', caseIds: ['LH-018'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /AccessTokenExpireTimeSpan\s*=\s*TimeSpan\.From(?:Minutes|Hours)\s*\(\s*(\d+)\s*\)/;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re);
        if (!m) continue;
        const minutes = /FromHours/.test(m[0]) ? parseInt(m[1], 10) * 60 : parseInt(m[1], 10);
        if (minutes < 300) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['LH-018'],
          confidence: 'CONFIRMED', severity: 'MEDIUM', category: 'security',
          cwe: ['CWE-613'], language: 'csharp',
          title: `Access token lifetime is ${minutes} minutes`,
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 3).join('\n'),
          problem: `Bearer tokens live ${minutes} minutes. With no refresh/revocation provider ` +
            'wired, a leaked token (or a disabled account) keeps working until expiry.',
          impact: 'Stolen tokens from logs, proxies or user devices grant access for hours after ' +
            'compromise; account disablement does not cut access.',
          attackScenario: 'Token exfiltrated from a log or MITM is replayed for the remainder of ' +
            'the window — nothing the defender does revokes it.',
          recommendation: 'Shorten the access-token window (< 30 min), add a refresh flow, and ' +
            'wire a revocation path honoured by the resource server.'
        }));
      }
    }
  },
];

module.exports = { CHECKS };
