// dotnet-codereview-framework — src/native/checks/csharp.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Native C# heuristic checks.
 *
 * Confidence discipline, applied per check and visible in every finding:
 *   - a construct whose presence IS the defect (BinaryFormatter, TypeNameHandling.Any)
 *     is LIKELY — the API being called is a fact; only reachability is unproven;
 *   - a content-dependent pattern (is the concatenated SQL string ever attacker-influenced?)
 *     is POSSIBLE — a lead, never a verdict.
 * Comments are stripped before matching so dead code does not generate findings; string
 * literals are deliberately preserved because two of the checks look INSIDE strings
 * (hardcoded secrets, connection-string options).
 */

const { finding } = require('../finding');

/** Remove // and /* *​/ comments per line, preserving string literals and line numbering. */
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
      const ch = raw[i];
      // String literal: copy verbatim — "//" and "/*" inside strings are NOT comments.
      // Without this, every URL/LDAP path/connection string made the whole line vanish.
      if (ch === '"' || ch === "'") {
        let j = i + 1;
        while (j < raw.length) {
          if (raw[j] === '\\') { j += 2; continue; }
          if (raw[j] === ch) { j++; break; }
          j++;
        }
        line += raw.slice(i, j);
        i = j; continue;
      }
      if (ch === '/' && raw[i + 1] === '/') break;      // rest of line is a comment
      if (ch === '/' && raw[i + 1] === '*') { inBlock = true; i += 2; continue; }
      line += ch; i++;
    }
    out.push(line);
  }
  return out;
}

const clean = s => s.replace(/\s+/g, ' ').trim();

/** A window of `radius` lines after (and including) line `n`, comment-stripped, joined. */
function windowAfter(stripped, n, radius = 2) {
  return clean(stripped.slice(n - 1, n + radius).join(' '));
}

/** A window of `radius` lines before (and including) line `n`, comment-stripped, joined. */
function windowBefore(stripped, n, radius = 3) {
  return clean(stripped.slice(Math.max(0, n - 1 - radius), n + 1).join(' '));
}

const SECRET_VALUE = /"(?:[^"\\]|\\.){6,}"/;
const SECRET_NAMES = /(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|client[_-]?secret|private[_-]?key)/i;

/** Each check: { id, caseIds, run(ctx) }. ctx: {relPath, text, lines, emit}. */
const CHECKS = [
  {
    id: 'cs-sql-concat',
    caseIds: ['C-001', 'C-002', 'C-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /(?:new\s+(?:Sql|OleDb|Odbc|MySql|Npgsql)?Command\s*\(|\.CommandText\s*=)/i;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 3);
        const concat = /"\s*\+\s*\w|\w\s*\+\s*"|\$"|string\.Format\s*\(|\{\w+\}/i.test(win);
        if (!concat) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-89'], language: 'csharp',
          title: 'SQL command built with string concatenation',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'A SQL statement is assembled by concatenating or interpolating values ' +
            'instead of parameterising them. Statically it cannot be shown that the values are ' +
            'never attacker-controlled — which is exactly why the pattern is flagged.',
          impact: 'If any concatenated value originates from a request, route, form, header, cookie ' +
            'or database text an attacker influences, they can terminate the string literal and ' +
            'append arbitrary SQL: read, modify or delete any data the connection can reach.',
          attackScenario: 'input \u2192 concatenation \u2192 ExecuteReader/NonQuery: a value like ' +
            "`x'; DELETE FROM orders; --` becomes a second executed statement.",
          recommendation: 'Parameterise every value (cmd.Parameters.AddWithValue / EF parameters) ' +
            'and keep identifier names (ORDER BY, table names) on a hardcoded allow-list.'
        }));
      }
    }
  },
  {
    id: 'cs-unsafe-deserializer',
    caseIds: ['J-001', 'S-006', 'S-008'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\b(BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter|XamlReader\s*\.\s*(?:Parse|Load))\b/;
      const reJs = /\bJavaScriptSerializer\s*\(\s*\)\s*\.\s*Deserialize(?:\s*<[^>]*>)?\s*\(/i;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re) || stripped[i].match(reJs);
        if (!m) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-502'], language: 'csharp',
          title: `Dangerous deserializer in use: ${m[0].replace(/\s+/g, '')}`,
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: `${m[0].replace(/\s+/g, '')} materialises arbitrary types from the payload. ` +
            'Its deserialisation is type-directed by data under the sender\u2019s control.',
          impact: 'Where any part of the payload is attacker-supplied, a gadget chain in the ' +
            'loaded assemblies turns deserialisation into unauthenticated remote code execution.',
          recommendation: 'Replace with a data-only format (JSON with TypeNameHandling.None, or a ' +
            'contract serializer with an explicit known-types list). Where BinaryFormatter cannot ' +
            'yet be removed, restrict its input to channels that are authenticated, integrity-protected ' +
            'and never attacker-writable — and schedule the migration.'
        }));
      }
    }
  },
  {
    id: 'cs-typename-handling',
    caseIds: ['J-002', 'S-011'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /TypeNameHandling\s*\.\s*(?!None\b)(Objects|All|Arrays|Auto)\b/;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re);
        if (!m) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-502'], language: 'csharp',
          title: `Newtonsoft TypeNameHandling.${m[1]} enabled`,
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: `TypeNameHandling.${m[1]} instructs the JSON serializer to read type metadata ` +
            'from the payload and construct those types.',
          impact: 'An attacker who controls any JSON this setting deserialises supplies a $type ' +
            'pointing at a dangerous type — the standard path to object-generation and code ' +
            'execution gadgets.',
          recommendation: 'Set TypeNameHandling.None (the default) at every serializer settings ' +
            'site. If polymorphism is genuinely required, pin it with a SerializationBinder that ' +
            'allow-lists exact types, and treat that binder as security code.'
        }));
      }
    }
  },
  {
    id: 'cs-cert-validation',
    caseIds: ['F-001', 'F-002'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator|ServicePointManager\s*\.\s*ServerCertificateValidationCallback)/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 3);
        const bypass = /=>\s*true|return\s+true\s*;|DangerousAcceptAnyServerCertificateValidator/.test(win + stripped[i]);
        if (!bypass) continue;
        const processWide = /ServicePointManager/i.test(stripped[i]);
        ctx.emit(finding({
          check: this.id, caseIds: processWide ? ['F-001'] : ['F-002'],
          confidence: 'LIKELY', severity: 'CRITICAL', category: 'security',
          cwe: ['CWE-295'], language: 'csharp',
          title: processWide
            ? 'TLS certificate validation disabled process-wide'
            : 'TLS certificate validation bypass on this handler',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'The certificate validation callback returns true unconditionally, so every ' +
            'certificate — self-signed, expired, or issued to a different host — is accepted' +
            (processWide ? ', and via ServicePointManager this applies to ALL outbound HTTPS in the process.' : '.'),
          impact: 'A machine on the network path (rogue Wi-Fi, compromised router, ARP/ARP-free ' +
            'MITM) intercepts TLS traffic and reads or rewrites credentials, tokens and payloads.',
          attackScenario: 'Attacker ARP-spoofs or DNS-spoofs the target host, presents any ' +
            'certificate, and the application connects as if nothing happened.',
          recommendation: 'Delete the bypass. If a self-signed internal endpoint is the reason, ' +
            'pin that endpoint\u2019s exact certificate or CA instead of disabling validation.'
        }));
      }
    }
  },
  {
    id: 'cs-response-write',
    caseIds: ['D-001'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /Response\s*\.\s*Write\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 2);
        const tainted = /Request(\[|\.QueryString|\.Form|\.Params)|\+\s*\w+|\$\w|\{\w+\}/.test(win);
        if (!tainted) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-79'], language: 'csharp',
          title: 'Response.Write of potentially unencoded input (reflected XSS)',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'Text is written straight into the response body via Response.Write; the ' +
            'pattern suggests request data reaches the output without visible encoding.',
          impact: 'Where the value is attacker-influenced, script executes in other users\u2019 ' +
            'browsers under the application\u2019s origin: sessions, CSRF tokens and DOM are the attacker\u2019s.',
          recommendation: 'Encode with HttpUtility.HtmlEncode / AntiXssEncoder.HtmlEncode at the ' +
            'output point, or bind through the view engine\u2019s encoded syntax (<%: %>). Never ' +
            'echo request data raw.'
        }));
      }
    }
  },
  {
    id: 'cs-command-injection',
    caseIds: ['C-007'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /Process\s*\.\s*(?:Start|StartInfo)\b/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 3);
        if (!/"\s*\+\s*\w|\w\s*\+\s*"|\$"|string\.Format\s*\(|\bRequest\b/.test(win)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-78'], language: 'csharp',
          title: 'OS command assembled from concatenated parts',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 4).join('\n'),
          problem: 'Process.Start is invoked with a command string that appears to be built from ' +
            'concatenated or interpolated values.',
          impact: 'If any part originates outside the program, shell metacharacters in that part ' +
            'execute as a second command with the worker process\u2019s privileges.',
          recommendation: 'Pass argument arrays (ProcessStartInfo.ArgumentList on .NET Core; on ' +
            'Framework, validate against a strict allow-list and avoid cmd.exe /c entirely).'
        }));
      }
    }
  },
  {
    id: 'cs-hardcoded-secret',
    caseIds: ['E-001', 'M-001'],
    run(ctx) {
      for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        if (/^\s*\/\//.test(line)) continue;
        const m = line.match(new RegExp('(\\w*(?:' + 'password|passwd|pwd|secret|apikey|api_key|apitoken|access_token|client_secret' + ')\\w*)\\s*=\\s*("[^"\\n]{6,}")', 'i'));
        if (!m) continue;
        const value = m[2];
        if (/^\s*""\s*$/.test(value)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-798'], language: 'csharp',
          title: `Hardcoded credential literal: ${m[1]}`,
          file: ctx.relPath, startLine: i + 1,
          snippet: line.replace(m[2], '***REDACTED***'),
          problem: `The identifier "${m[1]}" is assigned a string literal in source code. ` +
            'The value itself is redacted here — it must not be duplicated into any report.',
          impact: 'The secret ships to every reader of the repository and every build artefact. ' +
            'Rotation requires a code change and redeployment, so rotated copies keep working ' +
            'wherever old binaries run.',
          recommendation: 'Move the value to the environment or the platform secret store ' +
            '(Azure Key Vault, AWS Secrets Manager, user-secrets for development), read it at ' +
            'startup, and rotate the exposed value now that it has lived in history.',
          possibleNote: 'Confirmed: the literal exists in this file. Redacted from all evidence.'
        }));
      }
    }
  },
  {
    id: 'cs-weak-crypto',
    caseIds: ['E-008', 'E-006', 'E-004', 'E-009'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const rules = [
        [/new\s+(MD5|SHA1|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)\b/, null],
        [/CipherMode\s*\.\s*ECB/, null],
        [/new\s+Random\s*\(/, /token|nonce|otp|password|secret|salt|key|code|ref(eren(ce|al))?|id/i]
      ];
      for (let i = 0; i < stripped.length; i++) {
        for (const [re, ctxRe] of rules) {
          const m = stripped[i].match(re);
          if (!m) continue;
          if (ctxRe) {
            const win = windowAfter(stripped, i + 1, 3) + stripped[i];
            if (!ctxRe.test(win)) continue;
          }
          const isHash = /MD5|SHA1/.test(m[0]);
          const isCipher = /DES|RC2/.test(m[0]);
          const isEcB = /ECB/.test(m[0]);
          const isRandom = /Random/.test(m[0]);
          ctx.emit(finding({
            check: this.id, caseIds: this.caseIds,
            confidence: isRandom ? 'POSSIBLE' : 'LIKELY',
            severity: isHash && isRandom ? 'CRITICAL' : isRandom ? 'HIGH' : 'HIGH',
            category: 'security', cwe: isRandom ? ['CWE-338'] : isEcB ? ['CWE-327'] : ['CWE-327'],
            language: 'csharp',
            title: isRandom ? 'System.Random used where unpredictability matters'
              : isEcB ? 'ECB cipher mode selected'
                : `Weak cryptographic primitive: ${m[1] || m[0]}`,
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
            problem: isRandom
              ? 'System.Random is a seeded PRNG: its output is predictable from one observed value.'
                : isEcB
                  ? 'ECB encrypts identical blocks to identical ciphertext, leaking structure.'
                    : `${m[1] || m[0]} is cryptographically broken or deprecated for its purpose here.`,
            impact: isRandom
              ? 'Tokens, reset codes or ids generated here can be predicted from an observed value, ' +
                'which turns "unguessable" into guessable.'
                : isEcB
                  ? 'Patterns in plaintext survive encryption; for structured data this leaks content ' +
                    'without breaking the key.'
                    : isHash
                      ? 'Passwords or signatures hashed with this can be recovered or forged at ' +
                        'hardware cost considered routine today.'
                      : 'Broken cipher: ciphertext confidentiality is not credible against a modern adversary.',
            recommendation: isRandom
              ? 'Use RandomNumberGenerator.GetBytes / RNGCryptoServiceProvider for anything ' +
                'security-relevant; keep System.Random for simulations only.'
                : isEcB
                  ? 'Use CBC or GCM with a fresh random IV per message.'
                    : isHash
                      ? 'Use PBKDF2/Argon2 for passwords and SHA-256+ for signatures.'
                      : 'Move to AES-GCM (or AES-CBC with a MAC).'
          }));
        }
      }
    }
  },
  {
    id: 'cs-jwt-validation',
    caseIds: ['A-011', 'X-006', 'X-007'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /(ValidateAudience|ValidateIssuer|ValidateLifetime|ValidateIssuerSigningKey|ValidateActor|RequireExpirationTime)\s*=\s*false/;
      const reNonce = /\bnonce\b/i;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re);
        if (!m) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-347'], language: 'csharp',
          title: `Token validation disabled: ${m[1]} = false`,
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: `TokenValidationParameters turns off ${m[1]}. The corresponding claim in every ` +
            'presented token is accepted without comparison to an expected value.',
          impact: 'A token minted for another audience, issuer or lifetime is accepted here: ' +
            'cross-tenant replay, revoked-token reuse, or accepting an attacker\u2019s own ' +
            'self-minted token as a valid identity.',
          recommendation: 'Remove the false flags; pin ValidIssuer/ValidAudience (or IssuerSigningKey ' +
            'resolution) to this application\u2019s exact values and let lifetime validation run.'
        }));
        if (reNonce.test(stripped[i]) && /id[_-]?token|openid|oidc/i.test(windowAfter(stripped, i + 1, 3))) {
          ctx.emit(finding({
            check: this.id + '-nonce', caseIds: ['X-005'], confidence: 'POSSIBLE',
            severity: 'HIGH', category: 'security', cwe: ['CWE-347'], language: 'csharp',
            title: 'OIDC nonce handling present but unverified statically',
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
            problem: 'A nonce is referenced in an OpenID Connect context; static reading cannot ' +
              'confirm the nonce is actually compared against the id_token nonce claim.',
            impact: 'Without enforced nonce comparison, a replayed authorization-code or id_token ' +
              'from another session is accepted.',
            recommendation: 'Ensure the nonce sent in the authentication request is stored ' +
              'server-side (or in a protected cookie) and compared to the id_token nonce before acceptance.'
          }));
        }
      }
    }
  },
  {
    id: 'cs-antiforgery',
    caseIds: ['D-008', 'T-004'],
    run(ctx) {
      if (!/Controller\.cs$/i.test(ctx.relPath)) return;
      const stripped = stripComments(ctx.lines);
      const posts = stripped.filter(l => /\[Http(?:Post|Put|Delete|Patch)\]/i.test(l)).length;
      if (!posts) return;
      if (/ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|Antiforgery/i.test(ctx.text)) return;
      // CSRF needs AMBIENT credentials: the browser must attach them to a cross-site request
      // on its own. A Web API that authenticates with a bearer token the caller has to set
      // explicitly is not forgeable this way, so reporting it as HIGH is a false alarm that
      // costs the reader their attention. Cookie/forms auth anywhere in the app keeps it HIGH;
      // token-only auth downgrades it and says why.
      const az = (ctx.project && ctx.project.authz) || {};
      const ambient = !!az.cookieAuth || !az.tokenAuth;
      const webApi = /:\s*ApiController\b/.test(ctx.text);
      const csrfReachable = ambient || !webApi;
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: csrfReachable ? 'LIKELY' : 'POSSIBLE',
        severity: csrfReachable ? 'HIGH' : 'LOW',
        category: 'security', cwe: ['CWE-352'], language: 'csharp',
        title: `State-changing endpoints (${posts}) with no anti-forgery token in this controller`,
        file: ctx.relPath, startLine: stripped.findIndex(l => /\[Http(?:Post|Put|Delete|Patch)\]/i.test(l)) + 1,
        snippet: stripped.find(l => /\[Http(?:Post|Put|Delete|Patch)\]/i.test(l)),
        problem: 'The controller declares state-changing HTTP verbs but the file contains no ' +
          'ValidateAntiForgeryToken/Antiforgery usage anywhere.',
        impact: csrfReachable
          ? 'A third-party page the user visits can silently submit authenticated POSTs: ' +
            'the browser attaches the session cookie and the server accepts the forged action.'
          : 'Low as it stands: this application authenticates with bearer tokens, which a ' +
            'browser does not attach to a cross-site request by itself, so there are no ambient ' +
            'credentials to ride. It becomes exploitable the moment any cookie-based or ' +
            'session-based authentication is added alongside.',
        recommendation: 'Add [ValidateAntiForgeryToken] to every mutating action (or ' +
          '[AutoValidateAntiforgeryToken] globally) and emit the token in forms/AJAX headers.',
        possibleNote: 'Structural: the controller has mutating verbs and zero anti-forgery usage in file.'
      }));
    }
  },
  {
    // Found by running this framework against a real loan-origination API where 18 of 19
    // controllers carried no [Authorize] and no global filter existed. Every mutating banking
    // endpoint was reachable unauthenticated, and nothing in the pipeline said so -- while the
    // same controllers each produced a HIGH CSRF finding, which is the less severe problem by
    // a wide margin. Missing authorisation outranks forged authorisation.
    id: 'cs-controller-no-authorization',
    caseIds: ['B-001', 'B-010'],
    run(ctx) {
      if (!/Controller\.cs$/i.test(ctx.relPath)) return;
      const stripped = stripComments(ctx.lines);
      const text = stripped.join('\n');

      // Only MVC/Web API controllers, and only ones that actually expose actions.
      if (!/:\s*(?:Api)?Controller\b/.test(text)) return;
      const verbIdx = stripped.findIndex(l => /\[Http(?:Post|Put|Delete|Patch|Get)\]/i.test(l));
      const mutating = stripped.filter(l => /\[Http(?:Post|Put|Delete|Patch)\]/i.test(l)).length;
      if (verbIdx < 0) return;

      // Any authorisation requirement in the file clears it: attribute, policy or role.
      if (/\[Authorize|\[CustomAuthorize|\[ApiKey|\[BasicAuth|PrincipalPermission/i.test(text)) return;

      const az = (ctx.project && ctx.project.authz) || {};
      // A global filter means deny-by-default is already in force; nothing to report.
      if (az.globalFilter) return;

      const cls = (text.match(/class\s+(\w*Controller)\b/) || [])[1] || ctx.relPath;
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'LIKELY',
        severity: mutating ? 'CRITICAL' : 'HIGH',
        category: 'security', cwe: ['CWE-862'], language: 'csharp',
        title: `${cls} exposes ${mutating ? mutating + ' state-changing' : 'read'} endpoint(s) with no authorization requirement`,
        file: ctx.relPath, startLine: verbIdx + 1,
        snippet: stripped.slice(Math.max(0, verbIdx - 2), verbIdx + 3).join('\n'),
        problem: `${cls} declares action methods but carries no [Authorize] attribute at class ` +
          'or method level, and no global authorization filter is registered anywhere in the ' +
          'project (searched for Filters.Add(new Authorize...), AuthorizeFilter, ' +
          'RequireAuthorization() and FallbackPolicy). ASP.NET is allow-by-default: an action ' +
          'with no authorization requirement is anonymous.',
        impact: mutating
          ? 'Every mutating action on this controller can be invoked by an unauthenticated ' +
            'caller who merely knows the route. This is not a forged request from a logged-in ' +
            'victim, which is what an anti-forgery finding describes; it needs no victim and no ' +
            'session at all.'
          : 'The data these actions return is readable without authentication, which makes the ' +
            'controller the natural first target for enumeration.',
        recommendation: 'Prefer deny-by-default: register a global authorization filter ' +
          '(config.Filters.Add(new AuthorizeAttribute()) on Web API, or an AuthorizationOptions ' +
          'FallbackPolicy on ASP.NET Core) and mark the genuinely public endpoints ' +
          '[AllowAnonymous] explicitly. Attribute-by-attribute authorisation fails silently ' +
          'every time someone adds a controller.',
        possibleNote: 'Structural: controller has action verbs, no authorisation attribute in ' +
          'file, and no global filter found in the project.'
      }));
    }
  },
  {
    id: 'cs-anonymous-sensitive',
    caseIds: ['B-010', 'B-001'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const SENSITIVE = /(admin|user|manage|account|internal|debug|config|report|payment|invoice|customer)/i;
      const re = /\[AllowAnonymous\]/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 4);
        const name = win.match(/(?:class|public\s+\w[\w<>,\s]*\s)\s+(\w+)/);
        const isSensitive = SENSITIVE.test(win) && !/login|logout|register|forgot|reset|external|challenge/i.test(win);
        if (!isSensitive) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'HIGH',
          category: 'security', cwe: ['CWE-862'], language: 'csharp',
          title: 'AllowAnonymous on what looks like a sensitive endpoint',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 5).join('\n'),
          problem: '[AllowAnonymous] overrides authentication/authorisation here, and the ' +
            'surrounding names suggest the endpoint is not a login/register surface.',
          impact: 'Whatever this endpoint exposes or mutates is available pre-authentication; ' +
            'if it is administrative or data-bearing it becomes the first thing enumerated.',
          recommendation: 'Confirm intent. If the endpoint is not part of the authentication flow, ' +
            'remove [AllowAnonymous] and let the global deny-by-default policy apply.'
        }));
      }
    }
  },
  {
    id: 'cs-xxe',
    caseIds: ['J-003', 'J-004'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const rules = [
        [/\bDtdProcessing\s*=\s*(?:DtdProcessing\.)?Parse\b/, 'DtdProcessing.Parse allows DTDs'],
        [/\bProhibitDtd\s*=\s*false\b/, 'ProhibitDtd=false allows DTDs'],
        [/\.XmlResolver\s*=\s*(?!null\b)\w/, 'XmlResolver set to a resolving resolver']
      ];
      for (let i = 0; i < stripped.length; i++) {
        for (const [re, why] of rules) {
          if (!re.test(stripped[i])) continue;
          ctx.emit(finding({
            check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
            category: 'security', cwe: ['CWE-611'], language: 'csharp',
            title: 'XML external entity resolution enabled',
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
            problem: `${why} on an XML reader/document parsing input.`,
            impact: 'An attacker-supplied XML document can read local files, reach internal ' +
              'services (SSRF via file:// and http:// entities), or exhaust memory via entity expansion.',
            attackScenario: 'Upload or API accepts XML: DOCTYPE declares an entity pointing at ' +
              'web.config or a cloud metadata endpoint; the parser resolves it into the response or an error.',
            recommendation: 'Set DtdProcessing=Prohibit (the .NET 4.5.2+ default) and ' +
              'XmlResolver=null on every reader that touches untrusted XML.'
          }));
        }
      }
    }
  },
  {
    id: 'cs-open-redirect',
    caseIds: ['D-007', 'X-013'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /Response\s*\.\s*Redirect\s*\(|RedirectToAction\s*\(|return\s+Redirect\s*\(|LocalRedirect\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 2) + stripped[i];
        if (!/Request(\[|\.QueryString|\.Form)|ReturnUrl|returnUrl|redirect[_-]?uri/i.test(win)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'HIGH',
          category: 'security', cwe: ['CWE-601'], language: 'csharp',
          title: 'Redirect target taken from the request without an allow-list',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'The redirect destination appears to come from request data (ReturnUrl or a ' +
            'parameter) with no visible local-URL check.',
          impact: 'A crafted link redirects users through your domain to an attacker\u2019s phishing ' +
            'clone, lending the application\u2019s credibility to the lure; in OAuth flows it can ' +
            'leak codes to attacker-controlled redirect_uri values.',
          recommendation: 'Validate destinations as local (Url.IsLocalUrl / LocalRedirect) or ' +
            'match against an allow-list of exact origins; reject everything else.'
        }));
      }
    }
  },
  {
    id: 'cs-cors-code',
    caseIds: ['N-001', 'N-002'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      for (let i = 0; i < stripped.length; i++) {
        const line = stripped[i];
        const reflected = /Access-Control-Allow-Origin["']?\s*(?:,|\)|=).*Request\.Headers\[["']Origin/i.test(line) ||
          /Request\.Headers\[["']Origin["']\][^;\n]*Access-Control-Allow-Origin/i.test(line);
        const anyOrigin = /AllowAnyOrigin\s*\(\)|Access-Control-Allow-Origin["']?\s*[,:]=?\s*["']\*/i.test(line);
        const creds = /AllowCredentials\s*\(\)|AllowAnyHeader/.test(windowAfter(stripped, i + 1, 3)) ||
          /Access-Control-Allow-Credentials["']?\s*[,:]=?\s*true/i.test(windowAfter(stripped, i + 1, 3));
        if (reflected) {
          ctx.emit(finding({
            check: this.id, caseIds: ['N-001'], confidence: 'LIKELY', severity: 'CRITICAL',
            category: 'security', cwe: ['CWE-346'], language: 'csharp',
            title: 'CORS reflects the request Origin header',
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
            problem: 'The Origin header is copied into Access-Control-Allow-Origin, making every ' +
              'origin a permitted one.',
            impact: 'Any website a victim visits can read authenticated responses from this API in ' +
              'the victim\u2019s browser — the same-origin policy is disabled by reflection.',
            recommendation: 'Echo the Origin only when it exactly matches an allow-list of trusted ' +
              'origins; otherwise omit the header.'
          }));
        } else if (anyOrigin && creds) {
          ctx.emit(finding({
            check: this.id, caseIds: ['N-002'], confidence: 'LIKELY', severity: 'CRITICAL',
            category: 'security', cwe: ['CWE-942'], language: 'csharp',
            title: 'Wildcard CORS combined with credentials',
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 4).join('\n'),
            problem: 'The configuration allows any origin together with credentialed requests ' +
              '(AllowCredentials or a credentials header in the same policy path).',
            impact: 'Browsers enforce that the wildcard cannot be used with credentials — but the ' +
              'intent recorded here is permissive, and any relaxation (per-origin policy added ' +
              'later) inherits it.',
            recommendation: 'Replace AllowAnyOrigin with an explicit origin list; keep ' +
              'AllowCredentials only on policies naming exact origins.'
          }));
        }
      }
    }
  },
  {
    id: 'cs-regex-timeout',
    caseIds: ['P-004'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /new\s+Regex\s*\(|Regex\s*\.\s*(?:Match|Matches|IsMatch|Replace)\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 2) + stripped[i];
        if (/TimeSpan|matchTimeout|RegexOptions\.(?:NonBacktracking)/.test(win)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'MEDIUM',
          category: 'performance', cwe: ['CWE-1333'], language: 'csharp',
          title: 'Regex evaluated without a match timeout',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'The regex call has no timeout argument. Whether the pattern backtracks ' +
            'catastrophically depends on the pattern and input, which this check does not model.',
          impact: 'A crafted subject string can pin a CPU core for minutes-to-forever; one request ' +
            'per worker is a denial of service.',
          recommendation: 'Pass a matchTimeout TimeSpan (new Regex(pattern, options, TimeSpan.FromSeconds(1))) ' +
            'or use RegexOptions.NonBacktracking where available.'
        }));
      }
    }
  },
  {
    id: 'cs-reflection-input',
    caseIds: ['S-001', 'S-002', 'S-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\bType\s*\.\s*GetType\s*\(|\bActivator\s*\.\s*CreateInstance\s*\(|\bAssembly\s*\.\s*(?:Load|LoadFrom|LoadFile)\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        const win = windowAfter(stripped, i + 1, 2) + stripped[i];
        if (!/\bRequest\b|\bQuery\b|\[\s*"|\[\s*'\b|\w+Param|RouteData|Form\b|Header/i.test(win)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'POSSIBLE', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-470'], language: 'csharp',
          title: 'Reflection/type-loading on a request-influenced name',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'Type resolution, activation or assembly loading is called with a name that ' +
            'may come from the request rather than a hardcoded identifier.',
          impact: 'If the name is attacker-controlled, the attacker selects which type loads and ' +
            'constructs — arbitrary type instantiation is one step from code execution when any ' +
            'loadable type has a dangerous constructor or static initialiser.',
          recommendation: 'Resolve types from a hardcoded map (name -> Type) instead of reflecting ' +
            'over request data; validate with an allow-list before any Load/GetType call.'
        }));
      }
    }
  },
  {
    id: 'cs-scripting',
    caseIds: ['U-002', 'U-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\bCSharpScript\s*\.\s*(?:Evaluate|Run)\w*\s*\(|\bCodeDomProvider\s*\.\s*Compile\w*\s*\(|\bRoslynScript\b/;
      for (let i = 0; i < stripped.length; i++) {
        if (!re.test(stripped[i])) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'CRITICAL',
          category: 'security', cwe: ['CWE-94'], language: 'csharp',
          title: 'Server-side script/compilation engine invoked at runtime',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: 'The application compiles and executes script (Roslyn scripting or CodeDom) ' +
            'as part of request processing.',
          impact: 'Whatever reaches the script sees the process: secrets in memory, the file ' +
            'system, and the network. Any untrusted influence on script content is code execution.',
          recommendation: 'Remove runtime scripting. If expression evaluation is a product ' +
            'requirement, use a sandboxed expression language with no type access and test the ' +
            'sandbox against escape attempts.'
        }));
      }
    }
  },
  {
    id: 'cs-tls-versions',
    caseIds: ['F-004'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /SecurityProtocol\s*=?[^;\n]*\b(Ssl3|Tls)\b(?!2|3)/;
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(re);
        if (!m) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'LIKELY', severity: 'HIGH',
          category: 'security', cwe: ['CWE-327'], language: 'csharp',
          title: `Obsolete TLS version permitted: ${m[1]}`,
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 2).join('\n'),
          problem: `ServicePointManager/security protocol selection explicitly enables ${m[1]}.`,
          impact: 'Connections can be negotiated down to protocols with known attacks (POODLE, ' +
            'CBC padding issues), defeating TLS protections on that channel.',
          recommendation: 'Permit only TLS 1.2+ (SecurityProtocolType.Tls12 | Tls13); remove the ' +
            'legacy flags rather than OR-ing them in.'
        }));
      }
    }
  },
  {
    id: 'cs-connection-options',
    caseIds: ['F-006'],
    run(ctx) {
      const re = /(Encrypt\s*=\s*(?:False|false)|TrustServerCertificate\s*=\s*(?:True|true))/;
      for (let i = 0; i < ctx.lines.length; i++) {
        const m = ctx.lines[i].match(re);
        if (!m) continue;
        ctx.emit(finding({
          check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
          category: 'security', cwe: ['CWE-319'], language: 'csharp',
          title: 'Database connection encryption disabled or certificate trust skipped',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines[i].replace(/(password|pwd)=[^;"']+[^;"'\s]*/gi, '$1=***REDACTED***'),
          problem: `The connection string contains "${m[0]}" — traffic is not protected end to end.`,
          impact: 'Database credentials and data cross the network readable and modifiable by ' +
            'anyone on the path; TrustServerCertificate additionally accepts any MITM certificate.',
          recommendation: 'Remove Encrypt=False / TrustServerCertificate=true and deploy a server ' +
            'certificate the client actually validates.'
        }));
      }
    }
  }
];

module.exports = { CHECKS, stripComments, windowAfter, windowBefore, clean };
