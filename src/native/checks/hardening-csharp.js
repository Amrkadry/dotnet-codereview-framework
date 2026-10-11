// dotnet-codereview-framework — src/native/checks/hardening-csharp.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * C# hardening checks — the six mechanically decidable CH-* cases.
 *
 * Sources mined 2026-10-08: Security Code Scan rule catalog (SCS0001–SCS0034),
 * Microsoft CA security analyzers (CA5370 DataSet.ReadXml, CA5369 XmlSerializer
 * types, CA5389-family archive handling), Puma Scan — diffed against the existing
 * A–Z catalog; only genuine gaps landed here. NTLM exposure (CH-007) is
 * deliberately a manual-review case: endpoint trust boundaries are not decidable
 * from a single file.
 *
 * ctx: { relPath, text, lines, emit } — one .cs/.vb file per call.
 */

const { finding } = require('../finding');
// shared, string-aware helpers from the core C# check module
const { stripComments, windowAfter, windowBefore, clean } = require('./csharp');

const CHECKS = [
  {
    id: 'cs-ldap-dn-injection', caseIds: ['CH-001'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /new\s+DirectoryEntry\s*\(|\.Rename\s*\(|Invoke\s*\(\s*"SetPassword"|\.Path\s*=/;
      for (let i = 0; i < stripped.length; i++) {
        // raw line: stripComments would cut string literals at "//" (LDAP://, URLs)
        const line = ctx.lines[i];
        if (!re.test(line)) continue;
        if (!stripped[i] || !stripped[i].trim()) continue; // full-line comment
        const args = line + ' ' + ctx.lines.slice(i + 1, i + 3).join(' ');
        if (!/\+|\$"|string\.Format|Interpolate/.test(args)) continue;
        if (/LDAP:\/\//i.test(args) && /"/.test(args)) {
          // concatenation on an LDAP path — DN components unescaped
          ctx.emit(finding({
            check: this.id, caseIds: ['CH-001'],
            confidence: 'POSSIBLE', severity: 'HIGH', category: 'security',
            cwe: ['CWE-90'], language: 'csharp',
            title: 'LDAP distinguished name built by concatenation',
            file: ctx.relPath, startLine: i + 1,
            snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
            problem: 'A distinguished name (or LDAP path) is assembled from dynamic input. DN ' +
              'metacharacters (\\\\, /, #, +, <, >, ;) are not escaped, so a crafted value can point ' +
              'the operation at a different object in the directory.',
            impact: 'Create/rename/password operations land on an attacker-chosen object — account ' +
              'manipulation and privilege relocation without any directory rights escalation.',
            attackScenario: 'A name like "x,CN=Domain Admins" in the DN-joining field relocates the ' +
              'operation to a privileged container.',
            recommendation: 'Escape DN special characters per RFC 4514 before composing; prefer ' +
              'directory APIs that take structured attributes rather than string DNs.'
          }));
        }
      }
    }
  },
  {
    id: 'cs-dataset-readxml', caseIds: ['CH-003'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /\.(?:DataSet|DataTable)\s*\)|\bReadXml\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        const line = stripped[i];
        if (!/\bReadXml\s*\(/.test(line)) continue;
        const ctxLine = windowBefore(stripped, i + 1, 3) + ' ' + line;
        if (!/DataSet|DataTable/.test(ctxLine)) continue;
        const win = line + ' ' + windowAfter(stripped, i + 1, 2);
        // trusted usage: explicit ReadSchema/IgnoreSchema or an XmlReader from a known schema
        if (/XmlReadMode\.(?:ReadSchema|IgnoreSchema)|XmlReader\.Create/.test(win)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['CH-003'],
          confidence: 'POSSIBLE', severity: 'HIGH', category: 'security',
          cwe: ['CWE-502'], language: 'csharp',
          title: 'DataSet/DataTable.ReadXml without a type-restricted mode',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 2), i + 3).join('\n'),
          problem: 'ReadXml runs in the default XmlReadMode, which accepts inline schemas. A crafted ' +
            'payload can define types the serializer will instantiate (CVE-2020-1147 family).',
          impact: 'Untrusted XML becomes arbitrary type construction inside the process — ' +
            'information disclosure or remote code execution.',
          attackScenario: 'POST an XML document with an inline schema referencing a gadget type; ' +
            'ReadXml instantiates it during deserialization.',
          recommendation: 'Call ReadXml with XmlReadMode.ReadSchema against a trusted, deployed ' +
            'schema, or read through an XmlReader created with DtdProcessing=Ignore and a fixed ' +
            'schema; never deserialize dataset XML straight from requests.'
        }));
      }
    }
  },
  {
    id: 'cs-toctou-file-race', caseIds: ['CH-004'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      for (let i = 0; i < stripped.length; i++) {
        const m = stripped[i].match(/File\.Exists\s*\(\s*([A-Za-z_]\w*)\s*\)/);
        if (!m) continue;
        const v = m[1];
        const after = stripped[i] + ' ' + windowAfter(stripped, i + 2, 3);
        if (!new RegExp('File\\.(?:Delete|Open|Move|Copy|ReadAll|WriteAll)|new\\s+(?:StreamReader|FileStream)\\s*\\([^)]*\\b' + v + '\\b').test(after)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['CH-004'],
          confidence: 'POSSIBLE', severity: 'LOW', category: 'reliability',
          cwe: ['CWE-367'], language: 'csharp',
          title: 'File existence check racing the later file operation',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 5).join('\n'),
          problem: 'File.Exists guards a subsequent open/delete on the same path — the answer is ' +
            'stale the moment it returns (TOCTOU).',
          impact: 'Error paths on contested files, and symlink-swap attacks where an attacker ' +
            'replaces the checked path between the check and the use.',
          attackScenario: 'A local process (or an attacker-controlled upload directory) swaps the ' +
            'path for a symlink; the privileged delete/open follows the link.',
          recommendation: 'Drop the pre-check: open in try/catch and handle ' +
            'FileNotFoundException/IOException; open with FileOptions such as DeleteOnClose where relevant.'
        }));
      }
    }
  },
  {
    id: 'cs-serializer-dynamic-type', caseIds: ['CH-005'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /new\s+(?:XmlSerializer|JavaScriptSerializer|DataContractSerializer)\s*\(/;
      for (let i = 0; i < stripped.length; i++) {
        const args = stripped[i] + ' ' + windowAfter(stripped, i + 1, 2);
        if (!re.test(args)) continue;
        if (!/Type\.GetType\s*\(|GetType\s*\(\s*\w+\s*\+\s*\w|Assembly\.CreateInstance|Activator\.CreateInstance/.test(args)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['CH-005'],
          confidence: 'LIKELY', severity: 'HIGH', category: 'security',
          cwe: ['CWE-502'], language: 'csharp',
          title: 'Serializer constructed from a dynamically resolved type',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 3).join('\n'),
          problem: 'The serializer\u2019s target type is resolved at runtime from input-influenced ' +
            'text (Type.GetType/assembly-qualified names). Whoever controls the string chooses the ' +
            'type that gets constructed.',
          impact: 'Type confusion into gadget classes — the deserialization-equivalent of arbitrary ' +
            'object creation, up to RCE.',
          attackScenario: 'Pass an assembly-qualified gadget type name; the serializer does the rest.',
          recommendation: 'Build serializers for a fixed set of known types at startup; never take ' +
            'type names from requests, config or payloads.'
        }));
      }
    }
  },
  {
    id: 'cs-shell-powershell', caseIds: ['CH-006'],
    run(ctx) {
      const stripped = stripComments(ctx.lines);
      const re = /powershell(?:\.exe)?|pwsh(?:\.exe)?/i;
      for (let i = 0; i < stripped.length; i++) {
        const line = ctx.lines[i];
        if (!re.test(line)) continue;
        if (!stripped[i] || !stripped[i].trim()) continue; // full-line comment
        const args = line + ' ' + ctx.lines.slice(i + 1, i + 4).join(' ');
        if (!/-Command|-EncodedCommand|-File\s*\+|\+\s*"-/.test(args)) continue;
        ctx.emit(finding({
          check: this.id, caseIds: ['CH-006'],
          confidence: 'POSSIBLE', severity: 'HIGH', category: 'security',
          cwe: ['CWE-78'], language: 'csharp',
          title: 'PowerShell invoked with dynamically composed command text',
          file: ctx.relPath, startLine: i + 1,
          snippet: ctx.lines.slice(Math.max(0, i - 1), i + 4).join('\n'),
          problem: 'A shell-out to PowerShell carries -Command/-EncodedCommand/-File arguments ' +
            'built by concatenation. PowerShell is a full scripting host: the composed text is code.',
          impact: 'Any input that reaches the argument string executes arbitrary script under the ' +
            'application identity — full host compromise.',
          attackScenario: 'A filename or parameter containing "; Remove-Item ... -Recurse" (or an ' +
            'encoded command blob) is spliced into the argument string.',
          recommendation: 'Do not delegate to a shell. Use fixed .ps1 files with param() binding ' +
            'invoked via -File, or call the underlying API from .NET; allowlist every argument.'
        }));
      }
    }
  },
];

module.exports = { CHECKS };
