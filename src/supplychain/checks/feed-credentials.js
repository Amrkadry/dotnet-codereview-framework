// dotnet-codereview-framework — src/supplychain/checks/feed-credentials.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * CHECK 2 — feed and credential misconfiguration.
 *
 * What is detectable from the repository alone: plaintext credentials in nuget.config,
 * credentials embedded in a source URL, non-TLS feeds, explicit signature-validation
 * downgrades, and trusted roots that accept untrusted chains. Every credential is REDACTED
 * at parse time (src/supplychain/nuget-config.js), so no snippet here can echo a value —
 * the finding records THAT a secret exists and WHERE, never WHAT.
 *
 * What is deliberately not judged offline: whether a feed's host "belongs" to the
 * organisation. That needs context this analyzer does not have; an IP-literal host is the
 * one machine-checkable proxy and it is flagged at LOW confidence for a human to confirm.
 */

const { buildFinding } = require('../finding');
const { enabledFeeds } = require('../nuget-config');

function feedCredentials(inv) {
  const out = [];

  for (const cfg of inv.nugetConfigs) {
    const m = cfg.model;

    // ---- plaintext credentials ------------------------------------------------------------
    for (const cred of m.credentials) {
      const inUrl = cred.kind === 'credentials-in-URL';
      out.push(buildFinding('nuget-plaintext-credential', {
        title: inUrl
          ? `Feed URL in nuget.config embeds credentials for feed "${cred.feed}"`
          : `nuget.config stores a ${cred.kind} in plaintext for feed "${cred.feed}"`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        cwe: inUrl ? ['CWE-522', 'CWE-312'] : ['CWE-312'],
        owasp: ['A07:2021'],
        location: { file: cfg.file, startLine: cred.line },
        evidence: {
          snippet: cred.snippet,          // value already replaced by [REDACTED] at parse time
          language: 'xml',
          redacted: true,
          toolOutput: 'credential value withheld by the parser; only its presence and line are recorded'
        },
        problem: inUrl
          ? 'The package source URL carries userinfo credentials. Anything that renders the URL — ' +
            'CI logs, error messages, shell history, this report — receives the secret with it.'
          : `The ${cred.kind} element holds the feed credential as plaintext inside a file that is ` +
            'typically committed to source control.',
        impact: 'Anyone with repository read access (including every CI job, agent and former ' +
          'employee with historical access) holds a live feed credential, which is both a secret ' +
          'leak and a supply-chain pivot: whoever holds the feed credential can also PUBLISH to it.',
        recommendation: 'Move the credential out of the file into a secret store (environment ' +
          'variable, Azure Key Vault, CI secret) and let the NuGet credential providers supply it ' +
          'at restore time. Rotate the exposed value now — plaintext in git history is already ' +
          'disclosure, and this analyzer cannot see history to bound it.',
        tests: ['O-004'],
        effort: 'SMALL',
        priority: 'P1',
        sourceNote: 'value redacted before parsing; never stored in the model',
        engine: 'config-xml'
      }));
    }

    // ---- non-TLS feeds ---------------------------------------------------------------------
    for (const feed of enabledFeeds(m)) {
      if (!/^http:\/\//i.test(feed.url)) continue;
      out.push(buildFinding('nuget-non-tls-feed', {
        title: `Package feed "${feed.name}" is served over plain HTTP`,
        severity: feed.hasCredential ? 'HIGH' : 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-319'],
        owasp: ['A02:2021'],
        location: { file: cfg.file, startLine: feed.line },
        evidence: {
          snippet: feed.snippet,
          language: 'xml',
          toolOutput: `resolved URL: ${feed.urlSafe}${feed.hasCredential ? ' (this feed also carries a credential — see the plaintext-credential finding)' : ''}`
        },
        problem: 'The feed is consumed over http://, so packages, their hashes and any feed ' +
          'credentials traverse the network unencrypted.',
        impact: 'Any network path between the build machine and the feed (office LAN, VPN, CI egress) ' +
          'can substitute package bytes in transit — the same substitution outcome as dependency ' +
          'confusion, obtained without registering anything.',
        recommendation: 'Serve the feed over HTTPS. If it is an internal host, put TLS on it — an ' +
          'internal feed without TLS is reachable from every segment the build network touches.',
        tests: ['O-004'],
        effort: 'MEDIUM',
        priority: feed.hasCredential ? 'P1' : 'P2',
        engine: 'config-xml'
      }));
    }

    // ---- signature validation explicitly not required ---------------------------------------
    if (m.signature.declared && m.signature.mode && !/require/i.test(m.signature.mode)) {
      out.push(buildFinding('nuget-signature-validation-accept', {
        title: 'nuget.config explicitly accepts unsigned packages',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-494'],
        owasp: ['A08:2021'],
        location: { file: cfg.file, startLine: m.signature.line || 1 },
        evidence: {
          snippet: `signatureValidation mode="${m.signature.mode}"`,
          language: 'xml',
          toolOutput: 'signatureValidation section present with a non-Require mode'
        },
        problem: 'A signatureValidation section exists and its mode is not "Require", so packages ' +
          'are accepted without an author signature even though the project took the trouble to ' +
          'configure the section.',
        impact: 'Package integrity rests entirely on the feeds and the lockfile hashes; a compromised ' +
          'or malicious feed can ship arbitrary content with nothing cryptographic to notice.',
        recommendation: 'Set signatureValidation mode="Require" together with trustedSigners entries ' +
          'for the signers you actually consume, and let a restore of a tampered package fail loudly.',
        tests: ['O-004'],
        effort: 'SMALL',
        priority: 'P3',
        engine: 'config-xml'
      }));
    }

    // ---- trusted root that is not trusted ----------------------------------------------------
    for (const cert of m.signature.allowUntrustedRoot) {
      out.push(buildFinding('nuget-untrusted-signer-root', {
        title: 'Trusted signer accepts a certificate chain to an untrusted root',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        cwe: ['CWE-494', 'CWE-295'],
        owasp: ['A08:2021'],
        location: { file: cfg.file, startLine: cert.line },
        evidence: { snippet: cert.snippet, language: 'xml' },
        problem: 'allowUntrustedRoot="true" disables the chain check for this signer certificate.',
        impact: 'Any certificate with that fingerprint becomes acceptable regardless of who issued ' +
          'it — the signature check is reduced to a static string comparison an attacker can meet ' +
          'by copying a fingerprint.',
        recommendation: 'Remove allowUntrustedRoot unless a PKI team explicitly approved this exact ' +
          'self-signed signer; prefer chaining to a real root.',
        tests: ['O-004'],
        effort: 'TRIVIAL',
        priority: 'P2',
        engine: 'config-xml'
      }));
    }

    // ---- host we cannot attribute: IP-literal feed -------------------------------------------
    for (const feed of enabledFeeds(m)) {
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(feed.host || '')) continue;
      out.push(buildFinding('nuget-ip-literal-feed', {
        title: `Package feed "${feed.name}" points at a bare IP address`,
        severity: 'LOW',
        confidence: 'POSSIBLE',
        cvss: null,
        cwe: ['CWE-1357'],
        location: { file: cfg.file, startLine: feed.line },
        evidence: { snippet: feed.snippet, language: 'xml' },
        problem: 'The feed host is an IP literal, which cannot be attributed to an owner the way a ' +
          'corporate hostname can.',
        impact: 'UNKNOWN OFFLINE — whether this host is corporate infrastructure or an attacker- or ' +
          'hobbyist-controlled box cannot be decided from the repository. A human must confirm.',
        recommendation: 'Confirm the host is owned by the organisation, then move it behind a named, ' +
          'TLS-terminated internal endpoint so its identity is auditable.',
        tests: ['O-004'],
        effort: 'SMALL',
        priority: 'P3',
        engine: 'config-xml'
      }));
    }
  }
  return out;
}

module.exports = { feedCredentials };
