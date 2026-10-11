// dotnet-codereview-framework — src/native/checks/web-membership.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Membership password policy check (CH-002) — config-file lane.
 *
 * SCS0032/0033/0034 aligned: a <membership> provider with no minRequiredPasswordLength
 * runs with the Framework default of 1; a small minimum plus no strength expression is
 * the classic weak-credential entry point. ASP.NET Identity (modern) is a pass.
 */

const { finding } = require('../finding');

const CHECKS = [
  {
    id: 'web-membership-policy',
    caseIds: ['CH-002'],
    run(ctx) {
      if (!/<membership/i.test(ctx.text)) return;
      const prov = ctx.text.match(/<providers[^>]*>([\s\S]*?)<\/providers>/i);
      const seg = prov ? prov[1] : ctx.text;
      const min = seg.match(/minRequiredPasswordLength\s*=\s*"(\d+)"/i);
      const strength = /passwordStrengthRegularExpression\s*=\s*"[^"]+"/i.test(seg);
      const modern = /MicrosoftASPNETIdentity|IdentityOptions/i.test(ctx.text);
      const minN = min ? parseInt(min[1], 10) : null;
      if (modern || (minN !== null && minN >= 8 && strength)) return;
      const mOpen = ctx.text.match(/<membership/i) || { index: 0 };
      let line = 1, upto = 0;
      for (let i = 0; i < ctx.lines.length; i++) {
        upto += ctx.lines[i].length + 1;
        if (mOpen.index < upto) { line = i + 1; break; }
      }
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'MEDIUM',
        category: 'configuration', cwe: ['CWE-521'],
        title: 'Membership password policy weak or unspecified',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines.slice(line - 1, Math.min(ctx.lines.length, line + 6)).join('\n'),
        language: 'xml',
        problem: (minN === null
          ? 'The membership provider sets no minRequiredPasswordLength, so the Framework default of 1 applies.'
          : 'The membership provider accepts passwords of only ' + minN + ' characters.')
          + (strength ? '' : ' No passwordStrengthRegularExpression is configured either.'),
        impact: 'Short, uncomplex passwords are the cheapest path into any account — one weak ' +
          'credential cascades wherever that user touches the application.',
        recommendation: 'Set minRequiredPasswordLength >= 8 (15 without MFA per NIST) plus a ' +
          'strength expression, or migrate to ASP.NET Identity and its defaults.'
      }));
    }
  },
];

module.exports = { CHECKS };
