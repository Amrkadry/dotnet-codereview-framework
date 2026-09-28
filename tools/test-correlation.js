#!/usr/bin/env node
'use strict';
/**
 * Correlation test: proves that multiple tools reporting ONE issue produce ONE finding,
 * and that a tool which ran but did not report it is recorded as MISSED.
 */
const fs = require('fs'); const path = require('path');
const { correlate } = require('../src/correlate/merge');
const root = path.resolve(__dirname, '..');
const load = id => require(path.join(root, 'src/adapters', id))
  .parse(fs.readFileSync(path.join(root, 'fixtures', id + '.json'), 'utf8'), { sourcePath: root });

let fail = 0;
const t = (name, cond, detail) => {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!cond) fail++;
};

// --- 1. cross-tool secret dedup: trivy + gitleaks both flag SampleApp/Web.config
const trivy = load('trivy').filter(f => f.category === 'security');
const gitleaks = load('gitleaks');
const a = correlate([...trivy, ...gitleaks], { toolsThatRan: ['trivy', 'gitleaks', 'semgrep'] });
const merged = a.findings.filter(f =>
  (f.sources || []).filter(s => s.status === 'REPORTED').length > 1);
t('trivy + gitleaks secret findings correlate into one',
  merged.length >= 1, `${a.stats.inputFindings} in -> ${a.stats.canonicalFindings} out, merged ${a.stats.mergedAway}`);
t('a tool that ran but did not report is recorded as MISSED',
  a.findings.some(f => (f.sources || []).some(s => s.tool === 'semgrep' && s.status === 'MISSED')));

// --- 2. concept dedup across different rule ids: sonarqube S4830 vs semgrep cert-validation
const sonar = load('sonarqube');
const semgrep = load('semgrep');
const b = correlate([...sonar, ...semgrep], { toolsThatRan: ['sonarqube', 'semgrep'] });
const certBoth = b.findings.find(f =>
  (f.sources || []).some(s => s.tool === 'sonarqube') &&
  (f.sources || []).some(s => s.tool === 'semgrep' && s.status === 'REPORTED'));
t('S4830 and moraa-dotnet-disable-cert-validation merge via rule equivalence',
  !!certBoth, certBoth ? certBoth.findingId + ' ' + certBoth.severity : 'not merged');

const regexBoth = b.findings.find(f =>
  (f.sources || []).filter(s => s.status === 'REPORTED').length > 1 &&
  /regex|timeout/i.test(f.title));
t('S6444 and moraa-dotnet-regex-no-timeout merge via rule equivalence', !!regexBoth);

// --- 3. no duplicate canonical ids, and severity is the strongest of the merged set
const ids = b.findings.map(f => f.findingId);
t('canonical ids are unique', ids.length === new Set(ids).size);
if (certBoth) t('merged finding keeps the strongest severity',
  ['CRITICAL','HIGH'].includes(certBoth.severity), certBoth.severity);

// --- 4. dedup must not lose any tool's attribution
const allSources = b.findings.flatMap(f => f.sources.filter(s => s.status === 'REPORTED'));
t('no reported source is lost during merge',
  allSources.length === sonar.length + semgrep.length,
  `${allSources.length} kept of ${sonar.length + semgrep.length}`);

console.log(fail ? `\n${fail} correlation test(s) FAILED` : '\nall correlation tests passed');
process.exit(fail ? 1 : 0);
