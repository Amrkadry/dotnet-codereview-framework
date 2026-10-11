// dotnet-codereview-framework — src/discover/project.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Project discovery and CAPABILITY DETECTION.
 *
 * The framework's first principle is that it must never report a clean result it never obtained.
 * That requires knowing, before any scan, what the project shape actually permits. The clearest
 * example: `dotnet list package --vulnerable` cannot evaluate a non-SDK web project at all, so on
 * a packages.config solution an empty dependency result means "nothing looked", not "nothing found".
 *
 * Discovery is read-only. It never builds, never restores, never mutates the source tree.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = /^(bin|obj|packages|node_modules|\.git|\.vs|\.svn|\.idea|\.moraa-review|\.sonarqube|TestResults|dist|out)$/i;

function walk(root, onFile, depth = 0) {
  if (depth > 12) return;
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.test(e.name)) continue;
      walk(full, onFile, depth + 1);
    } else onFile(full, e.name);
  }
}

const read = p => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const exists = p => { try { return fs.existsSync(p); } catch { return false; } };

/** Parse a csproj for the facts that drive tool selection. */
function inspectProject(file) {
  const xml = read(file);
  const sdkStyle = /<Project\s+[^>]*Sdk\s*=/.test(xml);
  const tfm = (xml.match(/<TargetFrameworks?>([^<]+)</i) || [])[1] || '';
  const tfv = (xml.match(/<TargetFrameworkVersion>([^<]+)</i) || [])[1] || '';
  const dir = path.dirname(file);

  return {
    file,
    name: path.basename(file, path.extname(file)),
    sdkStyle,
    targetFramework: (tfm || tfv).trim() || 'unknown',
    isWebProject: /Microsoft\.WebApplication\.targets|<UseIISExpress>|Microsoft\.NET\.Sdk\.Web/i.test(xml),
    isTestProject: /<IsTestProject>\s*true|Microsoft\.NET\.Test\.Sdk|xunit|nunit|MSTest/i.test(xml) ||
      /\.tests?$/i.test(path.basename(file, path.extname(file))),
    usesPackagesConfig: exists(path.join(dir, 'packages.config')),
    usesPackageReference: /<PackageReference\b/.test(xml),
    hasLockFile: exists(path.join(dir, 'packages.lock.json')),
    analyzersEnabled: /<EnableNETAnalyzers>\s*true|<AnalysisMode>|<CodeAnalysisRuleSet>/i.test(xml),
    warningsAsErrors: /<TreatWarningsAsErrors>\s*true/i.test(xml),
    nugetAudit: /<NuGetAudit>\s*true/i.test(xml)
  };
}

function discover(sourcePath) {
  const solutions = [], projects = [], configs = [];
  let hasDockerfile = false, hasCI = false, ciFiles = [];

  walk(sourcePath, (full, name) => {
    if (/\.sln$/i.test(name)) solutions.push(full);
    else if (/\.(csproj|vbproj|fsproj)$/i.test(name)) projects.push(full);
    else if (/^(web|app)\.(\w+\.)?config$/i.test(name) || /^appsettings(\.\w+)?\.json$/i.test(name)) configs.push(full);
    else if (/^Dockerfile$/i.test(name)) hasDockerfile = true;
  });

  for (const f of ['azure-pipelines.yml', '.gitlab-ci.yml', 'Jenkinsfile', 'bitbucket-pipelines.yml']) {
    if (exists(path.join(sourcePath, f))) { hasCI = true; ciFiles.push(f); }
  }
  if (exists(path.join(sourcePath, '.github', 'workflows'))) {
    hasCI = true; ciFiles.push('.github/workflows');
  }

  const inspected = projects.map(inspectProject);
  const anyPackagesConfig = inspected.some(p => p.usesPackagesConfig);
  const anyNonSdk = inspected.some(p => !p.sdkStyle);
  const anyWebNonSdk = inspected.some(p => !p.sdkStyle && p.isWebProject);
  const testProjects = inspected.filter(p => p.isTestProject);

  const stack = inspected.length === 0 ? 'unknown'
    : inspected.every(p => p.sdkStyle) ? 'core'
      : inspected.some(p => p.sdkStyle) ? 'mixed' : 'framework';

  // ------------------------------------------------ capability detection
  const capabilities = {
    dotnetListPackage: {
      supported: !anyPackagesConfig && !anyWebNonSdk,
      reason: anyWebNonSdk
        ? 'A non-SDK web project imports Microsoft.WebApplication.targets, which the dotnet SDK does ' +
          'not ship, so project evaluation fails outright.'
        : anyPackagesConfig
          ? '`dotnet list package` does not support packages.config projects.'
          : 'SDK-style projects with PackageReference: supported.',
      alternative: 'Use Trivy, OSV-Scanner or OWASP Dependency-Check — all read the manifest ' +
        'directly and need no project evaluation.'
    },
    dotnetBuild: {
      supported: !anyWebNonSdk,
      reason: anyWebNonSdk
        ? 'Legacy web projects require MSBuild with the Visual Studio web targets.'
        : 'SDK-style projects build with the dotnet CLI.',
      alternative: 'Use MSBuild.exe from a Visual Studio installation.'
    },
    dotnetTest: {
      supported: testProjects.length > 0,
      reason: testProjects.length
        ? `${testProjects.length} test project(s) found.`
        : 'No test project exists in this solution, so there is nothing to run and no coverage to measure. ' +
          'This must be reported as NOT_APPLICABLE, never as a passing test run.',
      alternative: 'Add a test project before relying on any regression gate.'
    },
    sonarScanner: {
      supported: true,
      reason: anyNonSdk
        ? '.NET Framework requires the MSBuild scanner (SonarScanner.MSBuild.exe begin/build/end), ' +
          'not the plain CLI scanner, which would analyse no C#.'
        : 'Either scanner works; the CLI scanner is simplest for SDK-style projects.'
    },
    reproducibleRestore: {
      supported: inspected.some(p => p.hasLockFile),
      reason: inspected.some(p => p.hasLockFile)
        ? 'A lockfile is present.'
        : 'No packages.lock.json, so restores are neither reproducible nor integrity-checked. ' +
          'packages.config cannot carry hashes at all.'
    },
    buildTimeAnalysis: {
      supported: inspected.some(p => p.analyzersEnabled) ||
        exists(path.join(sourcePath, 'Directory.Build.props')) ||
        exists(path.join(sourcePath, '.editorconfig')),
      reason: 'Analyzers must be enabled for SDK security rules (CA5359, CA1305, CA3075) to run at all.'
    }
  };

  return {
    sourcePath,
    name: path.basename(sourcePath),
    stack,
    solution: solutions[0] ? path.relative(sourcePath, solutions[0]).replace(/\\/g, '/') : null,
    solutions: solutions.map(s => path.relative(sourcePath, s).replace(/\\/g, '/')),
    projects: inspected.map(p => Object.assign({}, p, {
      file: path.relative(sourcePath, p.file).replace(/\\/g, '/')
    })),
    configFiles: configs.map(c => path.relative(sourcePath, c).replace(/\\/g, '/')),
    counts: {
      solutions: solutions.length,
      projects: inspected.length,
      testProjects: testProjects.length,
      configFiles: configs.length
    },
    flags: {
      anyPackagesConfig, anyNonSdk, anyWebNonSdk,
      hasTests: testProjects.length > 0,
      hasLockFile: inspected.some(p => p.hasLockFile),
      hasAnalyzers: capabilities.buildTimeAnalysis.supported,
      hasDockerfile, hasCI, ciFiles,
      isGitRepo: exists(path.join(sourcePath, '.git'))
    },
    capabilities
  };
}

/** Findings that discovery itself can establish — no tool required. */
function discoveryFindings(project) {
  const out = [];
  const mk = (o) => Object.assign({
    category: 'process', severity: 'MEDIUM', confidence: 'CONFIRMED', cvss: null,
    evidence: { snippet: '', language: 'text' },
    sources: [{ tool: 'discover', status: 'REPORTED', note: 'established by repository inspection' }],
    status: 'OPEN', detection: { class: 'DETERMINISTIC', rules: [] }
  }, o);

  if (!project.flags.hasTests) {
    out.push(mk({
      title: 'Solution contains no test project',
      category: 'testing', severity: 'HIGH',
      location: { file: project.solution || '.' },
      evidence: {
        snippet: `projects: ${project.counts.projects}, test projects: 0`, language: 'text',
        toolOutput: 'discover: no project matched a test SDK or test framework reference'
      },
      problem: 'No project in the solution references a test SDK or a test framework.',
      impact: 'Every finding in this report is currently un-regression-testable. Remediating security ' +
        'defects without a test suite risks trading a security defect for a behavioural one, which ' +
        'makes this a prerequisite for safely fixing the rest, not a follow-up.',
      recommendation: 'Add a test project targeting the same framework, seed it with the regression ' +
        'test named on each P0/P1 finding, and make the test run a blocking CI gate.',
      tests: ['R-007'], priority: 'P1', effort: 'LARGE'
    }));
  }

  if (!project.capabilities.dotnetListPackage.supported) {
    out.push(mk({
      title: 'Dependency vulnerability auditing is not possible with first-party tooling',
      category: 'dependency', severity: 'MEDIUM',
      location: { file: (project.projects[0] && project.projects[0].file) || '.' },
      evidence: {
        snippet: project.capabilities.dotnetListPackage.reason, language: 'text',
        toolOutput: 'discover: capability check — dotnetListPackage unsupported'
      },
      problem: project.capabilities.dotnetListPackage.reason,
      impact: 'Without a manifest-reading scanner the vulnerability status of the dependencies is ' +
        'UNKNOWN. An empty dependency result is absence of evidence, not evidence of absence.',
      recommendation: project.capabilities.dotnetListPackage.alternative +
        ' Longer term, migrate packages.config to PackageReference, which enables NuGetAudit and a lockfile.',
      tests: ['O-001', 'O-002'], priority: 'P1', effort: 'MEDIUM'
    }));
  }

  if (!project.flags.hasLockFile && project.flags.anyPackagesConfig) {
    out.push(mk({
      title: 'No package lockfile, so restores are not reproducible',
      category: 'dependency', severity: 'LOW',
      location: { file: (project.projects[0] && project.projects[0].file) || '.' },
      evidence: { snippet: 'packages.lock.json: absent', language: 'text' },
      problem: 'packages.config pins versions but records no content hashes, and no lockfile exists.',
      impact: 'A restore verifies nothing about package integrity, and resolution can drift over time, ' +
        'so a fix verified once is not guaranteed to be what ships.',
      recommendation: 'Migrate to PackageReference with RestorePackagesWithLockFile, commit the lockfile, ' +
        'restore with --locked-mode in CI, and restrict restore to one trusted feed via packageSourceMapping.',
      tests: ['O-003', 'O-004'], priority: 'P3', effort: 'MEDIUM'
    }));
  }

  if (!project.flags.hasAnalyzers) {
    out.push(mk({
      title: 'No static analysis enforced at build time',
      category: 'configuration', severity: 'MEDIUM',
      location: { file: (project.projects[0] && project.projects[0].file) || '.' },
      evidence: {
        snippet: 'no <EnableNETAnalyzers>, no <CodeAnalysisRuleSet>, no Directory.Build.props, no .editorconfig',
        language: 'text'
      },
      problem: 'No Roslyn analyzers, ruleset, .editorconfig or warning escalation is configured.',
      impact: 'Security rules that ship free with the SDK never run — CA5359 (disabled certificate ' +
        'validation), CA1305 (missing IFormatProvider), CA3075 (XXE), CA2100 (SQL injection). The build ' +
        'is green because nothing is enforced, not because the code is clean.',
      recommendation: 'Add Directory.Build.props enabling EnableNETAnalyzers with AnalysisMode All, and ' +
        'escalate the security rules via WarningsAsErrors.',
      tests: ['N-015'], priority: 'P1', effort: 'SMALL'
    }));
  }

  if (!project.flags.hasCI) {
    out.push(mk({
      title: 'No CI/CD pipeline definition in the repository',
      category: 'deployment', severity: 'MEDIUM',
      location: { file: '.' },
      evidence: { snippet: 'no .github/workflows, azure-pipelines.yml, .gitlab-ci.yml or Jenkinsfile', language: 'text' },
      problem: 'The repository contains no pipeline definition.',
      impact: 'Every recommendation that ends "wire this into CI" is currently un-actionable: there is ' +
        'nowhere for the secret scan, dependency audit, analyzers or tests to run as a gate.',
      recommendation: 'Adopt the reference pipeline in ci/github-actions.yml, starting analyzer and ' +
        'dependency gates as warnings on legacy code and blocking on new code. The secret gate should ' +
        'block from day one, with a canary proving it is active.',
      tests: ['R-009'], priority: 'P1', effort: 'MEDIUM'
    }));
  }

  if (!project.flags.isGitRepo) {
    out.push(mk({
      title: 'Source is not under version control at the reviewed location',
      category: 'process', severity: 'LOW',
      location: { file: '.' },
      evidence: { snippet: 'no .git directory', language: 'text' },
      problem: 'The delivered source has no repository metadata.',
      impact: 'There is no history or blame, so it is impossible to establish when a credential was ' +
        'introduced or whether a rotation ever happened, and secret scanners cannot examine history — ' +
        'only the current tree.',
      recommendation: 'Place the source under version control and rotate every credential on the ' +
        'assumption that history is unavailable for audit.',
      tests: ['R-008'], priority: 'P3', effort: 'SMALL'
    }));
  }

  return out;
}

module.exports = { discover, discoveryFindings, inspectProject };
