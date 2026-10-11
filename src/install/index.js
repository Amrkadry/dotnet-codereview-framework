'use strict';
/**
 * Install the external scanners this framework can orchestrate.
 *
 * The pipeline runs with zero external tools, but every absent tool is a real coverage gap:
 * with no gitleaks, nothing in the run looks for the credentials in Web.config that are the
 * most common critical finding on .NET. Reporting "gitleaks is not installed" and leaving the
 * user to work out the incantation for their OS is a gap the framework can close itself.
 *
 * Two rules shape this module.
 *
 * Nothing is installed unless asked. Installing software changes the user's machine, so the
 * default is to PRINT the plan and exit; execution requires an explicit --yes. The plan is
 * always shown first, so what runs is never a surprise.
 *
 * Recipes are per-platform and per-manager, chosen from what is actually on PATH. A Windows
 * box with winget gets a winget command; the same tool on Debian gets apt or the language
 * installer. Where no manager fits, the recipe is reported as manual with a URL rather than
 * guessed at.
 */

const { spawnSync } = require('child_process');
const PLATFORM = require('../core/platform');

/** Is this executable resolvable on PATH? */
function onPath(bin) {
  const probe = process.platform === 'win32' ? 'where' : 'which';
  const r = spawnSync(probe, [bin], { stdio: 'ignore', shell: false });
  return r.status === 0;
}

/**
 * Package managers, in the order we prefer them. Language installers come last: they work
 * everywhere, but they put binaries somewhere the user's PATH may not already cover.
 */
const MANAGERS = [
  { id: 'winget', bin: 'winget', when: p => p.isWindows },
  { id: 'choco', bin: 'choco', when: p => p.isWindows },
  { id: 'scoop', bin: 'scoop', when: p => p.isWindows },
  { id: 'brew', bin: 'brew', when: p => p.isMac || p.isLinux },
  { id: 'apt', bin: 'apt-get', when: p => p.isLinux },
  { id: 'dnf', bin: 'dnf', when: p => p.isLinux },
  { id: 'pacman', bin: 'pacman', when: p => p.isLinux },
  { id: 'pipx', bin: 'pipx', when: () => true },
  { id: 'pip', bin: 'pip3', when: () => true },
  { id: 'go', bin: 'go', when: () => true },
  { id: 'npm', bin: 'npm', when: () => true }
];

/**
 * Install recipes. Elevation is never baked into a recipe: apt/dnf/pacman are marked
 * privileged instead, so the user is told why sudo is needed rather than having it applied
 * silently on their behalf.
 */
const RECIPES = {
  gitleaks: {
    probe: 'gitleaks',
    why: 'Secret scanning. On .NET this is the single most valuable external tool: credentials '
      + 'in Web.config are the most common critical finding, and nothing else in the pipeline '
      + 'hunts for them.',
    by: {
      winget: ['winget', ['install', '--id', 'Gitleaks.Gitleaks', '-e',
        '--accept-package-agreements', '--accept-source-agreements']],
      choco: ['choco', ['install', 'gitleaks', '-y']],
      scoop: ['scoop', ['install', 'gitleaks']],
      brew: ['brew', ['install', 'gitleaks']],
      // The Go module path is still the pre-rename zricethezav one: installing from
      // github.com/gitleaks/gitleaks fails with a version-constraints conflict, because the
      // module declares the old path. Verified against v8.30.1.
      go: ['go', ['install', 'github.com/zricethezav/gitleaks/v8@latest']]
    },
    manual: 'https://github.com/gitleaks/gitleaks/releases'
  },
  semgrep: {
    probe: 'semgrep',
    why: 'Pattern-based SAST with a C# ruleset, including taint-style rules the built-in '
      + 'engine does not attempt.',
    by: {
      pipx: ['pipx', ['install', 'semgrep']],
      pip: ['pip3', ['install', '--user', 'semgrep']],
      brew: ['brew', ['install', 'semgrep']]
    },
    manual: 'https://semgrep.dev/docs/getting-started/'
  },
  trivy: {
    probe: 'trivy',
    why: 'Dependency CVEs, secrets and misconfiguration. Reads packages.config directly, so it '
      + 'works on legacy non-SDK projects where `dotnet list package` cannot evaluate the project.',
    by: {
      winget: ['winget', ['install', '--id', 'AquaSecurity.Trivy', '-e',
        '--accept-package-agreements', '--accept-source-agreements']],
      choco: ['choco', ['install', 'trivy', '-y']],
      scoop: ['scoop', ['install', 'trivy']],
      brew: ['brew', ['install', 'trivy']],
      apt: ['apt-get', ['install', '-y', 'trivy']],
      dnf: ['dnf', ['install', '-y', 'trivy']]
    },
    manual: 'https://trivy.dev/latest/getting-started/installation/'
  },
  snyk: {
    probe: 'snyk',
    why: 'Dependency scanning against a curated advisory database. Needs `snyk auth` after install.',
    by: {
      npm: ['npm', ['install', '-g', 'snyk']],
      brew: ['brew', ['install', 'snyk']],
      scoop: ['scoop', ['install', 'snyk']]
    },
    manual: 'https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli'
  },
  'osv-scanner': {
    probe: 'osv-scanner',
    why: 'Free dependency vulnerability scanning from OSV.dev, with no account or token — a '
      + 'good substitute for Snyk when no licence is available.',
    by: {
      brew: ['brew', ['install', 'osv-scanner']],
      go: ['go', ['install', 'github.com/google/osv-scanner/cmd/osv-scanner@latest']],
      scoop: ['scoop', ['install', 'osv-scanner']]
    },
    manual: 'https://google.github.io/osv-scanner/installation/'
  },
  'sonar-scanner': {
    probe: 'sonar-scanner',
    why: 'Quality and maintainability analysis. On .NET Framework the MSBuild scanner is the one '
      + 'that works (SonarScanner.MSBuild.exe begin/build/end); this CLI alone would analyse no C#.',
    by: {
      brew: ['brew', ['install', 'sonar-scanner']],
      choco: ['choco', ['install', 'sonarscanner-msbuild-net46', '-y']],
      scoop: ['scoop', ['install', 'sonar-scanner']]
    },
    manual: 'https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/'
      + 'scanners/sonarscanner-for-dotnet/'
  }
};

/** Which managers are usable on this machine right now. */
function availableManagers() {
  const p = PLATFORM.describe();
  return MANAGERS.filter(m => m.when(p) && onPath(m.bin)).map(m => m.id);
}

/** Does this manager need elevation on this platform? */
function needsPrivilege(managerId) {
  if (process.platform === 'win32') return false;
  return ['apt', 'dnf', 'pacman'].indexOf(managerId) !== -1;
}

/**
 * Build the plan: for every requested tool, whether it is already present, and the single
 * best recipe for this machine.
 */
function plan(requested) {
  const names = (requested && requested.length)
    ? requested.filter(n => RECIPES[n])
    : Object.keys(RECIPES);
  const unknown = (requested || []).filter(n => !RECIPES[n]);
  const managers = availableManagers();

  const items = names.map(name => {
    const r = RECIPES[name];
    const installed = onPath(r.probe);
    const managerId = managers.find(m => r.by[m]) || null;
    const recipe = managerId ? r.by[managerId] : null;
    return {
      name,
      installed,
      why: r.why,
      manual: r.manual,
      manager: managerId,
      command: recipe ? [recipe[0]].concat(recipe[1]).join(' ') : null,
      argv: recipe,
      privileged: managerId ? needsPrivilege(managerId) : false
    };
  });
  return { items, managers, unknown, platform: PLATFORM.describe() };
}

/**
 * Execute a plan. Each tool is attempted independently: one failure is reported and the rest
 * continue, because a partial toolchain is still better coverage than none.
 *
 * A manager that exits 0 is not taken at its word — the binary is probed again afterwards,
 * because an install that lands outside PATH leaves the tool just as unavailable to a run.
 */
function execute(p, opts) {
  const log = (opts && opts.log) || console.log;
  const results = [];
  for (const it of p.items) {
    if (it.installed || !it.argv) continue;
    const bin = it.argv[0];
    const args = it.argv[1];
    const useSudo = it.privileged && onPath('sudo');
    const cmd = useSudo ? 'sudo' : bin;
    const argv = useSudo ? [bin].concat(args) : args;
    log('  installing ' + it.name + ' via ' + it.manager + ' ...');
    const r = spawnSync(cmd, argv, { stdio: 'inherit', shell: false });
    const ok = r.status === 0 && onPath(RECIPES[it.name].probe);
    results.push({
      name: it.name,
      ok,
      detail: r.status === 0
        ? (ok
          ? 'installed'
          : 'the manager reported success but the binary is not on PATH yet — open a new shell')
        : ('exit ' + (r.status === null ? 'signal ' + r.signal : r.status))
    });
  }
  return results;
}

module.exports = { plan, execute, availableManagers, needsPrivilege, RECIPES, onPath };
