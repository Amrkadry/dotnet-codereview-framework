// dotnet-codereview-framework — tests/discover.project.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Unit tests for src/discover/project.js.
 *
 * Discovery drives CAPABILITY DETECTION: on a packages.config or legacy web project,
 * `dotnet list package` / `dotnet build` cannot work at all, and reporting a clean result from
 * a tool that could not run is the framework's cardinal sin. These tests pin that the detector
 * recognises each project shape and flips the right capability switches — using throwaway
 * synthetic trees in the OS temp dir, never the repo itself.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { discover, discoveryFindings } = require('../src/discover/project');

const SDK_CSPROJ = `<!DOCTYPE html><Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>`;

// Non-SDK, non-web class library: old-style csproj with a framework version only.
const NON_SDK_CSPROJ = `<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>
  </PropertyGroup>
  <Import Project="$(MSBuildBinPath)\\Microsoft.CSharp.targets" />
</Project>`;

// Non-SDK WEB project: the Microsoft.WebApplication.targets import is what makes the
// dotnet CLI unable to evaluate or build it.
const NON_SDK_WEB_CSPROJ = `<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <TargetFrameworkVersion>v4.8</TargetFrameworkVersion>
  </PropertyGroup>
  <Import Project="$(MSBuildBinPath)\\Microsoft.CSharp.targets" />
  <Import Project="$(VSToolsPath)\\WebApplications\\Microsoft.WebApplication.targets" Condition="'$(VSToolsPath)' != ''" />
</Project>`;

const PACKAGES_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.1" targetFramework="net472" />
</packages>`;

let root;      // temp root holding one subdir per scenario
const dir = name => path.join(root, name);

before(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-test-'));

  const write = (rel, content) => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  };

  // 1. SDK-style project with PackageReference
  write('sdk-app/App.csproj', SDK_CSPROJ);

  // 2. non-SDK legacy web project
  write('framework-web/Legacy.Web.csproj', NON_SDK_WEB_CSPROJ);

  // 3a. packages.config next to the csproj
  write('packages-config/Legacy.Lib.csproj', NON_SDK_CSPROJ);
  write('packages-config/packages.config', PACKAGES_CONFIG);
  // 3b. PackageReference-only (the sdk-app scenario) is the negative case

  // 4. mixed solution: one SDK project + one non-SDK project
  write('mixed/App.csproj', SDK_CSPROJ);
  write('mixed/Legacy.Lib.csproj', NON_SDK_CSPROJ);

  // 5a. no .NET project at all: empty dir — 5b: only a README
  write('only-readme/README.md', '# nothing to analyse here');

  // 6. test-project detection: by NAME and by PROPERTY
  write('test-projects/Foo.Tests.csproj', SDK_CSPROJ);
  write('test-projects/Bar.Services.csproj', SDK_CSPROJ.replace(
    '</PropertyGroup>', '<IsTestProject>true</IsTestProject></PropertyGroup>'));

  // 7. a plain non-test, non-CI, analyzer-free SDK app for discoveryFindings
  write('plain-app/App.csproj', SDK_CSPROJ);
});

after(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('discover: project shapes and capabilities', () => {
  test('SDK-style csproj with PackageReference -> core, fully supported', () => {
    const d = discover(dir('sdk-app'));
    assert.equal(d.stack, 'core');
    assert.equal(d.flags.anyNonSdk, false);
    assert.equal(d.capabilities.dotnetListPackage.supported, true);
    assert.equal(d.flags.anyPackagesConfig, false, 'PackageReference-only -> no packages.config flag');
    assert.equal(d.capabilities.dotnetBuild.supported, true);
  });

  test('non-SDK web csproj -> framework, list-package AND build unsupported', () => {
    const d = discover(dir('framework-web'));
    assert.equal(d.stack, 'framework');
    assert.equal(d.flags.anyWebNonSdk, true);
    assert.equal(d.flags.anyNonSdk, true);
    assert.equal(d.capabilities.dotnetListPackage.supported, false,
      'dotnet list package cannot evaluate a legacy web project');
    assert.equal(d.capabilities.dotnetBuild.supported, false,
      'dotnet build cannot build a legacy web project');
  });

  test('packages.config next to the csproj sets anyPackagesConfig and disables list-package', () => {
    const d = discover(dir('packages-config'));
    assert.equal(d.flags.anyPackagesConfig, true);
    assert.equal(d.capabilities.dotnetListPackage.supported, false,
      'dotnet list package does not support packages.config projects');
  });

  test('one SDK + one non-SDK project -> mixed stack', () => {
    const d = discover(dir('mixed'));
    assert.equal(d.stack, 'mixed');
    assert.equal(d.counts.projects, 2);
    assert.equal(d.flags.anyNonSdk, true);
  });

  test('no .NET project at all -> unknown stack, zero projects, no crash', () => {
    for (const scenario of [dir('no-dotnet-at-all'), dir('only-readme')]) {
      let d;
      assert.doesNotThrow(() => { d = discover(scenario); },
        `discover must not throw on ${path.basename(scenario)}`);
      assert.equal(d.counts.projects, 0);
      assert.equal(d.stack, 'unknown');
      assert.equal(d.flags.hasTests, false);
    }
  });

  test('test projects are detected by name suffix AND by <IsTestProject>', () => {
    const d = discover(dir('test-projects'));
    assert.equal(d.counts.projects, 2);
    assert.equal(d.counts.testProjects, 2, 'Foo.Tests.csproj (by name) + Bar.Services.csproj (by property)');
    assert.equal(d.flags.hasTests, true);
    assert.equal(d.capabilities.dotnetTest.supported, true,
      'with a test project present, dotnet test is runnable');
  });
});

describe('discoveryFindings', () => {
  test('a test-less, CI-less, analyzer-less project reports all three structural findings', () => {
    const titles = discoveryFindings(discover(dir('plain-app'))).map(f => f.title);
    assert.ok(titles.includes('Solution contains no test project'),
      'no test project -> structural finding: ' + JSON.stringify(titles));
    assert.ok(titles.includes('No static analysis enforced at build time'),
      'no analyzers -> structural finding');
    assert.ok(titles.includes('No CI/CD pipeline definition in the repository'),
      'no CI -> structural finding');
    assert.ok(!titles.includes('Dependency vulnerability auditing is not possible with first-party tooling'),
      'an SDK app with PackageReference CAN be audited — this finding must be absent');
  });

  test('when test projects exist, the no-test finding is absent', () => {
    const titles = discoveryFindings(discover(dir('test-projects'))).map(f => f.title);
    assert.ok(!titles.includes('Solution contains no test project'),
      'must not demand tests that exist: ' + JSON.stringify(titles));
  });
});
