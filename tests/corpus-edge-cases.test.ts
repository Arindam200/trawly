import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseNpmPackageLock } from "../src/extractors/npm-package-lock.js";
import { parsePnpmLock } from "../src/extractors/pnpm-lock.js";
import { parseSbom } from "../src/extractors/sbom.js";
import { parseYarnLock } from "../src/extractors/yarn-lock.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "trawly-corpus-"));
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe("lockfile dialect corpus", () => {
  it("handles npm v2 workspaces, nested deps, optional/devOptional, links, and custom registries", () => {
    const dir = tempDir();
    const lockfile = join(dir, "package-lock.json");
    writeJson(lockfile, {
      lockfileVersion: 2,
      packages: {
        "": {
          dependencies: { react: "18.2.0" },
          devDependencies: { vitest: "2.1.9" },
          optionalDependencies: { fsevents: "2.3.3" },
        },
        "node_modules/react": {
          version: "18.2.0",
          resolved: "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
        },
        "node_modules/vitest": {
          version: "2.1.9",
          dev: true,
          hasInstallScript: true,
        },
        "node_modules/fsevents": {
          version: "2.3.3",
          optional: true,
          resolved: "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
        },
        "node_modules/react/node_modules/loose-envify": {
          version: "1.4.0",
          resolved: "https://custom.example/loose-envify-1.4.0.tgz",
        },
        "node_modules/workspace-pkg": {
          link: true,
          resolved: "packages/workspace-pkg",
        },
      },
    });

    const out = parseNpmPackageLock(lockfile);
    expect(out.map((p) => p.name).sort()).toEqual([
      "fsevents",
      "loose-envify",
      "react",
      "vitest",
    ]);
    expect(out.find((p) => p.name === "vitest")).toMatchObject({
      direct: true,
      dev: true,
      hasInstallScript: true,
    });
    expect(out.find((p) => p.name === "loose-envify")).toMatchObject({
      direct: false,
      registry: "https://custom.example",
    });
  });

  it("handles pnpm peer suffixes, multiple importers, scoped packages, and tarballs", () => {
    const dir = tempDir();
    writeJson(join(dir, "package.json"), {
      dependencies: { "@scope/app": "1.0.0" },
    });
    const lockfile = join(dir, "pnpm-lock.yaml");
    writeFileSync(
      lockfile,
      [
        "lockfileVersion: '9.0'",
        "importers:",
        "  .:",
        "    dependencies:",
        "      '@scope/app':",
        "        specifier: 1.0.0",
        "        version: 1.0.0(react@18.2.0)",
        "  packages/cli:",
        "    devDependencies:",
        "      chalk:",
        "        specifier: 5.3.0",
        "        version: 5.3.0",
        "packages:",
        "  '@scope/app@1.0.0(react@18.2.0)':",
        "    resolution:",
        "      tarball: https://registry.npmjs.org/@scope/app/-/app-1.0.0.tgz",
        "  chalk@5.3.0:",
        "    resolution:",
        "      tarball: https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
        "    dev: true",
        "",
      ].join("\n"),
    );

    const out = parsePnpmLock(lockfile);
    expect(out.find((p) => p.name === "@scope/app")).toMatchObject({
      version: "1.0.0",
      direct: true,
      registry: "https://registry.npmjs.org",
    });
    expect(out.find((p) => p.name === "chalk")).toMatchObject({
      dev: true,
      direct: true,
    });
  });

  it("handles Yarn classic multi-selector entries and Yarn Berry patch descriptors", () => {
    const classicDir = tempDir();
    writeJson(join(classicDir, "package.json"), {
      dependencies: { leftpad: "^1.0.0" },
    });
    const classic = join(classicDir, "yarn.lock");
    writeFileSync(
      classic,
      [
        'leftpad@^1.0.0, leftpad@~1.0.0:',
        '  version "1.0.1"',
        '  resolved "https://registry.yarnpkg.com/leftpad/-/leftpad-1.0.1.tgz"',
        "",
      ].join("\n"),
    );
    expect(parseYarnLock(classic)[0]).toMatchObject({
      name: "leftpad",
      version: "1.0.1",
      direct: true,
    });

    const berryDir = tempDir();
    writeJson(join(berryDir, "package.json"), {
      dependencies: { leftpad: "^1.0.0" },
    });
    const berry = join(berryDir, "yarn.lock");
    writeFileSync(
      berry,
      [
        "__metadata:",
        "  version: 6",
        "  cacheKey: 10",
        "",
        'leftpad@patch:leftpad@npm%3A1.0.1#./patches/leftpad.patch::version=1.0.1&hash=abc:',
        "  version: 1.0.1",
        '  resolution: "leftpad@patch:leftpad@npm%3A1.0.1#./patches/leftpad.patch::version=1.0.1&hash=abc"',
        "  checksum: 10/abc",
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );
    expect(parseYarnLock(berry)[0]).toMatchObject({
      name: "leftpad",
      version: "1.0.1",
    });
  });
});

describe("SBOM dialect corpus", () => {
  it("handles CycloneDX 1.6 JSON nested components and ignores missing or invalid PURLs", () => {
    const dir = tempDir();
    const sbom = join(dir, "bom.json");
    writeJson(sbom, {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        { type: "library", purl: "pkg:npm/%40scope/pkg@1.2.3" },
        { type: "library", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1" },
        { type: "library", purl: "not-a-purl" },
        { type: "library", name: "missing-purl", version: "1.0.0" },
      ],
    });

    expect(parseSbom(sbom).map((p) => `${p.ecosystem}:${p.name}@${p.version}`)).toEqual([
      "npm:@scope/pkg@1.2.3",
      "Maven:org.apache.logging.log4j/log4j-core@2.17.1",
    ]);
  });

  it("handles SPDX packages with multiple external refs and dedupes duplicate PURLs", () => {
    const dir = tempDir();
    const sbom = join(dir, "spdx.json");
    writeJson(sbom, {
      spdxVersion: "SPDX-2.2",
      packages: [
        {
          name: "pkg",
          externalRefs: [
            {
              referenceCategory: "SECURITY",
              referenceType: "cpe23Type",
              referenceLocator: "cpe:2.3:a:example:pkg:1.0.0:*:*:*:*:*:*:*",
            },
            {
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: "pkg:nuget/Newtonsoft.Json@13.0.3",
            },
            {
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: "pkg:nuget/Newtonsoft.Json@13.0.3",
            },
          ],
        },
      ],
    });

    const out = parseSbom(sbom);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      ecosystem: "NuGet",
      name: "Newtonsoft.Json",
      version: "13.0.3",
    });
  });
});
