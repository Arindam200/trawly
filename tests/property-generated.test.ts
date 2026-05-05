import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseNpmPackageLock } from "../src/extractors/npm-package-lock.js";
import { parsePnpmLock } from "../src/extractors/pnpm-lock.js";
import { parsePurlPackage } from "../src/extractors/sbom.js";
import { parseYarnDescriptorName } from "../src/extractors/yarn-lock.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "trawly-generated-"));
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const NAMES = [
  "plain",
  "with-dash",
  "with.dot",
  "@scope/pkg",
  "@another-scope/name-with-dash",
];

describe("generated parser properties", () => {
  it("round-trips npm package names from generated package-lock paths", () => {
    const dir = tempDir();
    const packages: Record<string, unknown> = {
      "": {
        dependencies: Object.fromEntries(NAMES.map((name) => [name, "1.0.0"])),
      },
    };
    for (const [idx, name] of NAMES.entries()) {
      packages[`node_modules/${name}`] = { version: `1.0.${idx}` };
      packages[`node_modules/parent/node_modules/${name}`] = {
        version: `2.0.${idx}`,
      };
    }
    const lockfile = join(dir, "package-lock.json");
    writeJson(lockfile, { lockfileVersion: 3, packages });

    const out = parseNpmPackageLock(lockfile);
    const expected = NAMES.flatMap((name, idx) => [
      `${name}@1.0.${idx}`,
      `${name}@2.0.${idx}`,
    ]).sort();
    expect(out.map((p) => `${p.name}@${p.version}`).sort()).toEqual(expected);
  });

  it("parses generated pnpm keys with peer suffixes without leaking peer text into versions", () => {
    const dir = tempDir();
    const lockfile = join(dir, "pnpm-lock.yaml");
    const packageLines = NAMES.flatMap((name, idx) => [
      `  '${name}@1.${idx}.0(peer@2.0.0)':`,
      "    resolution:",
      `      tarball: https://registry.npmjs.org/${encodeURIComponent(name)}/-/${name.split("/").pop()}-1.${idx}.0.tgz`,
    ]);
    writeFileSync(
      lockfile,
      ["lockfileVersion: '9.0'", "packages:", ...packageLines, ""].join("\n"),
    );

    const out = parsePnpmLock(lockfile);
    expect(out.map((p) => `${p.name}@${p.version}`).sort()).toEqual(
      NAMES.map((name, idx) => `${name}@1.${idx}.0`).sort(),
    );
  });

  it("extracts generated Yarn descriptor names for common protocols", () => {
    const descriptors = [
      "plain@npm:^1.0.0",
      "@scope/pkg@npm:~2.0.0",
      "with-dash@patch:with-dash@npm%3A1.0.0#./patch.patch",
      "@scope/pkg@workspace:^",
      "plain@file:../plain",
      "@scope/pkg@portal:../pkg",
    ];

    expect(descriptors.map(parseYarnDescriptorName)).toEqual([
      "plain",
      "@scope/pkg",
      "with-dash",
      "@scope/pkg",
      "plain",
      "@scope/pkg",
    ]);
  });

  it("normalizes generated PURLs across supported ecosystems", () => {
    const purls = [
      ["pkg:npm/%40scope/pkg@1.0.0", "npm", "@scope/pkg"],
      ["pkg:pypi/django@4.2.0", "PyPI", "django"],
      ["pkg:maven/org.example/lib@1.2.3", "Maven", "org.example/lib"],
      ["pkg:nuget/Newtonsoft.Json@13.0.3", "NuGet", "Newtonsoft.Json"],
      ["pkg:gem/rails@7.1.0", "RubyGems", "rails"],
      ["pkg:golang/github.com/gin-gonic/gin@1.9.1", "Go", "github.com/gin-gonic/gin"],
    ];

    for (const [purl, ecosystem, name] of purls) {
      expect(parsePurlPackage(purl)).toMatchObject({
        ecosystem,
        name,
      });
    }
  });
});
