import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parsePnpmLock,
  parsePnpmPackageKey,
} from "../src/extractors/pnpm-lock.js";
import {
  parseYarnDescriptorName,
  parseYarnLock,
} from "../src/extractors/yarn-lock.js";
import { parsePurlPackage, parseSbom } from "../src/extractors/sbom.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");

describe("parsePnpmLock", () => {
  it("extracts packages, direct/dev flags, registry, and build script signal", () => {
    const instances = parsePnpmLock(join(fixtures, "pnpm-lock.yaml"));
    const axios = instances.find((i) => i.name === "axios")!;
    const vitest = instances.find((i) => i.name === "vitest")!;
    const scoped = instances.find((i) => i.name === "@scope/pkg")!;

    expect(axios.version).toBe("1.6.7");
    expect(axios.direct).toBe(true);
    expect(axios.hasInstallScript).toBe(true);
    expect(axios.registry).toBe("https://registry.npmjs.org");
    expect(vitest.dev).toBe(true);
    expect(scoped.direct).toBe(false);
  });

  it("parses scoped pnpm package keys", () => {
    expect(parsePnpmPackageKey("@scope/pkg@1.2.3")).toEqual({
      name: "@scope/pkg",
      version: "1.2.3",
    });
  });
});

describe("parseYarnLock", () => {
  it("parses Yarn classic lockfiles", () => {
    const instances = parseYarnLock(join(fixtures, "yarn-v1", "yarn.lock"));
    const lodash = instances.find((i) => i.name === "lodash")!;
    const jest = instances.find((i) => i.name === "jest")!;

    expect(lodash.version).toBe("4.17.21");
    expect(lodash.direct).toBe(true);
    expect(lodash.registry).toBe("https://registry.yarnpkg.com");
    expect(jest.dev).toBe(true);
  });

  it("parses Yarn Berry lockfiles", () => {
    const instances = parseYarnLock(join(fixtures, "yarn-berry", "yarn.lock"));
    expect(instances.map((i) => i.name).sort()).toEqual([
      "@scope/pkg",
      "lodash",
    ]);
  });

  it("extracts descriptor names", () => {
    expect(parseYarnDescriptorName("@scope/pkg@npm:^1.0.0")).toBe(
      "@scope/pkg",
    );
    expect(parseYarnDescriptorName("lodash@^4.17.0")).toBe("lodash");
  });
});

describe("parseSbom", () => {
  it("parses CycloneDX JSON in PURL-only mode", () => {
    const instances = parseSbom(join(fixtures, "cyclonedx.json"));
    expect(instances.map((i) => `${i.ecosystem}:${i.name}@${i.version}`)).toEqual([
      "npm:lodash@4.17.20",
      "PyPI:django@4.2.0",
    ]);
  });

  it("parses CycloneDX XML", () => {
    const instances = parseSbom(join(fixtures, "cyclonedx.xml"));
    expect(instances).toHaveLength(1);
    expect(instances[0]?.purl).toBe("pkg:npm/lodash@4.17.20");
  });

  it("parses SPDX JSON and tag-value PURLs", () => {
    expect(parseSbom(join(fixtures, "spdx.json"))[0]?.name).toBe("lodash");
    expect(parseSbom(join(fixtures, "spdx.spdx"))[0]?.name).toBe("lodash");
  });

  it("normalizes npm scoped PURLs", () => {
    expect(parsePurlPackage("pkg:npm/%40scope/pkg@1.0.0")).toMatchObject({
      ecosystem: "npm",
      name: "@scope/pkg",
      version: "1.0.0",
    });
  });
});
