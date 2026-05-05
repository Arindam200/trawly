import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  parsePnpmLock,
  parsePnpmPackageKey,
} from "../src/extractors/pnpm-lock.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "fixtures", "pnpm-lock.yaml");

describe("parsePnpmPackageKey", () => {
  it("parses v9 unscoped keys", () => {
    expect(parsePnpmPackageKey("lodash@4.17.21")).toEqual({
      name: "lodash",
      version: "4.17.21",
    });
  });

  it("parses v9 scoped keys", () => {
    expect(parsePnpmPackageKey("@scope/foo@1.2.3")).toEqual({
      name: "@scope/foo",
      version: "1.2.3",
    });
  });

  it("parses v6 keys with leading slash", () => {
    expect(parsePnpmPackageKey("/lodash@4.17.21")).toEqual({
      name: "lodash",
      version: "4.17.21",
    });
    expect(parsePnpmPackageKey("/@scope/foo@1.2.3")).toEqual({
      name: "@scope/foo",
      version: "1.2.3",
    });
  });

  it("strips peer-deps suffix", () => {
    expect(parsePnpmPackageKey("vitest@2.0.0(@types/node@20.0.0)")).toEqual({
      name: "vitest",
      version: "2.0.0",
    });
  });

  it("returns null for malformed keys", () => {
    expect(parsePnpmPackageKey("nope")).toBeNull();
    expect(parsePnpmPackageKey("")).toBeNull();
  });
});

describe("parsePnpmLock", () => {
  it("extracts package instances from a v9 lockfile", () => {
    const instances = parsePnpmLock(FIXTURE);
    const names = instances.map((i) => i.name).sort();
    expect(names).toEqual([
      "@scope/sub",
      "lodash",
      "minimist",
      "safe-buffer",
      "vitest",
    ]);
  });

  it("marks direct and dev flags from importers", () => {
    const instances = parsePnpmLock(FIXTURE);
    const lodash = instances.find((i) => i.name === "lodash")!;
    const minimist = instances.find((i) => i.name === "minimist")!;
    const safeBuffer = instances.find((i) => i.name === "safe-buffer")!;
    const scoped = instances.find((i) => i.name === "@scope/sub")!;

    expect(lodash.direct).toBe(true);
    expect(lodash.dev).toBe(false);
    expect(lodash.version).toBe("4.17.20");

    expect(minimist.direct).toBe(true);
    expect(minimist.dev).toBe(true);

    expect(safeBuffer.direct).toBe(false);
    expect(safeBuffer.dev).toBe(false);

    expect(scoped.direct).toBe(true);
    expect(scoped.path).toBe("'@scope/sub@1.0.0'".replace(/'/g, ""));
  });

  it("preserves peer-suffixed key as path", () => {
    const instances = parsePnpmLock(FIXTURE);
    const vitest = instances.find((i) => i.name === "vitest")!;
    expect(vitest.version).toBe("2.0.0");
    expect(vitest.path).toContain("vitest@2.0.0");
  });

  it("rejects unsupported lockfile versions", () => {
    const dir = mkdtempSync(join(tmpdir(), "trawly-pnpm-"));
    const file = join(dir, "pnpm-lock.yaml");
    writeFileSync(
      file,
      "lockfileVersion: '5.4'\npackages: {}\n",
      "utf8",
    );
    expect(() => parsePnpmLock(file)).toThrow(/Unsupported pnpm lockfileVersion/);
  });
});
