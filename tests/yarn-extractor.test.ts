import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  parseYarnLock,
  parseYarnSpec,
  parseClassicEntries,
} from "../src/extractors/yarn-lock.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLASSIC = join(here, "fixtures", "yarn-classic", "yarn.lock");
const BERRY = join(here, "fixtures", "yarn-berry", "yarn.lock");

describe("parseYarnSpec", () => {
  it("parses unscoped specs", () => {
    expect(parseYarnSpec("lodash@^4.17.20")).toEqual({
      name: "lodash",
      selector: "^4.17.20",
    });
  });

  it("parses scoped specs", () => {
    expect(parseYarnSpec("@scope/sub@^1.0.0")).toEqual({
      name: "@scope/sub",
      selector: "^1.0.0",
    });
  });

  it("strips berry npm: protocol", () => {
    expect(parseYarnSpec("lodash@npm:^4.17.20")).toEqual({
      name: "lodash",
      selector: "^4.17.20",
    });
  });
});

describe("parseClassicEntries", () => {
  it("splits multi-spec headers", () => {
    const content = `lodash@^4, lodash@^4.17.20:\n  version "4.17.20"\n`;
    const entries = parseClassicEntries(content);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.specs).toEqual(["lodash@^4", "lodash@^4.17.20"]);
    expect(entries[0]?.fields.version).toBe("4.17.20");
  });

  it("handles quoted scoped specs", () => {
    const content = `"@scope/sub@^1.0.0":\n  version "1.0.0"\n`;
    const entries = parseClassicEntries(content);
    expect(entries[0]?.specs).toEqual(["@scope/sub@^1.0.0"]);
    expect(entries[0]?.fields.version).toBe("1.0.0");
  });
});

describe("parseYarnLock — classic v1", () => {
  it("extracts entries and uses package.json for direct/dev", () => {
    const instances = parseYarnLock(CLASSIC);
    const names = instances.map((i) => i.name).sort();
    expect(names).toEqual(["@scope/sub", "lodash", "minimist", "safe-buffer"]);

    const lodash = instances.find((i) => i.name === "lodash")!;
    const minimist = instances.find((i) => i.name === "minimist")!;
    const safeBuffer = instances.find((i) => i.name === "safe-buffer")!;
    const scoped = instances.find((i) => i.name === "@scope/sub")!;

    expect(lodash.direct).toBe(true);
    expect(lodash.dev).toBe(false);
    expect(lodash.version).toBe("4.17.20");
    expect(lodash.resolved).toContain("lodash-4.17.20.tgz");

    expect(minimist.direct).toBe(true);
    expect(minimist.dev).toBe(true);

    expect(safeBuffer.direct).toBe(false);
    expect(safeBuffer.dev).toBe(false);

    expect(scoped.direct).toBe(true);
  });
});

describe("parseYarnLock — berry", () => {
  it("extracts entries from a berry lockfile", () => {
    const instances = parseYarnLock(BERRY);
    const names = instances.map((i) => i.name).sort();
    expect(names).toEqual(["@scope/sub", "lodash", "minimist", "safe-buffer"]);

    const lodash = instances.find((i) => i.name === "lodash")!;
    const minimist = instances.find((i) => i.name === "minimist")!;
    expect(lodash.direct).toBe(true);
    expect(lodash.dev).toBe(false);
    expect(minimist.dev).toBe(true);
  });

  it("skips local workspace, patch, portal, and file locators", () => {
    const dir = mkdtempSync(join(tmpdir(), "trawly-yarn-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        dependencies: {
          local: "workspace:.",
          patched: "patch:patched@npm:1.0.0#./patched.patch",
          portal: "portal:../portal",
          filedep: "file:../filedep",
        },
      }),
    );
    const lockfile = join(dir, "yarn.lock");
    writeFileSync(
      lockfile,
      [
        "__metadata:",
        "  version: 6",
        "  cacheKey: 10",
        "",
        '"local@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "local@workspace:."',
        "",
        '"patched@patch:patched@npm%3A1.0.0#./patched.patch":',
        "  version: 1.0.0",
        '  resolution: "patched@patch:patched@npm%3A1.0.0#./patched.patch"',
        "",
        '"portal@portal:../portal":',
        "  version: 0.0.0-use.local",
        '  resolution: "portal@portal:../portal"',
        "",
        '"filedep@file:../filedep":',
        "  version: 0.0.0-use.local",
        '  resolution: "filedep@file:../filedep"',
        "",
      ].join("\n"),
    );

    expect(parseYarnLock(lockfile)).toEqual([]);
  });
});
