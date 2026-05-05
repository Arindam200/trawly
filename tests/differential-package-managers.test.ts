import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseNpmPackageLock } from "../src/extractors/npm-package-lock.js";
import { parsePnpmLock } from "../src/extractors/pnpm-lock.js";
import { parseYarnLock } from "../src/extractors/yarn-lock.js";
import type { PackageInstance } from "../src/types.js";

const PNPM_CLI = "pnpm@10.33.3";
const YARN_CLASSIC_CLI = "yarn@1.22.22";
const YARN_BERRY_CLI = "@yarnpkg/cli-dist@4.14.1";

const runDifferential = process.env.TRAWLY_DIFFERENTIAL === "1";
const describeDifferential = runDifferential ? describe : describe.skip;

const packageJson = {
  name: "trawly-differential-fixture",
  version: "1.0.0",
  private: true,
  dependencies: {
    "is-number": "7.0.0",
    "is-odd": "3.0.1",
  },
  devDependencies: {
    "left-pad": "1.3.0",
  },
};

interface DifferentialSummary {
  packages: string[];
  direct: string[];
  devDirect: string[];
}

interface PackageTree {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, PackageTree>;
  devDependencies?: Record<string, PackageTree> | Record<string, string>;
}

interface PnpmListNode {
  version?: string;
  dependencies?: Record<string, PnpmListNode>;
  devDependencies?: Record<string, PnpmListNode>;
}

interface YarnClassicTree {
  name: string;
  shadow?: boolean;
  children?: YarnClassicTree[];
}

interface YarnBerryInfoLine {
  value?: string;
  children?: {
    Version?: string;
    Dependencies?: Array<{ descriptor?: string; locator?: string }>;
  };
}

describeDifferential("package manager differential tests", () => {
  it("matches npm ls --package-lock-only output", () => {
    withProject("npm", (cwd) => {
      writePackageJson(cwd);
      run("npm", [
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--fund=false",
        "--audit=false",
        "--loglevel=error",
      ], cwd);

      const npmTree = JSON.parse(
        run("npm", [
          "ls",
          "--all",
          "--json",
          "--package-lock-only",
          "--long",
        ], cwd),
      ) as PackageTree;
      const manager = summarizeNpmTree(npmTree);
      const trawly = summarizeTrawly(
        parseNpmPackageLock(join(cwd, "package-lock.json")),
      );

      expect(trawly.packages).toEqual(manager.packages);
      expect(trawly.direct).toEqual(manager.direct);
      expect(trawly.devDirect).toEqual(manager.devDirect);
    });
  }, 120_000);

  it("matches pnpm list output", () => {
    withProject("pnpm", (cwd) => {
      writePackageJson(cwd);
      runPnpm([
        "install",
        "--ignore-scripts",
        "--store-dir",
        join(cwd, ".pnpm-store"),
        "--reporter=silent",
      ], cwd);

      const pnpmRoots = JSON.parse(
        runPnpm(["list", "--json", "--depth", "Infinity"], cwd),
      ) as PnpmListNode[];
      const manager = summarizePnpmList(pnpmRoots);
      const trawly = summarizeTrawly(parsePnpmLock(join(cwd, "pnpm-lock.yaml")));

      expect(trawly.packages).toEqual(manager.packages);
      expect(trawly.direct).toEqual(manager.direct);
      expect(trawly.devDirect).toEqual(manager.devDirect);
    });
  }, 120_000);

  it("matches Yarn classic list output", () => {
    withProject("yarn-v1", (cwd) => {
      writePackageJson(cwd);
      runYarnClassic([
        "install",
        "--ignore-scripts",
        "--non-interactive",
        "--silent",
      ], cwd);

      const manager = summarizeYarnClassicList(
        runYarnClassic(["list", "--json", "--depth=99", "--silent"], cwd),
      );
      const trawly = summarizeTrawly(parseYarnLock(join(cwd, "yarn.lock")));

      expect(trawly.packages).toEqual(manager.packages);
      expect(trawly.direct).toEqual(manager.direct);
    });
  }, 120_000);

  it("matches Yarn Berry info output", () => {
    withProject("yarn-berry", (cwd) => {
      writePackageJson(cwd, { packageManager: "yarn@4.14.1" });
      writeFileSync(
        join(cwd, ".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
      );
      runYarnBerry(["install", "--mode=skip-build", "--no-immutable"], cwd);

      const manager = summarizeYarnBerryInfo(
        runYarnBerry(["info", "--all", "--recursive", "--json"], cwd),
      );
      const trawly = summarizeTrawly(parseYarnLock(join(cwd, "yarn.lock")));

      expect(trawly.packages).toEqual(manager.packages);
      expect(trawly.direct).toEqual(manager.direct);
    });
  }, 120_000);
});

function withProject(name: string, fn: (cwd: string) => void): void {
  const cwd = mkdtempSync(join(tmpdir(), `trawly-${name}-diff-`));
  try {
    fn(cwd);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

function writePackageJson(
  cwd: string,
  overrides: Record<string, unknown> = {},
): void {
  writeFileSync(
    join(cwd, "package.json"),
    `${JSON.stringify({ ...packageJson, ...overrides }, null, 2)}\n`,
  );
}

function run(command: string, args: string[], cwd: string): string {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      CI: "1",
      npm_config_audit: "false",
      npm_config_fund: "false",
      npm_config_loglevel: "error",
    },
    maxBuffer: 10 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
  });
}

function runPnpm(args: string[], cwd: string): string {
  return run("npm", [
    "exec",
    "--yes",
    "--package",
    PNPM_CLI,
    "--",
    "pnpm",
    ...args,
  ], cwd);
}

function runYarnClassic(args: string[], cwd: string): string {
  return run("npm", [
    "exec",
    "--yes",
    "--package",
    YARN_CLASSIC_CLI,
    "--",
    "yarn",
    ...args,
  ], cwd);
}

function runYarnBerry(args: string[], cwd: string): string {
  return run("npm", [
    "exec",
    "--yes",
    "--package",
    YARN_BERRY_CLI,
    "--",
    "yarn",
    ...args,
  ], cwd);
}

function summarizeTrawly(instances: PackageInstance[]): DifferentialSummary {
  return {
    packages: sortUnique(instances.map(packageKey)),
    direct: sortUnique(
      instances.filter((pkg) => pkg.direct).map((pkg) => pkg.name),
    ),
    devDirect: sortUnique(
      instances
        .filter((pkg) => pkg.direct && pkg.dev)
        .map((pkg) => pkg.name),
    ),
  };
}

function summarizeNpmTree(root: PackageTree): DifferentialSummary {
  const packages = new Set<string>();
  const direct = new Set<string>();
  const devDirect = new Set<string>();
  for (const [name, node] of Object.entries(root.dependencies ?? {})) {
    direct.add(name);
    if (node.dev) devDirect.add(name);
    collectPackageTree(name, node, packages);
  }
  return {
    packages: sortSet(packages),
    direct: sortSet(direct),
    devDirect: sortSet(devDirect),
  };
}

function collectPackageTree(
  name: string,
  node: PackageTree,
  packages: Set<string>,
): void {
  if (node.version) packages.add(`${name}@${node.version}`);
  for (const [childName, childNode] of Object.entries(node.dependencies ?? {})) {
    collectPackageTree(childName, childNode, packages);
  }
}

function summarizePnpmList(roots: PnpmListNode[]): DifferentialSummary {
  const root = roots[0] ?? {};
  const packages = new Set<string>();
  const direct = new Set<string>();
  const devDirect = new Set<string>();
  for (const [name, node] of Object.entries(root.dependencies ?? {})) {
    direct.add(name);
    collectPnpmNode(name, node, packages);
  }
  for (const [name, node] of Object.entries(root.devDependencies ?? {})) {
    direct.add(name);
    devDirect.add(name);
    collectPnpmNode(name, node, packages);
  }
  return {
    packages: sortSet(packages),
    direct: sortSet(direct),
    devDirect: sortSet(devDirect),
  };
}

function collectPnpmNode(
  name: string,
  node: PnpmListNode,
  packages: Set<string>,
): void {
  if (node.version) packages.add(`${name}@${node.version}`);
  for (const [childName, childNode] of Object.entries(node.dependencies ?? {})) {
    collectPnpmNode(childName, childNode, packages);
  }
}

function summarizeYarnClassicList(output: string): DifferentialSummary {
  const packages = new Set<string>();
  const direct = new Set<string>();
  const treeLine = parseJsonLines(output).find((line) => line.type === "tree");
  const trees = treeLine?.data?.trees;
  if (!Array.isArray(trees)) {
    throw new Error("Yarn classic list output did not contain a tree payload.");
  }
  for (const tree of trees as YarnClassicTree[]) {
    const parsed = parseNameVersion(tree.name);
    if (parsed) direct.add(parsed.name);
    collectYarnClassicTree(tree, packages);
  }
  return {
    packages: sortSet(packages),
    direct: sortSet(direct),
    devDirect: [],
  };
}

function collectYarnClassicTree(
  tree: YarnClassicTree,
  packages: Set<string>,
): void {
  if (tree.shadow) return;
  const parsed = parseNameVersion(tree.name);
  if (parsed) packages.add(`${parsed.name}@${parsed.version}`);
  for (const child of tree.children ?? []) {
    collectYarnClassicTree(child, packages);
  }
}

function summarizeYarnBerryInfo(output: string): DifferentialSummary {
  const packages = new Set<string>();
  const direct = new Set<string>();
  for (const line of parseJsonLines(output) as YarnBerryInfoLine[]) {
    if (!line.value) continue;
    if (line.value.includes("@workspace:")) {
      for (const dep of line.children?.Dependencies ?? []) {
        const parsed = parseYarnBerryLocator(dep.locator ?? dep.descriptor);
        if (parsed) direct.add(parsed.name);
      }
      continue;
    }
    const parsed = parseYarnBerryLocator(line.value);
    if (parsed) packages.add(`${parsed.name}@${parsed.version}`);
  }
  return {
    packages: sortSet(packages),
    direct: sortSet(direct),
    devDirect: [],
  };
}

function parseJsonLines(output: string): Array<Record<string, any>> {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, any>);
}

function parseNameVersion(value: string): { name: string; version: string } | null {
  const at = versionSeparatorIndex(value);
  if (at === -1) return null;
  const name = value.slice(0, at);
  const version = value.slice(at + 1);
  if (!name || !version || version.startsWith("^")) return null;
  return { name, version };
}

function parseYarnBerryLocator(
  value: string | undefined,
): { name: string; version: string } | null {
  if (!value || value.includes("@workspace:")) return null;
  const marker = "@npm:";
  const at = value.lastIndexOf(marker);
  if (at <= 0) return null;
  return {
    name: value.slice(0, at),
    version: value.slice(at + marker.length),
  };
}

function versionSeparatorIndex(value: string): number {
  if (value.startsWith("@")) {
    const slash = value.indexOf("/");
    return slash === -1 ? -1 : value.indexOf("@", slash + 1);
  }
  return value.lastIndexOf("@");
}

function packageKey(pkg: PackageInstance): string {
  return `${pkg.name}@${pkg.version}`;
}

function sortUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function sortSet(values: Set<string>): string[] {
  return [...values].sort();
}
