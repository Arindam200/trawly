import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { matchesAny, scanEnv, type EnvIssue } from "../src/env-scan.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "trawly-env-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = join(tmp, rel);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
}

function git(...args: string[]): void {
  execSync(`git ${args.map((a) => JSON.stringify(a)).join(" ")}`, {
    cwd: tmp,
    stdio: "ignore",
  });
}

function initRepo(): void {
  git("init", "-q", "-b", "main");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  git("commit", "--allow-empty", "-q", "-m", "init");
}

function findIssue(
  issues: EnvIssue[],
  kind: EnvIssue["kind"],
  file?: string,
): EnvIssue | undefined {
  return issues.find(
    (i) => i.kind === kind && (file === undefined || i.file === file),
  );
}

describe("scanEnv: discovery", () => {
  it("finds .env, .env.local, .env.production at the root", async () => {
    write(".env", "A=1");
    write(".env.local", "A=1");
    write(".env.production", "A=1");
    write("README.md", "");
    write(".gitignore", ".env*\n");
    const result = await scanEnv({ cwd: tmp });
    expect(result.envFiles.sort()).toEqual([
      ".env",
      ".env.local",
      ".env.production",
    ]);
  });

  it("ignores node_modules and .git directories", async () => {
    write(".env", "A=1");
    write("node_modules/foo/.env", "A=1");
    write(".gitignore", ".env*\n");
    const result = await scanEnv({ cwd: tmp });
    expect(result.envFiles).toEqual([".env"]);
  });

  it("finds env files in monorepo subdirectories", async () => {
    write("apps/web/.env", "A=1");
    write("apps/api/.env.production", "A=1");
    write(".gitignore", ".env*\n");
    const result = await scanEnv({ cwd: tmp });
    expect(result.envFiles.sort()).toEqual([
      "apps/api/.env.production",
      "apps/web/.env",
    ]);
  });

  it("treats .env.example as an example file (not as a leak target)", async () => {
    write(".env.example", "API_KEY=your-key-here\n");
    write(".gitignore", ".env\n.env.local\n");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "not-gitignored")).toBeUndefined();
    expect(findIssue(result.issues, "tracked-by-git")).toBeUndefined();
  });
});

describe("scanEnv: gitignore coverage (in a git repo)", () => {
  it("flags an env file that exists but is not gitignored", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", "node_modules\n");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "not-gitignored", ".env")).toBeDefined();
  });

  it("does not flag an env file properly covered by .gitignore", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "not-gitignored")).toBeUndefined();
  });

  it("flags a missing .gitignore when env files are present", async () => {
    initRepo();
    write(".env", "A=1");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "no-gitignore")).toBeDefined();
  });
});

describe("scanEnv: tracked-by-git detection", () => {
  it("flags .env that is committed to the repo as critical", async () => {
    initRepo();
    write(".env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    git("add", ".env");
    git("commit", "-q", "-m", "leak");
    const result = await scanEnv({ cwd: tmp });
    const issue = findIssue(result.issues, "tracked-by-git", ".env");
    expect(issue).toBeDefined();
    expect(issue!.severity).toBe("critical");
    // Tracked file shouldn't double-report as not-gitignored.
    expect(findIssue(result.issues, "not-gitignored", ".env")).toBeUndefined();
  });
});

describe("scanEnv: npm publish exposure", () => {
  it("flags env file when files allowlist matches it explicitly", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    write(
      "package.json",
      JSON.stringify({ name: "p", version: "0.0.0", files: [".env"] }),
    );
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "would-be-published", ".env")).toBeDefined();
  });

  it("does not flag env file when files allowlist excludes it", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    write(
      "package.json",
      JSON.stringify({ name: "p", version: "0.0.0", files: ["dist"] }),
    );
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "would-be-published")).toBeUndefined();
  });

  it("falls back to .npmignore when no files field is set", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    write(".npmignore", "src\n"); // .env not listed
    write("package.json", JSON.stringify({ name: "p", version: "0.0.0" }));
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "would-be-published", ".env")).toBeDefined();
  });

  it("respects .gitignore when no files field and no .npmignore", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    write("package.json", JSON.stringify({ name: "p", version: "0.0.0" }));
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "would-be-published")).toBeUndefined();
  });

  it("skips publish check for private packages", async () => {
    initRepo();
    write(".env", "A=1");
    write(".gitignore", ".env*\n");
    write(
      "package.json",
      JSON.stringify({
        name: "p",
        version: "0.0.0",
        private: true,
        files: [".env"],
      }),
    );
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "would-be-published")).toBeUndefined();
  });
});

describe("scanEnv: secrets in example files", () => {
  it("flags an AWS key shape in .env.example", async () => {
    initRepo();
    write(".env.example", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    write(".gitignore", ".env\n");
    const result = await scanEnv({ cwd: tmp });
    expect(
      findIssue(result.issues, "secret-in-example", ".env.example"),
    ).toBeDefined();
  });

  it("does not flag placeholder values", async () => {
    initRepo();
    write(
      ".env.example",
      [
        "API_KEY=your-api-key",
        "PORT=3000",
        "TOKEN=<your-token>",
        "DB_URL=changeme",
      ].join("\n"),
    );
    write(".gitignore", ".env\n");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "secret-in-example")).toBeUndefined();
  });

  it("flags GitHub token shape", async () => {
    initRepo();
    write(
      ".env.example",
      "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    write(".gitignore", ".env\n");
    const result = await scanEnv({ cwd: tmp });
    expect(findIssue(result.issues, "secret-in-example")).toBeDefined();
  });
});

describe("matchesAny", () => {
  it("matches basename without slash", () => {
    expect(matchesAny(".env", [".env"])).toBe(true);
    expect(matchesAny("apps/web/.env", [".env"])).toBe(true);
  });

  it("matches glob with star", () => {
    expect(matchesAny(".env.local", [".env*"])).toBe(true);
    expect(matchesAny(".env", [".env*"])).toBe(true);
    expect(matchesAny("env-helper.js", [".env*"])).toBe(false);
  });

  it("respects negation", () => {
    expect(matchesAny(".env.example", [".env*", "!.env.example"])).toBe(false);
  });

  it("anchored pattern matches only at root", () => {
    expect(matchesAny(".env", ["/.env"])).toBe(true);
    expect(matchesAny("apps/.env", ["/.env"])).toBe(false);
  });
});
