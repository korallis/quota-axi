import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createOmpOAuthCredentialBroker,
  createPiAnthropicCredentialBroker,
} from "../../src/providers/local-oauth-credential.js";

const require = createRequire(import.meta.url);
const { DatabaseSync } = require("node:sqlite") as {
  DatabaseSync: new (path: string) => {
    exec(sql: string): void;
    prepare(sql: string): { run(...values: string[]): void };
    close(): void;
  };
};
const originalHome = process.env.HOME;
const originalPiAgentDir = process.env.PI_CODING_AGENT_DIR;
let directories: string[] = [];

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
  for (const directory of directories)
    rmSync(directory, { recursive: true, force: true });
  directories = [];
});

describe("additional read-only OAuth credential stores", () => {
  it("resolves only Pi anthropic OAuth access credentials", async () => {
    const home = temporaryDirectory();
    const agent = join(home, ".pi", "agent");
    mkdirSync(agent, { recursive: true });
    writeFileSync(
      join(agent, "auth.json"),
      JSON.stringify({
        anthropic: {
          type: "oauth",
          access: "synthetic-pi-access",
          refresh: "synthetic-pi-refresh",
          expires: Date.now() + 60_000,
        },
      }),
      { mode: 0o600 },
    );
    process.env.HOME = home;
    delete process.env.PI_CODING_AGENT_DIR;

    const broker = createPiAnthropicCredentialBroker({
      environment: process.env,
      homeDirectory: () => home,
    });
    await expect(broker.resolve()).resolves.toEqual({
      status: "available",
      credential: {
        accessToken: "synthetic-pi-access",
        expiresAt: expect.any(Number),
      },
    });
    await expect(broker.inspect()).resolves.toEqual({ status: "available" });
    expect(JSON.stringify(await broker.inspect())).not.toContain(
      "synthetic-pi-access",
    );
  });

  it("reads OMP OAuth fields from SQLite read-only and never selects refresh", async () => {
    const home = temporaryDirectory();
    const databasePath = join(home, ".omp", "agent", "agent.db");
    mkdirSync(dirname(databasePath), { recursive: true });
    const database = new DatabaseSync(databasePath);
    database.exec(
      "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT)",
    );
    database
      .prepare(
        "INSERT INTO auth_credentials (provider, credential_type, data) VALUES (?, ?, ?)",
      )
      .run(
        "google-antigravity",
        "oauth",
        JSON.stringify({
          access: "synthetic-omp-access",
          refresh: "synthetic-omp-refresh",
          expires: Date.now() + 60_000,
          email: "antigravity@example.test",
          projectId: "synthetic-project",
        }),
      );
    database.close();
    process.env.HOME = home;

    const broker = createOmpOAuthCredentialBroker("google-antigravity", {
      environment: process.env,
      homeDirectory: () => home,
    });
    await expect(broker.resolve()).resolves.toEqual({
      status: "available",
      credential: {
        accessToken: "synthetic-omp-access",
        expiresAt: expect.any(Number),
        email: "antigravity@example.test",
        projectId: "synthetic-project",
        accountId: undefined,
        organization: undefined,
      },
    });
    await expect(broker.inspect()).resolves.toEqual({ status: "available" });
    expect(JSON.stringify(await broker.inspect())).not.toContain(
      "synthetic-omp-access",
    );
    const { inputsDigest, withInputTrace } =
      await import("../../src/lib/input-trace.js");
    const traced = await withInputTrace(() => broker.resolve());
    expect(inputsDigest(traced.inputs.paths)).toBe(traced.inputs.digest);
    const changedDatabase = new DatabaseSync(databasePath);
    changedDatabase.exec("CREATE TABLE trace_change (value TEXT)");
    changedDatabase.close();
    expect(inputsDigest(traced.inputs.paths)).not.toBe(traced.inputs.digest);

    const implementation = readFileSync(
      new URL("../../src/providers/local-oauth-credential.ts", import.meta.url),
      "utf8",
    );
    expect(implementation).toContain(
      "new DatabaseSync(path, { readOnly: true })",
    );
    expect(implementation).not.toMatch(/json_extract\(data,\s*'\$\.refresh'\)/);
    expect(implementation).not.toMatch(
      /writeFile|UPDATE auth_credentials|DELETE FROM auth_credentials/,
    );
  });

  it("changes Claude's cache identity when either additional credential store changes", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    delete process.env.PI_CODING_AGENT_DIR;
    const { claudeCredentialContextId } = await import("../../src/lib/fs.js");
    const initial = claudeCredentialContextId();

    const piDirectory = join(home, ".pi", "agent");
    mkdirSync(piDirectory, { recursive: true });
    writeFileSync(
      join(piDirectory, "auth.json"),
      JSON.stringify({ anthropic: { type: "oauth", access: "synthetic" } }),
      { mode: 0o600 },
    );
    const withPiCredential = claudeCredentialContextId();
    expect(withPiCredential).not.toBe(initial);

    const databasePath = join(home, ".omp", "agent", "agent.db");
    mkdirSync(dirname(databasePath), { recursive: true });
    const database = new DatabaseSync(databasePath);
    database.exec(
      "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT)",
    );
    database.close();
    expect(claudeCredentialContextId()).not.toBe(withPiCredential);
  });

  it("reports missing provider entries without treating another provider as a match", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    await expect(
      createOmpOAuthCredentialBroker("anthropic", {
        environment: process.env,
        homeDirectory: () => home,
      }).resolve(),
    ).resolves.toEqual({ status: "missing" });
  });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "quota-axi-local-oauth-"));
  directories.push(directory);
  return directory;
}
