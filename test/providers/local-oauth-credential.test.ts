import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
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
  OMP_OAUTH_PROVIDERS,
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

  it("requires an OMP identity key for cache identity across replacements", async () => {
    const home = temporaryDirectory();
    const path = join(home, ".omp", "agent", "agent.db");
    mkdirSync(dirname(path), { recursive: true });
    const database = new DatabaseSync(path);
    database.exec(
      "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT, identity_key TEXT, updated_at TEXT)",
    );
    const insert = database.prepare(
      "INSERT INTO auth_credentials (provider, credential_type, data, updated_at) VALUES ('anthropic', 'oauth', ?, ?)",
    );
    insert.run(
      JSON.stringify({ access: "synthetic-account-a" }),
      "2026-09-25T00:00:00Z",
    );
    const broker = createOmpOAuthCredentialBroker("anthropic", {
      environment: { HOME: home },
      homeDirectory: () => home,
    });
    const first = await broker.resolve();
    expect(first.status).toBe("available");
    if (first.status === "available")
      expect(first.credential.cacheIdentity).toBeUndefined();
    insert.run(
      JSON.stringify({ access: "synthetic-account-b" }),
      "2026-09-25T00:00:00Z",
    );
    const second = await broker.resolve();
    expect(second.status).toBe("available");
    if (second.status === "available") {
      expect(second.credential.accessToken).toBe("synthetic-account-b");
      expect(second.credential.cacheIdentity).toBeUndefined();
    }
    database.close();
  });

  it.each(["OAuth", "OAUTH", "oAuth"])(
    "rejects the undocumented Pi Anthropic %s credential type",
    async (type) => {
      const home = temporaryDirectory();
      const agent = join(home, ".pi", "agent");
      mkdirSync(agent, { recursive: true });
      writeFileSync(
        join(agent, "auth.json"),
        JSON.stringify({
          anthropic: {
            type,
            access: "synthetic-pi-access",
          },
        }),
        { mode: 0o600 },
      );
      const broker = createPiAnthropicCredentialBroker({
        environment: { PI_CODING_AGENT_DIR: agent },
        homeDirectory: () => home,
      });
      await expect(broker.resolve()).resolves.toEqual({
        status: "unsupported",
      });
      await expect(broker.inspect()).resolves.toEqual({
        status: "unsupported",
      });
    },
  );

  it("reads OMP OAuth fields from SQLite read-only and never selects refresh", async () => {
    const home = temporaryDirectory();
    const databasePath = join(home, ".omp", "agent", "agent.db");
    mkdirSync(dirname(databasePath), { recursive: true });
    const database = new DatabaseSync(databasePath);
    database.exec(
      "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT, identity_key TEXT, updated_at TEXT)",
    );
    database
      .prepare(
        "INSERT INTO auth_credentials (provider, credential_type, data, identity_key, updated_at) VALUES (?, ?, ?, ?, ?)",
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
        "synthetic-identity",
        "2026-09-25T00:00:00Z",
      );
    const insertCredential = database.prepare(
      "INSERT INTO auth_credentials (provider, credential_type, data, identity_key, updated_at) VALUES (?, 'oauth', ?, ?, ?)",
    );
    for (const provider of OMP_OAUTH_PROVIDERS) {
      if (provider === "google-antigravity") continue;
      const access =
        provider === "devin"
          ? "devin-session-token$eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature"
          : `synthetic-omp-${provider}`;
      insertCredential.run(
        provider,
        JSON.stringify({
          access,
          refresh: "synthetic-omp-refresh",
          expires: Date.now() + 60_000,
        }),
        `identity-${provider}`,
        "2026-09-25T00:00:00Z",
      );
    }
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
        cacheIdentity: "omp:google-antigravity:identity:synthetic-identity",
      },
    });
    await expect(broker.inspect()).resolves.toEqual({ status: "available" });
    expect(JSON.stringify(await broker.inspect())).not.toContain(
      "synthetic-omp-access",
    );
    for (const provider of OMP_OAUTH_PROVIDERS) {
      const resolution = await createOmpOAuthCredentialBroker(provider, {
        environment: process.env,
        homeDirectory: () => home,
      }).resolve();
      expect(resolution.status).toBe("available");
      if (resolution.status !== "available") continue;
      expect(resolution.credential.accessToken).not.toContain(
        "synthetic-omp-refresh",
      );
    }
    const { inputsDigest, withInputTrace } =
      await import("../../src/lib/input-trace.js");
    const traced = await withInputTrace(() => broker.resolve());
    expect(inputsDigest(traced.inputs.paths)).toBe(traced.inputs.digest);
    const changedDatabase = new DatabaseSync(databasePath);
    changedDatabase.exec("CREATE TABLE trace_change (value TEXT)");
    changedDatabase.close();
    expect(inputsDigest(traced.inputs.paths)).not.toBe(traced.inputs.digest);

    chmodSync(databasePath, 0o400);
    await expect(broker.resolve()).resolves.toMatchObject({
      status: "available",
      credential: {
        cacheIdentity: "omp:google-antigravity:identity:synthetic-identity",
      },
    });
  });

  it.each([
    { refresh: "", refreshable: false },
    { refresh: "  ", refreshable: false },
    { refresh: "$REF", refreshable: false },
    { refresh: "prefix$REF", refreshable: false },
    { refresh: "!command", refreshable: false },
    { refresh: "line\nbreak", refreshable: false },
    { refresh: "synthetic-refresh-secret", refreshable: true },
  ])(
    "classifies OMP refresh presence without disclosing it: %#",
    async ({ refresh, refreshable }) => {
      const home = temporaryDirectory();
      const databasePath = join(home, ".omp", "agent", "agent.db");
      mkdirSync(dirname(databasePath), { recursive: true });
      const database = new DatabaseSync(databasePath);
      database.exec(
        "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT, identity_key TEXT, updated_at TEXT)",
      );
      database
        .prepare(
          "INSERT INTO auth_credentials (provider, credential_type, data) VALUES ('anthropic', 'oauth', ?)",
        )
        .run(
          JSON.stringify({
            access: "synthetic-access-token",
            refresh,
            expires: Date.now() - 60_000,
          }),
        );
      database.close();
      process.env.HOME = home;

      const broker = createOmpOAuthCredentialBroker("anthropic", {
        environment: process.env,
        homeDirectory: () => home,
      });
      const resolution = await broker.resolve();
      expect(resolution).toMatchObject({
        status: "expired",
        refreshable,
        credential: { accessToken: "synthetic-access-token" },
      });
      expect(JSON.stringify(resolution)).not.toContain(
        refresh || "never-present",
      );
      expect(await broker.inspect()).toEqual({ status: "expired" });
    },
  );

  it("scopes non-native Claude cache identity to the answering account", async () => {
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
    expect(claudeCredentialContextId()).toBe(initial);
    expect(claudeCredentialContextId("pi:anthropic:account-a")).not.toBe(
      claudeCredentialContextId("pi:anthropic:account-b"),
    );
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
