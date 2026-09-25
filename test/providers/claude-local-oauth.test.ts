import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

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
  vi.restoreAllMocks();
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
  for (const directory of directories)
    rmSync(directory, { recursive: true, force: true });
  directories = [];
});

describe("Claude Pi and OMP OAuth quota sources", () => {
  it("keeps an expired refreshable Pi credential read-only without delegating refresh", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    delete process.env.PI_CODING_AGENT_DIR;
    const agent = join(home, ".pi", "agent");
    mkdirSync(agent, { recursive: true });
    writeFileSync(
      join(agent, "auth.json"),
      JSON.stringify({
        anthropic: {
          type: "oauth",
          access: "synthetic-expired-pi-access",
          refresh: "synthetic-refresh-not-used",
          expires: Date.now() - 60_000,
        },
      }),
      { mode: 0o600 },
    );
    const fetchMock = vi.fn(async () => new Response(null, { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    const { fetchQuota } = await import("../../src/providers/claude.js");
    const result = await fetchQuota({
      allowKeychainPrompt: false,
      refreshCredentials: true,
    });

    expect(result.state.status).toBe("unavailable");
    expect(result.state.authStatus).toBe("expired_refreshable");
    expect(result.source).toBe("unavailable");
    expect(result.state.sourcesTried).toContain("pi:anthropic");
    expect(result.state.sourcesTried).not.toContain("claude-cli-refresh");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["Pi", "pi:anthropic", "synthetic-pi-anthropic", "pi"] as const,
    ["OMP", "omp:anthropic", "synthetic-omp-anthropic", "omp"] as const,
  ])(
    "uses %s anthropic OAuth with the native usage endpoint",
    async (_label, expectedSource, token, store) => {
      const home = temporaryDirectory();
      process.env.HOME = home;
      delete process.env.PI_CODING_AGENT_DIR;
      if (store === "pi") {
        const agent = join(home, ".pi", "agent");
        mkdirSync(agent, { recursive: true });
        writeFileSync(
          join(agent, "auth.json"),
          JSON.stringify({
            anthropic: {
              type: "oauth",
              access: token,
              refresh: "synthetic-refresh-not-used",
              expires: Date.now() + 60_000,
            },
          }),
          { mode: 0o600 },
        );
      } else {
        writeOmpCredential(home, "anthropic", {
          access: token,
          refresh: "synthetic-refresh-not-used",
          expires: Date.now() + 60_000,
          email: "claude@example.test",
        });
      }

      const fetchMock = vi.fn(
        async (input: string | URL | Request, init?: RequestInit) => {
          const url = String(input);
          expect(new Headers(init?.headers).get("authorization")).toBe(
            `Bearer ${token}`,
          );
          if (url.endsWith("/api/oauth/usage")) {
            return Response.json({
              five_hour: { utilization: 27, resets_at: "2026-09-25T16:35:02Z" },
            });
          }
          if (url.endsWith("/api/oauth/profile")) {
            return Response.json({
              account: { uuid: "synthetic-claude-account" },
            });
          }
          throw new Error("unexpected request URL");
        },
      );
      vi.stubGlobal("fetch", fetchMock);

      const { fetchQuota } = await import("../../src/providers/claude.js");
      const result = await fetchQuota({
        allowKeychainPrompt: false,
        refreshCredentials: false,
      });

      expect(result.state.status).toBe("fresh");
      expect(result.source).toBe("oauth");
      expect(result.state.sourcesTried).toContain(expectedSource);
      expect(result.account?.accountId).toBe("synthetic-claude-account");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    },
  );
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(
    join(tmpdir(), "quota-axi-claude-local-oauth-"),
  );
  directories.push(directory);
  return directory;
}

function writeOmpCredential(
  home: string,
  provider: string,
  data: Record<string, unknown>,
): void {
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
    .run(provider, "oauth", JSON.stringify(data));
  database.close();
}
