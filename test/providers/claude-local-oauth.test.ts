import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readCachedProvider, writeCachedProviders } from "../../src/cache.js";

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
const originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
const originalSecureStorageDir = process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
let directories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
  if (originalClaudeConfigDir === undefined)
    delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = originalClaudeConfigDir;
  if (originalSecureStorageDir === undefined)
    delete process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
  else process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR = originalSecureStorageDir;
  if (originalXdgCacheHome === undefined) delete process.env.XDG_CACHE_HOME;
  else process.env.XDG_CACHE_HOME = originalXdgCacheHome;
  for (const directory of directories)
    rmSync(directory, { recursive: true, force: true });
  directories = [];
});

describe("Claude Pi and OMP OAuth quota sources", () => {
  it.each([
    ["native", "pi"],
    ["native", "omp"],
    ["pi", "omp"],
  ] as const)(
    "retires rejected %s quota before a later %s transient verdict",
    async (first, second) => {
      const home = temporaryDirectory();
      process.env.HOME = home;
      process.env.XDG_CACHE_HOME = join(home, "cache");
      process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
      delete process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
      delete process.env.PI_CODING_AGENT_DIR;
      const piFile = join(home, ".pi", "agent", "auth.json");
      const ompFile = join(home, ".omp", "agent", "agent.db");
      const store = (source: "native" | "pi" | "omp") => {
        if (source === "native") {
          mkdirSync(process.env.CLAUDE_CONFIG_DIR!, { recursive: true });
          writeFileSync(
            join(process.env.CLAUDE_CONFIG_DIR!, ".credentials.json"),
            JSON.stringify({
              claudeAiOauth: {
                accessToken: "synthetic-native-access",
                expiresAt: "2035-01-01T00:00:00.000Z",
              },
            }),
            { mode: 0o600 },
          );
        } else if (source === "pi") {
          mkdirSync(dirname(piFile), { recursive: true });
          writeFileSync(
            piFile,
            JSON.stringify({
              anthropic: {
                type: "oauth",
                access: "synthetic-pi-access",
                accountId: "pi-account",
              },
            }),
            { mode: 0o600 },
          );
        } else {
          writeOmpCredential(home, "anthropic", {
            access: "synthetic-omp-access",
          });
        }
      };
      store(first);
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: string | URL | Request) =>
          String(input).endsWith("/api/oauth/profile")
            ? Response.json({ account: { uuid: "fixture-account" } })
            : Response.json({
                five_hour: {
                  utilization: 27,
                  resets_at: new Date(Date.now() + 3600_000).toISOString(),
                },
              }),
        ),
      );
      const { fetchQuota } = await import("../../src/providers/claude.js");
      const options = { allowKeychainPrompt: false, refreshCredentials: false };
      const fresh = await fetchQuota(options);
      expect(fresh.state.status).toBe("fresh");
      writeCachedProviders([fresh]);
      expect(readCachedProvider("claude")).toBeDefined();

      store(second);
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_input: unknown, init?: RequestInit) => {
          const bearer = new Headers(init?.headers).get("authorization");
          return new Response(null, {
            status: bearer === `Bearer synthetic-${first}-access` ? 401 : 503,
          });
        }),
      );
      const report = await fetchQuota(options);
      expect(report.state.status).not.toBe("auth_required");
      expect(report.attempts).toContainEqual(
        expect.objectContaining({
          source: first === "native" ? "oauth-file" : "pi:anthropic",
          status: "failed",
        }),
      );
      expect(report.attempts).toContainEqual(
        expect.objectContaining({
          source: second === "pi" ? "pi:anthropic" : "omp:anthropic",
          status: "failed",
        }),
      );
      expect(readCachedProvider("claude")).toBeUndefined();

      rmSync(second === "pi" ? piFile : ompFile, { force: true });
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 503 })),
      );
      const later = await fetchQuota(options);
      expect(later.state.status).not.toBe("stale");
      expect(later.windows).toEqual([]);
      expect(readCachedProvider("claude")).toBeUndefined();
      expect(JSON.stringify([report, later])).not.toMatch(
        /synthetic-(?:native|pi|omp)-access/,
      );
    },
  );

  it("preserves OMP quota when Pi is rejected before an OMP transient", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    process.env.XDG_CACHE_HOME = join(home, "cache");
    process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
    delete process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
    delete process.env.PI_CODING_AGENT_DIR;
    writeOmpCredential(home, "anthropic", { access: "synthetic-omp-access" });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) =>
        String(input).endsWith("/api/oauth/profile")
          ? Response.json({ account: { uuid: "fixture-account" } })
          : Response.json({
              five_hour: {
                utilization: 27,
                resets_at: new Date(Date.now() + 3600_000).toISOString(),
              },
            }),
      ),
    );
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const options = { allowKeychainPrompt: false, refreshCredentials: false };
    writeCachedProviders([await fetchQuota(options)]);
    const piFile = join(home, ".pi", "agent", "auth.json");
    mkdirSync(dirname(piFile), { recursive: true });
    writeFileSync(
      piFile,
      JSON.stringify({
        anthropic: {
          type: "oauth",
          access: "synthetic-pi-access",
          accountId: "pi-account",
        },
      }),
      { mode: 0o600 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_input: unknown, init?: RequestInit) =>
          new Response(null, {
            status:
              new Headers(init?.headers).get("authorization") ===
              "Bearer synthetic-pi-access"
                ? 401
                : 503,
          }),
      ),
    );
    const report = await fetchQuota(options);
    expect(report.source).toBe("cache");
    expect(report.state.status).toBe("stale");
    expect(readCachedProvider("claude")?.source).toBe("omp:anthropic");
  });

  it.each([
    ["omp", "pi"],
    ["pi", "omp"],
    ["native", "pi"],
    ["native", "omp"],
    ["pi", "native"],
    ["omp", "native"],
  ] as const)(
    "retains a %s snapshot when a different %s credential is rejected",
    async (cachedSource, rejectedSource) => {
      const home = temporaryDirectory();
      process.env.HOME = home;
      process.env.XDG_CACHE_HOME = join(home, "cache");
      process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
      delete process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
      delete process.env.PI_CODING_AGENT_DIR;
      const piFile = join(home, ".pi", "agent", "auth.json");
      const ompFile = join(home, ".omp", "agent", "agent.db");
      const nativeFile = join(home, ".claude", ".credentials.json");
      const store = (source: "native" | "pi" | "omp") => {
        if (source === "omp") {
          writeOmpCredential(home, "anthropic", {
            access: "synthetic-omp-access",
            email: "omp@example.test",
          });
        } else if (source === "pi") {
          mkdirSync(dirname(piFile), { recursive: true });
          writeFileSync(
            piFile,
            JSON.stringify({
              anthropic: {
                type: "oauth",
                access: "synthetic-pi-access",
                accountId: "pi-account",
              },
            }),
            { mode: 0o600 },
          );
        } else {
          mkdirSync(dirname(nativeFile), { recursive: true });
          writeFileSync(
            nativeFile,
            JSON.stringify({
              claudeAiOauth: {
                accessToken: "synthetic-native-access",
                expiresAt: "2035-01-01T00:00:00.000Z",
              },
            }),
            { mode: 0o600 },
          );
        }
      };
      const remove = (source: "native" | "pi" | "omp") =>
        rmSync(
          source === "native" ? nativeFile : source === "pi" ? piFile : ompFile,
          { force: true },
        );
      store(cachedSource);
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: string | URL | Request) =>
          String(input).endsWith("/api/oauth/profile")
            ? Response.json({ account: { uuid: "fixture-account" } })
            : Response.json({
                five_hour: {
                  utilization: 27,
                  resets_at: new Date(Date.now() + 3600_000).toISOString(),
                },
              }),
        ),
      );
      const { fetchQuota } = await import("../../src/providers/claude.js");
      const options = { allowKeychainPrompt: false, refreshCredentials: false };
      const fresh = await fetchQuota(options);
      expect(fresh.state.status).toBe("fresh");
      writeCachedProviders([fresh]);
      expect(readCachedProvider("claude")).toBeDefined();

      remove(cachedSource);
      store(rejectedSource);
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 401 })),
      );
      const rejected = await fetchQuota(options);
      expect(rejected.state.status).toBe("auth_required");
      expect(readCachedProvider("claude")).toBeDefined();

      remove(rejectedSource);
      store(cachedSource);
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 503 })),
      );
      const stale = await fetchQuota(options);
      expect(stale.state.status).toBe("stale");
      expect(stale.source).toBe("cache");
      expect(stale.windows).toHaveLength(1);
      expect(JSON.stringify([rejected, stale])).not.toMatch(
        /synthetic-(?:native|pi|omp)-access/,
      );
    },
  );

  it.each(["pi", "omp"] as const)(
    "retires a %s snapshot when its own credential is rejected",
    async (source) => {
      const home = temporaryDirectory();
      process.env.HOME = home;
      process.env.XDG_CACHE_HOME = join(home, "cache");
      process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
      delete process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
      delete process.env.PI_CODING_AGENT_DIR;
      if (source === "omp") {
        writeOmpCredential(home, "anthropic", {
          access: "synthetic-omp-access",
        });
      } else {
        const piFile = join(home, ".pi", "agent", "auth.json");
        mkdirSync(dirname(piFile), { recursive: true });
        writeFileSync(
          piFile,
          JSON.stringify({
            anthropic: {
              type: "oauth",
              access: "synthetic-pi-access",
              accountId: "pi-account",
            },
          }),
          { mode: 0o600 },
        );
      }
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: string | URL | Request) =>
          String(input).endsWith("/api/oauth/profile")
            ? Response.json({ account: { uuid: "fixture-account" } })
            : Response.json({
                five_hour: {
                  utilization: 27,
                  resets_at: new Date(Date.now() + 3600_000).toISOString(),
                },
              }),
        ),
      );
      const { fetchQuota } = await import("../../src/providers/claude.js");
      const options = { allowKeychainPrompt: false, refreshCredentials: false };
      const fresh = await fetchQuota(options);
      expect(fresh.state.status).toBe("fresh");
      writeCachedProviders([fresh]);
      expect(readCachedProvider("claude")).toBeDefined();
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 401 })),
      );
      const rejected = await fetchQuota(options);
      expect(rejected.state.status).toBe("auth_required");
      expect(readCachedProvider("claude")).toBeUndefined();
    },
  );

  it("does not consult Pi or OMP when a secure-storage profile is selected", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
    process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR = join(home, "selected");
    delete process.env.PI_CODING_AGENT_DIR;
    const agent = join(home, ".pi", "agent");
    mkdirSync(agent, { recursive: true });
    writeFileSync(
      join(agent, "auth.json"),
      JSON.stringify({
        anthropic: {
          type: "oauth",
          access: "synthetic-pi-claude",
          expires: Date.now() + 60_000,
        },
      }),
      { mode: 0o600 },
    );
    writeOmpCredential(home, "anthropic", {
      access: "synthetic-omp-claude",
      expires: Date.now() + 60_000,
    });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const { fetchQuota } = await import("../../src/providers/claude.js");
    const result = await fetchQuota({
      allowKeychainPrompt: false,
      refreshCredentials: false,
    });

    expect(result.state.status).not.toBe("fresh");
    expect(result.state.sourcesTried).not.toContain("pi:anthropic");
    expect(result.state.sourcesTried).not.toContain("omp:anthropic");
    expect(fetchMock).not.toHaveBeenCalled();
  });

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

  it("keeps native Claude OAuth ahead of valid Pi and OMP candidates", async () => {
    const home = temporaryDirectory();
    process.env.HOME = home;
    process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
    delete process.env.PI_CODING_AGENT_DIR;
    mkdirSync(process.env.CLAUDE_CONFIG_DIR, { recursive: true });
    writeFileSync(
      join(process.env.CLAUDE_CONFIG_DIR, ".credentials.json"),
      JSON.stringify({
        claudeAiOauth: {
          accessToken: "synthetic-native-claude",
          expiresAt: "2035-01-01T00:00:00.000Z",
        },
      }),
      { mode: 0o600 },
    );
    const agent = join(home, ".pi", "agent");
    mkdirSync(agent, { recursive: true });
    writeFileSync(
      join(agent, "auth.json"),
      JSON.stringify({
        anthropic: {
          type: "oauth",
          access: "synthetic-pi-claude",
          expires: Date.now() + 60_000,
        },
      }),
      { mode: 0o600 },
    );
    const fetchMock = vi.fn(async (input: string | URL | Request) =>
      String(input).endsWith("/api/oauth/profile")
        ? Response.json({ account: { uuid: "native-account" } })
        : Response.json({ five_hour: { utilization: 10 } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const { fetchQuota } = await import("../../src/providers/claude.js");
    const result = await fetchQuota({
      allowKeychainPrompt: false,
      refreshCredentials: false,
    });

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("oauth");
    expect(result.attempts).toContainEqual({
      source: "oauth-file",
      status: "success",
    });
    expect(result.attempts).not.toContainEqual(
      expect.objectContaining({ source: "pi:anthropic" }),
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["Pi", "pi:anthropic", "synthetic-pi-anthropic", "pi"] as const,
    ["OMP", "omp:anthropic", "synthetic-omp-anthropic", "omp"] as const,
  ])(
    "uses %s anthropic OAuth with the native usage endpoint",
    async (_label, expectedSource, token, store) => {
      const home = temporaryDirectory();
      process.env.HOME = home;
      process.env.CLAUDE_CONFIG_DIR = join(home, ".claude");
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
      expect(result.source).toBe(expectedSource);
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
    "CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT, identity_key TEXT, updated_at TEXT)",
  );
  database
    .prepare(
      "INSERT INTO auth_credentials (provider, credential_type, data, identity_key, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run(
      provider,
      "oauth",
      JSON.stringify(data),
      `account-${provider}`,
      "2026-09-25T00:00:00Z",
    );
  database.close();
}
