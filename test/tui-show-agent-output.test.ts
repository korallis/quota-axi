import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const BUILT_CLI_ENTRYPOINT = resolve("dist/bin/quota-axi.js");
const FIXED_NOW = Date.parse("2026-08-07T00:00:00.000Z");
let temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories) {
    rmSync(directory, { recursive: true, force: true });
  }
  temporaryDirectories = [];
});

/**
 * Runs the built CLI against a fake Codex app-server with a frozen clock, so
 * two runs that differ only in the environment can be compared byte for byte.
 */
function builtCli(): {
  run: (
    flags: string[],
    show?: string,
  ) => { status: number | null; stdout: string; stderr: string; cache: string };
} {
  const root = mkdtempSync(join(tmpdir(), "quota-axi-tui-show-"));
  temporaryDirectories.push(root);
  const home = join(root, "home");
  mkdirSync(home, { mode: 0o700 });
  const clock = join(root, "fixed-clock.mjs");
  writeFileSync(
    clock,
    `const RealDate = Date;
const FIXED_NOW = ${FIXED_NOW};
class FixedDate extends RealDate {
  constructor(...args) {
    if (args.length === 0) super(FIXED_NOW);
    else super(...args);
  }
  static now() {
    return FIXED_NOW;
  }
}
globalThis.Date = FixedDate;
`,
  );
  const codex = join(root, "codex-fixture");
  const resetsAt = Math.floor(FIXED_NOW / 1000) + 2 * 86_400;
  writeFileSync(
    codex,
    `#!${process.execPath}
let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  const lines = buffer.split(/\\r?\\n/);
  buffer = lines.pop() ?? "";
  for (const line of lines) {
    if (!line.trim()) continue;
    const request = JSON.parse(line);
    let result = {};
    if (request.method === "account/read") {
      result = {
        account: { type: "chatgpt", email: "cli@example.invalid", planType: "plus" },
        requiresOpenaiAuth: true
      };
    }
    if (request.method === "account/rateLimits/read") {
      result = {
        rateLimits: {
          limitId: "codex",
          limitName: null,
          primary: { usedPercent: 30, windowDurationMins: 10080, resetsAt: ${resetsAt} },
          secondary: null
        },
        rateLimitsByLimitId: {}
      };
    }
    process.stdout.write(JSON.stringify({ id: request.id, result }) + "\\n");
  }
});
`,
    { mode: 0o700 },
  );
  chmodSync(codex, 0o700);

  let runs = 0;
  return {
    run: (flags, show) => {
      // Every run starts from its own empty cache, so no run reads another's.
      const cacheHome = join(root, `cache-${runs++}`);
      mkdirSync(cacheHome, { mode: 0o700 });
      const result = spawnSync(
        process.execPath,
        [
          "--import",
          pathToFileURL(clock).href,
          BUILT_CLI_ENTRYPOINT,
          "--provider",
          "codex",
          ...flags,
        ],
        {
          encoding: "utf8",
          timeout: 10_000,
          env: {
            HOME: home,
            XDG_CACHE_HOME: cacheHome,
            QUOTA_AXI_CODEX_BINARY: codex,
            PATH: process.env.PATH ?? "",
            TZ: "UTC",
            ...(show === undefined ? {} : { QUOTA_AXI_TUI_SHOW: show }),
          },
        },
      );
      if (result.error) throw result.error;
      let cache = "";
      try {
        cache = readFileSync(
          join(cacheHome, "quota-axi", "quotas.json"),
          "utf8",
        );
      } catch {
        // A run that writes no cache compares as empty.
      }
      return {
        status: result.status,
        stdout: result.stdout,
        stderr: result.stderr,
        cache,
      };
    },
  };
}

describe("QUOTA_AXI_TUI_SHOW agent output", () => {
  it("leaves TOON, JSON, and the cache byte-identical whatever it is set to", () => {
    const cli = builtCli();
    for (const flags of [[], ["--full"], ["--json"], ["--json", "--full"]]) {
      const baseline = cli.run(flags);
      expect(baseline.status, baseline.stderr).toBe(0);
      expect(baseline.stdout).toContain("codex");
      expect(baseline.cache).not.toBe("");
      // `used` flips the TUI, and a value the TUI would reject never even
      // reaches an agent-facing surface.
      for (const show of ["used", "remaining", "sideways"]) {
        expect(cli.run(flags, show), `${flags.join(" ")} ${show}`).toEqual(
          baseline,
        );
      }
    }
  }, 60_000);

  it("flips only the --tui report", () => {
    const cli = builtCli();
    const remaining = cli.run(["--tui", "--once"]);
    const used = cli.run(["--tui", "--once"], "used");
    expect(remaining.status, remaining.stderr).toBe(0);
    expect(used.status, used.stderr).toBe(0);
    expect(remaining.stdout).toMatch(/│ {3}70% week +on pace ✓/);
    expect(remaining.stdout).toMatch(/│ {3}week +[━╸┃─]+ +70% +2d 0h/);
    expect(used.stdout).toMatch(/│ {3}30% used · week +on pace ✓/);
    expect(used.stdout).toMatch(/│ {3}week +[━╸┃─]+ +30% +2d 0h/);
    expect(used.cache).toBe(remaining.cache);
  }, 30_000);

  it("rejects an unknown --tui preference before reading any quota", () => {
    const rejected = builtCli().run(["--tui", "--once"], "left");
    expect(rejected.status).toBe(2);
    expect(rejected.stdout + rejected.stderr).toContain(
      "QUOTA_AXI_TUI_SHOW must be remaining or used",
    );
    expect(rejected.cache).toBe("");
  }, 30_000);
});
