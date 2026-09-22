import { describe, expect, it } from "vitest";
import {
  degradedSources,
  isDegradedSourceAttempt,
  providerPresence,
} from "../../src/lib/source-attempts.js";
import type { ProviderQuota, SourceAttempt } from "../../src/types.js";

describe("degraded source classification", () => {
  it("treats a tried-and-failed source as degraded", () => {
    expect(
      isDegradedSourceAttempt({
        source: "oauth",
        status: "failed",
        error: "HTTP 401",
      }),
    ).toBe(true);
  });

  it("treats a skipped source that still holds a credential as degraded", () => {
    expect(
      isDegradedSourceAttempt({
        source: "oauth",
        status: "skipped",
        error: "credentials_expired",
        credentialPresent: true,
      }),
    ).toBe(true);
  });

  it("does not treat an absent source as degraded", () => {
    expect(
      isDegradedSourceAttempt({
        source: "pi:openai-codex",
        status: "skipped",
        error: "credentials_missing",
      }),
    ).toBe(false);
  });

  it("lets a provider override the derivation for a non-credential attempt", () => {
    expect(
      isDegradedSourceAttempt({
        source: "web",
        status: "skipped",
        error: "model_auth_probe_live",
        credentialPresent: true,
        degraded: false,
      }),
    ).toBe(false);
  });

  it("names each degraded source once, in the order it was consulted", () => {
    expect(
      degradedSources([
        {
          source: "oauth",
          status: "skipped",
          error: "a",
          credentialPresent: true,
        },
        { source: "oauth", status: "failed", error: "b" },
        { source: "pi:openai-codex", status: "failed", error: "c" },
        { source: "cli-rpc", status: "success" },
      ]),
    ).toEqual([
      { source: "oauth", error: "a" },
      { source: "pi:openai-codex", error: "c" },
    ]);
  });

  it("clears a source that ultimately answered after an earlier failure", () => {
    expect(
      degradedSources([
        { source: "web", status: "failed", error: "credentials_expired" },
        { source: "web", status: "success" },
      ]),
    ).toEqual([]);
  });

  it("clears a source after explicit non-degraded recovery", () => {
    expect(
      degradedSources([
        { source: "web", status: "failed", error: "provider_auth_rejected" },
        {
          source: "web",
          status: "skipped",
          error: "model_auth_probe_live",
          credentialPresent: true,
          degraded: false,
        },
        { source: "pi:xai", status: "success", credentialPresent: true },
      ]),
    ).toEqual([]);
  });

  it("reports no degraded source for a report with no attempts", () => {
    expect(degradedSources(undefined)).toEqual([]);
  });
});

describe("provider presence classification", () => {
  function reading(
    status: ProviderQuota["state"]["status"],
    attempts?: SourceAttempt[],
  ): Pick<ProviderQuota, "state" | "attempts"> {
    return {
      state: { status, stale: status === "stale" },
      ...(attempts ? { attempts } : {}),
    };
  }

  const absent: SourceAttempt = {
    source: "env:MIMO_API_KEY",
    status: "skipped",
    error: "mimo_credential_unavailable",
  };

  it("counts any reading, fresh or stale, as live", () => {
    expect(providerPresence(reading("fresh", [absent]))).toBe("live");
    expect(providerPresence(reading("stale", [absent]))).toBe("live");
  });

  it("reads a provider as not set up only when every source was skipped as absent", () => {
    expect(
      providerPresence(
        reading("auth_required", [
          absent,
          {
            source: "pi:mimo",
            status: "skipped",
            error: "credentials_missing",
          },
        ]),
      ),
    ).toBe("absent");
    // A tool that is simply not installed says the same thing.
    expect(
      providerPresence(
        reading("unavailable", [
          {
            source: "cli",
            status: "skipped",
            error: "agy CLI is not installed",
            degraded: false,
          },
        ]),
      ),
    ).toBe("absent");
  });

  it("keeps a provider whose credential exists in view, however it failed", () => {
    for (const attempt of [
      // Present behind a Keychain prompt, expired, or unreadable.
      {
        source: "keychain",
        status: "skipped",
        error: "keychain_prompt_required",
        credentialPresent: true,
      },
      {
        source: "apps-json",
        status: "skipped",
        error: "credentials_read_error",
        degraded: true,
      },
      // Rejected, rate limited, or unparseable after a request.
      { source: "env:DEEPSEEK_API_KEY", status: "failed", error: "401" },
      // An installed tool that failed is still the user's tool.
      { source: "cli", status: "failed", error: "timeout", degraded: false },
    ] satisfies SourceAttempt[]) {
      expect(
        providerPresence(reading("auth_required", [absent, attempt])),
      ).toBe("attention");
    }
  });

  it("never folds a provider whose absence was not shown", () => {
    expect(providerPresence(reading("error"))).toBe("attention");
    expect(providerPresence(reading("error", []))).toBe("attention");
  });

  it("ignores a declared incidental source as evidence either way", () => {
    const ghLogin: SourceAttempt = {
      source: "gh:hosts.yml",
      status: "skipped",
      error: "credentials_keyring_storage",
      credentialPresent: true,
    };
    const ghRejected: SourceAttempt = {
      source: "gh:hosts.yml",
      status: "failed",
      error: "GitHub Copilot sign-in required",
    };
    for (const gh of [ghLogin, ghRejected]) {
      const copilot = reading("auth_required", [
        {
          source: "apps-json",
          status: "skipped",
          error: "credentials_missing",
        },
        gh,
      ]);
      expect(providerPresence(copilot)).toBe("attention");
      expect(providerPresence(copilot, ["gh:hosts.yml"])).toBe("absent");
    }
  });
});
