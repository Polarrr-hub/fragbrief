// @vitest-environment node
//
// Safety contract for the cross-family Gemini reviewer. The reviewer sends a PR diff
// to an external model, so the security boundary is: secrets must be redacted before
// the prompt leaves the runner, and a private key must HARD-BLOCK the send entirely.
// These tests prove the allowed path (clean/redacted prompt is sent) and the denied
// paths (private key => refuse to send; a spoofed comment from another user is never
// edited), plus standard embedding, untrusted-diff framing, model selection, and the
// create/update behaviour of the comment upsert.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  buildPrompt,
  scrubForSend,
  pickModel,
  assertDiff,
  composeReview,
  selectOwnComment,
  selectModel,
  upsertComment,
  COMMENT_TAG,
} from "./gemini-review.mjs";

// Always restore any global fetch stub between tests, even if an assertion threw.
afterEach(() => {
  vi.unstubAllGlobals();
});

// Synthetic, non-functional fixtures used only to exercise the redactor. Assembled
// from parts and clearly labelled so no realistic secret literal is committed
// (mirrors lib/security/redaction.test.mjs).
const D = "-----";
const FAKE_API_KEY = `sk-ant-api03-${"A1b2C3d4E5".repeat(4)}`; // fake test fixture, not a real key
const FAKE_PEM = `${D}BEGIN PRIVATE KEY${D}\nMIIFAKEbodyNotRealc2VjcmV0\n${D}END PRIVATE KEY${D}`; // fake test fixture

describe("gemini-review prompt assembly", () => {
  it("embeds the review standard and frames the diff as untrusted data", () => {
    const prompt = buildPrompt("+const x = 1;", "STANDARD-SENTINEL-TEXT");
    expect(prompt).toContain("STANDARD-SENTINEL-TEXT");
    expect(prompt).toContain("untrusted DATA");
    expect(prompt).toContain("----- BEGIN PR DIFF -----");
    expect(prompt).toContain("+const x = 1;");
  });
});

describe("gemini-review send-safety (redaction / refuse-to-send)", () => {
  it("allowed path: redacts a leaked API key before sending", () => {
    const diff = `+const key = "${FAKE_API_KEY}";`;
    const { safe, blocked, redactions } = scrubForSend(buildPrompt(diff, ""));
    expect(blocked).toBe(false);
    expect(safe).not.toContain(FAKE_API_KEY);
    expect(redactions.length).toBeGreaterThan(0);
  });

  it("allowed path: leaves ordinary code unredacted", () => {
    const { safe, blocked } = scrubForSend(buildPrompt("+const greeting = 'hello world';", ""));
    expect(blocked).toBe(false);
    expect(safe).toContain("hello world");
  });

  it("denied path: refuses to send when a private key is present", () => {
    const { safe, blocked, blockReason } = scrubForSend(buildPrompt(FAKE_PEM, ""));
    expect(blocked).toBe(true);
    expect(safe).toBe("");
    expect(blockReason).toMatch(/private key/i);
  });
});

describe("gemini-review composeReview (secret-gated main path)", () => {
  it("denied: a private key blocks the send and the model is never called", async () => {
    const generate = vi.fn();
    const out = await composeReview(FAKE_PEM, "", generate);
    expect(generate).not.toHaveBeenCalled();
    expect(out).toMatch(/skipped/i);
  });

  it("allowed: sends the redacted prompt and appends a redaction note", async () => {
    const generate = vi.fn(async (safe) => {
      expect(safe).not.toContain(FAKE_API_KEY);
      return "Verdict: Approve";
    });
    const out = await composeReview(`+const k = "${FAKE_API_KEY}";`, "", generate);
    expect(generate).toHaveBeenCalledOnce();
    expect(out).toContain("Verdict: Approve");
    expect(out).toMatch(/redacted before sending/);
  });

  it("allowed: a clean diff returns the model text with no redaction note", async () => {
    const out = await composeReview("+const a = 1;", "", async () => "Verdict: clean");
    expect(out).toBe("Verdict: clean");
  });
});

describe("gemini-review model selection", () => {
  it("prefers a non-lite flash model the key supports", () => {
    const names = ["models/gemini-3.1-flash-lite", "models/gemini-3.5-flash", "models/gemini-pro"];
    expect(pickModel(names)).toBe("models/gemini-3.5-flash");
  });

  it("falls back to any flash, then to a safe default", () => {
    expect(pickModel(["models/gemini-2.0-flash-lite"])).toBe("models/gemini-2.0-flash-lite");
    expect(pickModel([])).toBe("models/gemini-2.5-flash");
  });

  it("fetches the model list and applies the preference", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          models: [
            { name: "models/gemini-3.1-flash-lite", supportedGenerationMethods: ["generateContent"] },
            { name: "models/gemini-3.5-flash", supportedGenerationMethods: ["generateContent"] },
            { name: "models/text-embedding", supportedGenerationMethods: ["embedContent"] },
          ],
        }),
      })),
    );
    expect(await selectModel("key")).toBe("models/gemini-3.5-flash");
  });
});

describe("gemini-review assertDiff (fail closed on empty diff)", () => {
  it("throws on a missing or empty diff", () => {
    expect(() => assertDiff("")).toThrow(/empty/i);
    expect(() => assertDiff("   \n  ")).toThrow(/empty/i);
  });

  it("returns the diff when it has content", () => {
    expect(assertDiff("+const a = 1;")).toBe("+const a = 1;");
  });
});

describe("gemini-review comment upsert (auth boundary)", () => {
  it("selectOwnComment ignores a spoofed tagged comment from another author", () => {
    const comments = [
      { id: 1, user: { login: "attacker" }, body: `${COMMENT_TAG} — spoofed` },
      { id: 2, user: { login: "me" }, body: `${COMMENT_TAG} — ours` },
    ];
    expect(selectOwnComment(comments, "me", COMMENT_TAG).id).toBe(2);
    expect(selectOwnComment([comments[0]], "me", COMMENT_TAG)).toBeUndefined();
  });

  const realEnv = process.env;
  beforeEach(() => {
    process.env = { ...realEnv, GITHUB_API_URL: "https://api.github.com", GITHUB_REPOSITORY: "o/r", PR_NUMBER: "5", GEMINI_REVIEW_TOKEN: "t" };
  });
  afterEach(() => {
    process.env = realEnv;
    vi.unstubAllGlobals();
  });

  it("updates only our own comment, never the spoofed one", async () => {
    const calls = [];
    vi.stubGlobal("fetch", vi.fn(async (url, opts) => {
      calls.push({ url, method: (opts && opts.method) || "GET" });
      if (url.endsWith("/user")) return { ok: true, json: async () => ({ login: "me" }) };
      if (url.includes("/issues/5/comments")) {
        return { ok: true, json: async () => [
          { id: 11, user: { login: "attacker" }, body: `${COMMENT_TAG} spoof` },
          { id: 22, user: { login: "me" }, body: `${COMMENT_TAG} ours` },
        ] };
      }
      return { ok: true, json: async () => ({}) }; // PATCH
    }));
    expect(await upsertComment("new body")).toBe("updated 22");
    const patch = calls.find((c) => c.method === "PATCH");
    expect(patch.url).toContain("/comments/22");
    expect(calls.some((c) => c.url.includes("/comments/11"))).toBe(false);
  });

  it("creates a new comment when none of ours exists", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url, opts) => {
      if (url.endsWith("/user")) return { ok: true, json: async () => ({ login: "me" }) };
      if (url.includes("/issues/5/comments") && (!opts || opts.method !== "POST")) {
        return { ok: true, json: async () => [{ id: 11, user: { login: "attacker" }, body: `${COMMENT_TAG} spoof` }] };
      }
      return { ok: true, json: async () => ({ id: 99 }) }; // POST
    }));
    expect(await upsertComment("b")).toBe("created");
  });
});
