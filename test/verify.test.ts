import { describe, expect, it, vi } from "vitest";
import type { Target } from "../src/gerrit";
import { confirmChange, fetchChange, GerritError, trivialKind } from "../src/verify";

const REV = "0123456789abcdef0123456789abcdef01234567";
const OTHER = "89abcdef0123456789abcdef0123456789abcdef";

const target: Target = {
  project: "go-valkyrie/vali-scheme",
  branch: "main",
  change: 7,
  patchset: 2,
  ref: "refs/changes/07/7/2",
  revision: REV,
  url: "",
  uploader: "maintainer",
  trigger: "patchset-created",
};

/** A change as Gerrit's REST API returns it with ALL_REVISIONS, DETAILED_ACCOUNTS and MESSAGES. */
export function changeInfo(over: { uploader?: string; kind?: string; messages?: { author: string; message: string; ps: number }[] } = {}) {
  return {
    project: "go-valkyrie/vali-scheme",
    branch: "main",
    _number: 7,
    revisions: {
      [OTHER]: { _number: 1, ref: "refs/changes/07/7/1", uploader: { _account_id: 1, username: "outsider" } },
      [REV]: { _number: 2, ref: "refs/changes/07/7/2", uploader: { _account_id: 2, username: over.uploader ?? "maintainer" }, ...(over.kind ? { kind: over.kind } : {}) },
    },
    messages: (over.messages ?? []).map((m) => ({ author: { username: m.author }, message: m.message, _revision_number: m.ps })),
  };
}

const trusted = ["maintainer"];

describe("confirmChange", () => {
  it("confirms a trusted uploader's patch set", () => {
    expect(confirmChange(changeInfo(), target, trusted)).toEqual({ confirmed: true, uploader: "maintainer" });
  });

  it("refuses an event that claims a trusted uploader for someone else's patch set", () => {
    const c = confirmChange(changeInfo({ uploader: "outsider" }), target, trusted);
    expect(c.confirmed).toBe(false);
    if (!c.confirmed) expect(c.reason).toMatch(/uploaded by outsider/);
  });

  it("refuses revisions, patch sets and refs Gerrit doesn't have", () => {
    expect(confirmChange(changeInfo(), { ...target, revision: "f".repeat(40) }, trusted).confirmed).toBe(false);
    expect(confirmChange(changeInfo(), { ...target, patchset: 1 }, trusted).confirmed).toBe(false);
    expect(confirmChange(changeInfo(), { ...target, ref: "refs/changes/07/7/9" }, trusted).confirmed).toBe(false);
  });

  it("refuses a change in another project, or one Gerrit doesn't know", () => {
    expect(confirmChange({ ...changeInfo(), project: "someone/else" }, target, trusted).confirmed).toBe(false);
    expect(confirmChange({}, target, trusted).confirmed).toBe(false);
  });

  describe("rechecks", () => {
    const recheck: Target = { ...target, trigger: "recheck", uploader: "outsider" };

    it("confirms a recheck a trusted reviewer really wrote on that patch set", () => {
      const change = changeInfo({ uploader: "outsider", messages: [{ author: "maintainer", message: "Patch Set 2:\n\nrecheck", ps: 2 }] });
      expect(confirmChange(change, recheck, trusted)).toEqual({ confirmed: true, uploader: "outsider" });
    });

    it("refuses a recheck Gerrit has no record of", () => {
      expect(confirmChange(changeInfo({ uploader: "outsider" }), recheck, trusted).confirmed).toBe(false);
    });

    it("refuses a recheck by someone untrusted, or on another patch set", () => {
      const byOutsider = changeInfo({ uploader: "outsider", messages: [{ author: "outsider", message: "Patch Set 2:\n\nrecheck", ps: 2 }] });
      expect(confirmChange(byOutsider, recheck, trusted).confirmed).toBe(false);
      const earlier = changeInfo({ uploader: "outsider", messages: [{ author: "maintainer", message: "Patch Set 1:\n\nrecheck", ps: 1 }] });
      expect(confirmChange(earlier, recheck, trusted).confirmed).toBe(false);
    });
  });
});

describe("trivialKind", () => {
  it("names TRIVIAL_REBASE and NO_CHANGE patch sets, but nothing else", () => {
    expect(trivialKind(changeInfo({ kind: "TRIVIAL_REBASE" }), target)).toBe("TRIVIAL_REBASE");
    expect(trivialKind(changeInfo({ kind: "NO_CHANGE" }), target)).toBe("NO_CHANGE");
    expect(trivialKind(changeInfo({ kind: "REWORK" }), target)).toBeUndefined();
    expect(trivialKind(changeInfo({ kind: "MERGE_FIRST_PARENT_UPDATE" }), target)).toBeUndefined();
    expect(trivialKind(changeInfo({ kind: "NO_CODE_CHANGE" }), target)).toBeUndefined();
    expect(trivialKind(changeInfo(), target)).toBeUndefined();
    expect(trivialKind({}, target)).toBeUndefined();
  });

  it("never skips a recheck: a trusted reviewer explicitly asked for it", () => {
    const recheck: Target = { ...target, trigger: "recheck" };
    expect(trivialKind(changeInfo({ kind: "TRIVIAL_REBASE" }), recheck)).toBeUndefined();
    expect(trivialKind(changeInfo({ kind: "NO_CHANGE" }), recheck)).toBeUndefined();
  });
});

describe("fetchChange", () => {
  const gerrit = { url: "https://review.gerrithub.io", user: "ci-bot", password: "pw" };

  it("asks for every revision, account details and messages, as the bot, and strips the XSSI prefix", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(`)]}'\n${JSON.stringify(changeInfo())}`));
    const change = await fetchChange(target, gerrit, fetchImpl as unknown as typeof fetch);
    expect(change._number).toBe(7);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://review.gerrithub.io/a/changes/go-valkyrie%2Fvali-scheme~7?o=ALL_REVISIONS&o=DETAILED_ACCOUNTS&o=MESSAGES");
    expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("ci-bot:pw")}`);
  });

  it("treats a missing change as unknown, and other failures as errors", async () => {
    const notFound = vi.fn(async () => new Response("Not found", { status: 404 }));
    await expect(fetchChange(target, gerrit, notFound as unknown as typeof fetch)).resolves.toEqual({});
    const down = vi.fn(async () => new Response("oops", { status: 503 }));
    await expect(fetchChange(target, gerrit, down as unknown as typeof fetch)).rejects.toBeInstanceOf(GerritError);
  });
});
