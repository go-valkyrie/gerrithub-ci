import { describe, expect, it } from "vitest";
import { decide, isTrusted, type GerritEvent, type Policy } from "../src/gerrit";

const policy: Policy = {
  projects: { "go-valkyrie/vali-scheme": "go-valkyrie/vali-scheme" },
  trusted: ["maintainer", "Lead@Example.com"],
};

const REVISION = "0123456789abcdef0123456789abcdef01234567";

function patchset(uploader: Record<string, string>, overrides: Partial<GerritEvent> = {}): GerritEvent {
  return {
    type: "patchset-created",
    change: {
      project: "go-valkyrie/vali-scheme",
      branch: "main",
      number: 4321,
      url: "https://review.gerrithub.io/c/go-valkyrie/vali-scheme/+/4321",
    },
    patchSet: { number: 2, revision: REVISION, ref: "refs/changes/21/4321/2", uploader },
    uploader,
    ...overrides,
  };
}

function comment(author: Record<string, string>, text: string): GerritEvent {
  return { ...patchset({ username: "outsider" }), type: "comment-added", author, comment: text };
}

describe("decide", () => {
  it("runs a trusted uploader's new patch set", () => {
    const d = decide(patchset({ username: "maintainer" }), policy);
    expect(d).toEqual({
      run: true,
      target: {
        project: "go-valkyrie/vali-scheme",
        branch: "main",
        change: 4321,
        patchset: 2,
        ref: "refs/changes/21/4321/2",
        revision: REVISION,
        url: "https://review.gerrithub.io/c/go-valkyrie/vali-scheme/+/4321",
        uploader: "maintainer",
        trigger: "patchset-created",
      },
    });
  });

  it("matches trusted emails case-insensitively", () => {
    expect(decide(patchset({ email: "lead@example.com" }), policy).run).toBe(true);
  });

  it("does not run an untrusted uploader's patch set", () => {
    const d = decide(patchset({ username: "outsider" }), policy);
    expect(d.run).toBe(false);
  });

  it("runs an untrusted patch set when a trusted reviewer comments recheck", () => {
    const d = decide(comment({ username: "maintainer" }, "Patch Set 2:\n\nrecheck"), policy);
    expect(d.run).toBe(true);
    if (d.run) expect(d.target.trigger).toBe("recheck");
  });

  it("ignores a recheck from someone untrusted", () => {
    expect(decide(comment({ username: "outsider" }, "Patch Set 2:\n\nrecheck"), policy).run).toBe(false);
  });

  it("ignores comments that only mention recheck", () => {
    expect(decide(comment({ username: "maintainer" }, "Patch Set 2:\n\nplease recheck this later"), policy).run).toBe(false);
  });

  it("ignores projects without CI and other event types", () => {
    const other = patchset({ username: "maintainer" });
    other.change = { ...other.change, project: "someone/else" };
    expect(decide(other, policy).run).toBe(false);
    expect(decide({ ...patchset({ username: "maintainer" }), type: "change-merged" }, policy).run).toBe(false);
  });

  it("accepts the project as a top-level object", () => {
    const e = patchset({ username: "maintainer" });
    e.change = { ...e.change, project: undefined };
    e.project = { name: "go-valkyrie/vali-scheme" };
    expect(decide(e, policy).run).toBe(true);
  });

  it("refuses malformed refs and revisions", () => {
    const badRef = patchset({ username: "maintainer" });
    badRef.patchSet = { ...badRef.patchSet, ref: "refs/heads/main; rm -rf /" };
    expect(decide(badRef, policy).run).toBe(false);
    const badRev = patchset({ username: "maintainer" });
    badRev.patchSet = { ...badRev.patchSet, revision: "$(id)" };
    expect(decide(badRev, policy).run).toBe(false);
  });
});

describe("isTrusted", () => {
  it("is false for a missing account", () => {
    expect(isTrusted(undefined, ["maintainer"])).toBe(false);
  });
});
