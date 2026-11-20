import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { resetTokenCache } from "../src/github";
import { EventClaim } from "../src/muse";
import { handle, type Env } from "../src/index";
import { openTicket } from "../src/ticket";
import { testKey } from "./keys";

let env: Env;

const museTokens = {
  noteJob: async () => "advanced" as const,
  isRevoked: async () => false,
  completeRun: async () => "advanced" as const,
};

beforeAll(async () => {
  env = {
    WEBHOOK_SECRET: "s3cret",
    TICKET_SECRET: "ticket-key",
    EVENT_CLAIM: undefined as unknown as DurableObjectNamespace,
    MUSE_TOKENS: undefined as unknown as DurableObjectNamespace,
    GITHUB_APP_ID: "12345",
    GITHUB_APP_PRIVATE_KEY: (await testKey()).pkcs1Pem,
    GERRIT_USER: "ci-bot",
    GERRIT_HTTP_PASSWORD: "gerrit-pass",
    PROJECTS: JSON.stringify({ "go-valkyrie/vali-scheme": "go-valkyrie/vali-scheme" }),
    TRUSTED: JSON.stringify(["maintainer"]),
  };
});

beforeEach(() => resetTokenCache());

const NOW = 1_800_000_000;

const event = {
  type: "patchset-created",
  change: { project: "go-valkyrie/vali-scheme", branch: "main", number: 7, url: "https://review.gerrithub.io/c/x/+/7" },
  patchSet: {
    number: 1,
    revision: "0123456789abcdef0123456789abcdef01234567",
    ref: "refs/changes/07/7/1",
    uploader: { username: "maintainer" },
  },
};

function post(path: string, body: unknown): Request {
  return new Request(`https://relay.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** Change 7 as Gerrit reports it: patch set 1 uploaded by `uploader`. */
function gerritChange(uploader = "maintainer", kind?: string) {
  return {
    project: "go-valkyrie/vali-scheme",
    branch: "main",
    _number: 7,
    revisions: {
      "0123456789abcdef0123456789abcdef01234567": { _number: 1, ref: "refs/changes/07/7/1", uploader: { username: uploader }, ...(kind ? { kind } : {}) },
    },
    messages: [{ _revision_number: 1, message: "Patch Set 1:\n\nrecheck", author: { username: "maintainer" } }],
  };
}

/**
 * GitHub's API as the app sees it, and Gerrit's for change 7; `dispatchStatus`
 * is what the dispatch returns.
 */
function github(dispatchStatus = 204, uploader = "maintainer", kind?: string) {
  return vi.fn(async (url: string | URL | Request, _init?: RequestInit) => {
    const u = String(url);
    if (u.startsWith("https://review.gerrithub.io/a/changes/go-valkyrie%2Fvali-scheme~7?")) {
      return new Response(`)]}'\n${JSON.stringify(gerritChange(uploader, kind))}`);
    }
    if (u.endsWith("/installation")) return Response.json({ id: 99 });
    if (u.endsWith("/app/installations/99/access_tokens")) {
      return Response.json({ token: "ghs_installation", expires_at: new Date((NOW + 3600) * 1000).toISOString() }, { status: 201 });
    }
    if (u.endsWith("/dispatches")) return new Response(dispatchStatus === 204 ? null : "Bad credentials", { status: dispatchStatus });
    return new Response("unexpected", { status: 500 });
  });
}

/** Deps whose background work, sleeps and log lines the test can see. */
function deps(fetchImpl: unknown, claim: (key: string) => Promise<boolean> = async () => true) {
  const pending: Promise<unknown>[] = [];
  const logs: string[] = [];
  const sleeps: number[] = [];
  return {
    fetch: fetchImpl as typeof fetch,
    now: () => NOW,
    waitUntil: (work: Promise<unknown>) => {
      pending.push(work);
    },
    sleep: async (ms: number) => {
      sleeps.push(ms);
    },
    log: (line: string) => {
      logs.push(line);
    },
    claim,
    museTokens,
    logs,
    sleeps,
    /** Waits for the work done after the response. */
    settled: () => Promise.all(pending),
  };
}

function calls(fetchImpl: { mock: { calls: unknown[][] } }, suffix: string) {
  return fetchImpl.mock.calls.filter(([u]) => String(u).endsWith(suffix)).length;
}

function dispatchCall(fetchImpl: ReturnType<typeof github>) {
  return fetchImpl.mock.calls.find(([u]) => String(u).endsWith("/dispatches")) as unknown as [string, RequestInit] | undefined;
}

describe("/gerrit/<secret>", () => {
  it("dispatches a run to GitHub as the app, with a signed ticket", async () => {
    const fetchImpl = github();
    const d = deps(fetchImpl);
    const res = await handle(post("/gerrit/s3cret", event), env, d);
    expect(res.status).toBe(202);
    expect(await res.text()).toMatch(/^accepted change 7,1/);
    await d.settled();
    expect(d.logs).toEqual(["dispatched go-valkyrie/vali-scheme change 7,1 (patchset-created)"]);
    const call = dispatchCall(fetchImpl);
    expect(call).toBeDefined();
    const [url, init] = call!;
    expect(url).toBe("https://api.github.com/repos/go-valkyrie/vali-scheme/dispatches");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer ghs_installation");
    const body = JSON.parse(init.body as string);
    expect(body.event_type).toBe("gerrit-verify");
    expect(body.client_payload.ref).toBe("refs/changes/07/7/1");
    expect(body.client_payload.repo_url).toBe("https://review.gerrithub.io/go-valkyrie/vali-scheme");
    expect(Object.keys(body.client_payload).sort()).toEqual(["change", "patchset", "ref", "repo_url", "revision", "ticket"]);
    const ticket = await openTicket(body.client_payload.ticket, env.TICKET_SECRET, NOW);
    expect(ticket).toMatchObject({
      project: "go-valkyrie/vali-scheme",
      change: 7,
      patchset: 1,
      revision: "0123456789abcdef0123456789abcdef01234567",
      repo: "go-valkyrie/vali-scheme",
    });
  });

  it("hides itself behind the secret path", async () => {
    const fetchImpl = vi.fn();
    expect((await handle(post("/gerrit/wrong", event), env, deps(fetchImpl))).status).toBe(404);
    expect((await handle(post("/gerrit", event), env, deps(fetchImpl))).status).toBe(404);
    expect((await handle(post("/", event), env, deps(fetchImpl))).status).toBe(404);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("refuses a missing secret configuration", async () => {
    const res = await handle(post("/gerrit/", event), { ...env, WEBHOOK_SECRET: "" }, deps(vi.fn()));
    expect(res.status).toBe(404);
  });

  it("only accepts POST", async () => {
    const res = await handle(new Request("https://relay.example/gerrit/s3cret"), env, deps(vi.fn()));
    expect(res.status).toBe(405);
  });

  it("rejects a body that isn't JSON", async () => {
    const res = await handle(post("/gerrit/s3cret", "not json"), env, deps(vi.fn()));
    expect(res.status).toBe(400);
  });

  it("acknowledges ignored events with 200 and no dispatch", async () => {
    const fetchImpl = vi.fn();
    const res = await handle(post("/gerrit/s3cret", { ...event, type: "ref-updated" }), env, deps(fetchImpl));
    expect(res.status).toBe(200);
    expect(await res.text()).toMatch(/^ignored:/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("answers at once, before Gerrit or GitHub reply, so the webhook isn't retried", async () => {
    const fetchImpl = vi.fn(() => new Promise<Response>(() => {}));
    const d = deps(fetchImpl);
    const res = await handle(post("/gerrit/s3cret", event), env, d);
    expect(res.status).toBe(202);
  });

  it("retries GitHub server errors, then gives up and logs it", async () => {
    const fetchImpl = github(502);
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(calls(fetchImpl, "/dispatches")).toBe(3);
    expect(d.sleeps).toEqual([1000, 4000]);
    expect(d.logs.at(-1)).toMatch(/^failed change 7,1 \(patchset-created\): GitHub returned 502/);
  });

  it("doesn't retry a GitHub client error", async () => {
    const fetchImpl = github(401);
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(calls(fetchImpl, "/dispatches")).toBe(1);
    expect(d.sleeps).toEqual([]);
    expect(d.logs).toEqual([expect.stringMatching(/^failed change 7,1 .*GitHub returned 401/)]);
  });

  it("logs when the app can't get a token, after retrying", async () => {
    const gerritOnly = github();
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) =>
      String(url).startsWith("https://review.gerrithub.io/") ? gerritOnly(url, init) : new Response("Not Found", { status: 404 }),
    );
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(calls(fetchImpl, "/installation")).toBe(3);
    expect(d.logs.at(-1)).toMatch(/^failed change 7,1 .*installation on go-valkyrie\/vali-scheme returned 404/);
  });

  it("carries Gerrit's change kind in the ticket and payload, and still dispatches CI", async () => {
    const fetchImpl = github(204, "maintainer", "TRIVIAL_REBASE");
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(d.logs).toEqual(["dispatched go-valkyrie/vali-scheme change 7,1 (patchset-created)"]);
    const payload = JSON.parse(dispatchCall(fetchImpl)![1].body as string).client_payload;
    expect(payload.change_kind).toBe("TRIVIAL_REBASE");
    const ticket = await openTicket(payload.ticket, env.TICKET_SECRET, NOW);
    expect(ticket).toMatchObject({ change: 7, patchset: 1, kind: "TRIVIAL_REBASE" });
  });

  it("leaves the ticket kindless when Gerrit doesn't name one", async () => {
    const fetchImpl = github();
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    const ticket = await openTicket(JSON.parse(dispatchCall(fetchImpl)![1].body as string).client_payload.ticket, env.TICKET_SECRET, NOW);
    expect(ticket).toMatchObject({ change: 7, patchset: 1 });
    expect(ticket!.kind).toBeUndefined();
  });

  it("ignores a forged event that claims a trusted uploader Gerrit doesn't confirm", async () => {
    const fetchImpl = github(204, "outsider");
    const d = deps(fetchImpl);
    const res = await handle(post("/gerrit/s3cret", event), env, d);
    expect(res.status).toBe(202);
    await d.settled();
    expect(d.logs).toEqual([expect.stringMatching(/^ignored change 7,1 .*not confirmed by Gerrit: .*uploaded by outsider/)]);
    expect(dispatchCall(fetchImpl)).toBeUndefined();
  });

  it("asks Gerrit as the bot account before dispatching", async () => {
    const fetchImpl = github();
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    const gerritCall = fetchImpl.mock.calls.find(([u]) => String(u).startsWith("https://review.gerrithub.io/"));
    expect(gerritCall).toBeDefined();
    const init = gerritCall![1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("ci-bot:gerrit-pass")}`);
  });

  it("retries Gerrit, and dispatches nothing if it never answers", async () => {
    const fetchImpl = vi.fn(async () => new Response("unavailable", { status: 503 }));
    const d = deps(fetchImpl);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(d.logs.at(-1)).toMatch(/^failed change 7,1 .*Gerrit returned 503/);
  });
});

/** An in-memory stand-in for the Durable Object namespace: one claim per key. */
function memoryClaimer() {
  const seen = new Set<string>();
  const keys: string[] = [];
  const claim = async (key: string) => {
    keys.push(key);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };
  return { claim, keys };
}

const recheck = (createdOn: number, text = "Patch Set 1:\n\nrecheck") => ({
  type: "comment-added",
  eventCreatedOn: createdOn,
  author: { username: "maintainer" },
  comment: text,
  change: event.change,
  patchSet: event.patchSet,
});

describe("de-duplication", () => {
  it("dispatches once for five deliveries of one event", async () => {
    const fetchImpl = github();
    const { claim } = memoryClaimer();
    const d = deps(fetchImpl, claim);
    for (let i = 0; i < 5; i++) {
      expect((await handle(post("/gerrit/s3cret", event), env, d)).status).toBe(202);
    }
    await d.settled();
    expect(calls(fetchImpl, "/dispatches")).toBe(1);
    expect(d.logs.filter((l) => l === "duplicate delivery of change 7,1 (patchset-created); ignored")).toHaveLength(4);
  });

  it("runs two different rechecks on the same patch set, but not repeats of one", async () => {
    const fetchImpl = github();
    const { claim } = memoryClaimer();
    const d = deps(fetchImpl, claim);
    for (const e of [recheck(1000), recheck(1000), recheck(1000), recheck(2000), recheck(2000)]) {
      await handle(post("/gerrit/s3cret", e), env, d);
    }
    await d.settled();
    expect(calls(fetchImpl, "/dispatches")).toBe(2);
  });

  it("keys differ by type, patch set and comment, and ignore the delivery order", async () => {
    const { claim, keys } = memoryClaimer();
    const d = deps(github(), claim);
    const ps2 = { ...event.patchSet, number: 2, ref: "refs/changes/07/7/2" };
    for (const e of [event, { ...event, patchSet: ps2 }, recheck(1000), recheck(1000, "recheck\n\nplease")]) {
      await handle(post("/gerrit/s3cret", e), env, d);
    }
    await d.settled();
    expect(new Set(keys).size).toBe(4);
  });

  it("claims after the cheap checks, so an ignored event claims nothing", async () => {
    const claim = vi.fn(async () => true);
    const d = deps(github(), claim);
    await handle(post("/gerrit/s3cret", { ...event, type: "ref-updated" }), env, d);
    await d.settled();
    expect(claim).not.toHaveBeenCalled();
  });

  it("claims before asking Gerrit, so a duplicate makes no requests", async () => {
    const fetchImpl = github();
    const d = deps(fetchImpl, async () => false);
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("dispatches anyway, and logs it, when the claim fails", async () => {
    const fetchImpl = github();
    const d = deps(fetchImpl, async () => {
      throw new Error("Durable Object unavailable");
    });
    await handle(post("/gerrit/s3cret", event), env, d);
    await d.settled();
    expect(calls(fetchImpl, "/dispatches")).toBe(1);
    expect(d.logs[0]).toBe("could not claim change 7,1 (patchset-created) (Durable Object unavailable); dispatching anyway");
    expect(d.logs.at(-1)).toMatch(/^dispatched /);
  });
});

describe("EventClaim", () => {
  function fakeState() {
    const data = new Map<string, unknown>();
    let alarm: number | undefined;
    return {
      data,
      alarmAt: () => alarm,
      storage: {
        get: async (k: string) => data.get(k),
        put: async (k: string, v: unknown) => void data.set(k, v),
        setAlarm: async (t: number) => void (alarm = t),
        deleteAll: async () => {
          data.clear();
          alarm = undefined;
        },
      },
    };
  }

  it("grants the first claim and refuses the rest", async () => {
    const claim = new EventClaim(fakeState(), {}, () => 0);
    expect(await claim.claim()).toBe(true);
    expect(await claim.claim()).toBe(false);
    expect(await claim.claim()).toBe(false);
  });

  it("serves claims over fetch", async () => {
    const claim = new EventClaim(fakeState(), {}, () => 0);
    expect(await (await claim.fetch(new Request("https://x/"))).json()).toEqual({ claimed: true });
    expect(await (await claim.fetch(new Request("https://x/"))).json()).toEqual({ claimed: false });
  });

  it("sets an alarm ten minutes out, once, when first claimed", async () => {
    const state = fakeState();
    let now = 5_000;
    const claim = new EventClaim(state, {}, () => now);
    await claim.claim();
    expect(state.alarmAt()).toBe(5_000 + 600_000);
    now = 9_000;
    await claim.claim();
    expect(state.alarmAt()).toBe(5_000 + 600_000);
  });

  it("honours DEDUPE_WINDOW_SECONDS, and ignores a bad value", async () => {
    const a = fakeState();
    await new EventClaim(a, { DEDUPE_WINDOW_SECONDS: "30" }, () => 0).claim();
    expect(a.alarmAt()).toBe(30_000);
    const b = fakeState();
    await new EventClaim(b, { DEDUPE_WINDOW_SECONDS: "soon" }, () => 0).claim();
    expect(b.alarmAt()).toBe(600_000);
  });

  it("deletes everything when the alarm fires, and a later claim starts fresh", async () => {
    const state = fakeState();
    const claim = new EventClaim(state, {}, () => 0);
    await claim.claim();
    await claim.alarm();
    expect(state.data.size).toBe(0);
    expect(await claim.claim()).toBe(true);
  });
});
