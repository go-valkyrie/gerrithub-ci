import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { toBase64Url, utf8 } from "../src/encoding";
import { handle, type Env } from "../src/index";
import { GITHUB_ISSUER, resetKeyCache } from "../src/oidc";
import { MuseTokens, sha256Hex, signMuseToken, tokensFor, verifyMuseToken, type MuseTokensClient, type TokenStorage } from "../src/muse";
import { signTicket, type Ticket } from "../src/ticket";

const NOW = 1_800_000_000;
const REPO = "go-valkyrie/vali-scheme";
const REVISION = "0123456789abcdef0123456789abcdef01234567";
const LLM_KEY = "llm-secret-key";
const HOOK_SECRET = "hook-secret";

const env: Env = {
  EVENT_CLAIM: undefined as unknown as DurableObjectNamespace,
  MUSE_TOKENS: undefined as unknown as DurableObjectNamespace,
  WEBHOOK_SECRET: "s3cret",
  TICKET_SECRET: "ticket-key",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_PRIVATE_KEY: "unused here",
  GERRIT_USER: "ci-bot",
  GERRIT_HTTP_PASSWORD: "gerrit-pass",
  PROJECTS: JSON.stringify({ [REPO]: REPO }),
  TRUSTED: "[]",
  LLM_API_KEY: LLM_KEY,
  GITHUB_WEBHOOK_SECRET: HOOK_SECRET,
};

let keys: CryptoKeyPair;
let jwk: JsonWebKey;

beforeAll(async () => {
  const params = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  keys = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
});

/**
 * A stand-in for the Durable Object namespace: one MuseTokens instance per
 * run, shared by every client made from it — like isolates sharing the real
 * objects. A fresh namespace per test keeps tests isolated from each other.
 * The real client and fetch router run on top, so the whole stack is exercised.
 */
function memoryNamespace() {
  const objects = new Map<string, MuseTokens>();
  const at = (name: string) => {
    let o = objects.get(name);
    if (!o) {
      const data = new Map<string, unknown>();
      const storage: TokenStorage = {
        get: async (key: string) => data.get(key),
        put: async (key: string, value: unknown, opts?: { expirationTtl?: number }) => {
          data.set(key, value);
          void opts;
        },
        delete: async (key: string) => data.delete(key),
        list: async ({ prefix }: { prefix: string }) => new Map([...data].filter(([k]) => k.startsWith(prefix))),
      };
      o = new MuseTokens({ storage });
      objects.set(name, o);
    }
    return o;
  };
  const namespace = {
    idFromName: (name: string) => name,
    get: (id: string) => ({ fetch: (input: RequestInfo | URL, init?: RequestInit) => at(id).fetch(new Request(input, init)) }),
  } as unknown as DurableObjectNamespace;
  return { client: tokensFor(namespace) };
}

let tokens: MuseTokensClient;

beforeEach(() => {
  resetKeyCache();
  tokens = memoryNamespace().client;
});

const goodClaims = {
  iss: GITHUB_ISSUER,
  aud: "gerrithub-ci",
  exp: NOW + 300,
  nbf: NOW - 5,
  iat: NOW - 5,
  repository: REPO,
  ref: "refs/heads/main",
  workflow_ref: `${REPO}/.github/workflows/gerrit-verify.yml@refs/heads/main`,
  event_name: "repository_dispatch",
  run_id: "123456",
};

async function oidc(claims: object = goodClaims, signer: CryptoKey = keys.privateKey): Promise<string> {
  const h = toBase64Url(utf8.encode(JSON.stringify({ alg: "RS256", kid: "k1" })));
  const p = toBase64Url(utf8.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signer, utf8.encode(`${h}.${p}`));
  return `${h}.${p}.${toBase64Url(new Uint8Array(sig))}`;
}

const ticketFields: Ticket = { project: REPO, change: 42, patchset: 3, revision: REVISION, repo: REPO, iat: NOW - 600 };

/** fetch that serves GitHub's JWKS, Gerrit's setReview, and the LLM backend; records calls. */
function mockFetch(llmBody = "data: hello\n\ndata: world\n\n") {
  const gerritCalls: { url: string; init: RequestInit }[] = [];
  const llmCalls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    if (u === `${GITHUB_ISSUER}/.well-known/jwks`) {
      return Response.json({ keys: [{ ...jwk, kid: "k1", alg: "RS256", use: "sig" }] });
    }
    if (u.startsWith("https://review.gerrithub.io/a/changes/")) {
      gerritCalls.push({ url: u, init: init ?? {} });
      return Response.json({ ok: true });
    }
    if (u.startsWith("https://api.meta.ai/v1/") || u.startsWith("https://llm.example/v1/")) {
      llmCalls.push({ url: u, init: init ?? {} });
      return new Response(llmBody, { headers: { "Content-Type": "text/event-stream" } });
    }
    return new Response("unexpected", { status: 500 });
  });
  return { fetchImpl, gerritCalls, llmCalls };
}

function deps(fetchImpl: unknown, museTokens?: MuseTokensClient) {
  const logs: string[] = [];
  return {
    fetch: fetchImpl as typeof fetch,
    now: () => NOW,
    waitUntil: () => {},
    sleep: async () => {},
    log: (line: string) => void logs.push(line),
    claim: async () => true,
    museTokens: museTokens ?? tokens,
    logs,
  };
}

async function mintTicket(): Promise<string> {
  return signTicket(ticketFields, env.TICKET_SECRET);
}

interface Minted {
  token: string;
  expires_in: number;
  expires_at: string;
}

async function mint(token: string, ticket: string, e: Env = env): Promise<{ status: number; body: Minted }> {
  const { fetchImpl } = mockFetch();
  const req = new Request("https://relay.example/muse-token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ticket }),
  });
  const res = await handle(req, e, deps(fetchImpl));
  if (res.status !== 200) return { status: res.status, body: undefined as unknown as Minted };
  return { status: res.status, body: (await res.json()) as Minted };
}

async function hookSecret(raw: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8.encode(HOOK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8.encode(raw)));
  return `sha256=${Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function postWebhook(
  payload: unknown,
  e: Env = env,
  sign: boolean | "bad" = true,
): Promise<{ res: Response; logs: string[] }> {
  const raw = typeof payload === "string" ? payload : JSON.stringify(payload);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (sign !== false) {
    headers["X-Hub-Signature-256"] = sign === "bad" ? "sha256=00" : await hookSecret(raw);
  }
  const d = deps(vi.fn());
  const res = await handle(new Request("https://relay.example/github-webhook", { method: "POST", headers, body: raw }), e, d);
  return { res, logs: d.logs };
}

describe("POST /muse-token", () => {
  it("exchanges a GitHub OIDC token for an ephemeral token scoped to the ticket", async () => {
    const ticket = await mintTicket();
    const { status, body } = await mint(await oidc(), ticket);
    expect(status).toBe(200);
    expect(body.expires_in).toBe(1800);
    const claims = await verifyMuseToken(body.token, env.TICKET_SECRET, NOW);
    expect(claims).toMatchObject({ typ: "muse-ephemeral", repo: REPO, change: 42, patchset: 3, revision: REVISION, run_id: "123456" });
    expect(claims.ticket).toBe(await sha256Hex(ticket));
    expect(claims.exp - claims.iat).toBe(1800);
  });

  it("honours MUSE_TOKEN_TTL_SECONDS and clamps it to an hour", async () => {
    const ticket = await mintTicket();
    const short = await mint(await oidc(), ticket, { ...env, MUSE_TOKEN_TTL_SECONDS: "60" });
    expect(short.body.expires_in).toBe(60);
    const huge = await mint(await oidc(), ticket, { ...env, MUSE_TOKEN_TTL_SECONDS: "99999" });
    expect(huge.body.expires_in).toBe(3600);
  });

  it("signs with MUSE_TOKEN_SECRET when set", async () => {
    const ticket = await mintTicket();
    const e = { ...env, MUSE_TOKEN_SECRET: "muse-only" };
    const { status, body } = await mint(await oidc(), ticket, e);
    expect(status).toBe(200);
    await expect(verifyMuseToken(body.token, "muse-only", NOW)).resolves.toMatchObject({ repo: REPO });
    await expect(verifyMuseToken(body.token, env.TICKET_SECRET, NOW)).rejects.toThrow(/bad signature/);
  });

  it("refuses a missing bearer token, a foreign token and a bad ticket", async () => {
    const ticket = await mintTicket();
    const anon = new Request("https://relay.example/muse-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ticket }),
    });
    expect((await handle(anon, env, deps(vi.fn()))).status).toBe(401);

    const otherKeys = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    expect((await mint(await oidc(goodClaims, otherKeys.privateKey), ticket)).status).toBe(401);

    const forged = await signTicket(ticketFields, "wrong-key");
    expect((await mint(await oidc(), forged)).status).toBe(403);
  });

  it("binds the token to the ticket's repository, not the caller's", async () => {
    const ticket = await mintTicket();
    const forkClaims = { ...goodClaims, repository: "someone/fork", workflow_ref: `someone/fork/.github/workflows/gerrit-verify.yml@refs/heads/main` };
    expect((await mint(await oidc(forkClaims), ticket)).status).toBe(403);
  });

  it("refuses to mint for a trivial rebase or unchanged patch set, but mints for the rest", async () => {
    const trivial = await signTicket({ ...ticketFields, kind: "TRIVIAL_REBASE" }, env.TICKET_SECRET);
    const unchanged = await signTicket({ ...ticketFields, kind: "NO_CHANGE" }, env.TICKET_SECRET);
    expect((await mint(await oidc(), trivial)).status).toBe(409);
    expect((await mint(await oidc(), unchanged)).status).toBe(409);
    const rework = await signTicket({ ...ticketFields, kind: "REWORK" }, env.TICKET_SECRET);
    expect((await mint(await oidc(), rework)).status).toBe(200);
    // Old tickets predate the kind field entirely, and stay reviewable.
    expect((await mint(await oidc(), await mintTicket())).status).toBe(200);
  });

  it("still posts reviews for trivial patch sets: only minting is gated", async () => {
    const trivial = await signTicket({ ...ticketFields, kind: "TRIVIAL_REBASE" }, env.TICKET_SECRET);
    const { fetchImpl, gerritCalls } = mockFetch();
    const req = new Request("https://relay.example/review", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${await oidc()}` },
      body: JSON.stringify({ ticket: trivial, review: "Rebase looks clean." }),
    });
    const res = await handle(req, env, deps(fetchImpl));
    expect(res.status).toBe(200);
    expect(gerritCalls).toHaveLength(1);
  });

  it("only accepts POST", async () => {
    expect((await handle(new Request("https://relay.example/muse-token"), env, deps(vi.fn()))).status).toBe(405);
  });
});

describe("ephemeral tokens", () => {
  const scope = { repo: REPO, change: 42, patchset: 3, revision: REVISION, ticket: "ticket-text", run_id: "123456" };

  it("rejects expired tokens: the TTL is a backstop", async () => {
    const token = await signMuseToken(scope, env.TICKET_SECRET, NOW - 4000, 60);
    await expect(verifyMuseToken(token, env.TICKET_SECRET, NOW)).rejects.toThrow(/expired/);
  });

  it("rejects tokens signed with another secret", async () => {
    const token = await signMuseToken(scope, "another-secret", NOW);
    await expect(verifyMuseToken(token, env.TICKET_SECRET, NOW)).rejects.toThrow(/bad signature/);
  });

  it("rejects GitHub OIDC tokens: only ephemeral tokens pass", async () => {
    await expect(verifyMuseToken(await oidc(), env.TICKET_SECRET, NOW)).rejects.toThrow();
  });
});

describe("MuseTokens", () => {
  function recording() {
    const data = new Map<string, unknown>();
    const puts: { key: string; value: unknown; opts?: { expirationTtl?: number } }[] = [];
    const storage: TokenStorage = {
      get: async (key: string) => data.get(key),
      put: async (key: string, value: unknown, opts?: { expirationTtl?: number }) => {
        data.set(key, value);
        puts.push({ key, value, opts });
      },
      delete: async (key: string) => data.delete(key),
      list: async ({ prefix }: { prefix: string }) => new Map([...data].filter(([k]) => k.startsWith(prefix))),
    };
    return { data, state: new MuseTokens({ storage }), puts };
  }

  it("is forward-only per job, without revoking", async () => {
    const { state } = recording();
    expect(await state.isRevoked()).toBe(false);
    expect(await state.noteJob("7", "queued", 1800)).toBe("advanced");
    expect(await state.isRevoked()).toBe(false);
    expect(await state.noteJob("7", "queued", 1800)).toBe("stale");
    // A completed job moves its marker but revokes nothing: the run may still
    // be going, and the review runs after the verify job.
    expect(await state.noteJob("7", "completed", 1800)).toBe("advanced");
    expect(await state.isRevoked()).toBe(false);
    // A redelivery, or an older state arriving late, changes nothing.
    expect(await state.noteJob("7", "completed", 1800)).toBe("stale");
    expect(await state.noteJob("7", "in_progress", 1800)).toBe("stale");
  });

  it("tracks jobs independently and ignores unknown actions", async () => {
    const { state } = recording();
    expect(await state.noteJob("8", "completed", 1800)).toBe("advanced");
    expect(await state.isRevoked()).toBe(false);
    expect(await state.noteJob("9", "requested", 1800)).toBe("unknown");
  });

  it("expires every entry with the given TTL", async () => {
    const { state, puts } = recording();
    await state.noteJob("7", "in_progress", 60);
    await state.completeRun(60);
    expect(puts).toContainEqual({ key: "job:7", value: 1, opts: { expirationTtl: 60 } });
    expect(puts).toContainEqual({ key: "revoked", value: true, opts: { expirationTtl: 60 } });
    expect(puts).toContainEqual({ key: "done", value: true, opts: { expirationTtl: 60 } });
  });

  it("completing the run revokes its tokens and deletes its job markers, once", async () => {
    const { data, state } = recording();
    expect(await state.completeRun(1800)).toBe("advanced");
    expect(await state.isRevoked()).toBe(true);
    expect(await state.completeRun(1800)).toBe("stale");
    // A new delivery for the same job starts fresh: its markers are gone.
    expect(await state.noteJob("7", "queued", 1800)).toBe("advanced");
    expect(data.has("job:7")).toBe(true);
  });

  it("serves notes, completions and revocation over fetch", async () => {
    const { state } = recording();
    const post = (path: string, body: unknown) =>
      state.fetch(
        new Request(`https://tokens.invalid${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    expect(await (await post("/note", { jobId: "7", action: "queued", ttl: 1800 })).json()).toEqual({ progress: "advanced" });
    expect(await (await post("/complete", { ttl: 1800 })).json()).toEqual({ progress: "advanced" });
    expect(await (await post("/complete", { ttl: 1800 })).json()).toEqual({ progress: "stale" });
    expect(await (await state.fetch(new Request("https://tokens.invalid/revoked"))).json()).toEqual({ revoked: true });
    expect((await post("/note", { jobId: "7" })).status).toBe(400);
    expect((await post("/complete", { ttl: "soon" })).status).toBe(400);
    expect((await state.fetch(new Request("https://tokens.invalid/elsewhere"))).status).toBe(404);
  });

  it("shares one run's state between clients, like isolates sharing the object", async () => {
    const ns = memoryNamespace();
    const webhookClient = ns.client;
    const proxyClient = ns.client;
    expect(await proxyClient.isRevoked("123456")).toBe(false);
    expect(await webhookClient.completeRun("123456", 1800)).toBe("advanced");
    // The proxy's isolate never saw the webhook: it still sees the revocation.
    expect(await proxyClient.isRevoked("123456")).toBe(true);
    expect(await proxyClient.isRevoked("other-run")).toBe(false);
  });
});

describe("/v1/* proxy", () => {
  async function proxied(auth: string | undefined, e: Env = env, llmBody?: string) {
    const { fetchImpl, llmCalls } = mockFetch(llmBody);
    const d = deps(fetchImpl);
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (auth !== undefined) headers.Authorization = `Bearer ${auth}`;
    const req = new Request("https://relay.example/v1/chat/completions?model=x", {
      method: "POST",
      headers,
      body: JSON.stringify({ stream: true }),
    });
    const res = await handle(req, e, d);
    return { res, llmCalls, logs: d.logs };
  }

  it("swaps in the LLM key, keeps path and query, and streams SSE through", async () => {
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    const { res, llmCalls, logs } = await proxied(body.token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    expect(await res.text()).toBe("data: hello\n\ndata: world\n\n");
    expect(llmCalls).toHaveLength(1);
    expect(llmCalls[0].url).toBe("https://api.meta.ai/v1/chat/completions?model=x");
    const sent = (llmCalls[0].init.headers ?? {}) as Headers;
    const auth = sent instanceof Headers ? sent.get("Authorization") : (sent as Record<string, string>).Authorization;
    expect(auth).toBe(`Bearer ${LLM_KEY}`);
    // Nothing sensitive reaches the logs: no key, no token, no body.
    expect(logs.join("\n")).not.toContain(LLM_KEY);
    expect(logs.join("\n")).not.toContain(body.token);
  });

  it("uses LLM_BASE_URL when set", async () => {
    const { fetchImpl, llmCalls } = mockFetch();
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    await handle(
      new Request("https://relay.example/v1/models", { headers: { Authorization: `Bearer ${body.token}` } }),
      { ...env, LLM_BASE_URL: "https://llm.example/v1" },
      deps(fetchImpl),
    );
    expect(llmCalls[0].url).toBe("https://llm.example/v1/models");
  });

  it("rejects a GitHub OIDC token, a missing token and a forged token", async () => {
    expect((await proxied(await oidc())).res.status).toBe(401);
    expect((await proxied(undefined)).res.status).toBe(401);
    expect((await proxied("bogus.token.here")).res.status).toBe(401);
  });

  it("rejects expired ephemeral tokens", async () => {
    const old = await signMuseToken(
      { repo: REPO, change: 42, patchset: 3, revision: REVISION, ticket: "t", run_id: "1" },
      env.TICKET_SECRET,
      NOW - 4000,
      60,
    );
    expect((await proxied(old)).res.status).toBe(401);
  });

  it("answers 501 when no LLM key is configured", async () => {
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    const { res, llmCalls } = await proxied(body.token, { ...env, LLM_API_KEY: undefined });
    expect(res.status).toBe(501);
    expect(llmCalls).toHaveLength(0);
  });

  it("answers 502 when the backend is unreachable, and passes its errors through", async () => {
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    const failing = deps(vi.fn(async () => {
      throw new Error("connection reset");
    }));
    const down = await handle(
      new Request("https://relay.example/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${body.token}` } }),
      env,
      failing,
    );
    expect(down.status).toBe(502);

    const gateway = deps(vi.fn(async () => new Response("bad request", { status: 400 })));
    const passthrough = await handle(
      new Request("https://relay.example/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${body.token}` } }),
      env,
      gateway,
    );
    expect(passthrough.status).toBe(400);
    expect(await passthrough.text()).toBe("bad request");
  });
});

describe("POST /github-webhook", () => {
  const job = (action: string, id = 7, run_id = 123456) => ({ action, workflow_job: { id, run_id, status: action } });
  const run = (action: string, id = 123456) => ({ action, workflow_run: { id, status: action } });

  it("tracks jobs without revoking: a completed job is not the completed run", async () => {
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    const { fetchImpl } = mockFetch();
    const d = deps(fetchImpl);
    const proxy = (token: string) =>
      handle(new Request("https://relay.example/v1/x", { headers: { Authorization: `Bearer ${token}` } }), env, d);

    // The verify job completes while the review is still running: the proxy
    // must keep working until the whole run completes.
    expect(((await postWebhook(job("completed", 1))).res.status)).toBe(200);
    expect((await proxy(body.token)).status).toBe(200);
  });

  it("revokes the run's tokens and deletes its state when the run completes", async () => {
    const ticket = await mintTicket();
    const { body } = await mint(await oidc(), ticket);
    const { fetchImpl } = mockFetch();
    const d = deps(fetchImpl);
    const proxy = (token: string) =>
      handle(new Request("https://relay.example/v1/x", { headers: { Authorization: `Bearer ${token}` } }), env, d);

    expect((await proxy(body.token)).status).toBe(200);
    expect(((await postWebhook(job("queued"))).res.status)).toBe(200);
    expect((await proxy(body.token)).status).toBe(200);
    const done = await postWebhook(run("completed"));
    expect(done.res.status).toBe(200);
    expect(done.logs.join("\n")).toContain("123456");
    expect((await proxy(body.token)).status).toBe(401);
    // A redelivered completion revokes nothing new and stays quiet.
    const again = await postWebhook(run("completed"));
    expect(await again.res.text()).toMatch(/stale/);
    expect(again.logs).toHaveLength(0);
  });

  it("stores entries with the configured token lifetime", async () => {
    const completed: { runId: string; ttl: number }[] = [];
    const client: MuseTokensClient = {
      noteJob: async () => "advanced",
      isRevoked: async () => false,
      completeRun: async (runId, ttl) => {
        completed.push({ runId, ttl });
        return "advanced";
      },
    };
    const raw = JSON.stringify(run("completed"));
    const headers = { "Content-Type": "application/json", "X-Hub-Signature-256": await hookSecret(raw) };
    const res = await handle(
      new Request("https://relay.example/github-webhook", { method: "POST", headers, body: raw }),
      { ...env, MUSE_TOKEN_TTL_SECONDS: "60" },
      deps(vi.fn(), client),
    );
    expect(res.status).toBe(200);
    expect(completed).toEqual([{ runId: "123456", ttl: 60 }]);
  });

  it("is forward-only: repeats and stale deliveries change nothing", async () => {
    expect(await (await postWebhook(job("queued"))).res.text()).toMatch(/advanced/);
    expect(await (await postWebhook(job("queued"))).res.text()).toMatch(/stale/);
    expect(await (await postWebhook(job("in_progress"))).res.text()).toMatch(/advanced/);
    expect(await (await postWebhook(job("completed"))).res.text()).toMatch(/advanced/);
    // A redelivered completion, or an older state arriving late, changes nothing.
    expect(await (await postWebhook(job("completed"))).res.text()).toMatch(/stale/);
    expect(await (await postWebhook(job("in_progress"))).res.text()).toMatch(/stale/);
  });

  it("ignores unknown actions, unfinished runs and pings", async () => {
    expect((await postWebhook(job("requested"))).res.status).toBe(200);
    expect(await (await postWebhook(job("requested"))).res.text()).toMatch(/unknown/);
    expect(await (await postWebhook(run("in_progress"))).res.text()).toMatch(/ignored/);
    const ping = await postWebhook({ zen: "hello", hook: { id: 1 } });
    expect(ping.res.status).toBe(200);
    expect(await ping.res.text()).toBe("pong\n");
    expect(ping.logs).toHaveLength(0);
  });

  it("verifies the HMAC signature", async () => {
    const payload = run("completed");
    expect((await postWebhook(payload, env, false)).res.status).toBe(401);
    expect((await postWebhook(payload, env, "bad")).res.status).toBe(401);
    expect((await postWebhook("not json{{{", env, "bad")).res.status).toBe(401);
    expect((await postWebhook("not json{{{", env)).res.status).toBe(400);
  });

  it("hides itself when no webhook secret is configured", async () => {
    const { res } = await postWebhook(run("completed"), { ...env, GITHUB_WEBHOOK_SECRET: undefined });
    expect(res.status).toBe(404);
  });

  it("only accepts POST", async () => {
    expect((await handle(new Request("https://relay.example/github-webhook"), env, deps(vi.fn()))).status).toBe(405);
  });
});

describe("POST /review", () => {
  async function review(opts: { token: string; ticket?: string; review?: unknown; codeReview?: unknown; env?: Env }) {
    const { fetchImpl, gerritCalls } = mockFetch();
    const d = deps(fetchImpl);
    const req = new Request("https://relay.example/review", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${opts.token}` },
      body: JSON.stringify({
        ticket: opts.ticket ?? (await mintTicket()),
        review: "review" in opts ? opts.review : "Looks good.",
        codeReview: opts.codeReview,
      }),
    });
    const res = await handle(req, opts.env ?? env, d);
    return { res, gerritCalls, logs: d.logs };
  }

  it("posts review markdown with no label unless asked", async () => {
    const { res, gerritCalls } = await review({ token: await oidc() });
    expect(res.status).toBe(200);
    expect(gerritCalls).toHaveLength(1);
    expect(gerritCalls[0].url).toBe(`https://review.gerrithub.io/a/changes/go-valkyrie%2Fvali-scheme~42/revisions/${REVISION}/review`);
    const sent = JSON.parse(gerritCalls[0].init.body as string);
    expect(sent.message).toBe("Looks good.");
    expect(sent.labels).toEqual({});
    expect(sent.tag).toBe("autogenerated:gerrithub-ci");
  });

  it("votes Code-Review +1 only when requested", async () => {
    const plus = await review({ token: await oidc(), codeReview: true });
    expect(JSON.parse(plus.gerritCalls[0].init.body as string).labels).toEqual({ "Code-Review": 1 });
    expect(await plus.res.text()).toMatch(/Code-Review \+1/);
  });

  it("never logs the review markdown", async () => {
    const secret = "this markdown must stay out of the logs";
    const { logs } = await review({ token: await oidc(), review: secret });
    expect(logs.join("\n")).not.toContain(secret);
  });

  it("rejects a missing, blank or oversized review", async () => {
    expect((await review({ token: await oidc(), review: undefined })).res.status).toBe(400);
    expect((await review({ token: await oidc(), review: "   " })).res.status).toBe(400);
    expect((await review({ token: await oidc(), review: "x".repeat(64 * 1024 + 1) })).res.status).toBe(400);
  });

  it("checks the token and ticket like /vote", async () => {
    const forged = await signTicket(ticketFields, "wrong-key");
    expect((await review({ token: await oidc(), ticket: forged })).res.status).toBe(403);
    const fork = { ...goodClaims, repository: "someone/fork", workflow_ref: `someone/fork/.github/workflows/gerrit-verify.yml@refs/heads/main` };
    expect((await review({ token: await oidc(fork) })).res.status).toBe(403);
    const anon = await handle(
      new Request("https://relay.example/review", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }),
      env,
      deps(vi.fn()),
    );
    expect(anon.status).toBe(401);
  });

  it("only accepts POST", async () => {
    expect((await handle(new Request("https://relay.example/review"), env, deps(vi.fn()))).status).toBe(405);
  });
});
