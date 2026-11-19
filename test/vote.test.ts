import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { toBase64Url, utf8 } from "../src/encoding";
import { handle, type Env } from "../src/index";
import { GITHUB_ISSUER, resetKeyCache } from "../src/oidc";
import { signTicket, TICKET_LIFETIME, type Ticket } from "../src/ticket";

const NOW = 1_800_000_000;
const REPO = "go-valkyrie/vali-scheme";
const REVISION = "0123456789abcdef0123456789abcdef01234567";

const env: Env = {
  EVENT_CLAIM: undefined as unknown as DurableObjectNamespace,
  WEBHOOK_SECRET: "s3cret",
  TICKET_SECRET: "ticket-key",
  GITHUB_APP_ID: "12345",
  GITHUB_APP_PRIVATE_KEY: "unused here",
  GERRIT_USER: "ci-bot",
  GERRIT_HTTP_PASSWORD: "gerrit-pass",
  PROJECTS: JSON.stringify({ [REPO]: REPO }),
  TRUSTED: "[]",
};

let keys: CryptoKeyPair;
let jwk: JsonWebKey;
let otherKeys: CryptoKeyPair;

beforeAll(async () => {
  const params = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  keys = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  otherKeys = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
});

beforeEach(() => resetKeyCache());

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

async function jwt(claims: object, signer: CryptoKey = keys.privateKey, header: object = { alg: "RS256", kid: "k1" }) {
  const h = toBase64Url(utf8.encode(JSON.stringify(header)));
  const p = toBase64Url(utf8.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signer, utf8.encode(`${h}.${p}`));
  return `${h}.${p}.${toBase64Url(new Uint8Array(sig))}`;
}

const ticketFields: Ticket = { project: REPO, change: 42, patchset: 3, revision: REVISION, repo: REPO, iat: NOW - 600 };

function mockFetch(gerritStatus = 200) {
  return vi.fn(async (url: string | URL | Request, _init?: RequestInit) => {
    const u = String(url);
    if (u === `${GITHUB_ISSUER}/.well-known/jwks`) {
      return Response.json({ keys: [{ ...jwk, kid: "k1", alg: "RS256", use: "sig" }] });
    }
    if (u.startsWith("https://review.gerrithub.io/a/changes/")) return new Response(")]}'\n{}", { status: gerritStatus });
    return new Response("unexpected", { status: 500 });
  });
}

async function vote(opts: { token?: string; ticket?: string; result?: string; fetchImpl?: ReturnType<typeof mockFetch>; env?: Env }) {
  const fetchImpl = opts.fetchImpl ?? mockFetch();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
  const req = new Request("https://relay.example/vote", {
    method: "POST",
    headers,
    body: JSON.stringify({ ticket: opts.ticket ?? (await signTicket(ticketFields, env.TICKET_SECRET)), result: opts.result ?? "success" }),
  });
  const res = await handle(req, opts.env ?? env, { fetch: fetchImpl as unknown as typeof fetch, now: () => NOW, waitUntil: () => {}, sleep: async () => {}, log: () => {}, claim: async () => true });
  return { res, fetchImpl };
}

function gerritCall(fetchImpl: ReturnType<typeof mockFetch>) {
  return fetchImpl.mock.calls.find(([u]) => String(u).startsWith("https://review.gerrithub.io/"));
}

describe("/vote", () => {
  it("votes Verified +1 with the Worker's own Gerrit credentials", async () => {
    const { res, fetchImpl } = await vote({ token: await jwt(goodClaims) });
    expect(res.status).toBe(200);
    const call = gerritCall(fetchImpl);
    expect(call).toBeDefined();
    const [url, init] = call as unknown as [string, RequestInit];
    expect(url).toBe(`https://review.gerrithub.io/a/changes/go-valkyrie%2Fvali-scheme~42/revisions/${REVISION}/review`);
    expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("ci-bot:gerrit-pass")}`);
    const body = JSON.parse(init.body as string);
    expect(body.labels).toEqual({ Verified: 1 });
    expect(body.message).toBe(`Build passed: https://github.com/${REPO}/actions/runs/123456`);
  });

  it("votes -1 on failure and leaves cancelled runs alone", async () => {
    const failed = await vote({ token: await jwt(goodClaims), result: "failure" });
    const [, init] = gerritCall(failed.fetchImpl) as unknown as [string, RequestInit];
    expect(JSON.parse(init.body as string).labels).toEqual({ Verified: -1 });
    const cancelled = await vote({ token: await jwt(goodClaims), result: "cancelled" });
    expect(cancelled.res.status).toBe(200);
    expect(gerritCall(cancelled.fetchImpl)).toBeUndefined();
  });

  it("requires a bearer token", async () => {
    const { res, fetchImpl } = await vote({});
    expect(res.status).toBe(401);
    expect(gerritCall(fetchImpl)).toBeUndefined();
  });

  it("refuses tokens GitHub didn't sign", async () => {
    const { res } = await vote({ token: await jwt(goodClaims, otherKeys.privateKey) });
    expect(res.status).toBe(401);
  });

  it("refuses unknown keys and other algorithms", async () => {
    expect((await vote({ token: await jwt(goodClaims, keys.privateKey, { alg: "RS256", kid: "nope" }) })).res.status).toBe(401);
    expect((await vote({ token: await jwt(goodClaims, keys.privateKey, { alg: "none", kid: "k1" }) })).res.status).toBe(401);
  });

  it.each([
    ["issuer", { iss: "https://evil.example" }],
    ["audience", { aud: "something-else" }],
    ["expiry", { exp: NOW - 120 }],
    ["not-before", { nbf: NOW + 120 }],
  ])("refuses a token with the wrong %s", async (_, override) => {
    const { res, fetchImpl } = await vote({ token: await jwt({ ...goodClaims, ...override }) });
    expect(res.status).toBe(401);
    expect(gerritCall(fetchImpl)).toBeUndefined();
  });

  it.each([
    ["another repository", { repository: "someone/fork" }],
    ["another event", { event_name: "pull_request" }],
    ["another branch", { ref: "refs/heads/evil", workflow_ref: `${REPO}/.github/workflows/gerrit-verify.yml@refs/heads/evil` }],
    ["another workflow", { workflow_ref: `${REPO}/.github/workflows/other.yml@refs/heads/main` }],
  ])("refuses a token from %s", async (_, override) => {
    const { res, fetchImpl } = await vote({ token: await jwt({ ...goodClaims, ...override }) });
    expect(res.status).toBe(403);
    expect(gerritCall(fetchImpl)).toBeUndefined();
  });

  it("refuses forged, tampered and expired tickets", async () => {
    const token = await jwt(goodClaims);
    const forged = await signTicket(ticketFields, "wrong-key");
    expect((await vote({ token, ticket: forged })).res.status).toBe(403);
    const good = await signTicket(ticketFields, env.TICKET_SECRET);
    const [, sig] = good.split(".");
    const tampered = `${toBase64Url(utf8.encode(JSON.stringify({ ...ticketFields, change: 1 })))}.${sig}`;
    expect((await vote({ token, ticket: tampered })).res.status).toBe(403);
    const expired = await signTicket({ ...ticketFields, iat: NOW - TICKET_LIFETIME - 10 }, env.TICKET_SECRET);
    expect((await vote({ token, ticket: expired })).res.status).toBe(403);
  });

  it("returns 502 when Gerrit refuses the vote", async () => {
    const { res } = await vote({ token: await jwt(goodClaims), fetchImpl: mockFetch(403) });
    expect(res.status).toBe(502);
  });

  it("rejects unknown results", async () => {
    const { res } = await vote({ token: await jwt(goodClaims), result: "maybe" });
    expect(res.status).toBe(400);
  });
});
