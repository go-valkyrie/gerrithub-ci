// Muse-review support: short-lived tokens that let a GitHub Actions job call
// an LLM through this Worker, without ever seeing the Worker's own LLM key.
//
// Flow:
//   1. POST /muse-token: the review job presents its GitHub OIDC token plus
//      the run's ticket. The Worker checks the OIDC token (issuer, audience,
//      expiry), checks the ticket, and checks the token may vote for the
//      ticket's repository. It answers with an ephemeral JWT scoped to that
//      repo, ticket, change and patch set, valid for ~30 minutes.
//   2. /v1/*: a transparent proxy to the LLM's API. It accepts only the
//      ephemeral token, swaps in the real LLM key, and streams the request
//      and response bodies through untouched (SSE included).
//   3. POST /github-webhook: GitHub's workflow_job events, HMAC-signed.
//      The Worker tracks each job forward-only (queued -> in_progress ->
//      completed) and revokes the run's tokens when its job completes.
//      The token's own expiry stays enforced as a backstop.
//
// Nothing here logs keys, tokens, prompts, reviews or diffs: the proxy
// never reads a body into memory, and handlers log only ids and statuses.

import { fromBase64Url, fromUtf8, sameBytes, toBase64Url, utf8 } from "./encoding";

/** How long an ephemeral token lasts, in seconds; the revocation list is only an addition. */
export const MUSE_TOKEN_TTL_SECONDS = 1800;

/** Clock skew allowed on ephemeral `exp` and `iat`, in seconds. */
const SKEW = 60;

/** The LLM API this Worker proxies to; override with LLM_BASE_URL. */
export const DEFAULT_LLM_BASE_URL = "https://api.meta.ai/v1";

/** What an ephemeral token is scoped to. */
export interface MuseTokenClaims {
  typ: "muse-ephemeral";
  /** GitHub "owner/repo" the run belongs to. */
  repo: string;
  change: number;
  patchset: number;
  revision: string;
  /** SHA-256 hex of the ticket string the token was minted for. */
  ticket: string;
  /** GitHub Actions run that may use it. */
  run_id: string;
  /** Unique per token. */
  jti: string;
  /** Issued at, and expires at, in seconds since the epoch. */
  iat: number;
  exp: number;
}

export class MuseTokenError extends Error {}

/** SHA-256 hex of `text`. Binds a token to the exact ticket it was minted for. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", utf8.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function randomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export interface MuseTokenScope {
  repo: string;
  change: number;
  patchset: number;
  revision: string;
  /** The ticket string, hashed into the token so it can't move to another ticket. */
  ticket: string;
  run_id: string;
}

/** Mints an ephemeral token for `scope`, signed with `secret`. */
export async function signMuseToken(scope: MuseTokenScope, secret: string, now: number, ttl = MUSE_TOKEN_TTL_SECONDS): Promise<string> {
  const header = toBase64Url(utf8.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = toBase64Url(
    utf8.encode(
      JSON.stringify({
        typ: "muse-ephemeral",
        repo: scope.repo,
        change: scope.change,
        patchset: scope.patchset,
        revision: scope.revision,
        ticket: await sha256Hex(scope.ticket),
        run_id: scope.run_id,
        jti: randomId(),
        iat: now,
        exp: now + ttl,
      } satisfies MuseTokenClaims),
    ),
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), utf8.encode(`${header}.${payload}`)));
  return `${header}.${payload}.${toBase64Url(mac)}`;
}

/** The claims of `token`, if `secret` signed it, its shape is right, and it hasn't expired. */
export async function verifyMuseToken(token: string, secret: string, now: number): Promise<MuseTokenClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new MuseTokenError("not a token");
  const [headerText, payloadText, signatureText] = parts;
  let header: { alg?: string };
  let claims: MuseTokenClaims;
  let signature: Uint8Array;
  try {
    header = JSON.parse(fromUtf8.decode(fromBase64Url(headerText)));
    claims = JSON.parse(fromUtf8.decode(fromBase64Url(payloadText)));
    signature = fromBase64Url(signatureText);
  } catch {
    throw new MuseTokenError("malformed token");
  }
  if (header.alg !== "HS256") throw new MuseTokenError("unexpected token algorithm");
  const key = await hmacKey(secret);
  if (!(await crypto.subtle.verify("HMAC", key, signature, utf8.encode(`${headerText}.${payloadText}`)))) {
    throw new MuseTokenError("bad signature");
  }
  if (claims.typ !== "muse-ephemeral") throw new MuseTokenError("not a review token");
  if (
    typeof claims.repo !== "string" ||
    typeof claims.change !== "number" ||
    typeof claims.patchset !== "number" ||
    typeof claims.revision !== "string" ||
    typeof claims.ticket !== "string" ||
    typeof claims.run_id !== "string" ||
    typeof claims.jti !== "string"
  ) {
    throw new MuseTokenError("malformed token claims");
  }
  if (typeof claims.exp !== "number" || now > claims.exp + SKEW) throw new MuseTokenError("expired");
  if (typeof claims.iat === "number" && now < claims.iat - SKEW) throw new MuseTokenError("issued in the future");
  return claims;
}

// --- per-run token state ----------------------------------------------------------
// A module-level Map would be per-isolate: a revocation written on one
// isolate is invisible to the rest. So each run's state lives in a Durable
// Object named after the run: every delivery of its jobs' events reaches the
// same instance, and revoking is one storage write next to the job's marker.
// Entries expire with the token lifetime; the token's own expiry is the
// backstop when the completion event never arrives.

/** The parts of DurableObjectStorage that per-run token state uses. */
export interface TokenStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
}

/** Progress of one workflow_job delivery. */
export type JobProgress = "advanced" | "stale" | "unknown";

const JOB_ORDER: Record<string, number> = { queued: 0, in_progress: 1, completed: 2 };

/**
 * One run's review-token state. Forward-only per job: an event at or behind
 * the latest seen state is a duplicate or a stale redelivery and changes
 * nothing. A genuine completion revokes the run's tokens in the same write.
 *
 * A plain class with a `fetch` method rather than an RPC `DurableObject`
 * subclass, so tests can build it without the Workers runtime.
 */
export class MuseTokens {
  constructor(private readonly state: { storage: TokenStorage }) {}

  /** Records a delivery of one of the run's jobs. */
  async noteJob(jobId: string, action: string, ttlSeconds: number): Promise<JobProgress> {
    const rank = JOB_ORDER[action];
    if (rank === undefined) return "unknown";
    const key = `job:${jobId}`;
    const prev = await this.state.storage.get(key);
    if (typeof prev === "number" && rank <= prev) return "stale";
    await this.state.storage.put(key, rank, { expirationTtl: ttlSeconds });
    if (action === "completed") {
      await this.state.storage.put("revoked", true, { expirationTtl: ttlSeconds });
    }
    return "advanced";
  }

  /** Whether a completed job revoked the run's tokens. */
  async isRevoked(): Promise<boolean> {
    return (await this.state.storage.get("revoked")) !== undefined;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/note") {
      let note: { jobId?: unknown; action?: unknown; ttl?: unknown };
      try {
        note = (await request.json()) as typeof note;
      } catch {
        return Response.json({ error: "body is not JSON" }, { status: 400 });
      }
      if (typeof note.jobId !== "string" || typeof note.action !== "string" || typeof note.ttl !== "number") {
        return Response.json({ error: "bad note" }, { status: 400 });
      }
      return Response.json({ progress: await this.noteJob(note.jobId, note.action, note.ttl) });
    }
    if (request.method === "GET" && url.pathname === "/revoked") {
      return Response.json({ revoked: await this.isRevoked() });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }
}

/** Per-run token state, addressed by run. */
export interface MuseTokensClient {
  noteJob(runId: string, jobId: string, action: string, ttlSeconds: number): Promise<JobProgress>;
  isRevoked(runId: string): Promise<boolean>;
}

/** A client that reaches the Durable Object named after the run. */
export function tokensFor(namespace: DurableObjectNamespace): MuseTokensClient {
  const stub = (runId: string) => namespace.get(namespace.idFromName(`muse-run:${runId}`));
  return {
    noteJob: async (runId, jobId, action, ttlSeconds) => {
      const res = await stub(runId).fetch("https://tokens.invalid/note", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jobId, action, ttl: ttlSeconds }),
      });
      if (!res.ok) throw new Error(`token store returned ${res.status}`);
      return ((await res.json()) as { progress: JobProgress }).progress;
    },
    isRevoked: async (runId) => {
      const res = await stub(runId).fetch("https://tokens.invalid/revoked");
      if (!res.ok) throw new Error(`token store returned ${res.status}`);
      return ((await res.json()) as { revoked: boolean }).revoked === true;
    },
  };
}

function hexToBytes(hex: string): Uint8Array | undefined {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return undefined;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * Whether GitHub signed `rawBody`: its `X-Hub-Signature-256` header must be
 * `sha256=<hex of HMAC-SHA256(rawBody, secret)>`.
 */
export async function verifyWebhookSignature(rawBody: string, header: string | null, secret: string): Promise<boolean> {
  const match = /^sha256=([0-9a-fA-F]+)$/.exec((header ?? "").trim());
  if (!match) return false;
  const given = hexToBytes(match[1]);
  if (!given) return false;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), utf8.encode(rawBody)));
  return sameBytes(given, mac);
}

// --- proxy --------------------------------------------------------------------

/** Headers never forwarded upstream; Authorization is replaced, the rest are dropped. */
const DROP_HEADERS = new Set(["authorization", "host", "content-length", "connection", "keep-alive", "transfer-encoding", "upgrade"]);

/**
 * Forwards `request` to `baseUrl + suffix + query` with the caller's
 * Authorization swapped for the Worker's LLM key. Bodies stream through in
 * both directions, so SSE responses arrive chunk by chunk; nothing is
 * buffered or logged here.
 */
export async function proxyToLlm(
  request: Request,
  suffix: string,
  query: string,
  llmKey: string,
  baseUrl: string,
  fetchImpl: typeof fetch,
): Promise<Response> {
  const upstream = `${baseUrl.replace(/\/+$/, "")}${suffix}${query}`;
  const headers = new Headers();
  request.headers.forEach((value, name) => {
    if (!DROP_HEADERS.has(name.toLowerCase())) headers.append(name, value);
  });
  headers.set("Authorization", `Bearer ${llmKey}`);
  const method = request.method.toUpperCase();
  const upstreamRes = await fetchImpl(upstream, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : request.body,
    // Lets the runtime stream an SSE response instead of buffering it.
    ...(request.signal ? { signal: request.signal } : {}),
  });
  // Forward the upstream answer untouched: status, headers and stream.
  return new Response(upstreamRes.body, { status: upstreamRes.status, headers: upstreamRes.headers });
}
