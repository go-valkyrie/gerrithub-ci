// Muse-review support: short-lived tokens that let a GitHub Actions job call
// an LLM through this Worker, without ever seeing the Worker's own LLM key.
//
// Flow:
//   1. POST /muse-token: the review job presents its GitHub OIDC token plus
//      the run's ticket. The Worker checks the OIDC token (issuer, audience,
//      expiry), checks the ticket, and checks the token may vote for the
//      ticket's repository. It answers with an ephemeral JWT scoped to that
//      repo, ticket, change and patch set, valid for ~30 minutes.
//   2. /v1/* and /muse-code/*: a transparent proxy to the LLM's API (the
//      latter is Muse Code's model catalog, served from the API's origin).
//      It accepts only the ephemeral token, swaps in the real LLM key, and streams the request
//      and response bodies through untouched (SSE included).
//   3. POST /github-webhook: GitHub's workflow_job and workflow_run events,
//      HMAC-signed. Jobs are tracked forward-only (queued -> in_progress ->
//      completed); when the run completes, its tokens are revoked and its
//      job markers deleted. Revocation waits for the run, not a job: the
//      review job runs after the verify job, so revoking on job completion
//      would lock it out of the proxy mid-run. The token's own expiry stays
//      enforced as a backstop.
//
// State lives in two Durable Objects, so every isolate sees the same state
// instead of a per-isolate Map:
//   - EventClaim: one per Gerrit delivery, deleted after a short window.
//   - MuseTokens: one per GitHub run, holding its jobs' progress and
//     revocation. Every entry expires with the token lifetime, so a missed
//     completion can't leave dead objects around forever.
//
// Nothing here logs keys, tokens, prompts, reviews or diffs: the proxy
// never reads a body into memory, and handlers log only ids and statuses.

import { fromBase64Url, fromUtf8, sameBytes, toBase64Url, utf8 } from "./encoding";
import type { GerritEvent, Target } from "./gerrit";

/** How long an ephemeral token lasts, in seconds; entries expire with it. */
export const MUSE_TOKEN_TTL_SECONDS = 1800;

/** How long a claimed delivery is remembered, in seconds. */
export const DEFAULT_WINDOW_SECONDS = 600;

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

// --- delivery keys --------------------------------------------------------------
// One Gerrit event arrives about five times (one per Gerrit node), so each
// delivery is claimed in a Durable Object before any work happens.

function who(account: GerritEvent["author"]): string {
  return (account?.username ?? account?.email ?? account?.name ?? "").toLowerCase();
}

/**
 * The key that identifies one Gerrit event, the same in every node's delivery
 * of it and different from any other event.
 *
 * - A patch set is created once, so the type, project, change, patch set and
 *   revision name the event. Nothing time-dependent is needed.
 * - A comment-added event isn't unique to the patch set: the same reviewer can
 *   comment "recheck" twice, and both must run. So a comment adds the author,
 *   the comment text, and `eventCreatedOn`, the time Gerrit created the event
 *   (seconds since the epoch). Gerrit stamps it when the event is created, and
 *   events are forwarded to other nodes with the stamp intact, so every node
 *   reports the same value. Two comments would need the same author, text and
 *   second to collide.
 *
 * The Worker's own clock is deliberately not used: the deliveries arrive at
 * different moments. The key is hashed, since comment text is unbounded.
 */
export async function eventKey(event: GerritEvent, target: Target): Promise<string> {
  const parts = [event.type ?? "", target.project, String(target.change), String(target.patchset), target.revision];
  if (event.type === "comment-added") {
    parts.push(who(event.author), String(event.eventCreatedOn ?? ""), event.comment ?? "");
  }
  // JSON, so that no field can run into the next.
  const bytes = new TextEncoder().encode(JSON.stringify(parts));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- EventClaim: de-duplication --------------------------------------------------
// GerritHub runs several Gerrit nodes, and each node's webhooks plugin posts
// every event to the Worker, so one event arrives about five times within a
// few seconds. Each delivery would dispatch a run; the workflow's concurrency
// group cancels all but one, which wastes the rest. Before dispatching, the
// Worker claims the event's key in a Durable Object named after that key: the
// first claim wins, and the others are dropped.

/** The parts of DurableObjectStorage that EventClaim uses. */
export interface ClaimStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  setAlarm(time: number): Promise<void>;
  deleteAll(): Promise<void>;
}

/**
 * One claimed delivery. The object is named after the event's key, so every
 * delivery of the event reaches the same instance, which handles them one at
 * a time. The alarm deletes everything after the window. Durable Object
 * storage has no per-key expiry (`expirationTtl` is a Workers KV option), so
 * the alarm is the only cleanup the marker gets.
 *
 * This is a plain class with a `fetch` method rather than an RPC
 * `DurableObject` subclass, so tests can build it without the Workers runtime.
 */
export class EventClaim {
  private readonly windowMs: number;

  constructor(
    private readonly state: { storage: ClaimStorage },
    env: { DEDUPE_WINDOW_SECONDS?: string } = {},
    private readonly now: () => number = Date.now,
  ) {
    const seconds = Number(env.DEDUPE_WINDOW_SECONDS);
    this.windowMs = (Number.isFinite(seconds) && seconds > 0 ? seconds : DEFAULT_WINDOW_SECONDS) * 1000;
  }

  /** True the first time, false afterwards (until the window ends). */
  async claim(): Promise<boolean> {
    const { storage } = this.state;
    if ((await storage.get("claimed")) !== undefined) return false;
    // The alarm first: if the write fails after it, the alarm cleans up;
    // the other order could leave a key that is never deleted.
    await storage.setAlarm(this.now() + this.windowMs);
    await storage.put("claimed", true);
    return true;
  }

  async fetch(_request: Request): Promise<Response> {
    return Response.json({ claimed: await this.claim() });
  }

  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}

/** Claims `key`: true for the first caller, false for every later one. */
export type Claimer = (key: string) => Promise<boolean>;

/** A Claimer that asks the Durable Object named `key`. */
export function claimerFor(namespace: DurableObjectNamespace): Claimer {
  return async (key) => {
    const stub = namespace.get(namespace.idFromName(key));
    const response = await stub.fetch("https://claim.invalid/");
    if (!response.ok) throw new Error(`claim returned ${response.status}`);
    const body = (await response.json()) as { claimed?: boolean };
    return body.claimed === true;
  };
}

// --- MuseTokens: one Durable Object per run ---------------------------------------
// A module-level Map would be per-isolate: a revocation written on one
// isolate is invisible to the rest. So each run's jobs and revocation live in
// a Durable Object named after the run: every delivery of its jobs' events
// reaches the same instance. Completing the run revokes its tokens and
// deletes its job markers. Durable Object storage has no per-key expiry, so
// the object sets an alarm on its first write, for the token lifetime plus a
// margin, and the alarm deletes everything. That also cleans up a run whose
// completion event never arrives; the token's own expiry makes its job
// markers moot by then.

/** The parts of DurableObjectStorage that per-run token state uses. */
export interface TokenStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
  list(opts: { prefix: string }): Promise<Map<string, unknown>>;
  getAlarm(): Promise<number | null>;
  setAlarm(time: number): Promise<void>;
  deleteAll(): Promise<void>;
}

/** How long past the token lifetime the alarm waits, so `revoked` outlives every token. */
export const ALARM_MARGIN_SECONDS = 60;

/** Progress of one workflow_job delivery, or of a run's completion. */
export type JobProgress = "advanced" | "stale" | "unknown";

const JOB_ORDER: Record<string, number> = { queued: 0, in_progress: 1, completed: 2 };

/**
 * One run's jobs and revocation. Forward-only per job: an event at or behind
 * the latest seen state is a duplicate or a stale redelivery and changes
 * nothing. A completed job only moves its marker — revocation waits for the
 * run — so the review keeps working after the verify job finishes.
 *
 * A plain class with a `fetch` method rather than an RPC `DurableObject`
 * subclass, so tests can build it without the Workers runtime.
 */
export class MuseTokens {
  constructor(
    private readonly state: { storage: TokenStorage },
    _env: unknown = undefined, // the runtime passes the Worker's env here
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Makes sure the cleanup alarm fires after a token issued now would have
   * expired. It is set on the first write and only ever pushed later, never
   * earlier, so a short-lived write can't cut short a longer one. Called
   * before the write: if the write fails, the alarm still cleans up.
   */
  private async ensureAlarm(ttlSeconds: number): Promise<void> {
    const at = this.now() + (ttlSeconds + ALARM_MARGIN_SECONDS) * 1000;
    const current = await this.state.storage.getAlarm();
    if (current === null || current < at) await this.state.storage.setAlarm(at);
  }

  /** Deletes the run's state once its tokens can no longer be live. */
  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }

  /** Records a delivery of one of the run's jobs. */
  async noteJob(jobId: string, action: string, ttlSeconds: number): Promise<JobProgress> {
    const rank = JOB_ORDER[action];
    if (rank === undefined) return "unknown";
    const key = `job:${jobId}`;
    const prev = await this.state.storage.get(key);
    if (typeof prev === "number" && rank <= prev) return "stale";
    await this.ensureAlarm(ttlSeconds);
    await this.state.storage.put(key, rank);
    return "advanced";
  }

  /**
   * Completes the run: revokes its tokens and deletes its job markers, so
   * redelivered completions report "stale" instead of logging twice. The
   * revoked flag itself stays, expiring with the TTL, so stragglers fail
   * closed.
   */
  async completeRun(ttlSeconds: number): Promise<"advanced" | "stale"> {
    if ((await this.state.storage.get("done")) !== undefined) return "stale";
    await this.ensureAlarm(ttlSeconds);
    await this.state.storage.put("revoked", true);
    await this.state.storage.put("done", true);
    for (const key of (await this.state.storage.list({ prefix: "job:" })).keys()) {
      await this.state.storage.delete(key);
    }
    return "advanced";
  }

  /** Whether the run's tokens were revoked. */
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
    if (request.method === "POST" && url.pathname === "/complete") {
      let done: { ttl?: unknown };
      try {
        done = (await request.json()) as typeof done;
      } catch {
        return Response.json({ error: "body is not JSON" }, { status: 400 });
      }
      if (typeof done.ttl !== "number") return Response.json({ error: "bad completion" }, { status: 400 });
      return Response.json({ progress: await this.completeRun(done.ttl) });
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
  completeRun(runId: string, ttlSeconds: number): Promise<"advanced" | "stale">;
}

/** A client that reaches the Durable Object named after the run. */
export function tokensFor(namespace: DurableObjectNamespace): MuseTokensClient {
  const stub = (runId: string) => namespace.get(namespace.idFromName(`muse-run:${runId}`));
  async function post<T>(name: string, path: string, body: unknown): Promise<T> {
    const res = await stub(name).fetch(`https://tokens.invalid${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`token store returned ${res.status}`);
    return (await res.json()) as T;
  }
  return {
    noteJob: async (runId, jobId, action, ttlSeconds) =>
      (await post<{ progress: JobProgress }>(`muse-run:${runId}`, "/note", { jobId, action, ttl: ttlSeconds })).progress,
    isRevoked: async (runId) => {
      const res = await stub(`muse-run:${runId}`).fetch("https://tokens.invalid/revoked");
      if (!res.ok) throw new Error(`token store returned ${res.status}`);
      return ((await res.json()) as { revoked: boolean }).revoked === true;
    },
    completeRun: async (runId, ttlSeconds) =>
      (await post<{ progress: "advanced" | "stale" }>(`muse-run:${runId}`, "/complete", { ttl: ttlSeconds })).progress,
  };
}

// --- workflow_job webhook -----------------------------------------------------

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
