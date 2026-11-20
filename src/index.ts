// A Cloudflare Worker that runs GitHub Actions for GerritHub changes and
// votes Verified on them, without GitHub holding any GerritHub credential.
//
// POST /gerrit/<WEBHOOK_SECRET>
//   GerritHub's webhooks plugin posts each event here. The plugin can't send
//   an auth header, so the secret is part of the path. Events that should run
//   CI become a repository_dispatch on the mirrored GitHub repository,
//   carrying a signed ticket that names the patch set.
//
// POST /vote
//   The workflow's vote job posts its result here with the ticket, and
//   authenticates with its GitHub Actions OIDC token. The Worker checks the
//   token came from the expected workflow on the expected repository and
//   branch, checks the ticket, and votes Verified with its own Gerrit
//   credentials.
//
// POST /muse-token
//   The review job exchanges its GitHub OIDC token plus the ticket for a
//   short-lived token scoped to the repo, ticket, change and patch set.
//
// /v1/*
//   Proxies to the LLM's API with the Worker's key. Accepts only the
//   short-lived token above, and streams the answer through.
//
// POST /github-webhook
//   GitHub's workflow_job events, HMAC-signed. Revokes a run's tokens when
//   its job completes.
//
// POST /review
//   Like /vote, but posts review markdown to Gerrit, adding Code-Review +1
//   only when asked.

import { claimerFor, eventKey, type Claimer } from "./claims";
import { sameBytes, utf8 } from "./encoding";
import { decide, type GerritEvent, type Policy, type Target } from "./gerrit";
import { apiHeaders, installationToken } from "./github";
import {
  DEFAULT_LLM_BASE_URL,
  MUSE_TOKEN_TTL_SECONDS,
  MuseTokenError,
  noteJobEvent,
  proxyToLlm,
  revokeRun,
  signMuseToken,
  verifyMuseToken,
  verifyWebhookSignature,
} from "./muse";
import { confirmChange, fetchChange } from "./verify";
import { TokenError, verifyGithubToken, type GithubClaims } from "./oidc";
import { openTicket, signTicket, type Ticket } from "./ticket";

export { EventClaim } from "./claims";

export interface Env {
  /** Durable Object namespace that de-duplicates deliveries; see src/claims.ts. */
  EVENT_CLAIM: DurableObjectNamespace;
  /** How long an event is remembered, in seconds; defaults to 600. */
  DEDUPE_WINDOW_SECONDS?: string;
  /** Secret path segment GerritHub posts to. */
  WEBHOOK_SECRET: string;
  /** Key that signs tickets. */
  TICKET_SECRET: string;
  /** The GitHub App that sends repository_dispatch: its ID, and its private key (PEM). */
  GITHUB_APP_ID: string;
  GITHUB_APP_PRIVATE_KEY: string;
  /** Gerrit account the Worker votes as, and its HTTP password. */
  GERRIT_USER: string;
  GERRIT_HTTP_PASSWORD: string;
  /** JSON object: Gerrit project name -> "owner/repo" on GitHub. */
  PROJECTS: string;
  /** JSON array of trusted Gerrit usernames or emails. */
  TRUSTED: string;
  /** Gerrit's base URL; defaults to https://review.gerrithub.io. */
  GERRIT_URL?: string;
  /** The repository_dispatch event type; defaults to "gerrit-verify". */
  EVENT_TYPE?: string;
  /** Audience the vote job requests its OIDC token for; defaults to "gerrithub-ci". */
  OIDC_AUDIENCE?: string;
  /** Workflow file allowed to vote; defaults to ".github/workflows/gerrit-verify.yml". */
  WORKFLOW?: string;
  /** Branch the voting workflow must run from; defaults to "main". */
  BRANCH?: string;
  /** Key for the LLM API behind /v1/*. Unset, and the proxy answers 501. */
  LLM_API_KEY?: string;
  /** Base URL the proxy forwards /v1/* to; defaults to https://api.meta.ai/v1. */
  LLM_BASE_URL?: string;
  /** Signs ephemeral review tokens; defaults to TICKET_SECRET. */
  MUSE_TOKEN_SECRET?: string;
  /** Ephemeral token lifetime in seconds; defaults to 1800. Clamped to one hour. */
  MUSE_TOKEN_TTL_SECONDS?: string;
  /** Signs GitHub's workflow_job webhook (X-Hub-Signature-256). Unset, and it answers 404. */
  GITHUB_WEBHOOK_SECRET?: string;
}

type Fetch = typeof fetch;

export interface Deps {
  fetch: Fetch;
  /** Seconds since the epoch. */
  now: () => number;
  /** Keeps the Worker alive for work that finishes after the response is sent. */
  waitUntil: (work: Promise<unknown>) => void;
  sleep: (ms: number) => Promise<void>;
  /** Where background work reports what it did: the Worker's logs. */
  log: (line: string) => void;
  /** Claims an event key: true for the first delivery of an event, false for repeats. */
  claim: Claimer;
}

function depsFor(ctx: ExecutionContext, env: Env): Deps {
  return {
    claim: claimerFor(env.EVENT_CLAIM),
    fetch: (...args) => fetch(...args),
    now: () => Math.floor(Date.now() / 1000),
    waitUntil: (work) => ctx.waitUntil(work),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    log: (line) => console.log(line),
  };
}

function text(body: string, status: number, headers: Record<string, string> = {}): Response {
  return new Response(body.endsWith("\n") ? body : `${body}\n`, { status, headers });
}

function policyOf(env: Env): Policy {
  return {
    projects: JSON.parse(env.PROJECTS || "{}") as Record<string, string>,
    trusted: JSON.parse(env.TRUSTED || "[]") as string[],
  };
}

function gerritUrl(env: Env): string {
  return (env.GERRIT_URL || "https://review.gerrithub.io").replace(/\/+$/, "");
}

// --- /gerrit/<secret> -------------------------------------------------------

async function dispatch(env: Env, repo: string, target: Target, deps: Deps): Promise<Response> {
  const ticket = await signTicket(
    {
      project: target.project,
      change: target.change,
      patchset: target.patchset,
      revision: target.revision,
      repo,
      iat: deps.now(),
    },
    env.TICKET_SECRET,
  );
  const token = await installationToken(
    repo,
    { appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY },
    deps.fetch,
    deps.now(),
  );
  return deps.fetch(`https://api.github.com/repos/${repo}/dispatches`, {
    method: "POST",
    headers: { ...apiHeaders(token), "Content-Type": "application/json" },
    // client_payload may have at most 10 top-level properties.
    body: JSON.stringify({
      event_type: env.EVENT_TYPE || "gerrit-verify",
      client_payload: {
        project: target.project,
        branch: target.branch,
        change: target.change,
        patchset: target.patchset,
        ref: target.ref,
        revision: target.revision,
        url: target.url,
        uploader: target.uploader,
        trigger: target.trigger,
        ticket,
      },
    }),
  });
}

async function handleGerrit(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });

  let event: GerritEvent;
  try {
    event = (await request.json()) as GerritEvent;
  } catch {
    return text("body is not JSON", 400);
  }

  let policy: Policy;
  try {
    policy = policyOf(env);
  } catch {
    return text("PROJECTS or TRUSTED is not valid JSON", 500);
  }

  const decision = decide(event, policy);
  if (!decision.run) {
    // 200, so Gerrit doesn't retry an event we chose to ignore.
    return text(`ignored: ${decision.reason}`, 200);
  }

  // Answer at once and do the rest in the background. The webhooks plugin
  // retries any delivery that takes longer than its socket timeout, and
  // every retry would confirm and dispatch again.
  deps.waitUntil(confirmAndDispatch(env, policy, event, decision.target, deps));
  const { change, patchset, trigger } = decision.target;
  return text(`accepted change ${change},${patchset} (${trigger}); confirming it with Gerrit`, 202);
}

/** A failure that retrying won't fix. */
class Permanent extends Error {}

/** Waits before each retry; one more attempt than delays. */
const RETRY_DELAYS_MS = [1000, 4000];

async function withRetries<T>(what: string, deps: Deps, attempt: () => Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await attempt();
    } catch (e) {
      if (e instanceof Permanent || i >= RETRY_DELAYS_MS.length) throw e;
      deps.log(`${what} failed (${(e as Error).message}); retrying in ${RETRY_DELAYS_MS[i]} ms`);
      await deps.sleep(RETRY_DELAYS_MS[i]);
    }
  }
}

/**
 * Confirms the event with Gerrit and, if Gerrit agrees, dispatches the run.
 * Runs after the webhook has been answered, so it reports to the logs.
 */
async function confirmAndDispatch(env: Env, policy: Policy, event: GerritEvent, hint: Target, deps: Deps): Promise<void> {
  const label = `change ${hint.change},${hint.patchset} (${hint.trigger})`;
  try {
    // Every Gerrit node posts the event, so claim it before doing any work.
    // This is after the cheap checks in decide(), so a forged event can at
    // worst use up a key, and before the Gerrit call, so repeats cost nothing.
    // If the claim itself fails, dispatch anyway: a duplicate run is better
    // than none.
    let first = true;
    try {
      first = await deps.claim(await eventKey(event, hint));
    } catch (e) {
      deps.log(`could not claim ${label} (${(e as Error).message}); dispatching anyway`);
    }
    if (!first) {
      deps.log(`duplicate delivery of ${label}; ignored`);
      return;
    }
    // The event is only a hint: GerritHub can't sign it, so confirm it with Gerrit.
    const gerrit = { url: gerritUrl(env), user: env.GERRIT_USER, password: env.GERRIT_HTTP_PASSWORD };
    const change = await withRetries("asking Gerrit", deps, () => fetchChange(hint, gerrit, deps.fetch));
    const confirmation = confirmChange(change, hint, policy.trusted);
    if (!confirmation.confirmed) {
      deps.log(`ignored ${label}: not confirmed by Gerrit: ${confirmation.reason}`);
      return;
    }
    const target = { ...hint, uploader: confirmation.uploader };
    const repo = policy.projects[target.project];
    await withRetries("dispatching to GitHub", deps, async () => {
      const response = await dispatch(env, repo, target, deps);
      if (!response.ok) {
        const detail = await response.text().catch(() => "");
        const message = `GitHub returned ${response.status}: ${detail}`;
        // A client error other than rate limiting won't go away on its own.
        if (response.status >= 400 && response.status < 500 && response.status !== 429) throw new Permanent(message);
        throw new Error(message);
      }
    });
    deps.log(`dispatched ${repo} ${label}`);
  } catch (e) {
    deps.log(`failed ${label}: ${(e as Error).message}`);
  }
}

// --- runners: /vote, /review, /muse-token ---------------------------------------
// Every runner endpoint trusts the same thing: a GitHub OIDC token from the
// expected workflow, run and branch, plus the ticket the dispatch carried.
// The body is read once here and handed to each handler with the claims.

interface Runner {
  claims: GithubClaims;
  ticket: Ticket;
  /** The ticket string the caller sent, for binding minted tokens to it. */
  ticketText: string;
  /** The request's JSON body. */
  body: Record<string, unknown>;
}

/** Why the token's workflow may not act for `repo`, or undefined if it may. */
function refuseWorkflow(claims: GithubClaims, repo: string, env: Env): string | undefined {
  const workflow = env.WORKFLOW || ".github/workflows/gerrit-verify.yml";
  const branch = `refs/heads/${env.BRANCH || "main"}`;
  if (claims.repository !== repo) return `token is for ${claims.repository}, ticket is for ${repo}`;
  if (claims.event_name !== "repository_dispatch") return `token is from a ${claims.event_name} run`;
  if (claims.ref !== branch) return `token is from ${claims.ref}, not ${branch}`;
  if (claims.workflow_ref !== `${repo}/${workflow}@${branch}`) return `token is from workflow ${claims.workflow_ref}`;
  return undefined;
}

async function authenticateRunner(request: Request, env: Env, deps: Deps): Promise<Runner | Response> {
  const auth = request.headers.get("Authorization") ?? "";
  const bearer = /^Bearer\s+(\S+)$/i.exec(auth);
  if (!bearer) return text("missing bearer token", 401, { "WWW-Authenticate": "Bearer" });

  let claims: GithubClaims;
  try {
    claims = await verifyGithubToken(bearer[1], env.OIDC_AUDIENCE || "gerrithub-ci", deps.fetch, deps.now());
  } catch (e) {
    if (e instanceof TokenError) return text(`bad token: ${e.message}`, 401, { "WWW-Authenticate": "Bearer" });
    return text(`could not verify the token: ${(e as Error).message}`, 502);
  }

  let body: VoteBody;
  try {
    body = (await request.json()) as VoteBody;
  } catch {
    return text("body is not JSON", 400);
  }
  if (typeof body.ticket !== "string") return text("missing ticket", 400);
  const ticket = await openTicket(body.ticket, env.TICKET_SECRET, deps.now());
  if (!ticket) return text("bad or expired ticket", 403);

  const refusal = refuseWorkflow(claims, ticket.repo, env);
  if (refusal) return text(`refused: ${refusal}`, 403);
  return { claims, ticket, ticketText: body.ticket, body: body as Record<string, unknown> };
}

function setReviewUrl(env: Env, ticket: Ticket): string {
  const changeId = `${encodeURIComponent(ticket.project)}~${ticket.change}`;
  return `${gerritUrl(env)}/a/changes/${changeId}/revisions/${ticket.revision}/review`;
}

/** Posts `message` with `labels` to the ticket's revision. Returns a response on failure. */
async function postSetReview(
  env: Env,
  deps: Deps,
  ticket: Ticket,
  message: string,
  labels: Record<string, number>,
): Promise<Response | undefined> {
  const credentials = btoa(`${env.GERRIT_USER}:${env.GERRIT_HTTP_PASSWORD}`);
  const res = await deps.fetch(setReviewUrl(env, ticket), {
    method: "POST",
    headers: { Authorization: `Basic ${credentials}`, "Content-Type": "application/json" },
    body: JSON.stringify({ message, labels, tag: "autogenerated:gerrithub-ci" }),
  });
  if (!res.ok) return text("Gerrit refused the review", 502);
  return undefined;
}

// --- /vote --------------------------------------------------------------------

interface VoteBody {
  ticket?: string;
  /** The verify job's result: needs.verify.result in the workflow. */
  result?: string;
}

async function handleVote(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });

  const auth = await authenticateRunner(request, env, deps);
  if (auth instanceof Response) return auth;
  const { claims, ticket } = auth;
  const result = auth.body.result as VoteBody["result"];

  let vote: number;
  let word: string;
  switch (result) {
    case "success":
      vote = 1;
      word = "passed";
      break;
    case "failure":
      vote = -1;
      word = "failed";
      break;
    case "cancelled":
    case "skipped":
      // Superseded by a newer patch set, or never ran: leave the vote alone.
      return text(`not voting on a ${result} run`, 200);
    default:
      return text(`unknown result ${String(result)}`, 400);
  }

  const runUrl = `https://github.com/${claims.repository}/actions/runs/${claims.run_id}`;
  const failed = await postSetReview(env, deps, ticket, `Build ${word}: ${runUrl}`, { Verified: vote });
  if (failed) return failed;
  return text(`voted Verified ${vote > 0 ? "+1" : "-1"} on change ${ticket.change},${ticket.patchset}`, 200);
}

// --- /review ------------------------------------------------------------------

interface ReviewBody {
  ticket?: string;
  /** The review markdown to post on the patch set. */
  review?: string;
  /** When true, the review also votes Code-Review +1. Never voted otherwise. */
  codeReview?: boolean;
}

/** Largest review the Worker forwards to Gerrit. */
const MAX_REVIEW_CHARS = 64 * 1024;

async function handleReview(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });

  const auth = await authenticateRunner(request, env, deps);
  if (auth instanceof Response) return auth;
  const review = auth.body.review as ReviewBody["review"];
  const codeReview = auth.body.codeReview as ReviewBody["codeReview"];
  if (typeof review !== "string" || review.trim() === "") return text("missing review", 400);
  if (review.length > MAX_REVIEW_CHARS) return text("review is too long", 400);

  const { ticket } = auth;
  const labels: Record<string, number> = codeReview === true ? { "Code-Review": 1 } : {};
  const failed = await postSetReview(env, deps, ticket, review, labels);
  if (failed) return failed;
  const voted = codeReview === true ? " with Code-Review +1" : "";
  return text(`posted review on change ${ticket.change},${ticket.patchset}${voted}`, 200);
}

// --- /muse-token ----------------------------------------------------------------
// Minting needs the same OIDC token and ticket as voting; the ticket's repo,
// change, patch set and revision become the token's scope, and the OIDC
// run_id names the run whose completion revokes it.

function museSecret(env: Env): string {
  return env.MUSE_TOKEN_SECRET || env.TICKET_SECRET;
}

function museTtl(env: Env): number {
  const seconds = Number(env.MUSE_TOKEN_TTL_SECONDS);
  if (!Number.isFinite(seconds) || seconds <= 0) return MUSE_TOKEN_TTL_SECONDS;
  return Math.min(Math.floor(seconds), 3600);
}

async function handleMuseToken(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });

  const auth = await authenticateRunner(request, env, deps);
  if (auth instanceof Response) return auth;
  const { claims, ticket, ticketText } = auth;

  const ttl = museTtl(env);
  const now = deps.now();
  const token = await signMuseToken(
    { repo: ticket.repo, change: ticket.change, patchset: ticket.patchset, revision: ticket.revision, ticket: ticketText, run_id: claims.run_id },
    museSecret(env),
    now,
    ttl,
  );
  return Response.json({ token, expires_in: ttl, expires_at: new Date((now + ttl) * 1000).toISOString() });
}

// --- /v1/* proxy ----------------------------------------------------------------
// Accepts only ephemeral tokens from /muse-token: a GitHub OIDC token fails
// the HMAC check. The LLM key travels only between the Worker and the LLM.

async function handleProxy(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (!env.LLM_API_KEY) return text("review proxy is not configured", 501);
  const header = request.headers.get("Authorization") ?? "";
  const token = /^Bearer\s+(\S+)$/i.exec(header)?.[1];
  if (!token) return text("missing bearer token", 401, { "WWW-Authenticate": "Bearer" });
  // Rejected before anything is forwarded: unknown, expired and revoked
  // tokens all land here, as does any non-ephemeral token.
  try {
    await verifyMuseToken(token, museSecret(env), deps.now());
  } catch (e) {
    if (e instanceof MuseTokenError) return text("bad review token", 401, { "WWW-Authenticate": "Bearer" });
    return text("could not check the review token", 502);
  }
  const url = new URL(request.url);
  const suffix = url.pathname.slice("/v1".length) || "/";
  try {
    return await proxyToLlm(request, suffix, url.search, env.LLM_API_KEY, env.LLM_BASE_URL || DEFAULT_LLM_BASE_URL, deps.fetch);
  } catch (e) {
    return text(`review backend failed: ${(e as Error).message}`, 502);
  }
}

// --- /github-webhook ------------------------------------------------------------
// GitHub's workflow_job events. Only the job's forward progress matters:
// queued -> in_progress -> completed. A completed job revokes its run's
// review tokens; anything else only moves the job's marker.

interface WorkflowJobBody {
  action?: string;
  workflow_job?: { id?: number | string; run_id?: number | string };
}

async function handleGithubWebhook(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });
  if (!env.GITHUB_WEBHOOK_SECRET) return text("not found", 404);
  const raw = await request.text().catch(() => "");
  const signed = await verifyWebhookSignature(raw, request.headers.get("X-Hub-Signature-256"), env.GITHUB_WEBHOOK_SECRET);
  if (!signed) return text("bad webhook signature", 401);
  let body: WorkflowJobBody;
  try {
    body = JSON.parse(raw) as WorkflowJobBody;
  } catch {
    return text("body is not JSON", 400);
  }
  // GitHub's ping when the webhook is created: acknowledge it and stop.
  if (!body.workflow_job) return text("pong", 200);
  const jobId = body.workflow_job.id;
  const action = body.action ?? "";
  if (jobId === undefined) return text("ignored: no job", 200);
  const progress = noteJobEvent(String(jobId), action);
  if (progress === "advanced" && action === "completed" && body.workflow_job.run_id !== undefined) {
    revokeRun(String(body.workflow_job.run_id), deps.now());
    deps.log(`run ${body.workflow_job.run_id} completed; revoked its review tokens`);
  }
  return text(`job ${jobId} ${action}: ${progress}`, 200);
}

// --- routing ------------------------------------------------------------------

function secretMatches(given: string, secret: string): boolean {
  return secret.length > 0 && sameBytes(utf8.encode(given), utf8.encode(secret));
}

export async function handle(request: Request, env: Env, deps: Deps): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (path === "/vote") return handleVote(request, env, deps);
  if (path === "/review") return handleReview(request, env, deps);
  if (path === "/muse-token") return handleMuseToken(request, env, deps);
  if (path === "/github-webhook") return handleGithubWebhook(request, env, deps);
  if (path === "/v1" || path.startsWith("/v1/")) return handleProxy(request, env, deps);
  const gerrit = /^\/gerrit\/([^/]+)$/.exec(path);
  if (gerrit && secretMatches(decodeURIComponent(gerrit[1]), env.WEBHOOK_SECRET || "")) {
    return handleGerrit(request, env, deps);
  }
  return text("not found", 404);
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(request, env, depsFor(ctx, env));
  },
};
