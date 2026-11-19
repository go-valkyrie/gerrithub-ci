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

import { sameBytes, utf8 } from "./encoding";
import { decide, type GerritEvent, type Policy, type Target } from "./gerrit";
import { apiHeaders, installationToken } from "./github";
import { TokenError, verifyGithubToken, type GithubClaims } from "./oidc";
import { openTicket, signTicket } from "./ticket";

export interface Env {
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
}

type Fetch = typeof fetch;

export interface Deps {
  fetch: Fetch;
  /** Seconds since the epoch. */
  now: () => number;
}

const defaultDeps: Deps = { fetch: (...args) => fetch(...args), now: () => Math.floor(Date.now() / 1000) };

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

  const repo = policy.projects[decision.target.project];
  let response: Response;
  try {
    response = await dispatch(env, repo, decision.target, deps);
  } catch (e) {
    // 502, so the webhooks plugin retries once GitHub or the app is reachable.
    return text(`could not authenticate to GitHub: ${(e as Error).message}`, 502);
  }
  if (!response.ok) {
    // 502, so the webhooks plugin retries.
    const detail = await response.text().catch(() => "");
    return text(`GitHub returned ${response.status}: ${detail}`, 502);
  }
  const { change, patchset, trigger } = decision.target;
  return text(`dispatched ${repo} change ${change},${patchset} (${trigger})`, 202);
}

// --- /vote --------------------------------------------------------------------

interface VoteBody {
  ticket?: string;
  /** The verify job's result: needs.verify.result in the workflow. */
  result?: string;
}

/** Why the token's workflow may not vote, or undefined if it may. */
function refuseWorkflow(claims: GithubClaims, repo: string, env: Env): string | undefined {
  const workflow = env.WORKFLOW || ".github/workflows/gerrit-verify.yml";
  const branch = `refs/heads/${env.BRANCH || "main"}`;
  if (claims.repository !== repo) return `token is for ${claims.repository}, ticket is for ${repo}`;
  if (claims.event_name !== "repository_dispatch") return `token is from a ${claims.event_name} run`;
  if (claims.ref !== branch) return `token is from ${claims.ref}, not ${branch}`;
  if (claims.workflow_ref !== `${repo}/${workflow}@${branch}`) return `token is from workflow ${claims.workflow_ref}`;
  return undefined;
}

async function handleVote(request: Request, env: Env, deps: Deps): Promise<Response> {
  if (request.method !== "POST") return text("method not allowed", 405, { Allow: "POST" });

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

  let vote: number;
  let word: string;
  switch (body.result) {
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
      return text(`not voting on a ${body.result} run`, 200);
    default:
      return text(`unknown result ${String(body.result)}`, 400);
  }

  const runUrl = `https://github.com/${claims.repository}/actions/runs/${claims.run_id}`;
  const changeId = `${encodeURIComponent(ticket.project)}~${ticket.change}`;
  const credentials = btoa(`${env.GERRIT_USER}:${env.GERRIT_HTTP_PASSWORD}`);
  const res = await deps.fetch(`${gerritUrl(env)}/a/changes/${changeId}/revisions/${ticket.revision}/review`, {
    method: "POST",
    headers: { Authorization: `Basic ${credentials}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Build ${word}: ${runUrl}`,
      labels: { Verified: vote },
      tag: "autogenerated:gerrithub-ci",
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    return text(`Gerrit returned ${res.status}: ${detail}`, 502);
  }
  return text(`voted Verified ${vote > 0 ? "+1" : "-1"} on change ${ticket.change},${ticket.patchset}`, 200);
}

// --- routing ------------------------------------------------------------------

function secretMatches(given: string, secret: string): boolean {
  return secret.length > 0 && sameBytes(utf8.encode(given), utf8.encode(secret));
}

export async function handle(request: Request, env: Env, deps: Deps = defaultDeps): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (path === "/vote") return handleVote(request, env, deps);
  const gerrit = /^\/gerrit\/([^/]+)$/.exec(path);
  if (gerrit && secretMatches(decodeURIComponent(gerrit[1]), env.WEBHOOK_SECRET || "")) {
    return handleGerrit(request, env, deps);
  }
  return text("not found", 404);
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env);
  },
};
