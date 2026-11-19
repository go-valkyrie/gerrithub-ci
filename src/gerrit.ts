// Gerrit events, as the webhooks plugin posts them (the same JSON as
// `gerrit stream-events`), and the decision whether one should run CI.

export interface Account {
  name?: string;
  email?: string;
  username?: string;
}

export interface Change {
  project?: string;
  branch?: string;
  number?: number;
  url?: string;
  wip?: boolean;
}

export interface PatchSet {
  number?: number;
  revision?: string;
  ref?: string;
  uploader?: Account;
  kind?: string;
}

export interface GerritEvent {
  type?: string;
  project?: string | { name?: string };
  change?: Change;
  patchSet?: PatchSet;
  uploader?: Account;
  author?: Account;
  comment?: string;
}

/** What a CI run needs to know about the patch set it verifies. */
export interface Target {
  project: string;
  branch: string;
  change: number;
  patchset: number;
  ref: string;
  revision: string;
  url: string;
  uploader: string;
  trigger: "patchset-created" | "recheck";
}

export type Decision =
  | { run: true; target: Target }
  | { run: false; reason: string };

export interface Policy {
  /** Gerrit project names that have CI, mapped to the GitHub repository to dispatch to. */
  projects: Record<string, string>;
  /** Gerrit usernames or emails whose patch sets run without a recheck. */
  trusted: string[];
}

const REF = /^refs\/changes\/\d{2}\/\d+\/\d+$/;
const REVISION = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
// A review comment reads "Patch Set N:\n\nrecheck" or "Patch Set N: Code-Review+1\n\nrecheck".
export const RECHECK = /^\s*recheck\s*$/im;

function projectOf(event: GerritEvent): string | undefined {
  if (event.change?.project) return event.change.project;
  if (typeof event.project === "string") return event.project;
  return event.project?.name;
}

function identities(account: Account | undefined): string[] {
  if (!account) return [];
  return [account.username, account.email]
    .filter((s): s is string => typeof s === "string" && s.length > 0)
    .map((s) => s.toLowerCase());
}

export function isTrusted(account: Account | undefined, trusted: string[]): boolean {
  const allowed = new Set(trusted.map((s) => s.toLowerCase()));
  return identities(account).some((id) => allowed.has(id));
}

function display(account: Account | undefined): string {
  return account?.username ?? account?.email ?? account?.name ?? "unknown";
}

/**
 * Whether `event` should start a CI run, and for which patch set.
 *
 * A new patch set runs only when its uploader is trusted. Anyone else's patch
 * set runs when a trusted reviewer comments "recheck" on it, so untrusted code
 * never reaches CI unless a maintainer asks for it.
 */
export function decide(event: GerritEvent, policy: Policy): Decision {
  const type = event.type;
  if (type !== "patchset-created" && type !== "comment-added") {
    return { run: false, reason: `event ${type ?? "(none)"} is not handled` };
  }
  const project = projectOf(event);
  if (!project || !(project in policy.projects)) {
    return { run: false, reason: `project ${project ?? "(none)"} has no CI` };
  }
  const change = event.change;
  const patchSet = event.patchSet;
  if (!change?.number || !patchSet?.number || !patchSet.ref || !patchSet.revision) {
    return { run: false, reason: "event lacks a change or patch set" };
  }
  if (!REF.test(patchSet.ref) || !REVISION.test(patchSet.revision)) {
    return { run: false, reason: "patch set ref or revision is malformed" };
  }

  let trigger: Target["trigger"];
  if (type === "patchset-created") {
    const uploader = patchSet.uploader ?? event.uploader;
    if (!isTrusted(uploader, policy.trusted)) {
      return { run: false, reason: `uploader ${display(uploader)} is not trusted; a trusted reviewer can comment "recheck"` };
    }
    trigger = "patchset-created";
  } else {
    if (!RECHECK.test(event.comment ?? "")) {
      return { run: false, reason: "comment is not a recheck" };
    }
    if (!isTrusted(event.author, policy.trusted)) {
      return { run: false, reason: `recheck by ${display(event.author)}, who is not trusted` };
    }
    trigger = "recheck";
  }

  return {
    run: true,
    target: {
      project,
      branch: change.branch ?? "",
      change: change.number,
      patchset: patchSet.number,
      ref: patchSet.ref,
      revision: patchSet.revision,
      url: change.url ?? "",
      uploader: display(patchSet.uploader ?? event.uploader),
      trigger,
    },
  };
}
