// Confirming a webhook event against Gerrit's REST API before acting on it.
//
// GerritHub's webhooks plugin can't authenticate its requests, so anyone who
// learned the webhook URL could post a forged event: say, a "patch set by a
// trusted uploader" that is really someone else's. The Worker therefore
// treats each event only as a hint. It fetches the change from Gerrit, as the
// bot account, and runs CI only if Gerrit itself says the patch set exists
// with that revision and ref and was uploaded by a trusted account, or, for a
// recheck, that a trusted reviewer really commented "recheck" on it.

import { isTrusted, RECHECK, type Account, type Target } from "./gerrit";

interface AccountInfo {
  _account_id?: number;
  name?: string;
  email?: string;
  username?: string;
}

interface RevisionInfo {
  _number?: number;
  ref?: string;
  uploader?: AccountInfo;
  /** How the patch set differs from the previous one, e.g. REWORK or TRIVIAL_REBASE. */
  kind?: string;
}

interface ChangeMessageInfo {
  author?: AccountInfo;
  message?: string;
  _revision_number?: number;
}

interface ChangeInfo {
  project?: string;
  branch?: string;
  _number?: number;
  revisions?: Record<string, RevisionInfo>;
  messages?: ChangeMessageInfo[];
}

export interface GerritAccess {
  url: string;
  user: string;
  password: string;
}

export class GerritError extends Error {}

export type Confirmation = { confirmed: true; uploader: string } | { confirmed: false; reason: string };

function account(info: AccountInfo | undefined): Account | undefined {
  return info && { name: info.name, email: info.email, username: info.username };
}

function display(info: AccountInfo | undefined): string {
  return info?.username ?? info?.email ?? info?.name ?? `account ${info?._account_id ?? "unknown"}`;
}

/** The change, as Gerrit sees it, with every revision, their uploaders, and its messages. */
export async function fetchChange(target: Target, gerrit: GerritAccess, fetchImpl: typeof fetch): Promise<ChangeInfo> {
  const id = `${encodeURIComponent(target.project)}~${target.change}`;
  const url = `${gerrit.url}/a/changes/${id}?o=ALL_REVISIONS&o=DETAILED_ACCOUNTS&o=MESSAGES`;
  const res = await fetchImpl(url, {
    headers: { Authorization: `Basic ${btoa(`${gerrit.user}:${gerrit.password}`)}`, Accept: "application/json" },
  });
  if (res.status === 404) return {};
  if (!res.ok) throw new GerritError(`Gerrit returned ${res.status} for change ${target.change}`);
  // Gerrit prefixes JSON with ")]}'" against XSSI.
  const body = (await res.text()).replace(/^\)\]\}'\s*/, "");
  try {
    return JSON.parse(body) as ChangeInfo;
  } catch {
    throw new GerritError(`Gerrit's answer for change ${target.change} is not JSON`);
  }
}

/** Whether Gerrit confirms what the event claimed about `target`. */
export function confirmChange(change: ChangeInfo, target: Target, trusted: string[]): Confirmation {
  if (change._number !== target.change) return { confirmed: false, reason: `Gerrit has no change ${target.change}` };
  if (change.project !== target.project) {
    return { confirmed: false, reason: `change ${target.change} is in ${change.project ?? "no project"}, not ${target.project}` };
  }
  const revision = change.revisions?.[target.revision];
  if (!revision) return { confirmed: false, reason: `change ${target.change} has no revision ${target.revision}` };
  if (revision._number !== target.patchset || revision.ref !== target.ref) {
    return { confirmed: false, reason: `revision ${target.revision} is not patch set ${target.patchset} at ${target.ref}` };
  }

  if (target.trigger === "patchset-created") {
    if (!isTrusted(account(revision.uploader), trusted)) {
      return { confirmed: false, reason: `Gerrit says patch set ${target.patchset} was uploaded by ${display(revision.uploader)}, who is not trusted` };
    }
  } else {
    const recheck = (change.messages ?? []).find(
      (m) =>
        m._revision_number === target.patchset &&
        RECHECK.test(m.message ?? "") &&
        isTrusted(account(m.author), trusted),
    );
    if (!recheck) {
      return { confirmed: false, reason: `Gerrit has no recheck by a trusted reviewer on patch set ${target.patchset}` };
    }
  }
  return { confirmed: true, uploader: display(revision.uploader) };
}

/** Change kinds with no new code to verify: CI would only repeat the last vote. */
const SKIP_KINDS = new Set(["TRIVIAL_REBASE", "NO_CHANGE"]);

/**
 * The `target` patch set's change kind, if Gerrit says it carries no new
 * code worth verifying. Only fresh patch sets are ever skipped: a recheck
 * always runs, because a trusted reviewer explicitly asked for it. Unknown
 * or absent kinds run too, so an older Gerrit changes nothing.
 */
export function trivialKind(change: ChangeInfo, target: Target): string | undefined {
  if (target.trigger !== "patchset-created") return undefined;
  const kind = change.revisions?.[target.revision]?.kind;
  return kind && SKIP_KINDS.has(kind) ? kind : undefined;
}
