// De-duplication of webhook deliveries.
//
// GerritHub runs several Gerrit nodes, and each node's webhooks plugin posts
// every event to the Worker, so one event arrives about five times within a
// few seconds. Each delivery would dispatch a run; the workflow's concurrency
// group cancels all but one, which wastes the rest. Before dispatching, the
// Worker claims the event's key in a Durable Object named after that key: the
// first claim wins, and the others are dropped.

import type { GerritEvent, Target } from "./gerrit";

/** How long a claimed key is remembered, in seconds. */
export const DEFAULT_WINDOW_SECONDS = 600;

/** Claims `key`: true for the first caller, false for every later one. */
export type Claimer = (key: string) => Promise<boolean>;

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
 * different moments. The key is hashed, since comment text is unbounded and a
 * Durable Object name is limited to 1024 bytes.
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

/** The parts of `DurableObjectStorage` that EventClaim uses. */
export interface ClaimStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  setAlarm(time: number): Promise<void>;
  deleteAll(): Promise<void>;
}

/**
 * One claimed key. The object is named after the event's key, so every
 * delivery of the event reaches the same instance, which handles them one at
 * a time. The first claim sets an alarm; when it fires the object deletes
 * everything, and a claim after that starts fresh.
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
