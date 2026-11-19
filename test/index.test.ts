import { describe, expect, it, vi } from "vitest";
import { handle, type Env } from "../src/index";
import { openTicket } from "../src/ticket";

export const env: Env = {
  WEBHOOK_SECRET: "s3cret",
  TICKET_SECRET: "ticket-key",
  GITHUB_TOKEN: "ghp_test",
  GERRIT_USER: "ci-bot",
  GERRIT_HTTP_PASSWORD: "gerrit-pass",
  PROJECTS: JSON.stringify({ "go-valkyrie/vali-scheme": "go-valkyrie/vali-scheme" }),
  TRUSTED: JSON.stringify(["maintainer"]),
};

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

function deps(fetchImpl: unknown) {
  return { fetch: fetchImpl as typeof fetch, now: () => NOW };
}

describe("/gerrit/<secret>", () => {
  it("dispatches a run to GitHub with a signed ticket", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const res = await handle(post("/gerrit/s3cret", event), env, deps(fetchImpl));
    expect(res.status).toBe(202);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.github.com/repos/go-valkyrie/vali-scheme/dispatches");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer ghp_test");
    const body = JSON.parse(init.body as string);
    expect(body.event_type).toBe("gerrit-verify");
    expect(body.client_payload.ref).toBe("refs/changes/07/7/1");
    expect(Object.keys(body.client_payload).length).toBeLessThanOrEqual(10);
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

  it("returns 502 when GitHub refuses, so Gerrit retries", async () => {
    const fetchImpl = vi.fn(async () => new Response("Bad credentials", { status: 401 }));
    const res = await handle(post("/gerrit/s3cret", event), env, deps(fetchImpl));
    expect(res.status).toBe(502);
  });
});
