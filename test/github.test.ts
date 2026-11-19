import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fromBase64Url, fromUtf8, utf8 } from "../src/encoding";
import { appJwt, importPrivateKey, installationToken, resetTokenCache } from "../src/github";
import { testKey, type TestKey } from "./keys";

const NOW = 1_800_000_000;
let key: TestKey;

beforeAll(async () => {
  key = await testKey();
});

beforeEach(() => resetTokenCache());

async function verifies(jwt: string): Promise<boolean> {
  const [h, p, s] = jwt.split(".");
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key.pair.publicKey, fromBase64Url(s), utf8.encode(`${h}.${p}`));
}

function claims(jwt: string) {
  return JSON.parse(fromUtf8.decode(fromBase64Url(jwt.split(".")[1])));
}

describe("importPrivateKey", () => {
  it("imports GitHub's PKCS#1 keys and PKCS#8 keys", async () => {
    await expect(importPrivateKey(key.pkcs1Pem)).resolves.toBeDefined();
    await expect(importPrivateKey(key.pkcs8Pem)).resolves.toBeDefined();
  });

  it("accepts a key whose newlines arrived as literal \\n", async () => {
    await expect(importPrivateKey(key.pkcs1Pem.replace(/\n/g, "\\n"))).resolves.toBeDefined();
  });

  it("refuses anything else", async () => {
    await expect(importPrivateKey("not a key")).rejects.toThrow(/not a PEM private key/);
  });
});

describe("appJwt", () => {
  it("is signed by the app's key, issued by the app, and short-lived", async () => {
    for (const privateKey of [key.pkcs1Pem, key.pkcs8Pem]) {
      const jwt = await appJwt({ appId: "12345", privateKey }, NOW);
      expect(await verifies(jwt)).toBe(true);
      const c = claims(jwt);
      expect(c.iss).toBe("12345");
      expect(c.exp - NOW).toBeLessThanOrEqual(600);
      expect(c.iat).toBeLessThanOrEqual(NOW);
    }
  });
});

describe("installationToken", () => {
  function github(expiresIn = 3600) {
    return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u === "https://api.github.com/repos/go-valkyrie/vali-scheme/installation") {
        return Response.json({ id: 99 });
      }
      if (u === "https://api.github.com/app/installations/99/access_tokens" && init?.method === "POST") {
        return Response.json(
          { token: "ghs_installation", expires_at: new Date((NOW + expiresIn) * 1000).toISOString() },
          { status: 201 },
        );
      }
      return new Response("unexpected", { status: 500 });
    });
  }
  const creds = () => ({ appId: "12345", privateKey: key.pkcs1Pem });

  it("exchanges an app JWT for a token limited to the repository and Contents: write", async () => {
    const fetchImpl = github();
    const token = await installationToken("go-valkyrie/vali-scheme", creds(), fetchImpl as unknown as typeof fetch, NOW);
    expect(token).toBe("ghs_installation");
    const [, lookup] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    const jwt = (lookup.headers as Record<string, string>).Authorization.replace(/^Bearer /, "");
    expect(await verifies(jwt)).toBe(true);
    const [, create] = fetchImpl.mock.calls[1] as unknown as [string, RequestInit];
    expect(JSON.parse(create.body as string)).toEqual({
      repositories: ["vali-scheme"],
      permissions: { contents: "write" },
    });
  });

  it("caches the token until five minutes before it expires", async () => {
    const fetchImpl = github(3600);
    const f = fetchImpl as unknown as typeof fetch;
    await installationToken("go-valkyrie/vali-scheme", creds(), f, NOW);
    await installationToken("go-valkyrie/vali-scheme", creds(), f, NOW + 3000);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    await installationToken("go-valkyrie/vali-scheme", creds(), f, NOW + 3400);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  it("fails clearly when the app isn't installed on the repository", async () => {
    const fetchImpl = vi.fn(async () => new Response("Not Found", { status: 404 }));
    await expect(
      installationToken("someone/else", creds(), fetchImpl as unknown as typeof fetch, NOW),
    ).rejects.toThrow(/installation on someone\/else returned 404/);
  });
});
