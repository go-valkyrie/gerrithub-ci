// Authenticating to GitHub as a GitHub App: an app JWT, exchanged for an
// installation token limited to one repository and Contents: write.
// See https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app.

import { toBase64Url, utf8 } from "./encoding";

export interface AppCredentials {
  appId: string;
  /** The app's private key, PEM, as GitHub hands it out (PKCS#1) or as PKCS#8. */
  privateKey: string;
}

const API = "https://api.github.com";

export function apiHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "gerrithub-ci",
  };
}

// --- keys ---------------------------------------------------------------------

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let m = n; m > 0; m >>= 8) bytes.unshift(m & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

function der(tag: number, content: Uint8Array): Uint8Array {
  const len = derLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Wraps a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo, which WebCrypto can import. */
export function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const version = Uint8Array.from([0x02, 0x01, 0x00]);
  // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1), NULL parameters.
  const algorithm = Uint8Array.from([
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  ]);
  return der(0x30, concat(version, algorithm, der(0x04, pkcs1)));
}

function pemBody(pem: string, label: string): Uint8Array | undefined {
  const match = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(pem);
  if (!match) return undefined;
  const binary = atob(match[1].replace(/\s+/g, ""));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function importPrivateKey(pem: string): Promise<CryptoKey> {
  // Secrets pasted through some shells arrive with literal "\n"s.
  const text = pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
  const pkcs8 = pemBody(text, "PRIVATE KEY") ?? (() => {
    const pkcs1 = pemBody(text, "RSA PRIVATE KEY");
    return pkcs1 && pkcs1ToPkcs8(pkcs1);
  })();
  if (!pkcs8) throw new Error("GITHUB_APP_PRIVATE_KEY is not a PEM private key");
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

// --- tokens -------------------------------------------------------------------

/** A JWT that authenticates as the app itself, valid for under ten minutes. */
export async function appJwt(creds: AppCredentials, now: number): Promise<string> {
  const header = toBase64Url(utf8.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  // iat a minute back allows for clock drift; GitHub refuses exp more than 10 minutes out.
  const payload = toBase64Url(utf8.encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: creds.appId })));
  const key = await importPrivateKey(creds.privateKey);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, utf8.encode(`${header}.${payload}`));
  return `${header}.${payload}.${toBase64Url(new Uint8Array(signature))}`;
}

const tokens = new Map<string, { token: string; expires: number }>();

/** Forgets cached installation tokens. For tests. */
export function resetTokenCache(): void {
  tokens.clear();
}

export class GithubError extends Error {}

/**
 * An installation token for `repo` ("owner/name"), allowed only Contents:
 * write on that repository. Cached until five minutes before it expires.
 */
export async function installationToken(
  repo: string,
  creds: AppCredentials,
  fetchImpl: typeof fetch,
  now: number,
): Promise<string> {
  const cached = tokens.get(repo);
  if (cached && now < cached.expires - 300) return cached.token;

  const jwt = await appJwt(creds, now);
  const installation = await fetchImpl(`${API}/repos/${repo}/installation`, { headers: apiHeaders(jwt) });
  if (!installation.ok) {
    throw new GithubError(`finding the app's installation on ${repo} returned ${installation.status}`);
  }
  const { id } = (await installation.json()) as { id: number };

  const [, name] = repo.split("/");
  const created = await fetchImpl(`${API}/app/installations/${id}/access_tokens`, {
    method: "POST",
    headers: { ...apiHeaders(jwt), "Content-Type": "application/json" },
    body: JSON.stringify({ repositories: [name], permissions: { contents: "write" } }),
  });
  if (!created.ok) {
    throw new GithubError(`creating an installation token for ${repo} returned ${created.status}`);
  }
  const { token, expires_at } = (await created.json()) as { token: string; expires_at: string };
  tokens.set(repo, { token, expires: Math.floor(Date.parse(expires_at) / 1000) });
  return token;
}
