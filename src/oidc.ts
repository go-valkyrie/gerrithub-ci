// Verifying the OIDC token a GitHub Actions job gets with `id-token: write`.
// See https://docs.github.com/actions/reference/openid-connect-reference.

import { fromBase64Url, fromUtf8, utf8 } from "./encoding";

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${GITHUB_ISSUER}/.well-known/jwks`;
const JWKS_TTL_MS = 60 * 60 * 1000;
/** Clock skew allowed on `exp`, `nbf` and `iat`, in seconds. */
const SKEW = 60;

/** The claims this Worker reads. GitHub's tokens carry more. */
export interface GithubClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat?: number;
  repository: string;
  ref: string;
  workflow_ref: string;
  event_name: string;
  run_id: string;
  run_attempt?: string;
}

interface Jwk extends JsonWebKey {
  kid?: string;
}

let cache: { keys: Jwk[]; fetched: number } | undefined;

/** Forgets the cached signing keys. For tests. */
export function resetKeyCache(): void {
  cache = undefined;
}

async function signingKey(kid: string, fetchImpl: typeof fetch, nowMs: number): Promise<Jwk | undefined> {
  const fresh = cache && nowMs - cache.fetched < JWKS_TTL_MS;
  let found = fresh ? cache!.keys.find((k) => k.kid === kid) : undefined;
  if (found) return found;
  // Unknown key or stale cache: GitHub may have rotated its keys.
  const res = await fetchImpl(JWKS_URL, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`fetching GitHub's signing keys returned ${res.status}`);
  const { keys } = (await res.json()) as { keys: Jwk[] };
  cache = { keys, fetched: nowMs };
  found = keys.find((k) => k.kid === kid);
  return found;
}

export class TokenError extends Error {}

/**
 * The claims of `token`, if it is a GitHub Actions OIDC token for `audience`
 * that GitHub signed and that is valid at `now` (seconds).
 */
export async function verifyGithubToken(
  token: string,
  audience: string,
  fetchImpl: typeof fetch,
  now: number,
): Promise<GithubClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("not a JWT");
  const [headerText, payloadText, signatureText] = parts;

  let header: { alg?: string; kid?: string };
  let claims: GithubClaims;
  let signature: Uint8Array;
  try {
    header = JSON.parse(fromUtf8.decode(fromBase64Url(headerText)));
    claims = JSON.parse(fromUtf8.decode(fromBase64Url(payloadText)));
    signature = fromBase64Url(signatureText);
  } catch {
    throw new TokenError("malformed JWT");
  }
  if (header.alg !== "RS256" || !header.kid) throw new TokenError("unexpected JWT algorithm or key");

  const jwk = await signingKey(header.kid, fetchImpl, now * 1000);
  if (!jwk) throw new TokenError("unknown signing key");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signed = utf8.encode(`${headerText}.${payloadText}`);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed))) {
    throw new TokenError("bad signature");
  }

  if (claims.iss !== GITHUB_ISSUER) throw new TokenError("wrong issuer");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(audience)) throw new TokenError("wrong audience");
  if (typeof claims.exp !== "number" || now > claims.exp + SKEW) throw new TokenError("expired");
  if (typeof claims.nbf === "number" && now < claims.nbf - SKEW) throw new TokenError("not yet valid");
  if (typeof claims.iat === "number" && now < claims.iat - SKEW) throw new TokenError("issued in the future");
  return claims;
}
