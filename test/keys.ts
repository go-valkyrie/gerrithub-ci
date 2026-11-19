// RSA keys for tests, as PEM in the two forms GitHub and WebCrypto use.

export interface TestKey {
  pair: CryptoKeyPair;
  /** PKCS#8, labelled PRIVATE KEY. */
  pkcs8Pem: string;
  /** PKCS#1, labelled RSA PRIVATE KEY, as GitHub hands out app keys. */
  pkcs1Pem: string;
}

function pem(label: string, der: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** Reads a DER length at `at`, returning [length, bytes used]. */
function readLength(der: Uint8Array, at: number): [number, number] {
  const first = der[at];
  if (first < 0x80) return [first, 1];
  const count = first & 0x7f;
  let n = 0;
  for (let i = 1; i <= count; i++) n = (n << 8) | der[at + i];
  return [n, 1 + count];
}

/** The PKCS#1 key inside a PKCS#8 PrivateKeyInfo: its last element, an OCTET STRING. */
function pkcs8ToPkcs1(pkcs8: Uint8Array): Uint8Array {
  let at = 1;
  const [, outer] = readLength(pkcs8, at);
  at += outer;
  // version INTEGER, then the AlgorithmIdentifier SEQUENCE, then the OCTET STRING.
  for (let skip = 0; skip < 2; skip++) {
    at += 1;
    const [len, used] = readLength(pkcs8, at);
    at += used + len;
  }
  if (pkcs8[at] !== 0x04) throw new Error("expected an OCTET STRING");
  at += 1;
  const [len, used] = readLength(pkcs8, at);
  return pkcs8.slice(at + used, at + used + len);
}

export async function testKey(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  return { pair, pkcs8Pem: pem("PRIVATE KEY", pkcs8), pkcs1Pem: pem("RSA PRIVATE KEY", pkcs8ToPkcs1(pkcs8)) };
}
