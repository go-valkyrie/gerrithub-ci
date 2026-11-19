// A ticket names the patch set a dispatch asked CI to verify. The Worker signs
// it when it dispatches and checks it when the vote comes back, so it only
// votes on patch sets it sent to CI.

import { fromBase64Url, fromUtf8, sameBytes, toBase64Url, utf8 } from "./encoding";

export interface Ticket {
  /** Gerrit project. */
  project: string;
  change: number;
  patchset: number;
  revision: string;
  /** GitHub "owner/repo" the dispatch went to. */
  repo: string;
  /** Issued at, in seconds since the epoch. */
  iat: number;
}

/** How long a ticket stays valid: a CI run must vote within this time. */
export const TICKET_LIFETIME = 12 * 60 * 60;

async function key(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", utf8.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function mac(secret: string, body: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", await key(secret), utf8.encode(body)));
}

export async function signTicket(ticket: Ticket, secret: string): Promise<string> {
  const body = toBase64Url(utf8.encode(JSON.stringify(ticket)));
  return `${body}.${toBase64Url(await mac(secret, body))}`;
}

/** The ticket's contents, if `text` was signed with `secret` and hasn't expired. */
export async function openTicket(text: string, secret: string, now: number): Promise<Ticket | undefined> {
  const parts = text.split(".");
  if (parts.length !== 2) return undefined;
  const [body, signature] = parts;
  let given: Uint8Array;
  try {
    given = fromBase64Url(signature);
  } catch {
    return undefined;
  }
  if (!sameBytes(given, await mac(secret, body))) return undefined;
  let ticket: Ticket;
  try {
    ticket = JSON.parse(fromUtf8.decode(fromBase64Url(body))) as Ticket;
  } catch {
    return undefined;
  }
  if (typeof ticket.iat !== "number" || now < ticket.iat - 60 || now > ticket.iat + TICKET_LIFETIME) {
    return undefined;
  }
  return ticket;
}
