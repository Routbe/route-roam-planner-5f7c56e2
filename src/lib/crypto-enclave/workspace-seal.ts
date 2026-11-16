/**
 * Workspace group encryption (db/0285).
 *
 * A workspace owns one RVE1 key pair per epoch -- the *workspace key*. Its public half is
 * published (`workspace_keys`, db/0285) so an anonymous visitor can seal a question
 * to it; its secret half never leaves a manager's device: it travels only as a `wsk` envelope,
 * the workspace secret sealed to one manager's own device key.
 *
 *   wsk  workspace key   sealed to a manager's member-device key (holder member_device).
 *   wq   question        sealed to the workspace key (holder member_device: only a manager
 *                        who opened their own wsk can reach the secret half).
 *   wa   private answer  sealed to the visitor's reply key (holder booking_guest).
 *
 * A visitor generates a 32-byte token; the reply key pair is *derived* from it, so the
 * fragment `#token=…` is the single thing they must keep: it both finds the answer (by its
 * hash) and opens it. The token never goes to a server, only its SHA-256.
 *
 * Contexts bind every envelope to its owner and purpose, so a ciphertext moved to another
 * workspace, epoch, member or visitor never opens. Plaintext is padded with the same three
 * buckets booking payloads use, so an envelope reveals only its bucket.
 *
 * Browser-safe: no server imports, no database access.
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { pad, unpad } from "./booking-seal";
import { generateRecipientKeys, openEnvelope, PUBLIC_KEY_BYTES, sealEnvelope, type RecipientKeys } from "./pqc-envelope";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

/** The visitor's secret: 32 random bytes, kept in the address fragment. */
export const WORKSPACE_TOKEN_BYTES = 32;
/** Fragment parameter the ask page writes: `#token=<43 base64url characters>`. */
export const WORKSPACE_TOKEN_PARAM = "token";
/** Question and answer lengths, matching the publish checks of db/0285. */
export const WORKSPACE_QUESTION_MAX = 2000;
export const WORKSPACE_ANSWER_MAX = 4000;
export const WORKSPACE_ENVELOPE_KINDS = ["wsk", "wq", "wa"] as const;

const TOKEN_LABEL = enc.encode("rout.ws.token.v1");
const REPLY_LABEL = enc.encode("rout.ws.reply.v1");
const ANSWER_LABEL = enc.encode("rout.ws.answer.v1");
const ANSWER_VERSION = 1;

export class WorkspaceSealError extends Error {
  constructor() {
    super("workspace_seal_invalid");
    this.name = "WorkspaceSealError";
  }
}

const wipe = (...a: (Uint8Array | null | undefined)[]) => {
  for (const x of a) x?.fill(0);
};

function checkUuid(id: string): string {
  if (!UUID.test(id)) throw new WorkspaceSealError();
  return id;
}

function checkEpoch(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > 1_000_000) throw new WorkspaceSealError();
  return epoch;
}

function checkText(value: unknown, max: number): string {
  if (typeof value !== "string" || Array.from(value).length > max || value.includes("\u0000")) throw new WorkspaceSealError();
  return value.normalize("NFC");
}

/** A fresh visitor token. All-zero is refused: it would derive a guessable reply key. */
export function newWorkspaceToken(): Uint8Array {
  const token = randomBytes(WORKSPACE_TOKEN_BYTES);
  if (token.every((b) => b === 0)) {
    wipe(token);
    throw new WorkspaceSealError();
  }
  return token;
}

/** The only form of the token a server ever sees: SHA-256 over a labelled preimage. */
export function workspaceTokenHash(token: Uint8Array): Uint8Array {
  if (token.length !== WORKSPACE_TOKEN_BYTES || token.every((b) => b === 0)) throw new WorkspaceSealError();
  const buf = new Uint8Array(TOKEN_LABEL.length + token.length);
  buf.set(TOKEN_LABEL);
  buf.set(token, TOKEN_LABEL.length);
  try {
    return sha256(buf);
  } finally {
    wipe(buf);
  }
}

/**
 * The visitor's reply key pair, derived from their token. Because it is a derivation and not
 * a second secret, the fragment only has to carry the token: the same token always yields the
 * same reply key, so an answer filed today still opens after a reload.
 */
export function workspaceReplyKeys(token: Uint8Array): RecipientKeys {
  if (token.length !== WORKSPACE_TOKEN_BYTES || token.every((b) => b === 0)) throw new WorkspaceSealError();
  const buf = new Uint8Array(REPLY_LABEL.length + token.length);
  buf.set(REPLY_LABEL);
  buf.set(token, REPLY_LABEL.length);
  try {
    return generateRecipientKeys("booking_guest", sha256(buf));
  } finally {
    wipe(buf);
  }
}

/** `#token=<base64url>` -- the fragment the visitor keeps; never sent to a server. */
export function workspaceTokenFragment(token: Uint8Array): string {
  if (token.length !== WORKSPACE_TOKEN_BYTES) throw new WorkspaceSealError();
  let s = "";
  for (const b of token) s += String.fromCharCode(b);
  return `#${WORKSPACE_TOKEN_PARAM}=${btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

/** Reads the token back out of a fragment; null when it is not there or not strict. */
export function parseWorkspaceTokenFragment(fragment: string): Uint8Array | null {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const prefix = `${WORKSPACE_TOKEN_PARAM}=`;
  if (!raw.startsWith(prefix)) return null;
  const body = raw.slice(prefix.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(body)) return null;
  try {
    const out = Uint8Array.from(atob(body.replace(/-/g, "+").replace(/_/g, "/") + "="), (c) => c.charCodeAt(0));
    if (out.length !== WORKSPACE_TOKEN_BYTES || out.every((b) => b === 0)) return null;
    return out;
  } catch {
    return null;
  }
}

/** Every envelope is bound to its owner and purpose; a copy elsewhere never opens. */
export function workspaceKeyContext(workspaceId: string, epoch: number, memberRef: string): string {
  return `rout.ws.key.v1|ws=${checkUuid(workspaceId)}|epoch=${checkEpoch(epoch)}|member=${checkUuid(memberRef)}`;
}

export function workspaceQuestionContext(workspaceId: string, epoch: number, payloadId: string): string {
  return `rout.ws.question.v1|ws=${checkUuid(workspaceId)}|epoch=${checkEpoch(epoch)}|payload=${checkUuid(payloadId)}`;
}

/**
 * Binds a private answer to the visitor's reply key. Both sides know that key -- the manager
 * sees it on the question row, the visitor derives it from their token -- and hashing it keeps
 * the context well under the 1024-byte limit the envelope imposes.
 */
export function workspaceAnswerContext(replyPublicKey: Uint8Array): string {
  if (replyPublicKey.length !== PUBLIC_KEY_BYTES) throw new WorkspaceSealError();
  const digest = sha256(replyPublicKey);
  return `${dec.decode(ANSWER_LABEL)}|reply=${Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** The workspace's own key pair for one epoch. The 32-byte secret is the whole secret. */
export function workspaceGroupKeys(seed?: Uint8Array): RecipientKeys {
  return generateRecipientKeys("member_device", seed);
}

/**
 * The workspace secret for one manager: `wsk`, sealed to that manager's device key. The
 * plaintext is the raw 32-byte secret, padded like every other envelope.
 */
export function sealWorkspaceKey(input: {
  workspaceId: string;
  epoch: number;
  memberRef: string;
  memberPublicKey: Uint8Array;
  workspaceSecret: Uint8Array;
}): Uint8Array {
  const { workspaceId, epoch, memberRef, memberPublicKey, workspaceSecret } = input;
  if (workspaceSecret.length !== 32 || memberPublicKey.length !== PUBLIC_KEY_BYTES) throw new WorkspaceSealError();
  const context = workspaceKeyContext(workspaceId, epoch, memberRef);
  let padded: Uint8Array | null = null;
  try {
    padded = pad(workspaceSecret);
    return sealEnvelope({ kind: "wsk", holder: "member_device", recipientPublicKey: memberPublicKey, plaintext: padded, context });
  } finally {
    wipe(padded);
  }
}

/**
 * The workspace secret again, from the caller's own `wsk`. The caller owns the result and
 * must wipe it: it is the key that opens every question of that epoch.
 */
export function openWorkspaceKey(input: {
  workspaceId: string;
  epoch: number;
  memberRef: string;
  envelope: Uint8Array;
  deviceSecretKey: Uint8Array;
}): Uint8Array {
  const context = workspaceKeyContext(input.workspaceId, input.epoch, input.memberRef);
  let padded: Uint8Array | null = null;
  try {
    padded = openEnvelope({
      envelope: input.envelope,
      expectedKind: "wsk",
      holder: "member_device",
      secretKey: input.deviceSecretKey,
      context,
    });
    const secret = unpad(padded).slice();
    if (secret.length !== 32) throw new WorkspaceSealError();
    return secret;
  } catch {
    throw new WorkspaceSealError();
  } finally {
    wipe(padded);
  }
}

/** Canonical bytes of one question: fixed key order, so one text has exactly one encoding. */
function encodeQuestion(text: string): Uint8Array {
  const bytes = enc.encode(JSON.stringify({ v: ANSWER_VERSION, text: checkText(text, WORKSPACE_QUESTION_MAX) }));
  if (bytes.length > 16384 - 4) {
    wipe(bytes);
    throw new WorkspaceSealError();
  }
  return bytes;
}

function decodeQuestion(bytes: Uint8Array): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(dec.decode(bytes));
  } catch {
    throw new WorkspaceSealError();
  }
  if (typeof parsed !== "object" || parsed === null) throw new WorkspaceSealError();
  const o = parsed as { v?: unknown; text?: unknown };
  if (o.v !== ANSWER_VERSION) throw new WorkspaceSealError();
  return checkText(o.text, WORKSPACE_QUESTION_MAX);
}

/** Canonical bytes of one private answer: the question is repeated so the visitor sees both. */
function encodeAnswer(question: string, answer: string): Uint8Array {
  const bytes = enc.encode(
    JSON.stringify({ v: ANSWER_VERSION, question: checkText(question, WORKSPACE_QUESTION_MAX), answer: checkText(answer, WORKSPACE_ANSWER_MAX) }),
  );
  if (bytes.length > 16384 - 4) {
    wipe(bytes);
    throw new WorkspaceSealError();
  }
  return bytes;
}

function decodeAnswer(bytes: Uint8Array): { question: string; answer: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(dec.decode(bytes));
  } catch {
    throw new WorkspaceSealError();
  }
  if (typeof parsed !== "object" || parsed === null) throw new WorkspaceSealError();
  const o = parsed as { v?: unknown; question?: unknown; answer?: unknown };
  if (o.v !== ANSWER_VERSION) throw new WorkspaceSealError();
  return { question: checkText(o.question, WORKSPACE_QUESTION_MAX), answer: checkText(o.answer, WORKSPACE_ANSWER_MAX) };
}

/**
 * One anonymous question, sealed to the workspace's live key. `hash` is BLAKE3 over the exact
 * ciphertext: the value the database stores so a solved proof cannot be replayed.
 */
export function sealWorkspaceQuestion(input: {
  workspaceId: string;
  epoch: number;
  payloadId: string;
  workspacePublicKey: Uint8Array;
  text: string;
}): { envelope: Uint8Array; hash: Uint8Array } {
  const { workspaceId, epoch, payloadId, workspacePublicKey } = input;
  if (workspacePublicKey.length !== PUBLIC_KEY_BYTES) throw new WorkspaceSealError();
  const context = workspaceQuestionContext(workspaceId, epoch, payloadId);
  let body: Uint8Array | null = null;
  let padded: Uint8Array | null = null;
  try {
    body = encodeQuestion(input.text);
    padded = pad(body);
    const envelope = sealEnvelope({ kind: "wq", holder: "member_device", recipientPublicKey: workspacePublicKey, plaintext: padded, context });
    return { envelope, hash: blake3(envelope) };
  } finally {
    wipe(body, padded);
  }
}

/** A manager's view of one question, opened with the workspace secret. */
export function openWorkspaceQuestion(input: {
  workspaceId: string;
  epoch: number;
  payloadId: string;
  envelope: Uint8Array;
  workspaceSecret: Uint8Array;
}): string {
  const context = workspaceQuestionContext(input.workspaceId, input.epoch, input.payloadId);
  let padded: Uint8Array | null = null;
  try {
    padded = openEnvelope({
      envelope: input.envelope,
      expectedKind: "wq",
      holder: "member_device",
      secretKey: input.workspaceSecret,
      context,
    });
    return decodeQuestion(unpad(padded));
  } catch {
    throw new WorkspaceSealError();
  } finally {
    wipe(padded);
  }
}

/**
 * A private answer for one visitor, sealed to their reply key. The manager sees the reply key
 * on the question row; the visitor re-derives it from the token in their fragment.
 */
export function sealWorkspaceAnswer(input: {
  replyPublicKey: Uint8Array;
  question: string;
  answer: string;
}): { envelope: Uint8Array; hash: Uint8Array } {
  if (input.replyPublicKey.length !== PUBLIC_KEY_BYTES) throw new WorkspaceSealError();
  const context = workspaceAnswerContext(input.replyPublicKey);
  let body: Uint8Array | null = null;
  let padded: Uint8Array | null = null;
  try {
    body = encodeAnswer(input.question, input.answer);
    padded = pad(body);
    const envelope = sealEnvelope({ kind: "wa", holder: "booking_guest", recipientPublicKey: input.replyPublicKey, plaintext: padded, context });
    return { envelope, hash: blake3(envelope) };
  } finally {
    wipe(body, padded);
  }
}

/** The visitor's own view: the answer their token finds and their reply key opens. */
export function openWorkspaceAnswer(input: { token: Uint8Array; envelope: Uint8Array }): { question: string; answer: string } {
  const keys = workspaceReplyKeys(input.token);
  const context = workspaceAnswerContext(keys.publicKey);
  let padded: Uint8Array | null = null;
  try {
    padded = openEnvelope({
      envelope: input.envelope,
      expectedKind: "wa",
      holder: "booking_guest",
      secretKey: keys.secretKey,
      context,
    });
    return decodeAnswer(unpad(padded));
  } catch {
    throw new WorkspaceSealError();
  } finally {
    wipe(padded, keys.secretKey);
  }
}
