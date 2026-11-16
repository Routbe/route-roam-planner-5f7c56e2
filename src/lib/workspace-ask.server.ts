/**
 * Anonymous workspace questions (db-pending/0285). The browser seals everything; this module
 * verifies the Hashcash proof and envelope shape, then hands ciphertext to the definers.
 * Before 0285 is applied every call answers "unavailable".
 */
import { sql } from "@/lib/neon";
import { b64uDecode } from "@/lib/booking-engine/sealed-booking";
import { bytesToHex } from "@/lib/booking-engine/sealed-schema.server";
import { checkSealedPow } from "@/lib/crypto-enclave/sealed-pow";

export type WsAskKey = { workspaceId: string; name: string; slug: string; epoch: number; kid: string; publicKey: string };
export type WsFaqItem = { id: string; question: string; answer: string; publishedAt: string };

async function ready(): Promise<boolean> {
  try {
    const rows = (await sql`select to_regclass('public.workspace_questions') is not null as ok`) as { ok: boolean }[];
    return rows[0]?.ok === true;
  } catch {
    return false;
  }
}

export async function readWsAskKey(slug: string): Promise<WsAskKey | null> {
  if (!(await ready())) return null;
  try {
    const rows = (await sql`select public.rout_public_ws_ask_key(${slug}) as r`) as { r: WsAskKey | null }[];
    return rows[0]?.r ?? null;
  } catch (e) {
    console.warn("[ws-ask] key unavailable", e instanceof Error ? e.message : "error");
    return null;
  }
}

export async function readWsFaq(slug: string): Promise<WsFaqItem[]> {
  if (!(await ready())) return [];
  try {
    const rows = (await sql`select * from public.rout_public_ws_faq(${slug})`) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: String(r["id"]),
      question: String(r["question_text"] ?? ""),
      answer: String(r["answer_text"] ?? ""),
      publishedAt: String(r["published_at"] ?? ""),
    }));
  } catch {
    return [];
  }
}

export type WsAskInput = {
  slug: string; payloadId: string; epoch: number; envelope: string;
  guestPublicKey: string; tokenHash: string; pow: { nonce: string; epoch: number };
};
export type WsAskOutcome = { ok: true } | { ok: false; reason: string };
const REASONS = new Set(["invalid", "pow_stale", "pow_invalid", "epoch", "rate_limited", "duplicate", "unavailable"]);

export async function createWsQuestion(input: WsAskInput): Promise<WsAskOutcome> {
  const envelope = b64uDecode(input.envelope);
  const tokenHash = b64uDecode(input.tokenHash);
  if (!envelope || !tokenHash || tokenHash.length !== 32) return { ok: false, reason: "invalid" };
  const key = await readWsAskKey(input.slug);
  if (!key) return { ok: false, reason: "unavailable" };
  const pow = checkSealedPow("wsask", input.payloadId, [{ ref: key.workspaceId, envelope }], input.pow, Date.now());
  envelope.fill(0);
  if (!pow.ok) return { ok: false, reason: pow.reason };
  const hash = pow.hashes.get(key.workspaceId)!;
  try {
    const rows = (await sql`
      select public.rout_ws_question_create(${input.slug}, ${input.payloadId}::uuid, ${input.epoch}::int,
        ${input.envelope}, decode(${bytesToHex(hash)}, 'hex'), ${input.pow.nonce}, ${input.pow.epoch}::int,
        ${input.guestPublicKey}, decode(${bytesToHex(tokenHash)}, 'hex')) as r`) as { r: { ok: boolean; reason?: string } }[];
    const r = rows[0]?.r;
    if (r?.ok) return { ok: true };
    return { ok: false, reason: r?.reason && REASONS.has(r.reason) ? r.reason : "invalid" };
  } catch (e) {
    console.error("[ws-ask] create failed", e instanceof Error ? e.message : "error");
    return { ok: false, reason: "unavailable" };
  } finally {
    hash.fill(0);
    tokenHash.fill(0);
  }
}

export type WsAnswerState =
  | { ok: true; status: string; envelope: string | null; workspaceName: string; slug: string }
  | { ok: false; reason: string };

export async function fetchWsAnswer(tokenHashB64: string): Promise<WsAnswerState> {
  const tokenHash = b64uDecode(tokenHashB64);
  if (!tokenHash || tokenHash.length !== 32) return { ok: false, reason: "invalid" };
  if (!(await ready())) return { ok: false, reason: "unavailable" };
  try {
    const rows = (await sql`select public.rout_ws_answer_fetch(decode(${bytesToHex(tokenHash)}, 'hex')) as r`) as { r: WsAnswerState }[];
    return rows[0]?.r ?? { ok: false, reason: "not_found" };
  } catch {
    return { ok: false, reason: "unavailable" };
  } finally {
    tokenHash.fill(0);
  }
}
