import { sql } from "@/lib/neon";

export type PublicIdentity = { diditVerified: boolean; realHuman: boolean };

const NONE: PublicIdentity = { diditVerified: false, realHuman: false };

/**
 * Public identity result per member id, read through db/0282 (rout_public_identity_badges).
 * Only a completed Didit attestation sets diditVerified; profiles.verified and is_paid are
 * ignored. Fails closed: an unreachable database or an older schema gives no mark.
 */
export async function readPublicIdentities(userIds: readonly string[]): Promise<Map<string, PublicIdentity>> {
  const ids = [...new Set(userIds.filter(Boolean))].slice(0, 200);
  const out = new Map<string, PublicIdentity>();
  if (!ids.length) return out;
  try {
    const rows = (await sql`select user_id, didit_legal_identity, real_human
        from public.rout_public_identity_badges(${ids}::uuid[])`) as Record<string, unknown>[];
    for (const r of rows) {
      out.set(String(r["user_id"]), { diditVerified: r["didit_legal_identity"] === true, realHuman: r["real_human"] === true });
    }
  } catch (error) {
    console.warn("[public-identity:skipped]", error);
  }
  return out;
}

export async function readPublicIdentity(userId: string): Promise<PublicIdentity> {
  return (await readPublicIdentities([userId])).get(userId) ?? NONE;
}
