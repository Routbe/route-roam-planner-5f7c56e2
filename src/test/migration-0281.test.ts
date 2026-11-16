// @vitest-environment node
/**
 * db/0281 on an offline replay of db/: a visitor (rout_app without member context) learns
 * only whether a verified profile passed a legal-identity check (Didit) or a unique-human
 * check, never the attestation itself. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const DIDIT = "00000000-0000-4000-8000-0000000000a1";
const UPGRADED = "00000000-0000-4000-8000-0000000000a2";
const HUMAN = "00000000-0000-4000-8000-0000000000a3";
const NOT_VERIFIED = "00000000-0000-4000-8000-0000000000a4";
const FAILED = "00000000-0000-4000-8000-0000000000a5";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  const ids = [DIDIT, UPGRADED, HUMAN, NOT_VERIFIED, FAILED];
  await db.exec(`
    insert into public.users (id, email) values ${ids.map((id, i) => `('${id}', 'm${i}@example.test')`).join(", ")};
    insert into public.profiles (id, username, verified) values
      ('${DIDIT}', 'didit', true), ('${UPGRADED}', 'upgraded', true), ('${HUMAN}', 'human', true),
      ('${NOT_VERIFIED}', 'notverified', false), ('${FAILED}', 'failed', true)
      on conflict (id) do update set username = excluded.username, verified = excluded.verified;
    insert into public.identity_verifications (user_id, is_verified, verified_real_name, verification_provider, unique_human_id) values
      ('${DIDIT}', true, 'Ann Didit', 'didit', 'h1'),
      ('${UPGRADED}', true, 'Bo W', 'w_identity', 'h2'),
      ('${HUMAN}', true, 'Cy W', 'w_identity', 'h3'),
      ('${NOT_VERIFIED}', true, 'Di Didit', 'didit', 'h4'),
      ('${FAILED}', false, 'Ed P', 'didit', 'h5');
    insert into public.verified_identities (user_id, identity_nullifier, provider, tier, tier_1_real_human, tier_2_legal_identity, national_id_nullifier, legal_name) values
      ('${UPGRADED}', 'n2', 'w_identity', 'tier_2_legal_identity', true, true, 'nid2', 'Bo Legal');
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

/** Calls the function as a visitor: rout_app with no member in the transaction context. */
async function asVisitor(id: string) {
  await db.exec("begin; set local role rout_app;");
  try {
    const r = await db.query<{ tier_1_real_human: boolean; tier_2_legal_identity: boolean }>(
      "select * from public.rout_public_identity_tiers($1::uuid)", [id]);
    return r.rows;
  } finally {
    await db.exec("rollback;");
  }
}

describe("db/0281 rout_public_identity_tiers", () => {
  it("visitors cannot read the Didit attestation table directly", async () => {
    await db.exec("begin; set local role rout_app;");
    try {
      const r = await db.query("select * from public.identity_verifications");
      expect(r.rows).toHaveLength(0);
    } finally { await db.exec("rollback;"); }
  });
  it("shows legal identity for a Didit-verified profile", async () => {
    expect(await asVisitor(DIDIT)).toEqual([{ tier_1_real_human: true, tier_2_legal_identity: true }]);
  });
  it("shows legal identity after a tier-1 to Didit upgrade", async () => {
    expect(await asVisitor(UPGRADED)).toEqual([{ tier_1_real_human: true, tier_2_legal_identity: true }]);
  });
  it("shows only real human for a W Identity check", async () => {
    expect(await asVisitor(HUMAN)).toEqual([{ tier_1_real_human: true, tier_2_legal_identity: false }]);
  });
  it("a Didit check that did not pass gives no tier", async () => {
    expect(await asVisitor(FAILED)).toEqual([{ tier_1_real_human: false, tier_2_legal_identity: false }]);
  });
  it("returns nothing for a profile that is not verified", async () => {
    expect(await asVisitor(NOT_VERIFIED)).toEqual([]);
  });
  it("PUBLIC cannot execute it; rout_app can", async () => {
    const can = async (role: string) => (await db.query<{ ok: boolean }>(
      "select has_function_privilege($1, 'public.rout_public_identity_tiers(uuid)', 'execute') as ok", [role])).rows[0]!.ok;
    expect(await can("rout_app")).toBe(true);
    const pub = await db.query<{ n: number }>(
      "select count(*)::int as n from aclexplode((select proacl from pg_proc where oid = 'public.rout_public_identity_tiers(uuid)'::regprocedure)) a where a.grantee = 0");
    expect(pub.rows[0]!.n).toBe(0);
  });
});
