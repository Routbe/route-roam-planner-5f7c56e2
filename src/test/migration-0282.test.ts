// @vitest-environment node
/**
 * db/0282 on an offline replay of db/: the blue identity mark comes only from a completed
 * Didit attestation. profiles.verified and is_paid (payment, Pro, admin grants) never count.
 * Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const DIDIT_UNPAID = "00000000-0000-4000-8000-0000000000b1";
const PAID_ONLY = "00000000-0000-4000-8000-0000000000b2";
const UPGRADED = "00000000-0000-4000-8000-0000000000b3";
const HUMAN = "00000000-0000-4000-8000-0000000000b4";
const FAILED = "00000000-0000-4000-8000-0000000000b5";
const ALL = [DIDIT_UNPAID, PAID_ONLY, UPGRADED, HUMAN, FAILED];

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values ${ALL.map((id, i) => `('${id}', 'b${i}@example.test')`).join(", ")};
    insert into public.profiles (id, username, verified, is_paid) values
      ('${DIDIT_UNPAID}', 'diditunpaid', false, false), ('${PAID_ONLY}', 'paidonly', true, true),
      ('${UPGRADED}', 'upgraded2', false, false), ('${HUMAN}', 'human2', false, false), ('${FAILED}', 'failed2', true, true)
      on conflict (id) do update set username = excluded.username, verified = excluded.verified, is_paid = excluded.is_paid;
    insert into public.identity_verifications (user_id, is_verified, verified_real_name, verification_provider, unique_human_id) values
      ('${DIDIT_UNPAID}', true, 'Ann Didit', 'didit', 'k1'),
      ('${UPGRADED}', true, 'Bo W', 'w_identity', 'k3'),
      ('${HUMAN}', true, 'Cy W', 'w_identity', 'k4'),
      ('${FAILED}', false, 'Ed P', 'didit', 'k5');
    insert into public.verified_identities (user_id, identity_nullifier, provider, tier, tier_1_real_human, tier_2_legal_identity, national_id_nullifier, legal_name) values
      ('${UPGRADED}', 'm3', 'w_identity', 'tier_2_legal_identity', true, true, 'nid3', 'Bo Legal');
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

async function asVisitor<T>(query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    return (await db.query<T>(query, params)).rows;
  } finally {
    await db.exec("rollback;");
  }
}

type Badge = { user_id: string; didit_legal_identity: boolean; real_human: boolean };
async function badges(ids: string[]) {
  const rows = await asVisitor<Badge>("select * from public.rout_public_identity_badges($1::uuid[])", [ids]);
  return new Map(rows.map((r) => [r.user_id, r]));
}

describe("db/0282 rout_public_identity_badges", () => {
  it("a passed Didit check gives the mark even without payment", async () => {
    expect((await badges([DIDIT_UNPAID])).get(DIDIT_UNPAID)).toMatchObject({ didit_legal_identity: true, real_human: true });
  });
  it("a paid or legacy verified account without Didit gets no mark", async () => {
    expect((await badges([PAID_ONLY])).get(PAID_ONLY)).toMatchObject({ didit_legal_identity: false, real_human: false });
  });
  it("a tier-1 member upgraded through Didit keeps the mark", async () => {
    expect((await badges([UPGRADED])).get(UPGRADED)?.didit_legal_identity).toBe(true);
  });
  it("W Identity proves a real human, not a legal identity", async () => {
    expect((await badges([HUMAN])).get(HUMAN)).toMatchObject({ didit_legal_identity: false, real_human: true });
  });
  it("a Didit check that did not pass gives nothing, even on a paid account", async () => {
    expect((await badges([FAILED])).get(FAILED)).toMatchObject({ didit_legal_identity: false, real_human: false });
  });
  it("answers at most 200 ids per call", async () => {
    const many = [...Array.from({ length: 250 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`), DIDIT_UNPAID];
    expect((await badges(many)).has(DIDIT_UNPAID)).toBe(false);
  });
  it("the community count includes only Didit results", async () => {
    const [r] = await asVisitor<{ n: number }>("select public.rout_public_didit_member_count() as n");
    expect(r!.n).toBe(2);
  });
  it("PUBLIC cannot execute either function; rout_app can", async () => {
    for (const fn of ["public.rout_public_identity_badges(uuid[])", "public.rout_public_didit_member_count()"]) {
      const can = (await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [fn])).rows[0]!.ok;
      expect(can).toBe(true);
      const pub = await db.query<{ n: number }>(
        `select count(*)::int as n from aclexplode((select proacl from pg_proc where oid = '${fn}'::regprocedure)) a where a.grantee = 0`);
      expect(pub.rows[0]!.n).toBe(0);
    }
  });
});
