// @vitest-environment node
/**
 * db/0283 on an offline replay of db/: the workspace support page. Only owner/admin manage
 * it, the IBAN holder must match the owner's Didit name or the verified-domain workspace
 * name, visitors see only an active and still eligible page, and rout_app has no table
 * rights. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const OWNER = "00000000-0000-4000-8000-0000000000c1";
const ADMIN = "00000000-0000-4000-8000-0000000000c2";
const EDITOR = "00000000-0000-4000-8000-0000000000c3";
const OUTSIDER = "00000000-0000-4000-8000-0000000000c4";
const PLAIN_OWNER = "00000000-0000-4000-8000-0000000000c5";
const WS_DIDIT = "00000000-0000-4000-8000-0000000000d1";
const WS_DOMAIN = "00000000-0000-4000-8000-0000000000d2";
const WS_NONE = "00000000-0000-4000-8000-0000000000d3";
const IBAN = "BE68539007547034";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  const users = [OWNER, ADMIN, EDITOR, OUTSIDER, PLAIN_OWNER];
  await db.exec(`
    insert into public.users (id, email) values ${users.map((id, i) => `('${id}', 'c${i}@example.test')`).join(", ")};
    insert into public.workspaces (id, name, slug, domain, domain_verified_at) values
      ('${WS_DIDIT}', 'Didit Club', 'didit-club', null, null),
      ('${WS_DOMAIN}', 'Domein BV', 'domein-bv', 'domein.example', now()),
      ('${WS_NONE}', 'Nobody', 'nobody-ws', null, null);
    insert into public.workspace_members (workspace_id, user_id, role) values
      ('${WS_DIDIT}', '${OWNER}', 'owner'), ('${WS_DIDIT}', '${ADMIN}', 'admin'), ('${WS_DIDIT}', '${EDITOR}', 'editor'),
      ('${WS_DOMAIN}', '${PLAIN_OWNER}', 'owner'), ('${WS_NONE}', '${PLAIN_OWNER}', 'owner');
    insert into public.identity_verifications (user_id, is_verified, verified_real_name, verification_provider, unique_human_id) values
      ('${OWNER}', true, 'Ann Ëlise Didit', 'didit', 'w1');
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

async function as<T>(userId: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    return (await db.query<T>(query, params)).rows;
  } finally {
    await db.exec("rollback;");
  }
}
async function asCommit<T>(userId: string, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const r = (await db.query<T>(query, params)).rows;
    await db.exec("commit;");
    return r;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}

const SAVE = "select public.rout_ws_support_save($1::uuid, $2, $3, $4, $5::int[], true, 100, 'Dank je', false) as r";
const save = (user: string, ws: string, name: string, enabled = true) =>
  asCommit<{ r: string }>(user, SAVE, [ws, enabled, IBAN, name, [500, 1000]]).then((x) => x[0]!.r);

describe("db/0283 workspace support page", () => {
  it("rout_app cannot read or write the tables directly", async () => {
    await expect(as(OWNER, "select * from public.workspace_tip_settings")).rejects.toThrow(/permission denied/);
    await expect(as(OWNER, "select * from public.workspace_psp_credentials")).rejects.toThrow(/permission denied/);
  });
  it("editors and outsiders cannot manage the page", async () => {
    expect(await save(EDITOR, WS_DIDIT, "Ann Elise Didit")).toBe("forbidden");
    expect(await save(OUTSIDER, WS_DIDIT, "Ann Elise Didit")).toBe("forbidden");
    expect(await as(EDITOR, "select * from public.rout_ws_support_get($1::uuid)", [WS_DIDIT])).toEqual([]);
  });
  it("a workspace without a Didit owner or verified domain is not eligible", async () => {
    expect(await save(PLAIN_OWNER, WS_NONE, "Nobody")).toBe("not_eligible");
  });
  it("the holder must match the owner's Didit name (accents and spacing ignored)", async () => {
    expect(await save(ADMIN, WS_DIDIT, "Someone Else")).toBe("name_mismatch");
    expect(await save(ADMIN, WS_DIDIT, "ann elise  didit")).toBe("ok");
  });
  it("a verified domain lets the workspace name be the holder", async () => {
    expect(await save(PLAIN_OWNER, WS_DOMAIN, "Domein B.V.")).toBe("ok");
  });
  it("managers see eligibility without the owner's legal name", async () => {
    const [r] = await as<Record<string, unknown>>(ADMIN, "select * from public.rout_ws_support_get($1::uuid)", [WS_DIDIT]);
    expect(r).toMatchObject({ enabled: true, owner_didit: true, domain_verified: false });
    expect(Object.keys(r!)).not.toContain("legal_name");
  });
  it("visitors see an active page and nothing for an unknown or disabled one", async () => {
    const [p] = await as<Record<string, unknown>>(null, "select * from public.rout_public_ws_support('didit-club')");
    expect(p).toMatchObject({ slug: "didit-club", iban: IBAN, providers: [] });
    expect(await as(null, "select * from public.rout_public_ws_support('nobody-ws')")).toEqual([]);
  });
  it("the page closes when the owner's Didit result is gone", async () => {
    await db.exec(`update public.identity_verifications set verification_provider = 'w_identity' where user_id = '${OWNER}'`);
    try {
      expect(await as(null, "select * from public.rout_public_ws_support('didit-club')")).toEqual([]);
    } finally {
      await db.exec(`update public.identity_verifications set verification_provider = 'didit' where user_id = '${OWNER}'`);
    }
  });
  it("provider keys: managers only, never readable, and served only for an active page", async () => {
    expect((await as<{ r: string }>(EDITOR, "select public.rout_ws_psp_save($1::uuid, 'mollie', 'ct', 'iv', 'abcd', 'test', null) as r", [WS_DIDIT]))[0]!.r).toBe("forbidden");
    expect((await asCommit<{ r: string }>(ADMIN, "select public.rout_ws_psp_save($1::uuid, 'mollie', 'ct', 'iv', 'abcd', 'test', null) as r", [WS_DIDIT]))[0]!.r).toBe("ok");
    expect(await as(null, "select * from public.rout_ws_psp_tip_credential('didit-club', 'mollie')")).toEqual([]);
    await asCommit(ADMIN, "select public.rout_ws_support_save($1::uuid, true, $2, 'Ann Elise Didit', '{500}'::int[], true, 100, null, true)", [WS_DIDIT, IBAN]);
    const [p] = await as<{ providers: string[] }>(null, "select providers from public.rout_public_ws_support('didit-club')");
    expect(p!.providers).toEqual(["mollie"]);
    expect(await as(null, "select ciphertext from public.rout_ws_psp_tip_credential('didit-club', 'mollie')")).toEqual([{ ciphertext: "ct" }]);
    expect(await as(null, "select ciphertext from public.rout_ws_psp_tip_credential('didit-club', 'stripe')")).toEqual([]);
  });
  it("internal helpers are not callable by rout_app or PUBLIC", async () => {
    for (const fn of ["public.rout_ws_support_manager(uuid)", "public.rout_ws_support_names(uuid)", "public.rout_ws_support_norm(text)"]) {
      expect((await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [fn])).rows[0]!.ok).toBe(false);
    }
  });
});
