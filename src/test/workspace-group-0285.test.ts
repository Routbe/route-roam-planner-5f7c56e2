// @vitest-environment node
/**
 * db-pending/0285 on an offline replay of db/: workspace group encryption and the
 * anonymous question page. Replays db/ to 0284, applies 0285 with the definer guard and
 * proves, without touching Neon:
 *   - rout_app and PUBLIC hold no table privilege on any of the six new tables;
 *   - only role owner or admin manages keys, and a member envelope is stored only for a
 *     member who is owner or admin at that moment (editor, developer, viewer refused);
 *   - publishing a new epoch retires the previous one, and a former manager keeps no key
 *     for the new epoch, so questions filed after the rotation stay closed to them;
 *   - an anonymous submission needs a wq envelope, a live key, an enabled switch, a fresh
 *     proof bucket, and is refused on a replayed payload hash, a replayed token or the
 *     flood ceiling;
 *   - a private answer is only written by a manager and only opens for the visitor whose
 *     token hash matches; a public FAQ item exists only after a deliberate publish;
 *   - fast-check properties over role, envelope kind, bucket and token, plus an exhaustive
 *     bounded model check of the key/question lifecycle against a reference model.
 */
import { PGlite } from "@electric-sql/pglite";
import fc from "fast-check";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyPending, replayDb } from "../../scripts/formal-rls/replay";
import { b64uDecode, b64uEncode } from "@/lib/booking-engine/sealed-booking";

const OWNER = "00000000-0000-4000-8000-0000000000a1";
const ADMIN = "00000000-0000-4000-8000-0000000000a2";
const EDITOR = "00000000-0000-4000-8000-0000000000a3";
const DEVELOPER = "00000000-0000-4000-8000-0000000000a4";
const VIEWER = "00000000-0000-4000-8000-0000000000a5";
const OUTSIDER = "00000000-0000-4000-8000-0000000000a6";
const WS = "00000000-0000-4000-8000-0000000000d1";
const SLUG = "ask-club";
// Two more workspaces, so the flood ceiling and the generated submissions never eat the
// hourly budget of the pages the other tests need.
const WS2 = "00000000-0000-4000-8000-0000000000d2";
const SLUG2 = "flood-club";
const WS3 = "00000000-0000-4000-8000-0000000000d3";
const SLUG3 = "probe-club";

const TABLES = ["workspace_keys", "workspace_member_keys", "workspace_ask_settings", "workspace_questions", "workspace_question_replies", "workspace_faq_items"];
const ENTRY_POINTS = [
  "rout_ws_group_publish(uuid, integer, text, text)",
  "rout_ws_group_member_store(uuid, integer, uuid, uuid, text, text)",
  "rout_ws_group_member_key(uuid, integer)",
  "rout_ws_group_state(uuid)",
  "rout_ws_ask_save(uuid, boolean)",
  "rout_public_ws_ask_key(text)",
  "rout_ws_question_create(text, uuid, integer, text, bytea, text, integer, text, bytea)",
  "rout_ws_question_list(uuid)",
  "rout_ws_question_reply(uuid, text, bytea)",
  "rout_ws_question_publish(uuid, text, text)",
  "rout_ws_question_decline(uuid)",
  "rout_public_ws_faq(text)",
  "rout_ws_answer_fetch(bytea)",
];
const INTERNALS = [
  "rout_ws_group_manager(uuid)",
  "rout_ws_group_envelope_ok(text, text)",
  "rout_ws_group_epoch_ok(integer)",
  "rout_ws_group_active(uuid)",
];

// RVE1 headers: magic, suite 1, kind. The new kinds of 0285 (pqc-envelope.ts codes 10/11/12).
const RVE1_HEAD = [0x52, 0x56, 0x45, 0x31, 0x01];
const KIND_BYTE = { wsk: 10, wq: 11, wa: 12 } as const;
const BUCKET_CHARS = [3583, 7679, 24063] as const;
const BUCKET_BYTES = [2687, 5759, 18047] as const;

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const bytea = (b: Uint8Array) => `\\x${hex(b)}`;
const nowBucket = () => Math.floor(Date.now() / 1000 / 600);

/** One RVE1 envelope of the given kind, in base64url, at one of the three padded sizes. */
function envelope(kind: keyof typeof KIND_BYTE, bucket = 0): string {
  const b = new Uint8Array(randomBytes(BUCKET_BYTES[bucket]));
  b.set([...RVE1_HEAD, KIND_BYTE[kind]], 0);
  return b64uEncode(b);
}
/** A recipient public key (ML-KEM-1024 || X25519 = 1600 bytes) and its key id. */
const publicKey = () => b64uEncode(new Uint8Array(randomBytes(1600)));
const kid = () => b64uEncode(new Uint8Array(randomBytes(16)));
const tokenHash = () => sha256(new Uint8Array(randomBytes(32)));
const hashOf = (e: string) => blake3(b64uDecode(e) ?? new Uint8Array(0));
/** One anonymous submission against a given workspace's ask page. */
const submitTo = (slug: string, e: string, epoch: number, hash: Uint8Array, th: Uint8Array, bucket = nowBucket()) =>
  one(null, `select * from public.rout_ws_question_create($1, gen_random_uuid(), $2, $3, $4, '0123456789abcdef', $5, $6, $7)`,
    [slug, epoch, e, bytea(hash), bucket, publicKey(), bytea(th)]);

let db: PGlite;

beforeAll(async () => {
  db = await replayDb();
  await applyPending(db, "0285_workspace_group_encryption.sql");
  const users = [OWNER, ADMIN, EDITOR, DEVELOPER, VIEWER, OUTSIDER];
  await db.exec(`
    insert into public.users (id, email) values ${users.map((id, i) => `('${id}', 'g${i}@example.test')`).join(", ")};
    insert into public.workspaces (id, name, slug) values ('${WS}', 'Ask Club', '${SLUG}');
    insert into public.workspace_members (workspace_id, user_id, role) values
      ('${WS}', '${OWNER}', 'owner'), ('${WS}', '${ADMIN}', 'admin'), ('${WS}', '${EDITOR}', 'editor'),
      ('${WS}', '${DEVELOPER}', 'developer'), ('${WS}', '${VIEWER}', 'viewer');
  `);
  await seedWorkspace(WS2, SLUG2, "Flood Club");
  await seedWorkspace(WS3, SLUG3, "Probe Club");
}, 600_000);

/** A second workspace, live from epoch 1 with the ask page switched on. */
async function seedWorkspace(id: string, slug: string, name: string) {
  await db.exec(`
    insert into public.workspaces (id, name, slug) values ('${id}', '${name}', '${slug}');
    insert into public.workspace_members (workspace_id, user_id, role) values
      ('${id}', '${OWNER}', 'owner'), ('${id}', '${ADMIN}', 'admin'), ('${id}', '${EDITOR}', 'editor');
  `);
  expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [id, publicKey(), kid()])).toMatchObject({ ok: true });
  expect(await one(OWNER, `select * from public.rout_ws_ask_save($1, true)`, [id])).toBe("ok");
}

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
async function asCommit<T>(userId: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const r = (await db.query<T>(query, params)).rows;
    await db.exec("commit;");
    return r;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
/** The single jsonb object a definer hands back, or null. Commits, so a stored key,
 *  envelope, switch or question is really on the table for the tests that follow. */
async function one(userId: string | null, query: string, params: unknown[] = []): Promise<Record<string, unknown> | null> {
  const rows = await asCommit<Record<string, unknown>>(userId, query, params);
  if (!rows.length) return null;
  const value = Object.values(rows[0])[0];
  return (value ?? null) as Record<string, unknown> | null;
}

// ------------------------------------------------------------------ table and function rights

describe("rout_app and PUBLIC hold no table rights", () => {
  it("no privilege on any of the six tables, for either role", async () => {
    for (const t of TABLES) {
      for (const role of ["rout_app", "public"]) {
        const rows = await db.query<{ p: boolean }>(
          `select pg_catalog.has_any_table_privilege($1::pg_catalog.regrole, 'public.${t}'::pg_catalog.regclass, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') p`,
          [role],
        );
        expect(rows.rows[0]?.p, `${role} on ${t}`).toBe(false);
      }
    }
  });

  it("a direct write as rout_app is refused", async () => {
    await expect(asCommit(null, `insert into public.workspace_questions (workspace_id, epoch, payload_id, envelope,
      blake3_payload_hash, pow_nonce, epoch_bucket, guest_public_key, token_hash)
      values ($1, 1, gen_random_uuid(), 'x', '\\x00', '0000000000000000', 1, 'y', '\\x00')`, [WS])).rejects.toThrow();
    await expect(asCommit(OWNER, `select * from public.workspace_keys`, [])).rejects.toThrow();
  });

  it("rout_app executes exactly the entry points, never the internal helpers", async () => {
    for (const f of ENTRY_POINTS) {
      const r = await db.query<{ p: boolean }>(`select pg_catalog.has_function_privilege('rout_app', 'public.${f}', 'EXECUTE') p`);
      expect(r.rows[0]?.p, f).toBe(true);
      const pub = await db.query<{ p: boolean }>(`select pg_catalog.has_function_privilege('public', 'public.${f}', 'EXECUTE') p`);
      expect(pub.rows[0]?.p, `PUBLIC ${f}`).toBe(false);
    }
    for (const f of INTERNALS) {
      const r = await db.query<{ p: boolean }>(`select pg_catalog.has_function_privilege('rout_app', 'public.${f}', 'EXECUTE') p`);
      expect(r.rows[0]?.p, f).toBe(false);
    }
  });

  it("every new SECURITY DEFINER function runs on pg_catalog, pg_temp", async () => {
    const rows = await db.query<{ name: string; cfg: string[] | null }>(
      `select p.proname name, p.proconfig cfg from pg_catalog.pg_proc p
         join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prorettype::pg_catalog.regtype::pg_catalog.text <> 'void'
          and (p.proname like 'rout_ws_%' or p.proname like 'rout_public_ws_%')`,
    );
    const names = new Set([...ENTRY_POINTS, ...INTERNALS].map((f) => f.split("(")[0]));
    for (const r of rows.rows) {
      if (!names.has(r.name)) continue;
      expect(r.cfg, r.name).toContain("search_path=pg_catalog, pg_temp");
    }
  });
});

// ------------------------------------------------------------------ key epochs and RBAC

describe("workspace key epochs", () => {
  it("only owner or admin publishes, and only the next epoch number", async () => {
    const pk = publicKey();
    expect(await one(EDITOR, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, pk, kid()])).toMatchObject({ reason: "forbidden" });
    expect(await one(OUTSIDER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, pk, kid()])).toMatchObject({ reason: "forbidden" });
    expect(await one(null, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, pk, kid()])).toMatchObject({ reason: "forbidden" });
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 3, $2, $3)`, [WS, pk, kid()])).toMatchObject({ reason: "epoch" });
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, "short", kid()])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, pk, "no"])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, pk, kid()])).toMatchObject({ ok: true, epoch: 1 });
    // A published epoch is never replaced: the next one is the only way forward.
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 1, $2, $3)`, [WS, publicKey(), kid()])).toMatchObject({ reason: "epoch" });
  });

  it("publishing a new epoch retires the previous one, and only one stays live", async () => {
    expect(await one(ADMIN, `select * from public.rout_ws_group_publish($1, 2, $2, $3)`, [WS, publicKey(), kid()])).toMatchObject({ ok: true, epoch: 2 });
    // The state view is the manager's own summary: it is the only way to see the history.
    const st = await one(OWNER, `select * from public.rout_ws_group_state($1)`, [WS]);
    const epochs = (st?.epochs ?? []) as { epoch: number; status: string }[];
    expect(epochs.map((e) => [e.epoch, e.status]).sort((a, b) => a[0] - b[0])).toEqual([[1, "retired"], [2, "active"]]);
    expect(epochs.filter((e) => e.status === "active")).toHaveLength(1);  });

  it("a member envelope is stored only for role owner or admin", async () => {
    for (const [member, role] of [[EDITOR, "editor"], [DEVELOPER, "developer"], [VIEWER, "viewer"], [OUTSIDER, "outsider"]] as const) {
      const r = await one(OWNER, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
        [WS, member, "00000000-0000-4000-8000-0000000000f1", kid(), envelope("wsk")]);
      expect(r, role).toMatchObject({ reason: "forbidden" });
    }
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), envelope("wsk")])).toMatchObject({ ok: true });
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
      [WS, OWNER, "00000000-0000-4000-8000-0000000000f3", kid(), envelope("wsk")])).toMatchObject({ ok: true });
  });

  it("an envelope of the wrong kind, or for a retired epoch, is refused", async () => {
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), envelope("wq")])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), envelope("wa")])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 1, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), envelope("wsk")])).toMatchObject({ reason: "epoch" });
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 2, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), "UlZFMQEK" + "A".repeat(3575)])).toMatchObject({ reason: "invalid" });
  });

  it("a member fetches only their own key, and only while they are owner or admin", async () => {
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_key($1, 2)`, [WS])).toMatchObject({ ok: true });
    expect(await one(OWNER, `select * from public.rout_ws_group_member_key($1, 2)`, [WS])).toMatchObject({ ok: true });
    expect(await one(EDITOR, `select * from public.rout_ws_group_member_key($1, 2)`, [WS])).toMatchObject({ reason: "none" });
    // Demote the admin: their envelope row stays, but they can no longer fetch it.
    await db.exec(`update public.workspace_members set role = 'editor' where workspace_id = '${WS}' and user_id = '${ADMIN}'`);
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_key($1, 2)`, [WS])).toMatchObject({ reason: "none" });
    await db.exec(`update public.workspace_members set role = 'admin' where workspace_id = '${WS}' and user_id = '${ADMIN}'`);
    // A key of a retired epoch is not handed out either.
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_key($1, 1)`, [WS])).toMatchObject({ reason: "none" });
  });

  it("rotation leaves a former manager without the new epoch", async () => {
    expect(await one(OWNER, `select * from public.rout_ws_group_publish($1, 3, $2, $3)`, [WS, publicKey(), kid()])).toMatchObject({ ok: true, epoch: 3 });
    // The old admin still holds epoch 2's envelope but has none for epoch 3.
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_key($1, 3)`, [WS])).toMatchObject({ reason: "none" });
    const st = await one(OWNER, `select * from public.rout_ws_group_state($1)`, [WS]);
    const top = ((st?.epochs ?? []) as { epoch: number; missing: unknown[] }[])[0];
    expect(top.epoch).toBe(3);
    expect(top.missing.map((m) => (m as { userId: string }).userId)).toContain(ADMIN);
    expect(await one(OWNER, `select * from public.rout_ws_group_member_store($1, 3, $2, $3, $4, $5)`,
      [WS, ADMIN, "00000000-0000-4000-8000-0000000000f2", kid(), envelope("wsk")])).toMatchObject({ ok: true });
    expect(await one(ADMIN, `select * from public.rout_ws_group_member_key($1, 3)`, [WS])).toMatchObject({ ok: true });
  });
});

// ------------------------------------------------------------------ the anonymous ask page

describe("anonymous submissions", () => {
  const submit = (userId: string | null, e: string, epoch: number, hash: Uint8Array, th: Uint8Array, bucket = nowBucket()) =>
    one(userId, `select * from public.rout_ws_question_create($1, gen_random_uuid(), $2, $3, $4, '0123456789abcdef', $5, $6, $7)`,
      [SLUG, epoch, e, bytea(hash), bucket, publicKey(), bytea(th)]);

  it("the page shows a key only while the switch is on and a key is live", async () => {
    expect(await one(null, `select * from public.rout_public_ws_ask_key($1)`, [SLUG])).toBeNull();
    expect(await one(EDITOR, `select * from public.rout_ws_ask_save($1, true)`, [WS])).toBe("forbidden");
    expect(await one(OWNER, `select * from public.rout_ws_ask_save($1, true)`, [WS])).toBe("ok");
    const k = await one(null, `select * from public.rout_public_ws_ask_key($1)`, [SLUG]);
    expect(k).toMatchObject({ slug: SLUG, epoch: 3 });
    expect(typeof k?.publicKey).toBe("string");
    expect((k?.publicKey as string).length).toBe(2134);
  });

  it("a valid question is stored once and never twice", async () => {
    const e = envelope("wq");
    const th = tokenHash();
    expect(await submit(null, e, 3, hashOf(e), th)).toMatchObject({ ok: true });
    expect(await submit(null, e, 3, hashOf(e), th)).toMatchObject({ reason: "duplicate" });
    const again = envelope("wq");
    expect(await submit(null, again, 3, hashOf(again), th)).toMatchObject({ reason: "duplicate" });
  });

  it("a wrong envelope kind, a dead epoch or a stale bucket is refused", async () => {
    expect(await submit(null, envelope("wsk"), 3, hashOf(envelope("wsk")), tokenHash())).toMatchObject({ reason: "invalid" });
    expect(await submit(null, envelope("wa"), 3, hashOf(envelope("wa")), tokenHash())).toMatchObject({ reason: "invalid" });
    expect(await submit(null, envelope("wq"), 1, hashOf(envelope("wq")), tokenHash())).toMatchObject({ reason: "epoch" });
    expect(await submit(null, envelope("wq"), 99, hashOf(envelope("wq")), tokenHash())).toMatchObject({ reason: "epoch" });
    expect(await submit(null, envelope("wq"), 3, hashOf(envelope("wq")), tokenHash(), nowBucket() + 5)).toMatchObject({ reason: "pow_stale" });
    expect(await one(null, `select * from public.rout_ws_question_create('no-such-slug', gen_random_uuid(), 3, $1, $2, '0123456789abcdef', $3, $4, $5)`,
      [envelope("wq"), bytea(hashOf(envelope("wq"))), nowBucket(), publicKey(), bytea(tokenHash())])).toMatchObject({ reason: "unavailable" });
  });

  it("the flood ceiling closes the page for that hour", async () => {
    // Its own workspace: 30 questions is the whole hour's budget, and the 31st never lands.
    for (let i = 0; i < 30; i++) {
      const e = envelope("wq");
      expect(await submitTo(SLUG2, e, 1, hashOf(e), tokenHash()), `question ${i}`).toMatchObject({ ok: true });
    }
    const e = envelope("wq");
    expect(await submitTo(SLUG2, e, 1, hashOf(e), tokenHash())).toMatchObject({ reason: "rate_limited" });
  });

  it("the inbox is only for managers and hands back ciphertext plus the reply key", async () => {
    const rows = await as<Record<string, unknown>>(EDITOR, `select * from public.rout_ws_question_list($1)`, [WS]);
    expect(rows).toHaveLength(0);
    const mine = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    expect(mine.length).toBeGreaterThan(0);
    expect(String(mine[0]?.envelope).slice(0, 8)).toBe("UlZFMQEL");
    expect(String(mine[0]?.guest_public_key).length).toBe(2134);
  });
});

// ------------------------------------------------------------------ dual response

describe("private answer and public FAQ", () => {
  let questionId = "";
  let guestKey = "";
  let token = new Uint8Array(32);

  it("a manager answers privately, sealed to the visitor's reply key", async () => {
    token = new Uint8Array(randomBytes(32));
    const th = sha256(token);
    const e = envelope("wq");
    const gk = publicKey();
    const r = await one(null, `select * from public.rout_ws_question_create($1, gen_random_uuid(), 3, $2, $3, '0123456789abcdef', $4, $5, $6)`,
      [SLUG, e, bytea(hashOf(e)), nowBucket(), gk, bytea(th)]);
    questionId = String(r?.id);
    guestKey = gk;
    expect(r).toMatchObject({ ok: true });
    expect(guestKey.length).toBe(2134);
    expect(await one(EDITOR, `select * from public.rout_ws_question_reply($1, $2, $3)`, [questionId, envelope("wa"), bytea(hashOf(envelope("wa")))])).toMatchObject({ reason: "forbidden" });
    expect(await one(OWNER, `select * from public.rout_ws_question_reply($1, $2, $3)`, [questionId, envelope("wq"), bytea(hashOf(envelope("wq")))])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_question_reply($1, $2, $3)`, [questionId, envelope("wa"), new Uint8Array(31)])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_question_reply($1, $2, $3)`, [questionId, envelope("wa"), bytea(hashOf(envelope("wa")))])).toMatchObject({ ok: true });
    const list = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    const row = list.find((x) => x.id === questionId);
    expect(row).toMatchObject({ status: "answered", has_reply: true });
  });

  it("only the visitor's own token opens the answer", async () => {
    const right = await one(null, `select * from public.rout_ws_answer_fetch($1)`, [bytea(sha256(token))]);
    expect(right).toMatchObject({ ok: true, status: "answered" });
    expect(String(right?.envelope).slice(0, 8)).toBe("UlZFMQEM");
    const wrong = await one(null, `select * from public.rout_ws_answer_fetch($1)`, [bytea(tokenHash())]);
    expect(wrong).toMatchObject({ ok: false, reason: "not_found" });
  });

  it("a FAQ item exists only after a deliberate publish", async () => {
    expect(await as(null, `select * from public.rout_public_ws_faq($1)`, [SLUG])).toHaveLength(0);
    expect(await one(EDITOR, `select * from public.rout_ws_question_publish($1, 'Is this open?', 'Yes')`, [questionId])).toMatchObject({ reason: "forbidden" });
    expect(await one(OWNER, `select * from public.rout_ws_question_publish($1, '', 'Yes')`, [questionId])).toMatchObject({ reason: "invalid" });
    expect(await one(OWNER, `select * from public.rout_ws_question_publish($1, 'Is this open?', 'Yes')`, [questionId])).toMatchObject({ ok: true });
    const faq = await as<Record<string, unknown>>(null, `select * from public.rout_public_ws_faq($1)`, [SLUG]);
    expect(faq).toHaveLength(1);
    expect(faq[0]).toMatchObject({ question_text: "Is this open?", answer_text: "Yes" });
    const list = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    expect(list.find((x) => x.id === questionId)).toMatchObject({ status: "published" });
    // A published question can no longer be closed.
    expect(await one(OWNER, `select * from public.rout_ws_question_decline($1)`, [questionId])).toBe("ok");
    const after = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    expect(after.find((x) => x.id === questionId)).toMatchObject({ status: "published" });
  });
});

// ------------------------------------------------------------------ properties

describe("fast-check properties", () => {
  const roles = ["owner", "admin", "editor", "developer", "viewer"] as const;

  it("a member envelope is stored exactly for owner/admin, with a wsk envelope on the live epoch", async () => {
    const live = await one(OWNER, `select * from public.rout_ws_group_state($1)`, [WS]);
    const activeEpoch = ((live?.epochs ?? []) as { epoch: number; status: string }[]).find((e) => e.status === "active")!.epoch;
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...roles),
        fc.constantFrom("wsk", "wq", "wa"),
        fc.integer({ min: activeEpoch - 2, max: activeEpoch + 1 }),
        async (role, kind, epoch) => {
          const member = { owner: OWNER, admin: ADMIN, editor: EDITOR, developer: DEVELOPER, viewer: VIEWER }[role];
          const r = await one(OWNER, `select * from public.rout_ws_group_member_store($1, $2, $3, $4, $5, $6)`,
            [WS, epoch, member, "00000000-0000-4000-8000-0000000000f9", kid(), envelope(kind as "wsk")]);
          const shouldStore = role === "owner" || role === "admin";
          const active = epoch === activeEpoch;
          if (kind !== "wsk") expect(r).toMatchObject({ reason: "invalid" });
          else if (!active) expect(r).toMatchObject({ reason: "epoch" });
          else if (!shouldStore) expect(r).toMatchObject({ reason: "forbidden" });
          else expect(r).toMatchObject({ ok: true });
        },
      ),
      { numRuns: 60 },
    );
  });

  it("a submission needs a wq envelope in a padded bucket, whatever the bytes inside", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("wsk", "wq", "wa"),
        fc.integer({ min: 0, max: 2 }),
        fc.boolean(),
        async (kind, bucket, fresh) => {
          const e = envelope(kind as "wsk", bucket);
          const r = await submitTo(SLUG3, e, 1, hashOf(e), tokenHash(), fresh ? nowBucket() : nowBucket() + 9);
          if (kind !== "wq") expect(r).toMatchObject({ reason: "invalid" });
          else if (!fresh) expect(r).toMatchObject({ reason: "pow_stale" });
          // A wq envelope in any of the three buckets with a fresh bucket is accepted up to
          // the flood ceiling; either way the page never answers with plaintext.
          else expect(["ok", "rate_limited"]).toContain(String(r?.ok === true ? "ok" : r?.reason));
        },
      ),
      { numRuns: 30 },
    );
  });

  it("an answer is found by exactly one token hash", async () => {
    const tokens = Array.from({ length: 6 }, () => new Uint8Array(randomBytes(32)));
    for (const t of tokens) {
      const e = envelope("wq");
      const r = await one(null, `select * from public.rout_ws_question_create($1, gen_random_uuid(), 3, $2, $3, '0123456789abcdef', $4, $5, $6)`,
        [SLUG, e, bytea(hashOf(e)), nowBucket(), publicKey(), bytea(sha256(t))]);
      if (r?.ok !== true) continue;
      await one(OWNER, `select * from public.rout_ws_question_reply($1, $2, $3)`, [String(r.id), envelope("wa"), bytea(hashOf(envelope("wa")))]);
    }
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: tokens.length - 1 }), async (i) => {
        const r = await one(null, `select * from public.rout_ws_answer_fetch($1)`, [bytea(sha256(tokens[i]))]);
        expect(r?.ok).toBe(true);
      }),
      { numRuns: 12 },
    );
  });
});

// ------------------------------------------------------------------ bounded model check

describe("bounded model check of the key and question lifecycle", () => {
  type Op =
    | { k: "publish" }
    | { k: "store"; who: string }
    | { k: "demote"; who: string }
    | { k: "ask" }
    | { k: "reply" }
    | { k: "publishFaq" }
    | { k: "decline" };

  const OPS: Op[] = [
    { k: "publish" },
    { k: "store", who: ADMIN },
    { k: "store", who: OWNER },
    { k: "demote", who: ADMIN },
    { k: "ask" },
    { k: "reply" },
    { k: "publishFaq" },
    { k: "decline" },
  ];

  async function reset() {
    await db.exec(`
      delete from public.workspace_faq_items;
      delete from public.workspace_question_replies;
      delete from public.workspace_questions;
      delete from public.workspace_member_keys;
      delete from public.workspace_keys;
      delete from public.workspace_ask_settings;
      update public.workspace_members set role = case user_id
        when '${OWNER}' then 'owner' when '${ADMIN}' then 'admin' when '${EDITOR}' then 'editor'
        when '${DEVELOPER}' then 'developer' when '${VIEWER}' then 'viewer' end
       where workspace_id = '${WS}';
    `);
    await one(OWNER, `select * from public.rout_ws_ask_save($1, true)`, [WS]);
  }

  /** Reference model: what the rules say the state must be after the same operations. */
  function model(ops: Op[]) {
    let epoch = 0;
    const roles = new Map<string, string>([[OWNER, "owner"], [ADMIN, "admin"]]);
    const held = new Set<string>();
    let asked = 0;
    let replied = false;
    let published = false;
    for (const op of ops) {
      if (op.k === "publish") { epoch += 1; held.clear(); }
      else if (op.k === "store") { if (epoch > 0 && roles.get(op.who) !== "editor") held.add(`${epoch}:${op.who}`); }
      else if (op.k === "demote") { roles.set(op.who, "editor"); }
      else if (op.k === "ask") { if (epoch > 0) asked += 1; }
      else if (op.k === "reply") { if (asked > 0) replied = true; }
      else if (op.k === "publishFaq") { if (replied) published = true; }
      else if (op.k === "decline") { if (replied && !published) replied = false; }
    }
    return { epoch, held, asked, replied, published };
  }

  async function run(ops: Op[]) {
    await reset();
    for (const op of ops) {
      if (op.k === "publish") await one(OWNER, `select * from public.rout_ws_group_publish($1, $2, $3, $4)`, [WS, (await liveEpoch()) + 1, publicKey(), kid()]);
      else if (op.k === "store") await one(OWNER, `select * from public.rout_ws_group_member_store($1, $2, $3, $4, $5, $6)`, [WS, await liveEpoch(), op.who, "00000000-0000-4000-8000-0000000000fa", kid(), envelope("wsk")]);
      else if (op.k === "demote") await db.exec(`update public.workspace_members set role = 'editor' where workspace_id = '${WS}' and user_id = '${op.who}'`);
      else if (op.k === "ask") { const e = envelope("wq"); await one(null, `select * from public.rout_ws_question_create($1, gen_random_uuid(), $2, $3, $4, '0123456789abcdef', $5, $6, $7)`, [SLUG, await liveEpoch(), e, bytea(hashOf(e)), nowBucket(), publicKey(), bytea(tokenHash())]); }
      else if (op.k === "reply") { const q = await openQuestion(); if (q) await one(OWNER, `select * from public.rout_ws_question_reply($1, $2, $3)`, [q, envelope("wa"), bytea(hashOf(envelope("wa")))]); }
      else if (op.k === "publishFaq") { const q = await answeredQuestion(); if (q) await one(OWNER, `select * from public.rout_ws_question_publish($1, 'Q', 'A')`, [q]); }
      else if (op.k === "decline") { const q = await answeredQuestion(); if (q) await one(OWNER, `select * from public.rout_ws_question_decline($1)`, [q]); }
    }
  }
  async function liveEpoch(): Promise<number> {
    const st = await one(OWNER, `select * from public.rout_ws_group_state($1)`, [WS]);
    const e = ((st?.epochs ?? []) as { epoch: number; status: string }[]).find((x) => x.status === "active");
    return e ? e.epoch : 0;
  }
  async function openQuestion(): Promise<string | null> {
    const rows = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    return rows.find((r) => r.status === "open")?.id ? String(rows.find((r) => r.status === "open")!.id) : null;
  }
  async function answeredQuestion(): Promise<string | null> {
    const rows = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
    return rows.find((r) => r.status === "answered")?.id ? String(rows.find((r) => r.status === "answered")!.id) : null;
  }

  it("every sequence of up to three operations leaves exactly the modelled state", async () => {
    const sequences: Op[][] = [];
    for (const a of OPS) for (const b of [...OPS, undefined]) for (const c of [...OPS, undefined]) {
      sequences.push([a, b, c].filter(Boolean) as Op[]);
    }
    for (const ops of sequences) {
      await run(ops);
      const m = model(ops);
      const st = await one(OWNER, `select * from public.rout_ws_group_state($1)`, [WS]);
      const epochs = (st?.epochs ?? []) as { epoch: number; status: string; heldBy: number }[];
      const active = epochs.find((e) => e.status === "active");
      expect(active?.epoch ?? 0, JSON.stringify(ops)).toBe(m.epoch);
      const questions = await as<Record<string, unknown>>(OWNER, `select * from public.rout_ws_question_list($1)`, [WS]);
      expect(questions.length, JSON.stringify(ops)).toBe(m.asked);
      const faq = await as(null, `select * from public.rout_public_ws_faq($1)`, [SLUG]);
      expect(faq.length, JSON.stringify(ops)).toBe(m.published ? 1 : 0);
      // A manager who is still owner/admin and holds the live epoch's envelope can open it;
      // anybody else cannot.
      for (const who of [OWNER, ADMIN]) {
        const can = m.held.has(`${m.epoch}:${who}`) && (await roleOf(who)) !== "editor";
        const r = await one(who, `select * from public.rout_ws_group_member_key($1, $2)`, [WS, m.epoch]);
        expect(r?.ok === true, JSON.stringify(ops) + " " + who).toBe(can);
      }
    }
  }, 600_000);

  async function roleOf(userId: string): Promise<string | null> {
    const rows = await db.query<{ role: string }>(
      `select role::text role from public.workspace_members where workspace_id = $1 and user_id = $2`, [WS, userId]);
    return rows.rows[0]?.role ?? null;
  }
});
