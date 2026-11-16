// @vitest-environment node
/**
 * db/0284: the booking ledger. Replays db/ up to 0283 on PGlite, inserts a
 * pre-existing booking, applies 0284 with the definer guard, and checks:
 *   - rout_app has no direct rights on the ledger tables;
 *   - BLAKE3 in SQL equals @noble/hashes byte for byte, and
 *     detail_commit = BLAKE3(ciphertext || salt) with no plaintext input;
 *   - every write to public.bookings / booking_payloads appends to a per-host
 *     hash chain that src/lib/booking-engine/ledger.ts verifies byte for byte;
 *   - deleting a booking shreds its salt and ciphertext while the chain stays valid;
 *   - an exhaustive bounded model check: every sequence of up to MC_DEPTH
 *     operations (incl. rolled-back ones) gives exactly the events of the
 *     reference model below;
 *   - fast-check properties (immutability, non-repudiation, crypto-shredding,
 *     state transitions) over the same reference model.
 * Nothing here touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import fc from "fast-check";
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { isPinned, migrationDefinerGuardSql, searchPathFromConfig } from "../../scripts/security-definer-policy";
import { b64uDecode, b64uEncode } from "@/lib/booking-engine/sealed-booking";
import {
  detailCommit, encodePreimage, entryHash, genesisHash, ledgerKeyId, parsePreimage, planSignatures, signEntry,
  verifyEntrySignature, verifyLedger, type LedgerEvent, type LedgerKind, type LedgerRow,
} from "@/lib/booking-engine/ledger";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const LEDGER_FILE = "0284_booking_ledger.sql";
const LEDGER_SQL = readFileSync(join(DB_DIR, LEDGER_FILE), "utf8");

const HOST = "00000000-0000-4000-8000-0000000000a1";
const OTHER = "00000000-0000-4000-8000-0000000000b1";
const ET = "00000000-0000-4000-8000-0000000000e1";
const PRE = "00000000-0000-4000-8000-00000000f001"; // exists before 0284 runs: imported
const BK = "00000000-0000-4000-8000-00000000f002";
// Bounded model check: own hosts and bookings, so the chains above stay untouched.
const MA = "00000000-0000-4000-8000-0000000000c1";
const MB = "00000000-0000-4000-8000-0000000000c2";
const MX = "00000000-0000-4000-8000-00000000c001";
const MY = "00000000-0000-4000-8000-00000000c002";
const MC_DEPTH = 3;

const LEDGER_TABLES = ["booking_events", "booking_event_attestations", "booking_ledger_salts"];
const INTERNAL = [
  "rout_booking_ledger_immutable()", "rout_booking_ledger_append(public.bookings, text, bytea)",
  "rout_booking_ledger_salt(uuid)", "rout_booking_ledger_capture()", "rout_booking_ledger_payload_capture()",
  "rout_booking_ledger_caller()", "rout_booking_detail_commit(uuid, bytea)", "rout_booking_ledger_genesis(uuid)",
  "rout_booking_ledger_preimage(public.booking_events)", "rout_booking_ledger_hash(public.booking_events)",
  "rout_blake3(bytea)", "rout_blake3_words(bytea)", "rout_blake3_compress(bigint[], bigint[], bigint, integer, integer)",
  "rout_rve1_bytes(text)",
];

// RVE1 bkh envelopes as db/0278 stores them: base64url, header "UlZFMQEF", padded buckets.
const RVE1_HEAD = [0x52, 0x56, 0x45, 0x31, 0x01, 0x05];
const BUCKET_BYTES = [2687, 5759, 18047] as const; // 3583, 7679 and 24063 base64url characters
function makeEnvelope(bytes: number = BUCKET_BYTES[0]): string {
  const b = new Uint8Array(randomBytes(bytes));
  b.set(RVE1_HEAD, 0);
  return b64uEncode(b);
}
const ENV_BK = makeEnvelope();

const at = (hour: number, minute: number) =>
  `2030-01-01T${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:00.000000Z`;
const hex = (b: Uint8Array) => bytesToHex(b);

let db: PGlite;

async function asApp<T>(caller: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin");
  try {
    await db.exec("set local role rout_app");
    await db.query("select set_config('rout.current_user_id', $1, true)", [caller ?? ""]);
    const r = await db.query<T>(query, params);
    await db.exec("commit");
    return r.rows;
  } catch (e) {
    await db.exec("rollback");
    throw e;
  }
}

/** Inside an already open transaction: the owner, acting in a host's context. */
async function inCtx<T>(host: string, query: string): Promise<T[]> {
  await db.query("select set_config('rout.current_user_id', $1, true)", [host]);
  return (await db.query<T>(query)).rows;
}

const insertBooking = (id: string, startHour: number) =>
  db.query(
    `insert into public.bookings (id, event_type_id, host_user_id, start_utc, end_utc, block_start_utc, block_end_utc,
       status, guest_name, guest_email, guest_timezone, ics_uid)
     values ($1::uuid, $2, $3, $4::timestamptz, $5::timestamptz, $4::timestamptz, $5::timestamptz, 'confirmed', 'Guest', 'guest@example.test', 'Europe/Brussels', $1::text || '@rout.be')`,
    [id, ET, HOST, at(startHour, 0), at(startHour, 30)],
  );

/** Inserts or replaces the sealed host copy of a booking (as rout_booking_create_sealed would). */
const sealSql = (bookingId: string, env: string) =>
  db.query(
    `insert into public.booking_payloads (booking_id, host_user_id, payload_id, host_ref, encrypted_rve1_payload,
       blake3_payload_hash, pow_nonce, epoch_bucket)
     select b.id, b.host_user_id, gen_random_uuid(), gen_random_uuid(), $2, $3, '0123456789abcdef', 1
       from public.bookings b where b.id = $1
     on conflict (booking_id) do update
       set encrypted_rve1_payload = excluded.encrypted_rve1_payload, blake3_payload_hash = excluded.blake3_payload_hash`,
    [bookingId, env, blake3(b64uDecode(env)!)],
  );

async function saltOf(id: string): Promise<Uint8Array | null> {
  const r = await db.query<{ salt: Uint8Array }>("select salt from public.booking_ledger_salts where booking_id = $1", [id]);
  return r.rows[0] ? new Uint8Array(r.rows[0].salt) : null;
}

const entries = async (host = HOST) => asApp<LedgerRow>(host, "select * from public.rout_booking_ledger_entries(0, 1000)");
const kinds = async () => (await entries()).map((r) => parsePreimage(r.preimage).kind);

// ------------------------------------------------------------------ reference model
// The SQL rules of 0284, restated: which change appends which event, and what it commits to.
type Op =
  | { k: "create"; id: string; host: string; hour: number }
  | { k: "status" | "reschedule" | "private" | "unseal" | "transfer" | "delete"; id: string }
  | { k: "seal"; id: string; env: string }
  | { k: "rollback"; ops: Op[] };

type ModelBooking = { host: string; status: "confirmed" | "cancelled"; hour: number; env: string | null; salt: Uint8Array };
type ModelEntry = { row: LedgerRow; ev: LedgerEvent; at: number };

class LedgerModel {
  bookings = new Map<string, ModelBooking>();
  chains = new Map<string, ModelEntry[]>();
  tick = 0;
  constructor(readonly hosts: readonly [string, string], public newSalt: (id: string) => Uint8Array) {}

  clone(): LedgerModel {
    const m = new LedgerModel(this.hosts, this.newSalt);
    for (const [id, b] of this.bookings) m.bookings.set(id, { ...b });
    for (const [h, c] of this.chains) m.chains.set(h, [...c]);
    m.tick = this.tick;
    return m;
  }

  chain(host: string): ModelEntry[] {
    return this.chains.get(host) ?? [];
  }

  rows(host: string): LedgerRow[] {
    return this.chain(host).map((e) => e.row);
  }

  commit(b: ModelBooking): string {
    return hex(detailCommit(b.env === null ? new Uint8Array(0) : b64uDecode(b.env)!, b.salt));
  }

  private append(id: string, b: ModelBooking, kind: LedgerKind, commit: string | null) {
    const chain = this.chain(b.host);
    const prev = chain.length ? hexToBytes(chain[chain.length - 1]!.row.entry_hash) : genesisHash(b.host);
    const t = this.tick++;
    const ev: LedgerEvent = {
      hostUserId: b.host, hostSeq: chain.length + 1,
      occurredAt: new Date(Date.UTC(2031, 0, 1) + t * 1000).toISOString().replace(/\.(\d{3})Z$/, ".$1000Z"),
      bookingId: id, groupId: null, eventTypeId: ET, workspaceId: null, kind, status: b.status,
      startUtc: at(b.hour, 0), endUtc: at(b.hour, 30), blockStartUtc: at(b.hour, 0), blockEndUtc: at(b.hour, 30),
      icsSequence: 0, detailCommit: commit, actorUserId: null,
    };
    const preimage = encodePreimage(ev);
    const row = { host_seq: ev.hostSeq, preimage, prev_hash: hex(prev), entry_hash: hex(entryHash(prev, preimage)) };
    this.chains.set(b.host, [...chain, { row, ev, at: t }]);
  }

  apply(op: Op): void {
    if (op.k === "rollback") {
      const scratch = this.clone(); // a rolled-back transaction leaves nothing behind
      for (const o of op.ops) scratch.apply(o);
      return;
    }
    if (op.k === "create") {
      if (this.bookings.has(op.id)) return;
      const b: ModelBooking = { host: op.host, status: "confirmed", hour: op.hour, env: null, salt: this.newSalt(op.id) };
      this.bookings.set(op.id, b);
      this.append(op.id, b, "created", this.commit(b));
      return;
    }
    const b = this.bookings.get(op.id);
    if (!b) return;
    switch (op.k) {
      case "status":
        b.status = b.status === "confirmed" ? "cancelled" : "confirmed";
        return this.append(op.id, b, "status_changed", this.commit(b));
      case "reschedule":
        b.hour = b.hour % 2 === 0 ? b.hour + 1 : b.hour - 1;
        return this.append(op.id, b, "rescheduled", this.commit(b));
      case "private": // a plaintext column changes: an event, the commitment stays
        return this.append(op.id, b, "updated", this.commit(b));
      case "seal":
        if (b.env === op.env) return;
        b.env = op.env;
        return this.append(op.id, b, "sealed", this.commit(b));
      case "unseal":
        if (b.env === null) return;
        b.env = null;
        return this.append(op.id, b, "sealed", this.commit(b));
      case "transfer":
        this.append(op.id, b, "transferred_out", null);
        b.host = b.host === this.hosts[0] ? this.hosts[1] : this.hosts[0];
        return this.append(op.id, b, "transferred_in", this.commit(b));
      case "delete":
        this.append(op.id, b, "deleted", null);
        this.bookings.delete(op.id); // the salt goes with it
        return;
    }
  }
}

const project = (e: LedgerEvent) => ({
  seq: e.hostSeq, kind: e.kind, booking: e.bookingId, status: e.status, start: e.startUtc, end: e.endUtc, commit: e.detailCommit,
});

async function runSql(op: Op): Promise<void> {
  switch (op.k) {
    case "create":
      await db.query(
        `insert into public.bookings (id, event_type_id, host_user_id, start_utc, end_utc, block_start_utc, block_end_utc,
           status, guest_name, guest_email, guest_timezone, ics_uid)
         select $1::uuid, $2::uuid, $3::uuid, $4::timestamptz, $5::timestamptz, $4::timestamptz, $5::timestamptz, 'confirmed',
                'Guest', 'guest@example.test', 'Europe/Brussels', $1::text || '@rout.be'
          where not exists (select 1 from public.bookings x where x.id = $1::uuid)`,
        [op.id, ET, op.host, at(op.hour, 0), at(op.hour, 30)],
      );
      return;
    case "status":
      await db.query("update public.bookings set status = case when status = 'confirmed' then 'cancelled' else 'confirmed' end where id = $1", [op.id]);
      return;
    case "reschedule":
      await db.query(
        `update public.bookings b set start_utc = b.start_utc + s.d, end_utc = b.end_utc + s.d,
                block_start_utc = b.block_start_utc + s.d, block_end_utc = b.block_end_utc + s.d
           from (select case when extract(hour from x.start_utc at time zone 'UTC')::int % 2 = 0
                             then interval '1 hour' else interval '-1 hour' end as d
                   from public.bookings x where x.id = $1) s
          where b.id = $1`,
        [op.id],
      );
      return;
    case "private":
      await db.query("update public.bookings set guest_note = coalesce(guest_note, '') || 'x' where id = $1", [op.id]);
      return;
    case "seal":
      await sealSql(op.id, op.env);
      return;
    case "unseal":
      await db.query("delete from public.booking_payloads where booking_id = $1", [op.id]);
      return;
    case "transfer":
      await db.query("update public.bookings set host_user_id = case when host_user_id = $2::uuid then $3::uuid else $2::uuid end where id = $1::uuid", [op.id, MA, MB]);
      return;
    case "delete":
      await db.query("delete from public.bookings where id = $1", [op.id]);
      return;
    case "rollback":
      await db.exec("savepoint rb");
      for (const o of op.ops) await runSql(o);
      await db.exec("rollback to savepoint rb");
      await db.exec("release savepoint rb");
      return;
  }
}

beforeAll(async () => {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
    // 0284 itself runs after PRE exists, so the import of existing bookings is exercised.
    if (step.action === "run" && step.file !== LEDGER_FILE) {
      await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
    }
  }
  await db.exec(`
    insert into public.users (id, email) values ('${HOST}', 'host@example.test'), ('${OTHER}', 'other@example.test'),
      ('${MA}', 'ma@example.test'), ('${MB}', 'mb@example.test');
    insert into public.booking_event_types (id, user_id, slug, title, duration_minutes, minimum_notice_hours)
      values ('${ET}', '${HOST}', 'intro', 'Intro', 30, 0);`);
  await insertBooking(PRE, 8);
  await db.exec(`begin;\n${LEDGER_SQL}\n;\n${migrationDefinerGuardSql(LEDGER_FILE)};commit;`);
}, 300_000);

afterAll(async () => {
  await db?.close();
});

describe("0284 booking ledger (PGlite isolation)", () => {
  it("imports bookings that existed before the migration", async () => {
    expect(await kinds()).toEqual(["imported"]);
  });

  it("gives rout_app no direct rights on any ledger table", async () => {
    for (const t of LEDGER_TABLES) {
      for (const p of ["select", "insert", "update", "delete", "truncate", "references", "trigger"]) {
        const r = await db.query<{ ok: boolean }>("select has_table_privilege('rout_app', $1, $2) as ok", [`public.${t}`, p]);
        expect(r.rows[0]!.ok, `${t} ${p}`).toBe(false);
      }
    }
    await expect(asApp(HOST, "select * from public.booking_events")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "insert into public.booking_ledger_salts (booking_id, salt) values ($1, '\\x00')", [BK])).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "update public.booking_events set status = 'x'")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "delete from public.booking_event_attestations")).rejects.toThrow(/permission denied/);
    await expect(asApp(HOST, "truncate public.booking_events")).rejects.toThrow(/permission denied/);
  });

  it("refuses UPDATE, DELETE and TRUNCATE on the ledger even for the owner", async () => {
    await expect(db.exec("update public.booking_events set status = 'x'")).rejects.toThrow(/booking_ledger_immutable/);
    await expect(db.exec("delete from public.booking_events")).rejects.toThrow(/booking_ledger_immutable/);
    await expect(db.exec("truncate public.booking_events cascade")).rejects.toThrow(/booking_ledger_immutable/);
  });

  it("keeps internal helpers closed to rout_app and pins every definer", async () => {
    for (const f of INTERNAL) {
      const r = await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [`public.${f}`]);
      expect(r.rows[0]!.ok, f).toBe(false);
    }
    const defs = await db.query<{ name: string; cfg: string[] | null }>(
      `select p.proname as name, p.proconfig as cfg from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prosecdef and (p.proname like 'rout_booking_ledger%' or p.proname = 'rout_booking_detail_commit')`,
    );
    expect(defs.rows.length).toBeGreaterThanOrEqual(11);
    for (const d of defs.rows) expect(isPinned(searchPathFromConfig(d.cfg)), d.name).toBe(true);
  });

  it("computes BLAKE3 in SQL byte for byte like @noble/hashes", async () => {
    const sqlBlake3 = async (b: Uint8Array) =>
      hex(new Uint8Array((await db.query<{ h: Uint8Array }>("select public.rout_blake3($1) as h", [b])).rows[0]!.h));
    // Every block (64) and chunk (1024) boundary, a deep tree, and the three envelope buckets.
    for (const n of [0, 1, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073, 4096, 4097, 5121, 8192, 9217, ...BUCKET_BYTES]) {
      const b = new Uint8Array(randomBytes(n));
      expect(await sqlBlake3(b), `length ${n}`).toBe(hex(blake3(b)));
    }
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 4200 }), async (b) => {
        expect(await sqlBlake3(b)).toBe(hex(blake3(b)));
      }),
      { numRuns: 200 },
    );
    for (const size of BUCKET_BYTES) {
      const env = makeEnvelope(size);
      const r = await db.query<{ b: Uint8Array }>("select public.rout_rve1_bytes($1) as b", [env]);
      expect(hex(new Uint8Array(r.rows[0]!.b))).toBe(hex(b64uDecode(env)!));
    }
  }, 300_000);

  it("appends one event per booking change, in order", async () => {
    await insertBooking(BK, 10);
    await db.query("update public.bookings set status = 'cancelled' where id = $1", [BK]);
    await db.query("update public.bookings set guest_note = 'hello' where id = $1", [BK]);
    await db.query("update public.bookings set start_utc = start_utc + interval '1 hour', end_utc = end_utc + interval '1 hour', block_start_utc = block_start_utc + interval '1 hour', block_end_utc = block_end_utc + interval '1 hour' where id = $1", [BK]);
    await db.query("update public.bookings set guest_timezone = guest_timezone where id = $1", [BK]); // no change: no event
    await sealSql(BK, ENV_BK);
    expect(await kinds()).toEqual(["imported", "created", "status_changed", "updated", "rescheduled", "sealed"]);
  });

  it("commits to BLAKE3(ciphertext || salt) and never to a plaintext field", async () => {
    const salt = (await saltOf(BK))!;
    expect(salt.length).toBe(32);
    const evs = (await entries()).map((r) => parsePreimage(r.preimage)).filter((e) => e.bookingId === BK);
    const unsealed = hex(detailCommit(new Uint8Array(0), salt));
    const sealed = hex(detailCommit(b64uDecode(ENV_BK)!, salt));
    expect(unsealed).toBe(hex(blake3(salt)));
    expect(evs.map((e) => e.detailCommit)).toEqual([unsealed, unsealed, unsealed, unsealed, sealed]);
    // Rewriting every plaintext column moves no commitment.
    const text = (max: number) => fc.string({ maxLength: max }).map((s) => s.replace(/\u0000/g, ""));
    await fc.assert(
      fc.asyncProperty(fc.record({ name: text(100), email: text(60), note: text(300), answer: text(100) }), async (p) => {
        await db.query(
          "update public.bookings set guest_name = $2, guest_email = $3, guest_note = $4, intake_answers = jsonb_build_object('q', $5::text) where id = $1",
          [BK, `g${p.name}`, p.email, p.note, p.answer],
        );
        const last = parsePreimage((await entries()).at(-1)!.preimage);
        expect(last.bookingId).toBe(BK);
        expect(last.detailCommit).toBe(sealed);
      }),
      { numRuns: 40 },
    );
  }, 120_000);

  it("never lets a host read another host's chain", async () => {
    expect(await entries(OTHER)).toEqual([]);
    expect(await asApp(null, "select * from public.rout_booking_ledger_entries(0, 1000)")).toEqual([]);
    await expect(asApp(null, "select * from public.rout_booking_ledger_verify()")).rejects.toThrow(/forbidden/);
  });

  it("chains every entry_hash as SHA-256(prev_hash || preimage), matching ledger.ts", async () => {
    const rows = await entries();
    let prev = hex(genesisHash(HOST));
    for (const r of rows) {
      expect(r.prev_hash).toBe(prev);
      const node = createHash("sha256").update(Buffer.from(r.prev_hash, "hex")).update(Buffer.from(r.preimage, "utf8")).digest("hex");
      expect(r.entry_hash).toBe(node);
      expect(hex(entryHash(hexToBytes(r.prev_hash), r.preimage))).toBe(node);
      prev = r.entry_hash;
    }
    const v = verifyLedger(HOST, rows, [], new Map());
    expect(v.broken).toBeNull();
    expect(v.entries).toBe(rows.length);
    const db1 = await asApp<{ ok: boolean; entries: string; head_hash: string }>(HOST, "select * from public.rout_booking_ledger_verify()");
    expect(db1[0]!.ok).toBe(true);
    expect(db1[0]!.head_hash).toBe(v.headHash);
    expect(await asApp(HOST, "select * from public.rout_booking_ledger_drift()")).toEqual([]);
  });

  it("detects a tampered preimage in the TypeScript verifier", async () => {
    const rows = await entries();
    const bad = rows.map((r, i) => (i === 1 ? { ...r, preimage: r.preimage.replace("confirmed", "cancelled") } : r));
    expect(verifyLedger(HOST, bad, [], new Map()).broken).toEqual({ seq: 2, problem: "entry_hash" });
  });

  it("stores and verifies server signatures through rout_booking_ledger_attest", async () => {
    const sk = ed25519.utils.randomSecretKey();
    const pk = ed25519.getPublicKey(sk);
    const keyId = ledgerKeyId(pk);
    const rows = await entries();
    for (const r of rows) {
      const ok = await asApp<{ ok: boolean }>(HOST, "select public.rout_booking_ledger_attest($1, $2, $3) as ok", [r.host_seq, keyId, signEntry(sk, r.entry_hash)]);
      expect(ok[0]!.ok).toBe(true);
    }
    const att = await asApp<{ host_seq: string; key_id: string; signature: string }>(HOST, "select * from public.rout_booking_ledger_attestations(0, 1000)");
    const v = verifyLedger(HOST, rows, att, new Map([[keyId, pk]]));
    expect(v).toMatchObject({ ok: true, unsigned: [], forged: [] });
    // Another host cannot sign this host's events.
    const other = await asApp<{ ok: boolean }>(OTHER, "select public.rout_booking_ledger_attest(1, $1, $2) as ok", [keyId, "0".repeat(128)]);
    expect(other[0]!.ok).toBe(false);
  });

  it("crypto-shreds salt and ciphertext on delete while the chain stays valid", async () => {
    const count = async (table: string) =>
      (await db.query<{ n: number }>(`select count(*)::int as n from public.${table} where booking_id = $1`, [BK])).rows[0]!.n;
    expect(await count("booking_ledger_salts")).toBe(1);
    expect(await count("booking_payloads")).toBe(1);
    const sealedCommit = parsePreimage((await entries()).at(-1)!.preimage).detailCommit!;
    await db.query("delete from public.bookings where id = $1", [BK]);
    expect(await count("booking_ledger_salts")).toBe(0);
    expect(await count("booking_payloads")).toBe(0);
    const rows = await entries();
    const evs = rows.map((r) => parsePreimage(r.preimage)).filter((e) => e.bookingId === BK);
    expect(evs.at(-1)).toMatchObject({ kind: "deleted", detailCommit: null });
    expect(evs.slice(0, -1).every((e) => e.detailCommit !== null)).toBe(true);
    // Whoever still holds the old ciphertext cannot test it against the chain without the salt.
    expect(sealedCommit).not.toBe(hex(blake3(b64uDecode(ENV_BK)!)));
    expect(sealedCommit).not.toBe(hex(detailCommit(b64uDecode(ENV_BK)!, new Uint8Array(randomBytes(32)))));
    expect(verifyLedger(HOST, rows, [], new Map()).broken).toBeNull();
    expect((await asApp<{ ok: boolean }>(HOST, "select * from public.rout_booking_ledger_verify()"))[0]!.ok).toBe(true);
    expect(await asApp(HOST, "select * from public.rout_booking_ledger_drift()")).toEqual([]);
  });

  it(`model-checks every sequence of up to ${MC_DEPTH} operations, rollbacks included, against the reference model`, async () => {
    const X = { create: (): Op => ({ k: "create", id: MX, host: MA, hour: 10 }) };
    const ops: Record<string, () => Op> = {
      createX: X.create,
      createY: () => ({ k: "create", id: MY, host: MB, hour: 14 }),
      statusX: () => ({ k: "status", id: MX }),
      rescheduleX: () => ({ k: "reschedule", id: MX }),
      privateX: () => ({ k: "private", id: MX }),
      sealX: () => ({ k: "seal", id: MX, env: makeEnvelope() }),
      unsealX: () => ({ k: "unseal", id: MX }),
      transferX: () => ({ k: "transfer", id: MX }),
      deleteX: () => ({ k: "delete", id: MX }),
      deleteY: () => ({ k: "delete", id: MY }),
      rollback: () => ({ k: "rollback", ops: [{ k: "create", id: MY, host: MB, hour: 14 }, { k: "status", id: MX }, { k: "seal", id: MX, env: makeEnvelope() }] }),
    };
    const readSalts = async () => {
      const r = await db.query<{ booking_id: string; salt: Uint8Array }>(
        "select booking_id, salt from public.booking_ledger_salts where booking_id = any($1::uuid[])", [[MX, MY]]);
      return new Map(r.rows.map((x) => [x.booking_id, new Uint8Array(x.salt)]));
    };
    let nodes = 0;
    const check = async (model: LedgerModel, path: string, parent: Map<string, string[]> | null) => {
      nodes++;
      const heads = new Map<string, string[]>();
      for (const host of [MA, MB]) {
        const rows = await inCtx<LedgerRow>(host, "select * from public.rout_booking_ledger_entries(0, 1000)");
        expect(rows.map((r) => project(parsePreimage(r.preimage))), `${path} @${host}`).toEqual(model.chain(host).map((e) => project(e.ev)));
        const tv = verifyLedger(host, rows, [], new Map());
        expect(tv.broken, path).toBeNull();
        const [sv] = await inCtx<{ ok: boolean; head_hash: string }>(host, "select * from public.rout_booking_ledger_verify()");
        expect(sv, path).toMatchObject({ ok: true, head_hash: tv.headHash });
        expect(await inCtx(host, "select * from public.rout_booking_ledger_drift()"), path).toEqual([]);
        const hashes = rows.map((r) => r.entry_hash);
        if (parent) expect(hashes.slice(0, parent.get(host)!.length), `${path}: append-only`).toEqual(parent.get(host));
        for (const r of rows) expect(r.preimage, path).not.toMatch(/Guest|guest@example|Europe\/Brussels|@rout\.be/);
        heads.set(host, hashes);
      }
      const salts = await readSalts();
      for (const id of [MX, MY]) {
        const b = model.bookings.get(id);
        expect(salts.has(id) ? hex(salts.get(id)!) : null, `${path}: salt ${id}`).toBe(b ? hex(b.salt) : null);
      }
      return heads;
    };
    const step = async (model: LedgerModel, op: Op) => {
      await runSql(op);
      const salts = await readSalts();
      const next = model.clone();
      next.newSalt = (id) => salts.get(id) ?? new Uint8Array(32);
      next.apply(op);
      return next;
    };
    const dfs = async (model: LedgerModel, depth: number, path: string, parent: Map<string, string[]>) => {
      if (depth === 0) return;
      for (const [name, make] of Object.entries(ops)) {
        await db.exec(`savepoint mc${depth}`);
        const next = await step(model, make());
        const p = `${path} ${name}`;
        const heads = await check(next, p, parent);
        await dfs(next, depth - 1, p, heads);
        await db.exec(`rollback to savepoint mc${depth}`);
        await db.exec(`release savepoint mc${depth}`);
      }
    };
    await db.exec("begin");
    try {
      const root = await step(new LedgerModel([MA, MB], () => new Uint8Array(32)), X.create());
      await dfs(root, MC_DEPTH, "createX |", await check(root, "createX", null));
    } finally {
      await db.exec("rollback");
    }
    const n = Object.keys(ops).length;
    expect(nodes).toBe(1 + Array.from({ length: MC_DEPTH }, (_, i) => n ** (i + 1)).reduce((a, b) => a + b, 0));
  }, 600_000);
});

// ------------------------------------------------------------------ fast-check properties
const PH = ["00000000-0000-4000-8000-0000000000d1", "00000000-0000-4000-8000-0000000000d2"] as const;
const PIDS = ["00000000-0000-4000-8000-00000000d001", "00000000-0000-4000-8000-00000000d002", "00000000-0000-4000-8000-00000000d003"] as const;
const HOUR: Record<string, number> = { [PIDS[0]]: 8, [PIDS[1]]: 12, [PIDS[2]]: 16 };
const RUNS = 10_000;
const SIGNATURE_RUNS = 1_000;

const idArb = fc.constantFrom(...PIDS);
const envArb = fc.uint8Array({ minLength: 1, maxLength: 192 }).map(b64uEncode);
const simple = (k: "status" | "reschedule" | "private" | "unseal" | "transfer" | "delete") => idArb.map((id): Op => ({ k, id }));
const baseOpArb: fc.Arbitrary<Op> = fc.oneof(
  { weight: 3, arbitrary: fc.tuple(idArb, fc.constantFrom(...PH)).map(([id, host]): Op => ({ k: "create", id, host, hour: HOUR[id]! })) },
  { weight: 2, arbitrary: simple("status") },
  { weight: 1, arbitrary: simple("reschedule") },
  { weight: 1, arbitrary: simple("private") },
  { weight: 2, arbitrary: fc.tuple(idArb, envArb).map(([id, env]): Op => ({ k: "seal", id, env })) },
  { weight: 1, arbitrary: simple("unseal") },
  { weight: 1, arbitrary: simple("transfer") },
  { weight: 1, arbitrary: simple("delete") },
);
const opArb: fc.Arbitrary<Op> = fc.oneof(
  { weight: 9, arbitrary: baseOpArb },
  { weight: 1, arbitrary: fc.array(baseOpArb, { minLength: 1, maxLength: 3 }).map((ops): Op => ({ k: "rollback", ops })) },
);
const historyArb = fc.record({
  seed: fc.uint8Array({ minLength: 32, maxLength: 32 }),
  ops: fc.array(opArb, { minLength: 1, maxLength: 16 }),
});
type History = { seed: Uint8Array; ops: Op[] };

function runModel(h: History, first: Op[] = []): LedgerModel {
  let n = 0;
  const m = new LedgerModel(PH, (id) => sha256(new Uint8Array([...h.seed, ...new TextEncoder().encode(id), n >> 8, n++ & 255])));
  for (const op of [...first, ...h.ops]) m.apply(op);
  return m;
}
const allEntries = (m: LedgerModel) => PH.flatMap((h) => m.chain(h)).sort((a, b) => a.at - b.at);
const OPENERS: LedgerKind[] = ["created", "imported", "transferred_in"];
const CLOSERS: LedgerKind[] = ["deleted", "transferred_out"];

describe("0284 booking ledger (fast-check properties)", () => {
  it(`state transitions: ${RUNS} random histories verify, never fork a booking and replay to the bookings`, () => {
    fc.assert(
      fc.property(historyArb, (h) => {
        const m = runModel(h);
        for (const host of PH) {
          const v = verifyLedger(host, m.rows(host), [], new Map());
          expect(v.broken).toBeNull();
          expect(v.entries).toBe(m.chain(host).length);
        }
        const open = new Map<string, string>();
        const status = new Map<string, string>();
        for (const { ev } of allEntries(m)) {
          if (OPENERS.includes(ev.kind)) {
            expect(open.has(ev.bookingId)).toBe(false); // a booking lives on one chain at a time
            open.set(ev.bookingId, ev.hostUserId);
          } else {
            expect(open.get(ev.bookingId)).toBe(ev.hostUserId);
            if (CLOSERS.includes(ev.kind)) open.delete(ev.bookingId);
          }
          if (ev.kind !== "created" && ev.kind !== "status_changed") expect(ev.status).toBe(status.get(ev.bookingId));
          if (ev.kind === "status_changed") expect(ev.status).not.toBe(status.get(ev.bookingId));
          status.set(ev.bookingId, ev.status);
          expect(ev.detailCommit === null).toBe(CLOSERS.includes(ev.kind));
        }
        expect([...open].sort()).toEqual([...m.bookings].map(([id, b]) => [id, b.host]).sort());
        for (const [id, b] of m.bookings) {
          const last = allEntries(m).filter((e) => e.ev.bookingId === id).at(-1)!.ev;
          expect(last).toMatchObject({ status: b.status, startUtc: at(b.hour, 0), detailCommit: m.commit(b) });
        }
        // A rolled-back history leaves every chain byte-identical.
        const before = PH.map((host) => m.rows(host));
        m.apply({ k: "rollback", ops: h.ops.filter((o) => o.k !== "rollback").slice(0, 3) });
        expect(PH.map((host) => m.rows(host))).toEqual(before);
      }),
      { numRuns: RUNS },
    );
  }, 300_000);

  type Tamper = "preimage" | "prev_hash" | "entry_hash" | "drop" | "swap" | "append" | "rewrite";
  it(`strict append-only immutability: ${RUNS} random tamperings of a historic entry are all detected`, () => {
    const tamperArb = fc.constantFrom<Tamper>("preimage", "prev_hash", "entry_hash", "drop", "swap", "append", "rewrite");
    fc.assert(
      fc.property(historyArb, tamperArb, fc.nat(), fc.nat(), (h, kind, a, b) => {
        const m = runModel(h, [{ k: "create", id: PIDS[0], host: PH[0], hour: HOUR[PIDS[0]]! }]);
        const host = PH[0];
        const orig = m.rows(host);
        const n = orig.length;
        const i = a % n;
        const base = verifyLedger(host, orig, [], new Map());
        const flip = (s: string, at: number, alphabet: string) => {
          const c = s[at]!;
          return s.slice(0, at) + (c === alphabet[0] ? alphabet[1] : alphabet[0]) + s.slice(at + 1);
        };
        let rows = orig.map((r) => ({ ...r }));
        const effective: Tamper = kind === "swap" && n < 2 ? "entry_hash" : kind;
        let seq = i + 1; // where the verifier must stop: the first entry that is no longer original
        switch (effective) {
          case "preimage": rows[i]!.preimage = flip(rows[i]!.preimage, b % rows[i]!.preimage.length, "01"); break;
          case "prev_hash": rows[i]!.prev_hash = flip(rows[i]!.prev_hash, b % 64, "ab"); break;
          case "entry_hash": rows[i]!.entry_hash = flip(rows[i]!.entry_hash, b % 64, "ab"); break;
          case "drop": rows = rows.filter((_, j) => j !== i); seq = i + 2; break;
          case "swap": {
            const j = (i + 1 + (b % (n - 1))) % n;
            const ri = rows[i]!, rj = rows[j]!;
            rows[i] = { ...rj, host_seq: ri.host_seq };
            rows[j] = { ...ri, host_seq: rj.host_seq };
            seq = Math.min(i, j) + 1;
            break;
          }
          case "append": rows.push({ ...rows[i]!, host_seq: n + 1 }); seq = n + 1; break;
          case "rewrite": {
            // Recompute every hash from i on: only an anchored head or signature can catch this.
            let prev = i === 0 ? genesisHash(host) : hexToBytes(rows[i - 1]!.entry_hash);
            for (let j = i; j < n; j++) {
              const ev = parsePreimage(rows[j]!.preimage);
              const preimage = encodePreimage(j === i ? { ...ev, status: ev.status === "confirmed" ? "cancelled" : "confirmed" } : ev);
              const eh = entryHash(prev, preimage);
              rows[j] = { host_seq: j + 1, preimage, prev_hash: hex(prev), entry_hash: hex(eh) };
              prev = eh;
            }
            break;
          }
        }
        const v = verifyLedger(host, rows, [], new Map());
        const tailCut = effective === "drop" && i === n - 1;
        if (effective === "rewrite" || tailCut) {
          expect(v.headHash).not.toBe(base.headHash); // the anchored head no longer matches
          if (effective === "rewrite") expect(rows[i]!.entry_hash).not.toBe(orig[i]!.entry_hash);
        } else {
          expect(v.broken).not.toBeNull();
          expect(v.broken!.seq).toBe(seq); // flagged at the tampered entry itself
        }
      }),
      { numRuns: RUNS },
    );
  }, 300_000);

  it(`crypto-shredding: ${RUNS} random histories stay verifiable after every salt is gone, and no commitment links to its ciphertext`, () => {
    fc.assert(
      fc.property(historyArb, envArb, fc.uint8Array({ minLength: 32, maxLength: 32 }), (h, shared, guess) => {
        const m = runModel(h);
        // The same ciphertext sealed into two bookings: different salts, different commitments.
        for (const [id, host] of [[PIDS[0], PH[0]], [PIDS[1], PH[1]]] as const) {
          m.apply({ k: "create", id, host, hour: HOUR[id]! });
          m.apply({ k: "seal", id, env: shared });
        }
        const c0 = m.commit(m.bookings.get(PIDS[0])!);
        const c1 = m.commit(m.bookings.get(PIDS[1])!);
        expect(c0).not.toBe(c1);
        const raw = b64uDecode(shared)!;
        const before = PH.map((host) => m.rows(host).map((r) => r.entry_hash));
        for (const id of [...m.bookings.keys()]) m.apply({ k: "delete", id });
        expect(m.bookings.size).toBe(0); // every salt is gone
        for (const [k, host] of PH.entries()) {
          const rows = m.rows(host);
          expect(rows.slice(0, before[k]!.length).map((r) => r.entry_hash)).toEqual(before[k]); // history untouched
          expect(verifyLedger(host, rows, [], new Map()).broken).toBeNull();
          for (const r of rows) {
            const c = parsePreimage(r.preimage).detailCommit;
            if (c === null) continue;
            expect(c).not.toBe(hex(blake3(raw))); // unsalted guess
            expect(c).not.toBe(hex(detailCommit(raw, guess))); // guessed salt
          }
        }
      }),
      { numRuns: RUNS },
    );
  }, 300_000);

  it(`non-repudiation: ${SIGNATURE_RUNS} random signed chains cannot be claimed, re-signed or extended by another host or key`, () => {
    const hostOps = (ops: Op[]) =>
      ops.filter((o) => o.k !== "transfer" && o.k !== "rollback").map((o) => (o.k === "create" ? { ...o, host: PH[0] } : o)).slice(0, 5);
    fc.assert(
      fc.property(historyArb, fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 32, maxLength: 32 }), (h, sk, atk) => {
        fc.pre(hex(sk) !== hex(atk));
        const m = runModel({ seed: h.seed, ops: hostOps(h.ops) }, [{ k: "create", id: PIDS[0], host: PH[0], hour: HOUR[PIDS[0]]! }]);
        const rows = m.rows(PH[0]);
        const pk = ed25519.getPublicKey(sk);
        const kid = ledgerKeyId(pk);
        const trusted = new Map([[kid, pk]]);
        const atts = rows.map((r) => ({ host_seq: r.host_seq, key_id: kid, signature: signEntry(sk, r.entry_hash) }));
        expect(verifyLedger(PH[0], rows, atts, trusted)).toMatchObject({ ok: true, unsigned: [], forged: [] });
        // Another host cannot claim the chain.
        expect(verifyLedger(PH[1], rows, atts, trusted).broken).toEqual({ seq: 1, problem: "host" });
        // A key that is not configured proves nothing; under a trusted key id it is a forgery.
        const forged = rows.map((r) => signEntry(atk, r.entry_hash));
        const atkKid = ledgerKeyId(ed25519.getPublicKey(atk));
        const seqs = rows.map((r) => Number(r.host_seq));
        expect(verifyLedger(PH[0], rows, rows.map((r, i) => ({ host_seq: r.host_seq, key_id: atkKid, signature: forged[i]! })), trusted))
          .toMatchObject({ ok: true, unsigned: seqs, forged: [] });
        expect(verifyLedger(PH[0], rows, rows.map((r, i) => ({ host_seq: r.host_seq, key_id: kid, signature: forged[i]! })), trusted))
          .toMatchObject({ ok: false, unsigned: seqs, forged: seqs });
        // The signer refuses to sign another host's chain.
        expect(planSignatures(PH[1], rows.map((r) => ({ ...r, prev_signature: null })), atk).ok).toBe(false);
        // A signature belongs to exactly one entry.
        if (rows.length > 1) expect(verifyEntrySignature(pk, rows[1]!.entry_hash, atts[0]!.signature)).toBe(false);
      }),
      { numRuns: SIGNATURE_RUNS },
    );
  }, 300_000);
});
