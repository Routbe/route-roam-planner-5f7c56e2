// @vitest-environment node
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import pgcrypto from "@electric-sql/pglite/contrib/pgcrypto";
import btree_gist from "@electric-sql/pglite/contrib/btree_gist";
import { replayDb } from "../../scripts/formal-rls/replay.ts";

const SQL = readFileSync("db-pending/0285_workspace_group_encryption.sql", "utf8");

/** Split on ';' outside dollar quotes and single-quoted strings. */
function splitStatements(sql: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null; // ' or $$ tag
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];
    if (quote) {
      if (sql.startsWith(quote, i)) {
        cur += quote;
        i += quote.length;
        quote = null;
        continue;
      }
      cur += ch;
      i += 1;
      continue;
    }
    if (ch === "'") {
      quote = "'";
      cur += ch;
      i += 1;
      continue;
    }
    if (ch === "$") {
      const tag = /^\$[A-Za-z0-9_]*\$/.exec(sql.slice(i));
      if (tag) {
        quote = tag[0];
        cur += tag[0];
        i += tag[0].length;
        continue;
      }
    }
    if (ch === ";") {
      if (cur.trim()) out.push(cur);
      cur = "";
      i += 1;
      continue;
    }
    cur += ch;
    i += 1;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

describe("statement bisect", () => {
  it("finds the failing statement", async () => {
    const db = await replayDb();
    const stmts = splitStatements(SQL);
    console.log("statements:", stmts.length);
    let failed = 0;
    for (const [n, s] of stmts.entries()) {
      try {
        await db.exec(`begin;\n${s}\n;commit;`);
      } catch (e) {
        failed += 1;
        console.log(`FAIL #${n}:`, (e as Error).message);
        console.log("TEXT:", s.trim().slice(0, 400).replace(/\s+/g, " "));
        if (failed > 3) break;
      }
    }
    expect(failed).toBe(0);
    await db.close();
  }, 600_000);
});
