// @vitest-environment node
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import pgcrypto from "@electric-sql/pglite/contrib/pgcrypto";
import btree_gist from "@electric-sql/pglite/contrib/btree_gist";
import { replayDb } from "../../scripts/formal-rls/replay.ts";

const SQL = readFileSync("db-pending/0285_workspace_group_encryption.sql", "utf8");

describe("statement bisect", () => {
  it("finds the failing statement", async () => {
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    await replayDb(db);
    const re = /create or replace function public\.([a-z0-9_]+)\(/g;
    let m: RegExpExecArray | null;
    const seen = new Set<string>();
    while ((m = re.exec(SQL))) {
      if (seen.has(m[1])) continue;
      seen.add(m[1]);
      const start = m.index;
      const end = SQL.indexOf("\n$$;\n", start);
      const ddl = SQL.slice(start, end + 4);
      try {
        await db.exec(`begin;\n${ddl}\n;commit;`);
        console.log("OK   ", m[1]);
      } catch (e) {
        console.log("FAIL ", m[1], "->", (e as Error).message);
      }
    }
    expect(1).toBe(1);
    await db.close();
  }, 600_000);
});
