import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { replayDb, applyPending } from "./scripts/formal-rls/replay.ts";

const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
await replayDb(db);
try {
  await applyPending(db, "0285_workspace_group_encryption.sql");
  console.log("APPLIED WITH GUARD OK");
} catch (e) {
  console.log("APPLIED WITH GUARD FAILED ->", (e as Error).message);
}
await db.close();
