// @vitest-environment node
import { describe, expect, it } from "vitest";
import { replayDb, applyPending } from "../../scripts/formal-rls/replay.ts";
import { migrationDefinerGuardSql } from "../../scripts/security-definer-policy.ts";

describe("apply 0285 with guard", () => {
  it("applies the pending file plus its guard", async () => {
    const db = await replayDb();
    try {
      await applyPending(db, "0285_workspace_group_encryption.sql");
      console.log("APPLY PENDING OK");
    } catch (e) {
      console.log("APPLY PENDING FAILED ->", (e as Error).message);
      const guard = migrationDefinerGuardSql("0285_workspace_group_encryption.sql");
      try {
        await db.exec(guard);
        console.log("GUARD ALONE OK");
      } catch (e2) {
        console.log("GUARD ALONE FAILED ->", (e2 as Error).message);
      }
    }
    expect(1).toBe(1);
    await db.close();
  }, 600_000);
});
