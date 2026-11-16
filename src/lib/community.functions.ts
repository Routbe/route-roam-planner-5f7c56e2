import { createServerFn } from "@tanstack/react-start";

export type CommunityStats = { members: number; verified: number };
export type CommunityReview = { id: string; authorName: string; handle: string | null; quote: string };

/** Public: real aggregate counts only. Returns null when the database is unreachable. */
export const getCommunityStats = createServerFn({ method: "GET" }).handler(
  async (): Promise<CommunityStats | null> => {
    try {
      const { sql } = await import("@/lib/neon");
      const rows = (await sql`
        select count(*)::int as members from public.profiles where username is not null
      `) as { members: number }[];
      const r = rows[0];
      if (!r) return null;
      // "Verified" means a completed Didit check (db/0282), never a payment or admin flag.
      let verified = 0;
      try {
        const v = (await sql`select public.rout_public_didit_member_count() as n`) as { n: number }[];
        verified = Number(v[0]?.n) || 0;
      } catch {
        verified = 0;
      }
      return { members: Number(r.members) || 0, verified };
    } catch {
      return null;
    }
  },
);

/** Public: admin-approved reviews only. Empty list when none exist (or the table is missing). */
export const listApprovedReviews = createServerFn({ method: "GET" }).handler(
  async (): Promise<CommunityReview[]> => {
    try {
      const { sql } = await import("@/lib/neon");
      const rows = (await sql`
        select id, author_name, handle, quote from public.community_reviews
         where status = 'approved' order by approved_at desc nulls last limit 12
      `) as Record<string, unknown>[];
      return rows.map((r) => ({
        id: String(r["id"]),
        authorName: String(r["author_name"] ?? ""),
        handle: typeof r["handle"] === "string" ? r["handle"] : null,
        quote: String(r["quote"] ?? ""),
      }));
    } catch {
      return [];
    }
  },
);
