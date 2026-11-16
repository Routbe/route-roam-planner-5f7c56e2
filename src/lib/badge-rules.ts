import type { BadgeType } from "@/lib/profile-display";

/** Which trust badge a public root profile may show outside its own page (embed badge, share image). */
export type PublicBadge = "verified" | "human" | "domain" | "influencer" | null;

export function publicBadgeKind(input: {
  /** Completed Didit attestation (db/0282). Payment, Pro or an admin flag never counts. */
  diditVerified: boolean;
  isBusiness: boolean;
  isInfluencer: boolean;
  badgeVisible: boolean;
  badgeType: BadgeType;
}): PublicBadge {
  // Same gate as the profile page: a Didit-proven identity, and the owner did not hide the badge.
  if (input.diditVerified !== true || !input.badgeVisible || input.badgeType === "none") return null;
  if (input.isBusiness) return "domain";
  if (input.isInfluencer) return "influencer";
  return input.badgeType === "human" ? "human" : "verified";
}

/** Separate from identity: a paying/Pro member gets the discreet supporter crown, never the identity mark. */
export function showsSupporterCrown(input: { isPro: boolean; supporterBadgeVisible: boolean }): boolean {
  return input.isPro === true && input.supporterBadgeVisible !== false;
}
