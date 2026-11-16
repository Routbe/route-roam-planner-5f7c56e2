import { describe, expect, it } from "vitest";
import { publicBadgeKind, showsSupporterCrown } from "./badge-rules";

const base = { diditVerified: true, isBusiness: false, isInfluencer: false, badgeVisible: true, badgeType: "verified" as const };

describe("publicBadgeKind", () => {
  it("never shows a trust mark without a completed Didit check", () => {
    expect(publicBadgeKind({ ...base, diditVerified: false })).toBeNull();
    expect(publicBadgeKind({ ...base, diditVerified: false, badgeType: "human" })).toBeNull();
    expect(publicBadgeKind({ ...base, diditVerified: false, isBusiness: true })).toBeNull();
  });
  it("respects the owner hiding the badge", () => {
    expect(publicBadgeKind({ ...base, badgeVisible: false })).toBeNull();
    expect(publicBadgeKind({ ...base, badgeType: "none" })).toBeNull();
  });
  it("shows the privacy shield only for a verified member who chose it", () => {
    expect(publicBadgeKind({ ...base, badgeType: "human" })).toBe("human");
  });
  it("business and influencer badges come from server flags, not the chosen type", () => {
    expect(publicBadgeKind({ ...base, badgeType: "influencer" })).toBe("verified");
    expect(publicBadgeKind({ ...base, isInfluencer: true })).toBe("influencer");
    expect(publicBadgeKind({ ...base, isBusiness: true, isInfluencer: true })).toBe("domain");
  });
});

describe("showsSupporterCrown", () => {
  it("a Pro/paying member gets the crown, separate from identity", () => {
    expect(showsSupporterCrown({ isPro: true, supporterBadgeVisible: true })).toBe(true);
  });
  it("no crown without Pro, or when the member hides it", () => {
    expect(showsSupporterCrown({ isPro: false, supporterBadgeVisible: true })).toBe(false);
    expect(showsSupporterCrown({ isPro: true, supporterBadgeVisible: false })).toBe(false);
  });
});
