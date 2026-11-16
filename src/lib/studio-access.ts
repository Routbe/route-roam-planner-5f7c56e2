/** Verified-profile tab is unlocked only for verified, active (or paid) accounts. Pure + testable. */
export function verifiedTabUnlocked(state: { verified: boolean; status?: string | null; isPaid?: boolean } | null | undefined): boolean {
  if (!state) return false;
  return state.verified && (state.status === "active" || Boolean(state.isPaid));
}

export type VerificationCta = "verified" | "pending" | "request";

/** What the studio shows instead of / as the verification button. Pure + testable. */
export function verificationCta(
  state: { verified: boolean; status?: string | null; isPaid?: boolean } | null | undefined,
): VerificationCta {
  if (!state) return "request";
  if (state.verified) return "verified";
  if (state.status === "pending" || state.status === "pending_review") return "pending";
  return "request";
}

export type StudioPageMode = "profile" | "tip" | "booking" | "qa";

/**
 * Which pages the Studio page switcher offers for the selected profile. Bookings
 * exist only on the verified (main) profile and only while the platform-wide
 * bookings switch is on; aliases and switched-off platforms never show the tab.
 */
export function studioPageModes(opts: {
  variant: string;
  tipEnabled: boolean;
  qaEnabled: boolean;
  bookingsAvailable: boolean;
}): StudioPageMode[] {
  const modes: StudioPageMode[] = ["profile"];
  if (opts.tipEnabled) modes.push("tip");
  if (opts.variant === "verified" && opts.bookingsAvailable) modes.push("booking");
  if (opts.qaEnabled) modes.push("qa");
  return modes;
}
