/**
 * /studio/account is split into three portals. Older links (?tab=profile, security,
 * identities, payments, data, status) keep landing on the matching place.
 */
export const SETTINGS_PORTALS = ["account", "security", "session"] as const;
export type SettingsPortal = (typeof SETTINGS_PORTALS)[number];

export const ACCOUNT_SECTIONS = ["profile", "identities", "payments", "data", "control"] as const;
export type AccountSection = (typeof ACCOUNT_SECTIONS)[number];

export type SettingsView = { portal: SettingsPortal; section: AccountSection };

const LEGACY_ACCOUNT_TABS: Record<string, AccountSection> = {
  profile: "profile",
  identities: "identities",
  payments: "payments",
  data: "data",
  status: "control",
};

const isSection = (v: unknown): v is AccountSection => ACCOUNT_SECTIONS.includes(v as AccountSection);

export function resolveSettingsView(tab: unknown, section: unknown): SettingsView {
  if (tab === "security") return { portal: "security", section: "profile" };
  if (tab === "session") return { portal: "session", section: "profile" };
  if (typeof tab === "string" && tab in LEGACY_ACCOUNT_TABS) return { portal: "account", section: LEGACY_ACCOUNT_TABS[tab] };
  return { portal: "account", section: isSection(section) ? section : "profile" };
}

/** Address for a view; only the account portal carries a section. */
export function settingsHref(view: SettingsView): string {
  return view.portal === "account"
    ? `/studio/account?tab=account&section=${view.section}`
    : `/studio/account?tab=${view.portal}`;
}

/** Route search: keep only short string values; the page resolves them. */
export function validateSettingsSearch(search: Record<string, unknown>): { tab?: string; section?: string } {
  const pick = (v: unknown) => (typeof v === "string" && /^[a-z]{1,20}$/.test(v) ? v : undefined);
  const tab = pick(search.tab), section = pick(search.section);
  return { ...(tab ? { tab } : {}), ...(section ? { section } : {}) };
}
