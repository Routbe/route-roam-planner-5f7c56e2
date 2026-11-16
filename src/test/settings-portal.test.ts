import { describe, expect, it } from "vitest";
import { resolveSettingsView, settingsHref, validateSettingsSearch } from "@/lib/settings-portal";

describe("settings portals", () => {
  it("opens Profiel & Account by default", () => {
    expect(resolveSettingsView(undefined, undefined)).toEqual({ portal: "account", section: "profile" });
  });
  it("keeps old security links on Beveiliging & Enclave", () => {
    expect(resolveSettingsView("security", undefined).portal).toBe("security");
  });
  it("sends the old status tab to account control", () => {
    expect(resolveSettingsView("status", undefined)).toEqual({ portal: "account", section: "control" });
  });
  it("maps the old payments tab into Profiel & Account", () => {
    expect(resolveSettingsView("payments", undefined)).toEqual({ portal: "account", section: "payments" });
  });
  it("opens Sessie & Activiteit", () => {
    expect(resolveSettingsView("session", "payments").portal).toBe("session");
  });
  it("ignores an unknown section", () => {
    expect(resolveSettingsView("account", "nope").section).toBe("profile");
  });
  it("writes the section only for the account portal", () => {
    expect(settingsHref({ portal: "account", section: "data" })).toBe("/studio/account?tab=account&section=data");
    expect(settingsHref({ portal: "session", section: "data" })).toBe("/studio/account?tab=session");
  });
  it("drops odd search values", () => {
    expect(validateSettingsSearch({ tab: "security", section: "<x>" })).toEqual({ tab: "security" });
  });
});
