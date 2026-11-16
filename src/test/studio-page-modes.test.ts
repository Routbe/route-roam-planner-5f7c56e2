import { describe, expect, it } from "vitest";
import { studioPageModes } from "@/lib/studio-access";

const base = { tipEnabled: false, qaEnabled: false, bookingsAvailable: true };

describe("studioPageModes", () => {
  it("offers bookings on the verified main profile when bookings are on", () => {
    expect(studioPageModes({ ...base, variant: "verified" })).toContain("booking");
  });
  it("hides bookings on the privacy alias", () => {
    expect(studioPageModes({ ...base, variant: "alias" })).not.toContain("booking");
  });
  it("hides bookings when the platform bookings switch is off", () => {
    expect(studioPageModes({ ...base, variant: "verified", bookingsAvailable: false })).not.toContain("booking");
  });
  it("always keeps the main profile first", () => {
    expect(studioPageModes({ ...base, variant: "alias", tipEnabled: true, qaEnabled: true })).toEqual(["profile", "tip", "qa"]);
  });
});
