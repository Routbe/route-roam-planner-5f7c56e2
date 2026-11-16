/**
 * Workspace support page (/w/<slug>/support, db/0283). ROUT moves no money: an EPC/SEPA QR
 * with the workspace's own IBAN, and optionally the workspace's own Stripe/Mollie keys.
 * Owner/admin checks, eligibility (Didit owner OR verified domain) and the holder-name match
 * all run inside the database definers; this module only shapes input and output.
 */
import { sql } from "@/lib/neon";
import { isValidIban } from "@/lib/epc-qr";
import { checkStripeKey } from "@/lib/tip-rules";

type Row = Record<string, unknown>;
export type WsPspProvider = "stripe" | "mollie";
export type WsPspMethod = "card" | "bancontact" | "wero";
export type WsSupportResult = "ok" | "forbidden" | "not_eligible" | "name_mismatch" | "invalid" | "unavailable";

export type WsSupportSetup = {
  enabled: boolean;
  iban: string;
  accountName: string;
  presetsCents: number[];
  allowCustom: boolean;
  minCents: number;
  message: string;
  pspEnabled: boolean;
  ownerDidit: boolean;
  domainVerified: boolean;
  providers: { provider: WsPspProvider; last4: string; mode: string; verifiedAt: string }[];
};

/** Settings for an owner/admin; null for anyone else or before db/0283 is applied. */
export async function readWsSupportSetup(workspaceId: string): Promise<WsSupportSetup | null> {
  try {
    const rows = (await sql`select * from public.rout_ws_support_get(${workspaceId}::uuid)`) as Row[];
    const r = rows[0];
    if (!r) return null;
    return {
      enabled: r["enabled"] === true,
      iban: (r["iban"] as string | null) ?? "",
      accountName: (r["account_name"] as string | null) ?? "",
      presetsCents: Array.isArray(r["presets_cents"]) ? (r["presets_cents"] as number[]).map(Number) : [],
      allowCustom: r["allow_custom"] !== false,
      minCents: Number(r["min_cents"] ?? 100),
      message: (r["message"] as string | null) ?? "",
      pspEnabled: r["psp_enabled"] === true,
      ownerDidit: r["owner_didit"] === true,
      domainVerified: r["domain_verified"] === true,
      providers: Array.isArray(r["providers"]) ? (r["providers"] as WsSupportSetup["providers"]) : [],
    };
  } catch (error) {
    console.warn("[ws-support] setup unavailable", error);
    return null;
  }
}

export type WsSupportInput = {
  enabled: boolean;
  iban: string;
  accountName: string;
  presetsCents: number[];
  allowCustom: boolean;
  minCents: number;
  message: string;
  pspEnabled: boolean;
};

/** Normalises presets: unique, sorted, within [min, 5000 €], at most six. */
export function normalizePresets(presets: number[], minCents: number): number[] {
  return [...new Set(presets.map((c) => Math.round(c)).filter((c) => c >= minCents && c <= 500_000))].sort((a, b) => a - b).slice(0, 6);
}

export async function saveWsSupport(workspaceId: string, input: WsSupportInput): Promise<WsSupportResult> {
  const iban = input.iban.replace(/\s+/g, "").toUpperCase();
  if ((input.enabled || iban) && !isValidIban(iban)) return "invalid";
  const presets = normalizePresets(input.presetsCents, input.minCents);
  try {
    const rows = (await sql`select public.rout_ws_support_save(${workspaceId}::uuid, ${input.enabled}, ${iban || null},
        ${input.accountName.trim() || null}, ${presets}::int[], ${input.allowCustom}, ${input.minCents},
        ${input.message.trim() || null}, ${input.pspEnabled}) as r`) as Row[];
    return (rows[0]?.["r"] as WsSupportResult) ?? "invalid";
  } catch (error) {
    console.warn("[ws-support] save failed", error);
    return "unavailable";
  }
}

const KEY_SHAPE: Record<WsPspProvider, RegExp> = {
  stripe: /^rk_(live|test)_[A-Za-z0-9]{16,}$/,
  mollie: /^(live|test)_[A-Za-z0-9]{20,}$/,
};

async function probeKey(provider: WsPspProvider, secret: string): Promise<boolean> {
  try {
    if (provider === "stripe") {
      const res = await fetch("https://api.stripe.com/v1/payment_intents?limit=1", { headers: { Authorization: `Bearer ${secret}` } });
      return res.ok || res.status === 403;
    }
    const res = await fetch("https://api.mollie.com/v2/methods", { headers: { Authorization: `Bearer ${secret}` } });
    return res.ok;
  } catch {
    return false;
  }
}

/** Seal context: never collides with a member's personal key (`<userId>:<provider>`). */
const sealContext = (workspaceId: string, provider: WsPspProvider) => `workspace:${workspaceId}:${provider}`;

export async function saveWsPsp(workspaceId: string, provider: WsPspProvider, rawSecret: string, publishableKey?: string | null): Promise<WsSupportResult | "key_invalid" | "key_refused" | "no_encryption"> {
  const { encryptionConfigured, seal } = await import("./crypto/secretbox.server");
  if (!encryptionConfigured()) return "no_encryption";
  const secret = rawSecret.trim();
  let pk: string | null = null;
  if (provider === "stripe") {
    if (!checkStripeKey(secret).ok) return "key_invalid";
    pk = (publishableKey ?? "").trim();
    if (!/^pk_(live|test)_[A-Za-z0-9]{16,}$/.test(pk) || pk.slice(3, 7) !== secret.slice(3, 7)) return "key_invalid";
  }
  if (!KEY_SHAPE[provider].test(secret)) return "key_invalid";
  // Authorization first, so a non-manager never makes the server call a provider.
  const setup = await readWsSupportSetup(workspaceId);
  if (!setup) return "forbidden";
  if (!setup.ownerDidit && !setup.domainVerified) return "not_eligible";
  if (!(await probeKey(provider, secret))) return "key_refused";
  const mode = /(^|_)test_/.test(secret) ? "test" : "live";
  const { ciphertext, iv } = await seal(secret, sealContext(workspaceId, provider));
  const rows = (await sql`select public.rout_ws_psp_save(${workspaceId}::uuid, ${provider}, ${ciphertext}, ${iv},
      ${secret.slice(-4)}, ${mode}, ${pk}) as r`) as Row[];
  return (rows[0]?.["r"] as WsSupportResult) ?? "invalid";
}

export async function deleteWsPsp(workspaceId: string, provider: WsPspProvider): Promise<WsSupportResult> {
  const rows = (await sql`select public.rout_ws_psp_delete(${workspaceId}::uuid, ${provider}) as r`) as Row[];
  return (rows[0]?.["r"] as WsSupportResult) ?? "invalid";
}

export type PublicWsSupport = {
  slug: string;
  name: string;
  avatarUrl: string | null;
  accountName: string;
  iban: string;
  presetsCents: number[];
  allowCustom: boolean;
  minCents: number;
  message: string | null;
  psp: { provider: WsPspProvider; methods: WsPspMethod[] } | null;
};

/** The public page, or null when it is off, no longer eligible, or db/0283 is absent. */
export async function readPublicWsSupport(slug: string): Promise<PublicWsSupport | null> {
  if (!/^[a-z0-9][a-z0-9-]{1,38}$/.test(slug)) return null;
  try {
    const rows = (await sql`select * from public.rout_public_ws_support(${slug})`) as Row[];
    const r = rows[0];
    if (!r || !isValidIban(String(r["iban"] ?? ""))) return null;
    const providers = Array.isArray(r["providers"]) ? (r["providers"] as string[]) : [];
    return {
      slug: String(r["slug"]),
      name: String(r["name"]),
      avatarUrl: (r["avatar_url"] as string | null) ?? null,
      accountName: String(r["account_name"]),
      iban: String(r["iban"]),
      presetsCents: Array.isArray(r["presets_cents"]) ? (r["presets_cents"] as number[]).map(Number) : [],
      allowCustom: r["allow_custom"] !== false,
      minCents: Number(r["min_cents"] ?? 100),
      message: (r["message"] as string | null) ?? null,
      psp: providers.includes("mollie")
        ? { provider: "mollie", methods: ["card", "bancontact", "wero"] }
        : providers.includes("stripe")
          ? { provider: "stripe", methods: ["card"] }
          : null,
    };
  } catch (error) {
    console.warn("[ws-support] public read failed", error);
    return null;
  }
}

/** Creates a payment on the WORKSPACE's own provider account. ROUT never touches the money. */
export async function startWsSupportPayment(opts: { slug: string; amountCents: number; method: WsPspMethod; origin: string }) {
  const page = await readPublicWsSupport(opts.slug);
  if (!page?.psp || !page.psp.methods.includes(opts.method)) return { ok: false as const, message: "method_unavailable" };
  const { resolveTipAmount } = await import("./payment-amount-policy");
  const amount = resolveTipAmount(opts.amountCents, { presetsCents: page.presetsCents, allowCustom: page.allowCustom, minCents: page.minCents });
  if (amount === null) return { ok: false as const, message: "amount_invalid" };
  const rows = (await sql`select * from public.rout_ws_psp_tip_credential(${page.slug}, ${page.psp.provider})`) as Row[];
  const cred = rows[0];
  if (!cred) return { ok: false as const, message: "method_unavailable" };
  const { open } = await import("./crypto/secretbox.server");
  const secret = await open(String(cred["ciphertext"]), String(cred["iv"]), sealContext(String(cred["workspace_id"]), page.psp.provider));
  const back = `${opts.origin.replace(/\/$/, "")}/w/${encodeURIComponent(page.slug)}/support`;
  const description = `Steun voor ${page.name}`;
  try {
    if (page.psp.provider === "stripe") {
      const publishableKey = (cred["publishable_key"] as string | null) ?? null;
      if (!publishableKey) return { ok: false as const, message: "method_unavailable" };
      const body = new URLSearchParams({ amount: String(amount), currency: "eur", description, "automatic_payment_methods[enabled]": "true" });
      const res = await fetch("https://api.stripe.com/v1/payment_intents", {
        method: "POST",
        headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      const json = (await res.json()) as { client_secret?: string };
      if (!res.ok || !json.client_secret) {
        console.warn("[ws-support] stripe", res.status);
        return { ok: false as const, message: "provider_refused" };
      }
      return { ok: true as const, embedded: { clientSecret: json.client_secret, publishableKey, returnUrl: `${back}?status=success` } };
    }
    const payload: Record<string, unknown> = {
      amount: { currency: "EUR", value: (amount / 100).toFixed(2) },
      description,
      redirectUrl: `${back}?status=success`,
    };
    if (opts.method === "card") payload["method"] = "creditcard";
    if (opts.method === "bancontact") payload["method"] = "bancontact";
    const res = await fetch("https://api.mollie.com/v2/payments", {
      method: "POST",
      headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = (await res.json()) as { _links?: { checkout?: { href?: string } } };
    const url = json._links?.checkout?.href;
    if (!res.ok || !url) {
      console.warn("[ws-support] mollie", res.status);
      return { ok: false as const, message: "provider_refused" };
    }
    return { ok: true as const, url };
  } catch (error) {
    console.warn("[ws-support] psp failed", error);
    return { ok: false as const, message: "provider_unreachable" };
  }
}
