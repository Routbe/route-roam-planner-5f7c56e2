import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

const uuid = z.string().uuid();
const provider = z.enum(["stripe", "mollie"]);

/** Owner/admin only (decided in db/0283 from the session's member id). */
export const getWsSupportSetup = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ workspaceId: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { readWsSupportSetup } = await import("./workspace-support.server");
    return readWsSupportSetup(data.workspaceId);
  });

export const saveWsSupportSettings = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({
      workspaceId: uuid,
      enabled: z.boolean(),
      iban: z.string().max(40),
      accountName: z.string().max(70),
      presetsCents: z.array(z.number().int().min(100).max(500_000)).max(6),
      allowCustom: z.boolean(),
      minCents: z.number().int().min(100).max(500_000),
      message: z.string().max(400),
      pspEnabled: z.boolean(),
    }).parse(d),
  )
  .handler(async ({ data }) => {
    const { saveWsSupport } = await import("./workspace-support.server");
    const { workspaceId, ...input } = data;
    return { result: await saveWsSupport(workspaceId, input) };
  });

export const saveWsPspKey = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({ workspaceId: uuid, provider, secret: z.string().min(10).max(300), publishableKey: z.string().max(300).optional(), acceptDisclaimer: z.literal(true) }).parse(d),
  )
  .handler(async ({ data }) => {
    const { saveWsPsp } = await import("./workspace-support.server");
    return { result: await saveWsPsp(data.workspaceId, data.provider, data.secret, data.publishableKey ?? null) };
  });

export const deleteWsPspKey = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ workspaceId: uuid, provider }).parse(d))
  .handler(async ({ data }) => {
    const { deleteWsPsp } = await import("./workspace-support.server");
    return { result: await deleteWsPsp(data.workspaceId, data.provider) };
  });

/** Public: the active support page of a workspace, or null. */
export const getPublicWsSupport = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ slug: z.string().max(40) }).parse(d))
  .handler(async ({ data }) => {
    try {
      await (await import("@/lib/platform-features.server")).assertPlatformFeature("tips");
    } catch {
      return null;
    }
    const { readPublicWsSupport } = await import("./workspace-support.server");
    return readPublicWsSupport(data.slug.toLowerCase());
  });

/** Public: start a payment on the workspace's own provider. ALTCHA first, like personal tips. */
export const startWsSupportTip = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) =>
    z.object({
      slug: z.string().max(40),
      amountCents: z.number().int().min(100).max(500_000),
      method: z.enum(["card", "bancontact", "wero"]),
      origin: z.string().url().max(300),
      altcha: z.string().max(4000).nullable().optional(),
    }).parse(d),
  )
  .handler(async ({ data }) => {
    await (await import("@/lib/platform-features.server")).assertPlatformFeature("tips");
    const { assertHuman } = await import("./altcha.server");
    await assertHuman(data.altcha ?? null);
    const { getRequest } = await import("@tanstack/react-start/server");
    const { trustedCheckoutOrigin } = await import("./verification.server");
    const origin = trustedCheckoutOrigin(getRequest(), data.origin);
    const { startWsSupportPayment } = await import("./workspace-support.server");
    return startWsSupportPayment({ slug: data.slug.toLowerCase(), amountCents: data.amountCents, method: data.method, origin });
  });
