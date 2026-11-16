import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const slug = z.string().min(1).max(40).transform((s) => s.toLowerCase());
const b64u = (max: number) => z.string().max(max).regex(/^[A-Za-z0-9_-]+$/);

/** Public: live workspace key + published FAQ for /w/<slug>/ask; null key = questions off or 0285 absent. */
export const getWsAskPage = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ slug }).parse(d))
  .handler(async ({ data }) => {
    const { readWsAskKey, readWsFaq } = await import("./workspace-ask.server");
    const [key, faq] = await Promise.all([readWsAskKey(data.slug), readWsFaq(data.slug)]);
    return { key, faq };
  });

/** Public: one sealed question. Hashcash proof over the exact ciphertext is checked first. */
export const submitWsQuestion = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) =>
    z.object({
      slug,
      payloadId: z.string().uuid(),
      epoch: z.number().int().min(1).max(1_000_000),
      envelope: b64u(24063),
      guestPublicKey: b64u(2134),
      tokenHash: b64u(43),
      pow: z.object({ nonce: z.string().regex(/^[0-9a-f]{16}$/), epoch: z.number().int().positive() }),
    }).parse(d),
  )
  .handler(async ({ data }) => {
    const { createWsQuestion } = await import("./workspace-ask.server");
    return createWsQuestion(data);
  });

/** Public: status/answer envelope for the hash of the visitor's own token. */
export const getWsAnswer = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ tokenHash: b64u(43) }).parse(d))
  .handler(async ({ data }) => {
    const { fetchWsAnswer } = await import("./workspace-ask.server");
    return fetchWsAnswer(data.tokenHash);
  });
