import { lazy, Suspense, useMemo, useState } from "react";
import { useSearch } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { QRCodeSVG } from "qrcode.react";
import { Check, CheckCircle2, Copy, CreditCard, Landmark, Loader2, Lock } from "lucide-react";
import { toast } from "sonner";
import { Altcha } from "@/components/Altcha";
import { takeProof } from "@/lib/altcha-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { UserAvatar } from "@/components/UserAvatar";
import { buildEpcPayload } from "@/lib/epc-qr";
import { getPublicWsSupport, startWsSupportTip } from "@/lib/workspace-support.functions";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type PublicWsSupport = NonNullable<Awaited<ReturnType<typeof getPublicWsSupport>>>;
const StripeEmbeddedPay = lazy(() => import("@/components/tip/StripeEmbeddedPay"));
const groupIban = (iban: string) => iban.replace(/(.{4})/g, "$1 ").trim();

function CopyRow({ label, value, display, copyLabel }: { label: string; value: string; display?: string; copyLabel: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <div className="min-w-0">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className="truncate font-mono text-sm">{display ?? value}</p>
      </div>
      <Button
        type="button"
        size="icon"
        variant="ghost"
        className="size-11"
        aria-label={copyLabel}
        onClick={async () => {
          await navigator.clipboard.writeText(value).catch(() => undefined);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }}
      >
        {done ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  );
}

/** Public workspace support page: EPC QR + IBAN, optionally the workspace's own PSP. */
export function WorkspaceSupportPage({ page, slug }: { page: PublicWsSupport | null; slug: string }) {
  const { t, locale } = useI18n();
  const search = useSearch({ strict: false }) as { status?: string };
  const start = useServerFn(startWsSupportTip);
  const [amount, setAmount] = useState<number | null>(page?.presetsCents[0] ?? null);
  const [custom, setCustom] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [embedded, setEmbedded] = useState<{ clientSecret: string; publishableKey: string; returnUrl: string } | null>(null);
  const euro = (cents: number) => new Intl.NumberFormat(locale, { style: "currency", currency: "EUR" }).format(cents / 100);

  const cents = useMemo(() => {
    if (custom.trim()) {
      const v = Math.round(Number(custom.replace(",", ".")) * 100);
      return Number.isFinite(v) ? v : 0;
    }
    return amount ?? 0;
  }, [custom, amount]);

  if (!page) {
    return (
      <main className="grid min-h-screen place-items-center bg-background px-6 text-center">
        <div className="max-w-sm space-y-2">
          <Lock className="mx-auto h-6 w-6 text-muted-foreground" aria-hidden />
          <h1 className="text-lg font-medium">{t("wsSupport.none.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("wsSupport.none.body", { slug })}</p>
        </div>
      </main>
    );
  }

  const tooLow = cents < page.minCents;
  const reference = t("wsSupport.reference", { name: page.name });
  const epc = !tooLow ? buildEpcPayload({ beneficiary: page.accountName, iban: page.iban, amountCents: cents, reference }) : null;

  const pay = async (method: "card" | "bancontact" | "wero") => {
    if (tooLow) return toast.error(t("wsSupport.minimum", { amount: euro(page.minCents) }));
    setBusy(method);
    const res = await start({ data: { slug: page.slug, amountCents: cents, method, origin: window.location.origin, altcha: await takeProof() } }).catch(() => null);
    setBusy(null);
    if (res?.ok && "embedded" in res && res.embedded) setEmbedded(res.embedded);
    else if (res?.ok && "url" in res && res.url) window.location.href = res.url;
    else toast.error(t("wsSupport.payFailed"));
  };

  return (
    <main className="min-h-screen bg-background px-4 py-10 text-foreground sm:py-16">
      <div className="mx-auto w-full max-w-md space-y-6">
        <header className="flex flex-col items-center gap-3 text-center">
          <UserAvatar src={page.avatarUrl} name={page.name} className="h-20 w-20 ring-1 ring-border" />
          <h1 className="font-display text-2xl tracking-tight">{t("wsSupport.title", { name: page.name })}</h1>
          {page.message && <p className="text-sm text-muted-foreground">{page.message}</p>}
        </header>

        {search.status === "success" ? (
          <section className="rounded-3xl border border-border bg-card p-8 text-center">
            <CheckCircle2 className="mx-auto mb-3 h-10 w-10 text-primary" />
            <h2 className="text-lg font-medium">{t("wsSupport.thanks.title")}</h2>
            <p className="mt-1 text-sm text-muted-foreground">{t("wsSupport.thanks.body", { name: page.name })}</p>
          </section>
        ) : (
          <section className="flex flex-col gap-5 rounded-3xl border border-border bg-card p-5 sm:p-6">
            <div className="space-y-2">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">{t("wsSupport.pickAmount")}</p>
              <div className="grid grid-cols-3 gap-2">
                {page.presetsCents.map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => { setAmount(c); setCustom(""); }}
                    className={cn(
                      "h-11 rounded-full border text-sm font-medium transition-colors",
                      !custom && amount === c ? "border-primary bg-primary/10" : "border-border text-muted-foreground hover:border-foreground/40",
                    )}
                  >
                    {euro(c)}
                  </button>
                ))}
              </div>
              {page.allowCustom && (
                <Input inputMode="decimal" placeholder={t("wsSupport.otherAmount", { amount: euro(page.minCents) })} value={custom} onChange={(e) => setCustom(e.target.value)} className="h-11" aria-label={t("wsSupport.otherAmountLabel")} />
              )}
              {tooLow && <p className="text-xs text-destructive">{t("wsSupport.minimum", { amount: euro(page.minCents) })}</p>}
            </div>

            <div className="space-y-3">
              <p className="flex items-center gap-2 text-sm font-medium"><Landmark className="h-4 w-4" aria-hidden /> {t("wsSupport.scan")}</p>
              <div className="mx-auto w-fit rounded-2xl bg-background p-4 ring-1 ring-border">
                {epc ? (
                  <QRCodeSVG value={epc} size={200} level="M" marginSize={0} bgColor="transparent" fgColor="currentColor" className="text-foreground" aria-label={t("wsSupport.qrLabel", { amount: euro(cents) })} />
                ) : (
                  <div className="grid h-[200px] w-[200px] place-items-center text-center text-xs text-muted-foreground">{t("wsSupport.pickValid")}</div>
                )}
              </div>
              <p className="text-center text-xs text-muted-foreground">{t("wsSupport.bankToBank")}</p>
              <div className="divide-y divide-border rounded-2xl border border-border px-4">
                <CopyRow label={t("wsSupport.beneficiary")} value={page.accountName} copyLabel={t("wsSupport.copy", { field: t("wsSupport.beneficiary") })} />
                <CopyRow label="IBAN" value={page.iban} display={groupIban(page.iban)} copyLabel={t("wsSupport.copy", { field: "IBAN" })} />
                <CopyRow label={t("wsSupport.amount")} value={(cents / 100).toFixed(2)} display={euro(cents)} copyLabel={t("wsSupport.copy", { field: t("wsSupport.amount") })} />
                <CopyRow label={t("wsSupport.referenceLabel")} value={reference} copyLabel={t("wsSupport.copy", { field: t("wsSupport.referenceLabel") })} />
              </div>
            </div>

            {page.psp && (
              <div className="space-y-3 border-t border-border pt-5">
                <p className="text-sm font-medium">{t("wsSupport.payDirect")}</p>
                {embedded ? (
                  <Suspense fallback={<Loader2 className="mx-auto h-5 w-5 animate-spin" />}>
                    <StripeEmbeddedPay {...embedded} label={t("wsSupport.payAmount", { amount: euro(cents) })} onCancel={() => setEmbedded(null)} />
                  </Suspense>
                ) : (
                  <>
                    <Altcha />
                    <div className="grid gap-2">
                      {page.psp.methods.includes("card") && (
                        <Button variant="outline" className="h-12 justify-start gap-3 rounded-full" disabled={!!busy || tooLow} onClick={() => void pay("card")}>
                          {busy === "card" ? <Loader2 className="h-4 w-4 animate-spin" /> : <CreditCard className="h-4 w-4" />} {t("wsSupport.card")} · {euro(cents)}
                        </Button>
                      )}
                      {page.psp.methods.includes("bancontact") && (
                        <Button variant="outline" className="h-12 justify-start gap-3 rounded-full" disabled={!!busy || tooLow} onClick={() => void pay("bancontact")}>
                          {busy === "bancontact" ? <Loader2 className="h-4 w-4 animate-spin" /> : <span className="text-xs font-bold">BC</span>} Bancontact · {euro(cents)}
                        </Button>
                      )}
                      {page.psp.methods.includes("wero") && (
                        <Button variant="outline" className="h-12 justify-start gap-3 rounded-full" disabled={!!busy || tooLow} onClick={() => void pay("wero")}>
                          {busy === "wero" ? <Loader2 className="h-4 w-4 animate-spin" /> : <span className="text-xs font-bold">W</span>} {t("wsSupport.wero")} · {euro(cents)}
                        </Button>
                      )}
                    </div>
                  </>
                )}
                <p className="text-center text-[11px] text-muted-foreground">{t("wsSupport.pspNote", { name: page.name })}</p>
              </div>
            )}
          </section>
        )}
      </div>
    </main>
  );
}
