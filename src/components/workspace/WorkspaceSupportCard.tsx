import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { deleteWsPspKey, getWsSupportSetup, saveWsPspKey, saveWsSupportSettings } from "@/lib/workspace-support.functions";
import { useI18n } from "@/lib/i18n";

type Setup = NonNullable<Awaited<ReturnType<typeof getWsSupportSetup>>>;
const card = "space-y-4 rounded-2xl border border-border bg-card p-5";

/** Owner/admin card: the workspace's own support page (db/0283). Every check is server-side. */
export function WorkspaceSupportCard({ workspaceId, slug }: { workspaceId: string; slug: string }) {
  const { t } = useI18n();
  const load = useServerFn(getWsSupportSetup);
  const save = useServerFn(saveWsSupportSettings);
  const saveKey = useServerFn(saveWsPspKey);
  const removeKey = useServerFn(deleteWsPspKey);
  const [setup, setSetup] = useState<Setup | null | "loading">("loading");
  const [form, setForm] = useState({ enabled: false, iban: "", accountName: "", presets: "5, 10, 25", allowCustom: true, min: "1", message: "", pspEnabled: false });
  const [busy, setBusy] = useState(false);
  const [keyForm, setKeyForm] = useState({ provider: "mollie" as "mollie" | "stripe", secret: "", publishableKey: "", accept: false });

  async function refresh() {
    const s = await load({ data: { workspaceId } }).catch(() => null);
    setSetup(s);
    if (s) {
      setForm({
        enabled: s.enabled, iban: s.iban, accountName: s.accountName,
        presets: s.presetsCents.map((c) => (c / 100).toString()).join(", ") || "5, 10, 25",
        allowCustom: s.allowCustom, min: (s.minCents / 100).toString(), message: s.message, pspEnabled: s.pspEnabled,
      });
    }
  }
  useEffect(() => { void refresh(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [workspaceId]);

  if (setup === "loading") return <section className={card}><p className="text-sm text-muted-foreground">{t("wsSupport.admin.loading")}</p></section>;
  if (!setup) return null;
  const eligible = setup.ownerDidit || setup.domainVerified;

  async function submit() {
    const minCents = Math.round(Number(form.min.replace(",", ".")) * 100);
    const presetsCents = form.presets.split(/[;,\s]+/).filter(Boolean).map((v) => Math.round(Number(v.replace(",", ".")) * 100)).filter((c) => Number.isFinite(c) && c >= 100).slice(0, 6);
    setBusy(true);
    const res = await save({ data: { workspaceId, enabled: form.enabled, iban: form.iban, accountName: form.accountName, presetsCents, allowCustom: form.allowCustom, minCents: Number.isFinite(minCents) && minCents >= 100 ? minCents : 100, message: form.message, pspEnabled: form.pspEnabled } }).catch(() => null);
    setBusy(false);
    const r = res?.result ?? "unavailable";
    if (r === "ok") { toast.success(t("wsSupport.admin.saved")); void refresh(); }
    else toast.error(t(`wsSupport.result.${r}`));
  }

  async function submitKey() {
    setBusy(true);
    const res = await saveKey({ data: { workspaceId, provider: keyForm.provider, secret: keyForm.secret, publishableKey: keyForm.provider === "stripe" ? keyForm.publishableKey : undefined, acceptDisclaimer: true } }).catch(() => null);
    setBusy(false);
    const r = res?.result ?? "unavailable";
    if (r === "ok") { toast.success(t("wsSupport.admin.keySaved")); setKeyForm({ ...keyForm, secret: "", publishableKey: "", accept: false }); void refresh(); }
    else toast.error(t(`wsSupport.result.${r}`));
  }

  return (
    <section className={card} aria-labelledby="ws-support-title">
      <div className="space-y-1">
        <h2 id="ws-support-title" className="font-medium">{t("wsSupport.admin.title")}</h2>
        <p className="text-sm text-muted-foreground">{t("wsSupport.admin.intro")}</p>
      </div>

      <p className="rounded-xl border border-border bg-background/60 p-3 text-xs text-muted-foreground">
        {setup.ownerDidit ? t("wsSupport.admin.eligibleDidit") : setup.domainVerified ? t("wsSupport.admin.eligibleDomain") : t("wsSupport.admin.notEligible")}
      </p>

      {eligible && (
        <>
          <div className="flex items-center justify-between gap-4">
            <label htmlFor="ws-support-on" className="text-sm font-medium">{t("wsSupport.admin.enable")}</label>
            <Switch id="ws-support-on" checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-sm"><span className="input-label">IBAN</span>
              <Input value={form.iban} onChange={(e) => setForm({ ...form, iban: e.target.value })} autoComplete="off" maxLength={40} /></label>
            <label className="space-y-1 text-sm"><span className="input-label">{t("wsSupport.admin.holder")}</span>
              <Input value={form.accountName} onChange={(e) => setForm({ ...form, accountName: e.target.value })} maxLength={70} /></label>
          </div>
          <p className="text-xs text-muted-foreground">{t("wsSupport.admin.holderHelp")}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-sm"><span className="input-label">{t("wsSupport.admin.presets")}</span>
              <Input value={form.presets} onChange={(e) => setForm({ ...form, presets: e.target.value })} inputMode="decimal" /></label>
            <label className="space-y-1 text-sm"><span className="input-label">{t("wsSupport.admin.minimum")}</span>
              <Input value={form.min} onChange={(e) => setForm({ ...form, min: e.target.value })} inputMode="decimal" /></label>
          </div>
          <div className="flex items-center justify-between gap-4">
            <label htmlFor="ws-support-custom" className="text-sm">{t("wsSupport.admin.allowCustom")}</label>
            <Switch id="ws-support-custom" checked={form.allowCustom} onCheckedChange={(v) => setForm({ ...form, allowCustom: v })} />
          </div>
          <label className="block space-y-1 text-sm"><span className="input-label">{t("wsSupport.admin.message")}</span>
            <Textarea value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} maxLength={400} rows={3} /></label>
          <div className="flex items-center justify-between gap-4">
            <label htmlFor="ws-support-psp" className="text-sm">{t("wsSupport.admin.pspEnable")}</label>
            <Switch id="ws-support-psp" checked={form.pspEnabled} onCheckedChange={(v) => setForm({ ...form, pspEnabled: v })} />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button size="sm" onClick={() => void submit()} disabled={busy}>{t("wsSupport.admin.save")}</Button>
            {setup.enabled && <Button asChild size="sm" variant="outline"><Link to="/w/$slug/support" params={{ slug }}>{t("wsSupport.admin.view")}</Link></Button>}
          </div>

          <div className="space-y-3 border-t border-border pt-4">
            <h3 className="text-sm font-medium">{t("wsSupport.admin.keysTitle")}</h3>
            <p className="text-xs text-muted-foreground">{t("wsSupport.admin.keysIntro")}</p>
            {setup.providers.length > 0 && (
              <ul className="space-y-2">
                {setup.providers.map((p) => (
                  <li key={p.provider} className="flex items-center justify-between gap-3 rounded-xl border border-border px-3 py-2 text-sm">
                    <span>{p.provider === "stripe" ? "Stripe" : "Mollie"} · ••••{p.last4} · {p.mode}</span>
                    <Button size="sm" variant="ghost" disabled={busy} onClick={async () => { setBusy(true); await removeKey({ data: { workspaceId, provider: p.provider } }).catch(() => null); setBusy(false); void refresh(); }}>{t("wsSupport.admin.removeKey")}</Button>
                  </li>
                ))}
              </ul>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-1 text-sm"><span className="input-label">{t("wsSupport.admin.provider")}</span>
                <select className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={keyForm.provider} onChange={(e) => setKeyForm({ ...keyForm, provider: e.target.value as "mollie" | "stripe" })}>
                  <option value="mollie">Mollie</option>
                  <option value="stripe">Stripe</option>
                </select></label>
              <label className="space-y-1 text-sm"><span className="input-label">{keyForm.provider === "stripe" ? t("wsSupport.admin.stripeSecret") : t("wsSupport.admin.mollieSecret")}</span>
                <Input type="password" autoComplete="off" value={keyForm.secret} onChange={(e) => setKeyForm({ ...keyForm, secret: e.target.value })} /></label>
              {keyForm.provider === "stripe" && (
                <label className="space-y-1 text-sm sm:col-span-2"><span className="input-label">{t("wsSupport.admin.stripePublishable")}</span>
                  <Input autoComplete="off" value={keyForm.publishableKey} onChange={(e) => setKeyForm({ ...keyForm, publishableKey: e.target.value })} /></label>
              )}
            </div>
            <label className="flex items-start gap-2 text-xs text-muted-foreground">
              <input type="checkbox" className="mt-0.5 size-4" checked={keyForm.accept} onChange={(e) => setKeyForm({ ...keyForm, accept: e.target.checked })} />
              <span>{t("wsSupport.admin.disclaimer")}</span>
            </label>
            <Button size="sm" variant="outline" disabled={busy || !keyForm.accept || keyForm.secret.length < 10} onClick={() => void submitKey()}>{t("wsSupport.admin.saveKey")}</Button>
          </div>
        </>
      )}
    </section>
  );
}
