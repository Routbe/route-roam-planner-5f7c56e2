import { useCallback, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { KeyRound, Loader2, Lock, MonitorSmartphone, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/i18n";
import { getMyBookingKey, publishMyBookingKey } from "@/lib/booking-engine/booking.functions";
import { b64uDecode, hostRefOf, type HostBookingKeyDoc } from "@/lib/booking-engine/sealed-booking";
import type { BookingPayload } from "@/lib/crypto-enclave/booking-seal";

type KeyState =
  | { kind: "checking" }
  | { kind: "ready"; doc: HostBookingKeyDoc }
  | { kind: "needs_master" | "storage" | "mismatch" | "error" };

const codeOf = (e: unknown) => (e as { code?: string } | null)?.code;

/**
 * The host's booking key (Fase 1): created in the crypto worker on first use,
 * published as a document (public key + seed sealed under the Master Key),
 * and checked on every visit that this device can open it.
 */
export function useHostBookingKey(userId: string) {
  const getKey = useServerFn(getMyBookingKey);
  const publish = useServerFn(publishMyBookingKey);
  const [state, setState] = useState<KeyState>({ kind: "checking" });

  const run = useCallback(async (replace: boolean) => {
    setState({ kind: "checking" });
    try {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      if (!(await enclave.deviceKey.status(userId))) return setState({ kind: "needs_master" });
      const current = await getKey();
      if (!current.ok) return setState({ kind: "storage" });
      let doc: HostBookingKeyDoc;
      try {
        doc = (await enclave.bookingKey.ensure(userId, replace ? null : current.doc)).doc;
      } catch (e) {
        return setState({ kind: codeOf(e) === "key_mismatch" || codeOf(e) === "decrypt_failed" ? "mismatch" : "error" });
      }
      if (!current.doc || replace || current.doc.kid !== doc.kid) {
        const r = await publish({ data: { doc, replace } });
        if (!r.ok) return setState({ kind: r.reason === "exists" ? "mismatch" : r.reason === "storage_unavailable" ? "storage" : "error" });
      }
      setState({ kind: "ready", doc });
    } catch {
      setState({ kind: "error" });
    }
  }, [getKey, publish, userId]);

  useEffect(() => { void run(false); }, [run]);
  return { state, retry: () => void run(false), replace: () => void run(true) };
}

export function BookingKeyBanner({ state, onRetry, onReplace }: { state: KeyState; onRetry: () => void; onReplace: () => void }) {
  const { t } = useI18n();
  const box = "flex items-start gap-3 rounded-2xl border p-4 text-sm";
  if (state.kind === "checking") {
    return <div className={`${box} border-border bg-muted/40`} role="status"><Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin" />{t("booking.seal.checking")}</div>;
  }
  if (state.kind === "ready") {
    return <div className={`${box} border-border bg-muted/40`}><Lock className="mt-0.5 h-4 w-4 shrink-0 text-primary" /><p>{t("booking.seal.active")}</p></div>;
  }
  if (state.kind === "needs_master") return <MasterKeyRecoveryCard onRetry={onRetry} />;
  const text = state.kind === "storage" ? t("booking.seal.storage")
    : state.kind === "mismatch" ? t("booking.seal.mismatch") : t("booking.seal.error");
  return (
    <div className={`${box} border-destructive/40 bg-destructive/10`} role="alert">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
      <div className="min-w-0 space-y-2">
        <p>{text}</p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="soft" onClick={onRetry}>{t("booking.seal.retry")}</Button>
          {state.kind === "mismatch" && (
            <Button size="sm" variant="soft" onClick={() => { if (window.confirm(t("booking.seal.replaceConfirm"))) onReplace(); }}>
              <KeyRound className="h-4 w-4" />{t("booking.seal.replace")}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Shown when this device has no Master Key. Offers only the protocol's recovery
 * paths; nothing here creates or moves key material (that stays in the enclave
 * worker behind the recovery ceremony).
 */
function MasterKeyRecoveryCard({ onRetry }: { onRetry: () => void }) {
  const { t } = useI18n();
  return (
    <section aria-labelledby="master-key-recovery-title" className="rounded-2xl border border-border bg-card p-4 text-card-foreground shadow-sm sm:p-5">
      <div className="flex items-start gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-border bg-muted" aria-hidden>
          <KeyRound className="h-4 w-4" />
        </span>
        <div className="min-w-0 space-y-1">
          <h3 id="master-key-recovery-title" className="text-sm font-semibold">{t("booking.recover.title")}</h3>
          <p className="text-sm text-muted-foreground">{t("booking.recover.body")}</p>
        </div>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-2 rounded-xl border border-border bg-background p-3">
          <div className="flex items-center gap-2">
            <MonitorSmartphone className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="text-sm font-medium">{t("booking.recover.primary")}</span>
            <Badge variant="secondary" className="ml-auto">{t("booking.recover.soon")}</Badge>
          </div>
          <p className="text-xs text-muted-foreground">{t("booking.recover.primaryHint")}</p>
          <Button size="sm" variant="soft" disabled className="mt-auto w-full sm:w-fit">{t("booking.recover.primary")}</Button>
        </div>
        <div className="flex flex-col gap-2 rounded-xl border border-border bg-background p-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-primary" aria-hidden />
            <span className="text-sm font-medium">{t("booking.recover.shares")}</span>
          </div>
          <p className="text-xs text-muted-foreground">{t("booking.recover.sharesHint")}</p>
          <Button asChild size="sm" className="mt-auto w-full sm:w-fit">
            <Link to="/studio/account" search={{ tab: "security" }} hash="herstel">{t("booking.recover.shares")}</Link>
          </Button>
        </div>
      </div>
      <div className="mt-3 flex justify-end">
        <Button size="sm" variant="ghost" onClick={onRetry}>{t("booking.seal.retry")}</Button>
      </div>
    </section>
  );
}

export type SealedBookingRef = { id: string; hostUserId: string; sealed: { pid: string; hosts: Record<string, string> } | null };

/**
 * Opens the host copies of this member's own sealed bookings in one worker
 * call. Plaintext stays in component memory only (no query cache retention).
 */
export function useOpenedGuestDetails(userId: string, state: KeyState, bookings: SealedBookingRef[]) {
  const doc = state.kind === "ready" ? state.doc : null;
  const mine = useMemo(() => bookings.filter((b) => b.sealed && b.hostUserId === userId), [bookings, userId]);
  const q = useQuery({
    queryKey: ["booking-sealed-open", userId, doc?.kid ?? null, mine.map((b) => b.sealed!.pid).join(",")],
    enabled: Boolean(doc) && mine.length > 0,
    gcTime: 0,
    staleTime: Infinity,
    retry: false,
    queryFn: async () => {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      // Only this host's own copy: the one bound to the reference of its published key.
      const ref = hostRefOf(b64uDecode(doc!.publicKey)!);
      const items: { id: string; payloadId: string; envelope: Uint8Array }[] = [];
      const out = new Map<string, BookingPayload | null>();
      for (const b of mine) {
        const text = b.sealed!.hosts[ref];
        const envelope = text ? b64uDecode(text) : null;
        if (envelope) items.push({ id: b.id, payloadId: b.sealed!.pid, envelope });
        else out.set(b.id, null);
      }
      if (items.length > 0) {
        const { payloads } = await enclave.bookingKey.open(userId, doc!, items.map(({ payloadId, envelope }) => ({ payloadId, envelope })));
        items.forEach((it, i) => out.set(it.id, payloads[i] ?? null));
      }
      return out;
    },
  });
  return { opened: q.data ?? null, loading: q.isFetching, failed: q.isError };
}

export function SealedGuestDetails({ booking, userId, opened, loading, timezone, fields }: {
  booking: SealedBookingRef; userId: string; opened: Map<string, BookingPayload | null> | null; loading: boolean;
  timezone: string; fields: { id: string; label: string; type: string }[];
}) {
  const { t } = useI18n();
  if (booking.hostUserId !== userId) {
    return <p className="flex items-center gap-1.5 text-sm text-muted-foreground"><Lock className="h-3.5 w-3.5" />{t("booking.seal.otherHost")} · {timezone}</p>;
  }
  const p = opened?.get(booking.id);
  if (p === undefined) {
    return loading
      ? <p className="flex items-center gap-1.5 text-sm text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />{t("booking.seal.opening")}</p>
      : <p className="flex items-center gap-1.5 text-sm text-muted-foreground"><Lock className="h-3.5 w-3.5" />{timezone}</p>;
  }
  if (p === null) return <p className="flex items-center gap-1.5 text-sm text-destructive"><ShieldAlert className="h-3.5 w-3.5" />{t("booking.seal.unreadable")}</p>;
  const answers = (p.answers ?? []).map((a) => {
    const f = fields.find((x) => x.id === a.questionId);
    const value = f?.type === "checkbox" ? (a.value === "true" ? "✓" : "—") : a.value;
    return { label: f?.label ?? a.questionId, value };
  });
  return (
    <div className="space-y-1">
      <p className="flex min-w-0 items-center gap-1.5 text-sm text-muted-foreground">
        <Lock className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden />
        <span className="truncate">{[p.name, p.email, timezone].filter(Boolean).join(" · ")}</span>
      </p>
      {p.note && <p className="whitespace-pre-wrap text-sm text-muted-foreground">{p.note}</p>}
      {answers.length > 0 && (
        <dl className="mt-2 grid gap-1 rounded-lg border border-border bg-background p-2 text-sm">
          {answers.map((a) => (
            <div key={a.label} className="flex flex-wrap gap-x-2"><dt className="font-medium">{a.label}:</dt><dd className="whitespace-pre-wrap text-muted-foreground">{a.value}</dd></div>
          ))}
        </dl>
      )}
    </div>
  );
}
