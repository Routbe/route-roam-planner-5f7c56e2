import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { enclave } from "@/lib/crypto-enclave/client";
import { b64uDecode, b64uEncode } from "@/lib/booking-engine/sealed-booking";
import { getWsAnswer, submitWsQuestion } from "@/lib/workspace-ask.functions";
import type { WsAskKey, WsFaqItem } from "@/lib/workspace-ask.server";

type Props = { data: { key: WsAskKey | null; faq: WsFaqItem[] }; slug: string };
type View =
  | { kind: "form" }
  | { kind: "sending" }
  | { kind: "waiting"; status: string }
  | { kind: "answered"; question: string; answer: string }
  | { kind: "error"; message: string };

const TOKEN_RE = /(?:^|&)token=([A-Za-z0-9_-]{43})(?:&|$)/;

async function sha256B64u(token: string): Promise<string> {
  const raw = b64uDecode(token);
  if (!raw) throw new Error("invalid");
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  raw.fill(0);
  return b64uEncode(d);
}

export function WorkspaceAskPage({ data, slug }: Props) {
  const [text, setText] = useState("");
  const [view, setView] = useState<View>({ kind: "form" });
  const [token, setToken] = useState<string | null>(null);
  const submit = useServerFn(submitWsQuestion);
  const fetchAnswer = useServerFn(getWsAnswer);

  useEffect(() => {
    const m = TOKEN_RE.exec(window.location.hash.slice(1));
    if (m?.[1]) setToken(m[1]);
  }, []);

  useEffect(() => {
    if (!token) return;
    let stop = false;
    const poll = async () => {
      try {
        const r = await fetchAnswer({ data: { tokenHash: await sha256B64u(token) } });
        if (stop) return;
        if (!r.ok) return setView({ kind: "error", message: "Deze link is ongeldig of verlopen." });
        if (r.status === "answered" && r.envelope) {
          const env = b64uDecode(r.envelope);
          if (!env) return setView({ kind: "error", message: "Het antwoord kon niet worden gelezen." });
          const opened = await enclave.workspaceAsk.openAnswer(token, env);
          return setView({ kind: "answered", ...opened });
        }
        setView({ kind: "waiting", status: r.status });
      } catch {
        if (!stop) setView({ kind: "error", message: "Er ging iets mis bij het ophalen van je antwoord." });
      }
    };
    void poll();
    const t = setInterval(poll, 30_000);
    return () => { stop = true; clearInterval(t); };
  }, [token, fetchAnswer]);

  const key = data.key;
  const send = async () => {
    if (!key || !text.trim()) return;
    setView({ kind: "sending" });
    try {
      const pk = b64uDecode(key.publicKey);
      if (!pk) throw new Error("key");
      const s = await enclave.workspaceAsk.seal(key.workspaceId, key.epoch, pk, text.trim());
      const r = await submit({
        data: {
          slug, payloadId: s.payloadId, epoch: key.epoch,
          envelope: b64uEncode(s.envelope), guestPublicKey: b64uEncode(s.guestPublicKey),
          tokenHash: b64uEncode(s.tokenHash), pow: s.pow,
        },
      });
      if (!r.ok) {
        const msg = r.reason === "rate_limited" ? "Er zijn net te veel vragen gesteld. Probeer het later opnieuw."
          : "Je vraag kon niet worden verstuurd. Probeer het opnieuw.";
        return setView({ kind: "error", message: msg });
      }
      window.history.replaceState(null, "", `#token=${s.token}`);
      setText("");
      setToken(s.token);
      setView({ kind: "waiting", status: "open" });
    } catch {
      setView({ kind: "error", message: "Je vraag kon niet worden versleuteld of verstuurd." });
    }
  };

  return (
    <main className="mx-auto max-w-2xl px-4 py-12 text-foreground">
      <h1 className="text-3xl font-semibold">Anonieme vraag{key ? ` aan ${key.name}` : ""}</h1>
      <p className="mt-2 text-muted-foreground">
        Je vraag wordt in je eigen browser versleuteld. Alleen de beheerders kunnen ze lezen; ROUT niet.
      </p>

      <section className="mt-8 rounded-lg border border-border bg-card p-5">
        {!key && !token && <p>Vragen stellen is hier op dit moment niet mogelijk.</p>}
        {key && (view.kind === "form" || view.kind === "sending") && !token && (
          <div className="space-y-3">
            <Textarea value={text} maxLength={2000} rows={6} onChange={(e) => setText(e.target.value)}
              placeholder="Typ je vraag…" aria-label="Je vraag" />
            <Button onClick={send} disabled={view.kind === "sending" || !text.trim()}>
              {view.kind === "sending" ? "Versleutelen en versturen…" : "Anoniem versturen"}
            </Button>
          </div>
        )}
        {view.kind === "waiting" && (
          <div className="space-y-2">
            <p className="font-medium">
              {view.status === "declined" ? "Deze vraag werd niet beantwoord."
                : view.status === "published" ? "Je vraag werd openbaar beantwoord in de veelgestelde vragen hieronder."
                : "Je vraag is ontvangen. Wachten op antwoord…"}
            </p>
            <p className="text-sm text-muted-foreground">
              Bewaar de link in je adresbalk: alleen daarmee kun je het antwoord later lezen.
            </p>
          </div>
        )}
        {view.kind === "answered" && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">Jouw vraag</p>
            <p className="whitespace-pre-wrap">{view.question}</p>
            <p className="text-sm text-muted-foreground">Antwoord</p>
            <p className="whitespace-pre-wrap">{view.answer}</p>
          </div>
        )}
        {view.kind === "error" && <p className="text-destructive">{view.message}</p>}
      </section>

      {data.faq.length > 0 && (
        <section className="mt-10">
          <h2 className="text-xl font-semibold">Veelgestelde vragen</h2>
          <ul className="mt-4 space-y-4">
            {data.faq.map((f) => (
              <li key={f.id} className="rounded-lg border border-border p-4">
                <p className="font-medium whitespace-pre-wrap">{f.question}</p>
                <p className="mt-2 whitespace-pre-wrap text-muted-foreground">{f.answer}</p>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}
