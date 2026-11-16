import { Crown } from "lucide-react";
import { useI18n } from "@/lib/i18n";

/**
 * Discreet ROUT Supporter / Pro mark. Strictly separate from identity: it says the member
 * supports ROUT, never who they are. The blue identity mark comes only from Didit.
 */
export function SupporterCrownBadge({ color, className = "size-4" }: { color?: string; className?: string }) {
  const { t } = useI18n();
  const label = t("profile.supporter.label");
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className="inline-flex shrink-0 items-center justify-center opacity-80"
      style={color ? { color } : undefined}
    >
      <Crown className={className} strokeWidth={1.75} aria-hidden />
    </span>
  );
}
