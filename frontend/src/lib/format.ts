export const fmt = (value: any) => Number(value || 0).toLocaleString();
export function date(value: any) {
  if (!value) return "—";
  const raw = String(value);
  const parsed = new Date(/[zZ]$|[+-]\d{2}:\d{2}$/.test(raw) ? raw : raw + "Z");
  return Number.isNaN(parsed.getTime())
    ? "—"
    : parsed.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        ...(parsed.getFullYear() !== new Date().getFullYear()
          ? { year: "numeric" as const }
          : {}),
        hour: "numeric",
        minute: "2-digit",
      });
}
