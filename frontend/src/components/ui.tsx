import { date, fmt } from "../lib/format";
import { useEffect, useLayoutEffect, useRef, useState, useId } from "react";
import { X, Loader2, Maximize2, Minimize2 } from "lucide-react";

export function Badge({ value }: any) {
  return (
    <span
      className={
        "badge " +
        String(value || "")
          .toLowerCase()
          .replaceAll(" ", "-")
      }
    >
      {value || "Unassigned"}
    </span>
  );
}
export function IconButton({ label, children, onClick, ...props }: any) {
  return (
    <button
      type="button"
      className="icon-button"
      title={label}
      aria-label={label}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  );
}
export function Empty({ text = "No records found.", children }: any) {
  return (
    <div className="empty">
      <p>{text}</p>
      {children}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <Loader2 size={18} className="spin" />
      <span>Loading…</span>
    </div>
  );
}
let dialogLocks = 0;
let previousOverflow = "";
const dialogDrafts = new Map<
  HTMLDialogElement,
  { dirty: boolean; busy: boolean }
>();
const pendingInput = (element: Element | null) =>
  !!element?.querySelector('[data-pending-entry="true"]');

export function Dialog({
  title,
  children,
  onClose,
  wide = false,
  dirty = false,
  busy = false,
}: any) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useId();
  const [expanded, setExpanded] = useState(false);
  const close = () => {
    if (
      !busy &&
      (!(dirty || pendingInput(ref.current)) ||
        window.confirm("Discard unsaved changes?"))
    )
      onClose();
  };
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    ref.current?.showModal();
    if (dialogLocks++ === 0) {
      previousOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    }
    const target = ref.current?.querySelector<HTMLInputElement>(
      "input:not([type=checkbox]):not([type=file]):not([type=hidden]),textarea,[role=combobox]",
    );
    target?.focus();
    return () => {
      if (--dialogLocks === 0) document.body.style.overflow = previousOverflow;
      queueMicrotask(() => {
        if (previousFocus?.isConnected) previousFocus.focus();
      });
    };
  }, []);
  useLayoutEffect(() => {
    const element = ref.current!;
    dialogDrafts.set(element, { dirty, busy });
    const topmost = () =>
      [...document.querySelectorAll("dialog[open]")].at(-1) === ref.current;
    const navigate = (event: Event) => {
      const drafts = [...dialogDrafts.entries()];
      const blocked = drafts.some(([, state]) => state.busy);
      const unsaved = drafts.some(
        ([dialog, state]) => state.dirty || pendingInput(dialog),
      );
      if (
        topmost() &&
        (blocked || (unsaved && !window.confirm("Discard unsaved changes?")))
      )
        event.preventDefault();
    };
    const unload = (event: BeforeUnloadEvent) => {
      if (dirty || busy || pendingInput(element)) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("threatkb:before-navigate", navigate);
    window.addEventListener("beforeunload", unload);
    return () => {
      dialogDrafts.delete(element);
      window.removeEventListener("threatkb:before-navigate", navigate);
      window.removeEventListener("beforeunload", unload);
    };
  }, [dirty, busy]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={heading}
      className={(wide ? "wide " : "") + (expanded ? "expanded" : "")}
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
      onClick={(e) => {
        if (e.target === ref.current) close();
      }}
    >
      <div className="dialog-head">
        <h2 id={heading}>{title}</h2>
        <div className="button-row">
          <IconButton
            label={expanded ? "Reduce dialog" : "Expand dialog"}
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
          </IconButton>
          <IconButton label="Close dialog" disabled={busy} onClick={close}>
            <X size={18} />
          </IconButton>
        </div>
      </div>
      {children}
    </dialog>
  );
}

const detailLabels: Record<string, string> = {
  activity_text: "Activity",
  activity_date: "Date",
  created_at: "Created",
  date_created: "Created",
  started_at: "Started",
  finished_at: "Finished",
  created_user: "Created by",
  created_user_id: "Created by (user ID)",
  is_test_release: "Test release",
  num_signatures: "Signatures",
  num_ips: "IP indicators",
  num_dns: "Domain indicators",
};

export function DetailList({
  value,
  order = [],
}: {
  value: Record<string, any>;
  order?: string[];
}) {
  const keys = [
    ...new Set([...order.filter((key) => key in value), ...Object.keys(value)]),
  ];
  return (
    <dl className="detail-list">
      {keys.map((key) => {
        const item = value[key];
        return (
          <div key={key}>
            <dt>
              {detailLabels[key] ||
                key
                  .replaceAll("_", " ")
                  .replace(
                    /\b(id|ids|ip|ips|dns|asn|uuid|url|sha1|sha256|md5)\b/gi,
                    (word) => word.toUpperCase(),
                  )
                  .replace(/^./, (s) => s.toUpperCase())}
            </dt>
            <dd>
              {item == null || item === "" ? (
                "—"
              ) : typeof item === "boolean" ? (
                item ? (
                  "Yes"
                ) : (
                  "No"
                )
              ) : key === "status" ? (
                <Badge value={item} />
              ) : key === "is_test_release" ? (
                item ? (
                  "Yes"
                ) : (
                  "No"
                )
              ) : key === "progress" && typeof item === "number" ? (
                `${fmt(item)}%`
              ) : Number.isInteger(item) && !/(^|_)id$/.test(key) ? (
                fmt(item)
              ) : typeof item === "object" && item.email ? (
                item.email
              ) : typeof item === "object" ? (
                <pre className="detail-value">
                  {JSON.stringify(item, null, 2)}
                </pre>
              ) : typeof item === "string" &&
                /^\d{4}-\d{2}-\d{2}T/.test(item) ? (
                <time title={item}>{date(item)}</time>
              ) : (
                String(item)
              )}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
