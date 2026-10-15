import { useEffect, useRef, useState, useId } from "react";
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
    if (!busy && (!dirty || window.confirm("Discard unsaved changes?")))
      onClose();
  };
  useEffect(() => {
    ref.current?.showModal();
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const target = ref.current?.querySelector<HTMLInputElement>(
      "input:not([type=checkbox]):not([type=file]),textarea,select",
    );
    target?.focus();
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);
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
