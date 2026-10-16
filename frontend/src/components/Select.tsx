import {
  Children,
  isValidElement,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown, Search } from "lucide-react";

// Keep native form validation while presenting the same searchable control on every platform.
export function Select({
  children,
  value,
  onChange,
  className = "",
  renderValue,
  ...props
}: any) {
  const optionText = (node: any): string =>
    Children.toArray(node)
      .map((n: any) =>
        isValidElement(n) ? optionText((n.props as any).children) : String(n),
      )
      .join("");
  const options = Children.toArray(children)
    .filter(isValidElement)
    .map((child: any) => ({
      value: String(child.props.value ?? child.props.children),
      label: optionText(child.props.children),
      disabled: child.props.disabled,
    }));
  const root = useRef<HTMLSpanElement>(null),
    trigger = useRef<HTMLButtonElement>(null),
    popup = useRef<HTMLDivElement>(null),
    search = useRef<HTMLInputElement>(null);
  const id = useId();
  const [open, setOpen] = useState(false),
    [query, setQuery] = useState(""),
    [active, setActive] = useState(0),
    [label, setLabel] = useState(props["aria-label"] || "Choose a value"),
    [position, setPosition] = useState<any>({}),
    [host, setHost] = useState<HTMLElement | null>(null);
  const matches = options.filter((o) =>
    o.label.toLowerCase().includes(query.toLowerCase()),
  );
  const selected = options.find((o) => o.value === String(value ?? ""));
  useLayoutEffect(() => {
    setHost(root.current?.closest("dialog") || document.body);
    const parentLabel = root.current?.closest("label");
    if (parentLabel) parentLabel.htmlFor = id + "-trigger";
    if (!props["aria-label"]) {
      const text = Array.from(root.current?.closest("label")?.childNodes || [])
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent)
        .join(" ")
        .trim();
      if (text) setLabel(text);
    }
  }, [props["aria-label"]]);
  const close = (focus = false) => {
    setOpen(false);
    if (focus) trigger.current?.focus();
  };
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = trigger.current!.getBoundingClientRect(),
        below = innerHeight - rect.bottom - 12;
      const height = Math.min(320, Math.max(below, rect.top - 12));
      const width = Math.min(Math.max(rect.width, 224), innerWidth - 24);
      setPosition({
        position: "fixed",
        width,
        maxHeight: height,
        left: Math.max(12, Math.min(rect.left, innerWidth - width - 12)),
        ...(below >= 200 || below >= rect.top - 12
          ? { top: rect.bottom + 4 }
          : { bottom: innerHeight - rect.top + 4 }),
      });
    };
    place();
    search.current?.focus();
    const outside = (e: PointerEvent) => {
      if (
        !root.current?.contains(e.target as Node) &&
        !popup.current?.contains(e.target as Node)
      )
        close();
    };
    const scroll = (e: Event) => {
      if (!popup.current?.contains(e.target as Node)) place();
    };
    document.addEventListener("pointerdown", outside);
    window.addEventListener("resize", place);
    document.addEventListener("scroll", scroll, true);
    return () => {
      document.removeEventListener("pointerdown", outside);
      window.removeEventListener("resize", place);
      document.removeEventListener("scroll", scroll, true);
    };
  }, [open]);
  useEffect(() => {
    const option = document.getElementById(id + "-" + active),
      list = option?.parentElement;
    if (option && list) {
      if (option.offsetTop < list.scrollTop) list.scrollTop = option.offsetTop;
      else if (
        option.offsetTop + option.offsetHeight >
        list.scrollTop + list.clientHeight
      )
        list.scrollTop =
          option.offsetTop + option.offsetHeight - list.clientHeight;
    }
  }, [active, id, query]);
  const choose = (option: any) => {
    if (!option || option.disabled) return;
    onChange?.({
      target: { value: option.value, name: props.name },
      currentTarget: { value: option.value },
    });
    close(true);
  };
  return (
    <span className={"select-control " + className} ref={root}>
      <select
        {...props}
        className="sr-only"
        aria-hidden="true"
        tabIndex={-1}
        value={value ?? ""}
        onChange={onChange}
        onInvalid={(e) => {
          e.preventDefault();
          trigger.current?.focus();
          setOpen(true);
        }}
      >
        {children}
      </select>
      <button
        ref={trigger}
        id={id + "-trigger"}
        type="button"
        role="combobox"
        aria-label={props["aria-label"] || label}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? id : undefined}
        aria-required={props.required || undefined}
        disabled={props.disabled}
        title={props.title}
        className="select-trigger"
        onClick={() => {
          setQuery("");
          setActive(
            Math.max(
              0,
              options.findIndex((o) => o.value === String(value ?? "")),
            ),
          );
          setOpen(!open);
        }}
        onKeyDown={(e) => {
          if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
            e.preventDefault();
            setQuery("");
            setActive(
              Math.max(
                0,
                options.findIndex((o) => o.value === String(value ?? "")),
              ),
            );
            setOpen(true);
          }
        }}
      >
        <span>
          {renderValue && selected
            ? renderValue(selected.label)
            : selected?.label || props.placeholder || "Choose a value"}
        </span>
        <ChevronDown size={14} aria-hidden="true" />
      </button>
      {open &&
        host &&
        createPortal(
          <div
            className="select-popover"
            ref={popup}
            style={position}
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault();
                e.stopPropagation();
                close(true);
              }
              if (e.key === "Tab") close(true);
              if (["ArrowDown", "ArrowUp"].includes(e.key)) {
                e.preventDefault();
                const step = e.key === "ArrowDown" ? 1 : -1;
                let next = active + step;
                while (
                  next >= 0 &&
                  next < matches.length &&
                  matches[next].disabled
                )
                  next += step;
                if (next >= 0 && next < matches.length) setActive(next);
              }
              if (e.key === "Enter") {
                e.preventDefault();
                choose(matches[active]);
              }
            }}
          >
            <div className="select-search">
              <Search size={14} />
              <input
                ref={search}
                aria-label={"Search " + (props["aria-label"] || label)}
                placeholder="Search…"
                value={query}
                aria-controls={id}
                aria-activedescendant={
                  matches[active] ? id + "-" + active : undefined
                }
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActive(0);
                }}
              />
            </div>
            <div
              role="listbox"
              id={id}
              aria-label={props["aria-label"] || label}
              className="select-options"
            >
              {matches.map((option, i) => (
                <div
                  role="option"
                  id={id + "-" + i}
                  key={option.value}
                  aria-selected={option.value === String(value ?? "")}
                  aria-disabled={option.disabled || undefined}
                  className={i === active ? "highlighted" : ""}
                  onMouseMove={() => setActive(i)}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => choose(option)}
                >
                  <span>{option.label}</span>
                  {option.value === String(value ?? "") && <Check size={14} />}
                </div>
              ))}
              {!matches.length && (
                <div className="select-empty">No matching options</div>
              )}
            </div>
          </div>,
          host,
        )}
    </span>
  );
}
