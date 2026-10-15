import { createPortal, flushSync } from "react-dom";
import { useEffect, useLayoutEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import { api } from "../lib/api";

export function TagInput({
  value = [],
  onChange,
  label = "Tags",
  suggest = true,
  placeholder = "Add tags…",
}: any) {
  const [query, setQuery] = useState(""),
    [suggestions, setSuggestions] = useState<string[]>([]),
    [focused, setFocused] = useState(false),
    [active, setActive] = useState(-1),
    [position, setPosition] = useState<any>({}),
    [host, setHost] = useState<HTMLElement | null>(null);
  const input = useRef<HTMLInputElement>(null),
    root = useRef<HTMLDivElement>(null),
    id = useId();
  const tags: string[] = value.map((t: any) =>
    typeof t === "string" ? t : t.text,
  );
  useEffect(() => {
    if (!suggest) return;
    const controller = new AbortController();
    api("/tags", { signal: controller.signal })
      .then((r) => setSuggestions(r.map((t: any) => t.text)))
      .catch(() => {});
    return () => controller.abort();
  }, [suggest]);
  const matches = (suggest ? suggestions : [])
    .filter(
      (s) => !tags.includes(s) && s.toLowerCase().includes(query.toLowerCase()),
    )
    .slice(0, 8);
  useLayoutEffect(() => {
    if (!focused || !matches.length) return;
    setHost(root.current?.closest("dialog") || document.body);
    const place = () => {
      const rect = root.current!.getBoundingClientRect(),
        below = innerHeight - rect.bottom - 12;
      setPosition({
        position: "fixed",
        left: Math.max(12, rect.left),
        right: "auto",
        width: Math.min(rect.width, innerWidth - 24),
        maxHeight: Math.min(230, Math.max(below, rect.top - 12)),
        ...(below >= 180 || below >= rect.top - 12
          ? { top: rect.bottom + 4 }
          : { top: "auto", bottom: innerHeight - rect.top + 4 }),
      });
    };
    place();
    window.addEventListener("resize", place);
    document.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("resize", place);
      document.removeEventListener("scroll", place, true);
    };
  }, [focused, matches.length]);
  const add = (text: string) => {
    const next = text
      .split(/[,\n\t]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    onChange([...new Set([...tags, ...next])]);
    setQuery("");
    setActive(-1);
    setFocused(false);
  };
  useEffect(() => {
    const form = root.current?.closest("form");
    const commitPending = () => {
      if (query.trim()) flushSync(() => add(query));
    };
    form?.addEventListener("submit", commitPending, true);
    return () => form?.removeEventListener("submit", commitPending, true);
  }, [query, value]);
  return (
    <div
      ref={root}
      className="tag-input-wrap"
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          setFocused(false);
          if (query.trim()) add(query);
        }
      }}
    >
      <div className="tag-input" onClick={() => input.current?.focus()}>
        {tags.map((tag) => (
          <span className="tag editable-tag" key={tag}>
            <span title={tag}>{tag}</span>
            <button
              type="button"
              aria-label={"Remove tag " + tag}
              onClick={(e) => {
                e.stopPropagation();
                onChange(tags.filter((t) => t !== tag));
                input.current?.focus();
              }}
            >
              <X size={12} />
            </button>
          </span>
        ))}
        <input
          ref={input}
          aria-label={label}
          role="combobox"
          aria-expanded={focused && matches.length > 0}
          aria-autocomplete="list"
          aria-controls={focused && matches.length ? id : undefined}
          aria-activedescendant={
            active >= 0 && matches[active] ? id + "-" + active : undefined
          }
          placeholder={placeholder}
          value={query}
          onFocus={() => setFocused(true)}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(-1);
            setFocused(true);
          }}
          onPaste={(e) => {
            const text = e.clipboardData.getData("text");
            if (/[,\n\t]/.test(text)) {
              e.preventDefault();
              add(text);
            }
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape" && focused) {
              e.preventDefault();
              e.stopPropagation();
              if (query.trim()) add(query);
              setFocused(false);
            }
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              setFocused(true);
              setActive((i) =>
                Math.max(
                  0,
                  Math.min(
                    matches.length - 1,
                    i + (e.key === "ArrowDown" ? 1 : -1),
                  ),
                ),
              );
            }
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              if (active >= 0 && matches[active]) add(matches[active]);
              else if (query.trim()) add(query);
            }
            if (e.key === "Backspace" && !query && tags.length)
              onChange(tags.slice(0, -1));
          }}
        />
      </div>
      {focused &&
        matches.length > 0 &&
        host &&
        createPortal(
          <div
            style={position}
            className="tag-suggestions"
            role="listbox"
            id={id}
            aria-label="Existing tags"
          >
            {matches.map((tag, i) => (
              <div
                role="option"
                id={id + "-" + i}
                aria-selected={i === active}
                key={tag}
                onMouseDown={(e) => e.preventDefault()}
                onClick={(e) => {
                  e.preventDefault();
                  add(tag);
                  input.current?.focus();
                }}
              >
                {tag}
              </div>
            ))}
          </div>,
          host,
        )}
    </div>
  );
}

export function RecordTags({ tags, onFilter }: any) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={"tag-list " + (expanded ? "expanded" : "")}>
      {(expanded ? tags : tags.slice(0, 3)).map((tag: any) => (
        <button
          className="tag"
          title={"Filter by " + (tag.text || tag)}
          key={tag.text || tag}
          onClick={() => onFilter(tag.text || tag)}
        >
          {tag.text || tag}
        </button>
      ))}
      {tags.length > 3 && (
        <button
          className="tag-more"
          aria-label={
            expanded ? "Show fewer tags" : "Show all " + tags.length + " tags"
          }
          aria-expanded={expanded}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Less" : "+" + (tags.length - 3)}
        </button>
      )}
    </div>
  );
}
