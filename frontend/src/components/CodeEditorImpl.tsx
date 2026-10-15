import { useEffect, useRef, useState } from "react";
import { basicSetup } from "codemirror";
import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, keymap } from "@codemirror/view";
import { indentWithTab } from "@codemirror/commands";
import { openSearchPanel } from "@codemirror/search";
import {
  StreamLanguage,
  syntaxHighlighting,
  HighlightStyle,
} from "@codemirror/language";
import { yaml } from "@codemirror/legacy-modes/mode/yaml";
import { tags } from "@lezer/highlight";
import { MergeView } from "@codemirror/merge";
import { Search } from "lucide-react";

const yara = StreamLanguage.define({
  name: "yara",
  startState: () => ({ comment: false }),
  token(stream, state) {
    if (state.comment) {
      if (stream.skipTo("*/")) {
        stream.match("*/");
        state.comment = false;
      } else stream.skipToEnd();
      return "comment";
    }
    if (stream.eatSpace()) return null;
    if (stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }
    if (stream.match("/*")) {
      state.comment = true;
      return "comment";
    }
    if (stream.match(/"(?:[^"\\]|\\.)*(?:"|$)/)) return "string";
    if (
      stream.match(
        /\b(?:rule|private|global|meta|strings|condition|import|include|and|or|not|any|all|of|them|for|in|at|filesize|entrypoint|true|false|nocase|wide|ascii|fullword|xor|base64|base64wide)\b/,
      )
    )
      return "keyword";
    if (stream.match(/\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?)\b/)) return "number";
    if (stream.match(/\$[\w*]+|#[\w]+|@[\w]+|![\w]+/)) return "variableName";
    stream.next();
    return null;
  },
});
const highlighting = syntaxHighlighting(
  HighlightStyle.define([
    { tag: tags.keyword, color: "#a71d2a", fontWeight: "600" },
    { tag: tags.string, color: "#365f82" },
    { tag: tags.comment, color: "#74747d", fontStyle: "italic" },
    { tag: tags.number, color: "#8156a3" },
    { tag: tags.variableName, color: "#3e4e72" },
  ]),
);
const theme = EditorView.theme({
  "&": { fontSize: "12px", backgroundColor: "#fff" },
  ".cm-scroller": {
    fontFamily: "'SFMono-Regular',Consolas,monospace",
    overflow: "auto",
    overscrollBehavior: "contain",
    maxHeight: "420px",
  },
  ".cm-content": { padding: "9px 0", minHeight: "100px" },
  ".cm-gutters": {
    backgroundColor: "#f6f6f8",
    color: "#777782",
    borderRight: "1px solid #e4e4e8",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "#f7f3f4" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
    backgroundColor: "#ead4d9 !important",
  },
  ".cm-panels": { backgroundColor: "#f6f6f8", borderColor: "#dcdce0" },
});
function language(mode: string) {
  return mode === "yaml" ? StreamLanguage.define(yaml) : yara;
}
export function CodeEditor({
  value = "",
  onChange,
  readOnly = false,
  label,
  mode = "yara",
  className = "",
}: any) {
  const host = useRef<HTMLDivElement>(null),
    editor = useRef<EditorView | null>(null),
    change = useRef(onChange),
    wrapping = useRef(new Compartment()),
    [wrap, setWrap] = useState(true);
  change.current = onChange;
  useEffect(() => {
    const view = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: value,
        extensions: [
          basicSetup,
          language(mode),
          highlighting,
          theme,
          wrapping.current.of(EditorView.lineWrapping),
          EditorState.readOnly.of(readOnly),
          EditorView.editable.of(!readOnly),
          EditorView.contentAttributes.of({
            "aria-label": label,
            role: "textbox",
            "aria-multiline": "true",
            "aria-readonly": String(readOnly),
            spellcheck: "false",
          }),
          keymap.of([indentWithTab]),
          EditorView.updateListener.of((update) => {
            if (update.docChanged)
              change.current?.({
                target: { value: update.state.doc.toString() },
              });
          }),
        ],
      }),
    });
    editor.current = view;
    return () => {
      view.destroy();
      editor.current = null;
    };
  }, [readOnly, mode, label]);
  useEffect(() => {
    const view = editor.current;
    if (view && value !== view.state.doc.toString())
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
      });
  }, [value]);
  return (
    <div className={"code-editor " + className}>
      <div className="editor-toolbar">
        <button
          type="button"
          aria-label={"Find in " + label}
          onClick={() => {
            if (editor.current) {
              editor.current.focus();
              openSearchPanel(editor.current);
            }
          }}
        >
          <Search size={13} />
          Find
        </button>
        <label className="check-label">
          <input
            aria-label={"Wrap " + label}
            type="checkbox"
            checked={wrap}
            onChange={(e) => {
              setWrap(e.target.checked);
              editor.current?.dispatch({
                effects: wrapping.current.reconfigure(
                  e.target.checked ? EditorView.lineWrapping : [],
                ),
              });
            }}
          />
          Wrap
        </label>
      </div>
      <div ref={host} />
    </div>
  );
}
export function RevisionDiff({ left, right }: { left: string; right: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const extensions = [
      basicSetup,
      yara,
      highlighting,
      theme,
      EditorState.readOnly.of(true),
      EditorView.editable.of(false),
      EditorView.lineWrapping,
    ];
    const view = new MergeView({
      parent: host.current!,
      a: {
        doc: left,
        extensions: [
          ...extensions,
          EditorView.contentAttributes.of({
            "aria-label": "First revision source",
            role: "textbox",
          }),
        ],
      },
      b: {
        doc: right,
        extensions: [
          ...extensions,
          EditorView.contentAttributes.of({
            "aria-label": "Second revision source",
            role: "textbox",
          }),
        ],
      },
      highlightChanges: true,
      gutter: true,
    });
    return () => view.destroy();
  }, [left, right]);
  return <div className="revision-diff" ref={host} />;
}
