import { Component, lazy, Suspense, type ReactNode } from "react";
const Editor = lazy(() =>
  import("./CodeEditorImpl").then((module) => ({ default: module.CodeEditor })),
);
const Diff = lazy(() =>
  import("./CodeEditorImpl").then((module) => ({
    default: module.RevisionDiff,
  })),
);

class EditorBoundary extends Component<
  { children: ReactNode; fallback: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

export function CodeEditor(props: any) {
  return (
    <EditorBoundary
      fallback={
        <div className="editor-fallback">
          <p className="muted" role="status">
            Code editor unavailable. Plain-text{" "}
            {props.readOnly ? "view." : "editing enabled."}
          </p>
          <textarea
            aria-label={props.label}
            className={props.className}
            value={props.value}
            onChange={props.onChange}
            readOnly={props.readOnly}
            spellCheck={false}
            rows={8}
          />
        </div>
      }
    >
      <Suspense
        fallback={
          <div className="editor-loading" role="status">
            Loading editor…
          </div>
        }
      >
        <Editor {...props} />
      </Suspense>
    </EditorBoundary>
  );
}
export function RevisionDiff(props: any) {
  return (
    <EditorBoundary
      fallback={
        <div>
          <p className="muted" role="status">
            Comparison editor unavailable. Plain-text versions are shown below.
          </p>
          <div className="revision-compare">
            <pre className="source-preview">{props.left}</pre>
            <pre className="source-preview">{props.right}</pre>
          </div>
        </div>
      }
    >
      <Suspense
        fallback={
          <div className="editor-loading" role="status">
            Loading comparison…
          </div>
        }
      >
        <Diff {...props} />
      </Suspense>
    </EditorBoundary>
  );
}
