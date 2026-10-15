import { lazy, Suspense } from "react";
const Editor = lazy(() =>
  import("./CodeEditorImpl").then((module) => ({ default: module.CodeEditor })),
);
const Diff = lazy(() =>
  import("./CodeEditorImpl").then((module) => ({
    default: module.RevisionDiff,
  })),
);
export function CodeEditor(props: any) {
  return (
    <Suspense
      fallback={
        <div className="editor-loading" role="status">
          Loading editor…
        </div>
      }
    >
      <Editor {...props} />
    </Suspense>
  );
}
export function RevisionDiff(props: any) {
  return (
    <Suspense
      fallback={
        <div className="editor-loading" role="status">
          Loading comparison…
        </div>
      }
    >
      <Diff {...props} />
    </Suspense>
  );
}
