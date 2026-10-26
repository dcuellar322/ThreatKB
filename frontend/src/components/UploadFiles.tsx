import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { api } from "../lib/api";

export function UploadFiles({ entityId, notify, onUploaded }: any) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false),
    [dragging, setDragging] = useState(false);
  async function upload(files: FileList | File[]) {
    if (busy || !files.length) return;
    setBusy(true);
    try {
      for (const file of Array.from(files)) {
        const body = new FormData();
        body.append("file", file);
        if (entityId) {
          body.append("entity_type", "1");
          body.append("entity_id", String(entityId));
        }
        await api("/file_upload", { method: "POST", body });
      }
      await onUploaded();
      notify(
        files.length === 1
          ? "File uploaded."
          : files.length + " files uploaded.",
      );
    } catch (e: any) {
      notify(e.message, true);
      await onUploaded();
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="upload-wrapper">
      <button
        type="button"
        className={"upload-control " + (dragging ? "dragging" : "")}
        disabled={busy}
        onClick={() => input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          upload(e.dataTransfer.files);
        }}
      >
        <Upload size={15} />
        {busy ? "Uploading…" : "Upload files"}
      </button>
      <input
        ref={input}
        aria-label="Upload files"
        type="file"
        multiple
        disabled={busy}
        hidden
        onChange={(e) => {
          if (e.target.files) upload(e.target.files);
          e.target.value = "";
        }}
      />
    </div>
  );
}
