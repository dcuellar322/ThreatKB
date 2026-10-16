import { useRef, useState } from "react";
import {
  ScanLine,
  FileCode2,
  Plus,
  ArrowUpRight,
  Upload,
  X,
} from "lucide-react";
import { api, write } from "../lib/api";
import { fmt } from "../lib/format";

import { Badge, Empty, IconButton } from "./ui";
export function SampleLab({ notify }: any) {
  const input = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]),
    [result, setResult] = useState<any>(null),
    [name, setName] = useState("generated_candidate"),
    [busy, setBusy] = useState(false);
  async function run(generate = false) {
    if (!files.length) return;
    setBusy(true);
    try {
      const body = new FormData();
      if (generate) {
        files.forEach((f) => body.append("files", f));
        body.append("name", name);
      } else body.append("file", files[0]);
      setResult(
        await api(generate ? "/yara_rules/generate" : "/scan", {
          method: "POST",
          body,
        }),
      );
      notify(
        generate
          ? "Draft candidate generated and validated."
          : "Scan complete.",
      );
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="lab-grid">
      <section className="panel">
        <h2>Sample analysis</h2>
        <p className="muted">
          Scan one sample against your active signatures, or use related samples
          to generate a draft.
        </p>
        <button
          type="button"
          className="dropzone"
          disabled={busy}
          onClick={() => input.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            if (!busy) {
              setFiles(Array.from(e.dataTransfer.files));
              setResult(null);
            }
          }}
        >
          <Upload size={26} />
          <strong>Choose sample files</strong>
        </button>
        <input
          ref={input}
          aria-label="Choose sample files"
          type="file"
          multiple
          hidden
          disabled={busy}
          onChange={(e) => {
            setFiles(Array.from(e.target.files || []));
            setResult(null);
            e.target.value = "";
          }}
        />
        {files.map((f, index) => (
          <div className="file-row" key={f.name + index}>
            <FileCode2 size={17} />
            <span>{f.name}</span>
            <small>{fmt(f.size)} bytes</small>
            <IconButton
              label={"Remove " + f.name}
              disabled={busy}
              onClick={() => {
                setFiles(files.filter((_, i) => i !== index));
                setResult(null);
              }}
            >
              <X size={15} />
            </IconButton>
          </div>
        ))}
        <label>
          Candidate name
          <input
            aria-label="Candidate name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <div className="button-row">
          <button
            className="primary"
            disabled={!files.length || busy}
            onClick={() => run()}
          >
            <ScanLine size={17} />
            {files.length > 1 ? "Scan first sample" : "Scan sample"}
          </button>
          <button
            disabled={
              !files.length || busy || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
            }
            onClick={() => run(true)}
          >
            <Plus size={17} />
            Generate candidate
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="section-top">
          <h2>Analysis results</h2>
          {result && <Badge value="Complete" />}
        </div>
        {!result ? (
          <Empty text="Your results will appear here." />
        ) : result.source ? (
          <>
            <p>{result.review_note}</p>
            <pre className="source-preview">{result.source}</pre>
            <button
              className="primary"
              disabled={busy}
              onClick={async () => {
                if (busy) return;
                setBusy(true);
                try {
                  await write("/import", {
                    import_text: result.source,
                    autocommit: true,
                    extract_ip: false,
                    extract_dns: false,
                    shared_state: "Vetting",
                    tags: ["source:generated"],
                  });
                  notify("Candidate imported into Vetting.");
                } catch (e: any) {
                  notify(e.message, true);
                } finally {
                  setBusy(false);
                }
              }}
            >
              Import for review <ArrowUpRight size={16} />
            </button>
          </>
        ) : (
          <>
            <strong>{result.matches?.length || 0} signature matches</strong>
            {result.matches?.map((m: any) => (
              <article className="result-hit" key={m.rule}>
                <h3>{m.rule}</h3>
                {m.strings.map((s: any) => (
                  <p key={s.identifier}>
                    <code>{s.identifier}</code> · {s.instances.length}{" "}
                    occurrence(s)
                  </p>
                ))}
              </article>
            ))}
            {!result.matches?.length && (
              <p className="muted">No active signature matched this sample.</p>
            )}
          </>
        )}
      </section>
    </div>
  );
}
