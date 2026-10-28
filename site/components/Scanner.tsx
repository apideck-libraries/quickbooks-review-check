'use client';

import { useEffect, useRef, useState } from 'react';
import { Report, type Result } from './Report';
import { scanFiles, classifyFile, isSkippedDir, MAX_BYTES } from '@core/scan-core.js';
import sample from '@/lib/sample.json';

type Mode = 'live' | 'code';
type FileIn = { rel: string; kind: 'code' | 'env'; text: string };
const MAX_FILES = 8000;

function keep(rel: string) {
  const parts = rel.split('/');
  if (parts.slice(0, -1).some((p) => isSkippedDir(p))) return null;
  return classifyFile(parts[parts.length - 1]) as 'code' | 'env' | null;
}

async function readFiles(list: { rel: string; file: File }[]): Promise<FileIn[]> {
  const out: FileIn[] = [];
  for (const { rel, file } of list) {
    const kind = keep(rel);
    if (!kind || file.size > MAX_BYTES) continue;
    out.push({ rel, kind, text: await file.text() });
    if (out.length >= MAX_FILES) break;
  }
  return out;
}

export function Scanner() {
  const [mode, setMode] = useState<Mode>('live');
  const [url, setUrl] = useState('');
  const [callback, setCallback] = useState('');
  const [path, setPath] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [results, setResults] = useState<Result[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [meta, setMeta] = useState<{ target?: string; source?: string }>({});
  const [dragging, setDragging] = useState(false);
  const dirInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    dirInput.current?.setAttribute('webkitdirectory', '');
  }, [mode]);

  async function runLive(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!authorized) return setError('Tick the box to confirm you own this app or are authorized to test it.');
    setRunning(true);
    setResults([]);
    setMeta({ target: url });
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url, callback: callback || undefined, path: path || undefined, authorized }),
      });
      if (!res.ok || !res.body) {
        const j = await res.json().catch(() => ({}));
        setError(j.error || `The scan failed (${res.status}).`);
        setResults(null);
        return;
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          if (!line) continue;
          const msg = JSON.parse(line);
          if (msg.type === 'result') setResults((prev) => [...(prev || []), msg.result]);
          if (msg.type === 'start') setMeta({ target: msg.target });
          if (msg.type === 'error') setError(msg.message);
        }
      }
    } catch {
      setError('Lost the connection to the scanner. Try again.');
    } finally {
      setRunning(false);
    }
  }

  async function runCode(list: { rel: string; file: File }[]) {
    setError('');
    if (!list.length) return setError('That folder looks empty.');
    setRunning(true);
    setResults([]);
    const root = list[0].rel.split('/')[0];
    const stripped = list.map((f) => ({ ...f, rel: f.rel.includes('/') ? f.rel.slice(f.rel.indexOf('/') + 1) : f.rel }));
    const files = await readFiles(stripped);
    // Yield a frame so the "running" state paints before the synchronous scan.
    await new Promise((r) => requestAnimationFrame(() => r(null)));
    const { results: out, scanned } = scanFiles(files);
    setMeta({ source: `${root} (${scanned} files, scanned in your browser)` });
    setResults(out as Result[]);
    setRunning(false);
    if (!scanned) setError('No source files found. The scanner reads JS/TS, Python, Ruby, PHP, Java, C#, Go and templates.');
  }

  function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files || []);
    runCode(files.map((file) => ({ rel: (file as File & { webkitRelativePath: string }).webkitRelativePath || file.name, file })));
    e.target.value = '';
  }

  async function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const acc: { rel: string; file: File }[] = [];
    const items = Array.from(e.dataTransfer.items || []);
    for (const it of items) {
      const entry = it.webkitGetAsEntry?.();
      if (entry?.isDirectory) await walkDir(entry as FileSystemDirectoryEntry, `${entry.name}/`, acc);
      else {
        const file = it.getAsFile();
        if (file) acc.push({ rel: `files/${file.name}`, file });
      }
    }
    runCode(acc);
  }

  const shown = results ?? (sample as Result[]);
  const isSample = results === null;

  return (
    <div className="scanner">
      <div className="scanner-controls">
        <div className="tabs" role="tablist" aria-label="What to check">
          <button role="tab" type="button" aria-selected={mode === 'live'} onClick={() => setMode('live')}>Deployed app</button>
          <button role="tab" type="button" aria-selected={mode === 'code'} onClick={() => setMode('code')}>Source code</button>
        </div>

        {mode === 'live' ? (
          <form onSubmit={runLive} className="form">
            <label htmlFor="f-url">App URL</label>
            <input id="f-url" type="text" inputMode="url" autoComplete="url" placeholder="https://app.example.com" value={url} onChange={(e) => setUrl(e.target.value)} required />
            <div className="two">
              <div>
                <label htmlFor="f-cb">OAuth callback path <span className="opt">optional</span></label>
                <input id="f-cb" type="text" placeholder="/oauth/callback" value={callback} onChange={(e) => setCallback(e.target.value)} />
              </div>
              <div>
                <label htmlFor="f-path">Sensitive page <span className="opt">optional</span></label>
                <input id="f-path" type="text" placeholder="/dashboard" value={path} onChange={(e) => setPath(e.target.value)} />
              </div>
            </div>
            <label className="consent" htmlFor="f-auth">
              <input id="f-auth" type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              <span>I own this app or am authorized to test it. The scan sends about 30 ordinary requests and TLS handshakes.</span>
            </label>
            <button className="btn" type="submit" disabled={running}>{running ? 'Checking…' : 'Run checks'}</button>
            <p className="hint">Signed-in pages need a session cookie. Use the CLI for those, so your cookie never leaves your machine.</p>
          </form>
        ) : (
          <div className="form">
            <div
              className={`drop${dragging ? ' on' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
            >
              <svg width="36" height="36" viewBox="0 0 36 36" aria-hidden><path d="M5 10a3 3 0 0 1 3-3h7l3 3h10a3 3 0 0 1 3 3v13a3 3 0 0 1-3 3H8a3 3 0 0 1-3-3z" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M18 14v9M14 18l4-4 4 4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
              <p><b>Drop your repository folder here</b></p>
              <p className="hint">or</p>
              <label className="btn-sm" htmlFor="f-dir">Choose folder</label>
              <input id="f-dir" ref={dirInput} type="file" multiple onChange={onPick} className="sr" />
            </div>
            <p className="local"><span aria-hidden>●</span> Files are read and scanned in this browser tab. Nothing is uploaded. <code>node_modules</code>, build output and dot-folders are skipped.</p>
          </div>
        )}
        {error && <p className="err" role="alert">{error}</p>}
      </div>

      <Report results={shown} running={running} label={isSample ? 'Example · sample app' : undefined} target={meta.target} source={meta.source} />
    </div>
  );
}

// Walk a dropped folder via the File and Directory Entries API.
async function walkDir(dir: FileSystemDirectoryEntry, prefix: string, acc: { rel: string; file: File }[]) {
  const reader = dir.createReader();
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
    if (!batch.length) break;
    for (const e of batch) {
      if (acc.length >= MAX_FILES * 4) return;
      if (e.isDirectory) {
        if (!isSkippedDir(e.name)) await walkDir(e as FileSystemDirectoryEntry, `${prefix}${e.name}/`, acc);
      } else {
        const file = await new Promise<File>((res, rej) => (e as FileSystemFileEntry).file(res, rej));
        acc.push({ rel: prefix + e.name, file });
      }
    }
  }
}
