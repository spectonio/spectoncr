import { FormEvent, useState } from 'react';
import { getApiKey, postPilotChat, PilotChatMessage } from './api';

/** Floating chat sidebar for specton-pilot (design 007 / 019 P4). */
export function PilotSidebar() {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<PilotChatMessage[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(e: FormEvent) {
    e.preventDefault();
    const msg = input.trim();
    if (!msg || busy) return;
    if (!getApiKey()) {
      setError('Set an API key in the header bar first.');
      return;
    }
    setBusy(true);
    setError(null);
    setInput('');
    try {
      const resp = await postPilotChat({ message: msg, history, dry_run: true });
      setHistory(resp.messages);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className="pilot-fab"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls="pilot-sidebar"
        title="Specton pilot"
      >
        Pilot
      </button>
      {open && (
        <aside id="pilot-sidebar" className="pilot-sidebar" aria-label="Specton pilot chat">
          <header className="pilot-sidebar-head">
            <strong>Specton pilot</strong>
            <button type="button" className="icon-btn" onClick={() => setOpen(false)} aria-label="Close">
              ×
            </button>
          </header>
          <div className="pilot-sidebar-body">
            {history.length === 0 && (
              <p className="pilot-hint">
                Ask about repos, scans, rebuilds, or promotions. Mutating calls run in dry-run from
                this sidebar by default. Requires <code>[pilot] enabled = true</code>.
              </p>
            )}
            {history.map((m, i) => (
              <div key={i} className={`pilot-msg pilot-msg-${m.role}`}>
                <span className="pilot-role">{m.role}</span>
                <pre>{m.content}</pre>
              </div>
            ))}
            {error && <p className="pilot-error">{error}</p>}
          </div>
          <form className="pilot-sidebar-foot" onSubmit={send}>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask the registry agent…"
              aria-label="Pilot message"
              disabled={busy}
            />
            <button type="submit" disabled={busy || !input.trim()}>
              {busy ? '…' : 'Send'}
            </button>
          </form>
        </aside>
      )}
    </>
  );
}
