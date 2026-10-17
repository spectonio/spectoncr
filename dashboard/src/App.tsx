import { useState } from 'react';
import { searchCves, CveHit } from './api';
import { SevBadge, SearchIcon, CopyButton } from './ui';

// Common starting points so the empty state invites action instead of
// staring back blankly.
const SUGGESTIONS = ['openssl', 'log4j', 'curl', 'glibc', 'CVE-2024'];

// Home: connect an API key (in the steel bar), then search the scanner's own
// CVE database to sanity-check population. Results render as scannable cards.
// Scan drill-down moves to /scan/{digest} so links share as-is.
export function App() {
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<CveHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  async function doSearch(q: string) {
    if (!q.trim()) return;
    setLoading(true);
    setSearched(true);
    try {
      const resp = await searchCves({ q, limit: '25' });
      setHits(resp.results);
    } catch (err) {
      console.error(err);
      setHits([]);
    } finally {
      setLoading(false);
    }
  }

  function runSearch(e: React.FormEvent) {
    e.preventDefault();
    doSearch(query);
  }

  function runSuggestion(s: string) {
    setQuery(s);
    doSearch(s);
  }

  return (
      <main className="page">
        <div className="page-head">
          <h1>Vulnerability database</h1>
          <p>
            Search the CVEs SpectonCR has ingested — by keyword, package, or advisory ID —
            to confirm your feeds are populated before you rely on a scan verdict.
          </p>
        </div>

        <div className="card rule-top" style={{ marginBottom: 22 }}>
          <div className="card-body">
            <form className="search" onSubmit={runSearch}>
              <div className="field">
                <SearchIcon />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="e.g. openssl, CVE-2024-… , log4j"
                  aria-label="CVE search"
                />
              </div>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Searching…' : 'Search'}
              </button>
            </form>
          </div>
        </div>

        {searched && !loading && hits.length > 0 && (
          <p className="muted" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
            {hits.length} match{hits.length === 1 ? '' : 'es'}
          </p>
        )}

        {loading && (
          <div className="results" aria-hidden="true">
            {[0, 1, 2].map((i) => (
              <div key={i} className="result">
                <div className="skeleton" style={{ height: 15, width: '38%' }} />
                <div className="skeleton" style={{ height: 12, width: '80%', marginTop: 12 }} />
              </div>
            ))}
          </div>
        )}

        {!loading && hits.length > 0 && (
          <div className="results">
            {hits.map((h) => (
              <article key={h.id} className="result">
                <div className="result-top">
                  <code>{h.id}</code>
                  <CopyButton value={h.id} label="CVE ID" />
                  <SevBadge severity={h.severity} />
                  {typeof h.cvss_score === 'number' && (
                    <span className="chip tabular">CVSS {h.cvss_score.toFixed(1)}</span>
                  )}
                  {h.source && <span className="result-src">{h.source}</span>}
                </div>
                {h.summary && <p className="result-sum">{h.summary}</p>}
                {h.affected.length > 0 && (
                  <div className="result-affected">
                    {h.affected.slice(0, 4).map((a, i) => (
                      <span key={i} className="chip">
                        {a.ecosystem}:{a.package}
                        {a.fixed ? <span className="fix"> → {a.fixed}</span> : ''}
                      </span>
                    ))}
                    {h.affected.length > 4 && (
                      <span className="chip muted">+{h.affected.length - 4} more</span>
                    )}
                  </div>
                )}
              </article>
            ))}
          </div>
        )}

        {searched && !loading && hits.length === 0 && (
          <div className="card">
            <div className="empty">
              <SearchIcon />
              <h3>No matches</h3>
              <p>Nothing in the database matched “{query}”. Try a package name or a CVE ID.</p>
            </div>
          </div>
        )}

        {!searched && !loading && (
          <div className="card">
            <div className="empty">
              <SearchIcon />
              <h3>Search the vulnerability feed</h3>
              <p>Enter a keyword, package, or advisory ID above to query the ingested CVE data.</p>
              <div className="suggest">
                {SUGGESTIONS.map((s) => (
                  <button key={s} onClick={() => runSuggestion(s)}>{s}</button>
                ))}
              </div>
            </div>
          </div>
        )}

        <p className="footnote">
          Live scan drill-down — open <code>/scan/&lt;digest&gt;</code> to watch a scan stream over
          WebSocket, with the severity breakdown and policy verdict.
        </p>
      </main>
  );
}
