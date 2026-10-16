import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchLiveScan, ScanResult, Vulnerability } from './api';
import { PilotSidebar } from './PilotSidebar';
import { Header, SevBadge, SEVERITIES, SeverityBar, sortBySeverity, CopyButton } from './ui';

// Scan drill-down: subscribes to /v2/ws/scan/{digest} and streams results.
// Panels are ordered by what an operator decides on first: the policy verdict
// (the thesis), then the severity breakdown (which doubles as a filter), then
// the findings table. Falls back to an HTTP fetch if WebSocket is unavailable.
export function ScanDetail() {
  const { digest = '' } = useParams<{ digest: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<string>('connecting');
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    let ws: WebSocket | null = null;
    try {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${location.host}/v2/ws/scan/${digest}`);
      ws.onmessage = (ev) => {
        try {
          const frame = JSON.parse(ev.data);
          setStatus(frame.status);
          if (frame.result) setResult(frame.result);
        } catch {}
      };
      ws.onerror = () => setStatus('error');
      ws.onclose = () => setStatus((s) => (s === 'connecting' ? 'disconnected' : s));
    } catch {
      fetchLiveScan(digest)
        .then((r) => {
          setStatus(r.status);
          setResult(r.result || null);
        })
        .catch(() => setStatus('fetch failed'));
    }
    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [digest]);

  const visible: Vulnerability[] = useMemo(() => {
    const vs = result?.vulnerabilities ?? [];
    const filtered = filter === 'all' ? vs : vs.filter((v) => v.severity.toLowerCase() === filter);
    return sortBySeverity(filtered); // triage order: severity desc, then CVSS
  }, [result, filter]);

  const total = result
    ? SEVERITIES.reduce((n, k) => n + (result.summary[k] ?? 0), 0)
    : 0;

  // How many findings have a fix available — the number an operator can act on.
  const fixable = useMemo(
    () => (result?.vulnerabilities ?? []).filter((v) => v.fixed_version && !v.suppressed).length,
    [result],
  );

  const statusClass =
    status === 'completed' ? 'done'
    : status === 'failed' || status.includes('error') || status === 'disconnected' ? 'error'
    : status === 'in_progress' || status === 'connecting' || status === 'queued' ? 'live'
    : '';

  const statusPill = (
    <span className={`status ${statusClass}`}>
      <span className="dot" aria-hidden="true" />
      {status.replace(/_/g, ' ')}
    </span>
  );

  return (
    <div className="shell">
      <Header right={statusPill} />
      <PilotSidebar />

      <main className="page">
        <div className="page-head">
          <div className="crumb">
            <span>scan</span>
            <code>{digest.length > 24 ? `${digest.slice(0, 24)}…` : digest || '—'}</code>
            {digest && <CopyButton value={digest} label="digest" />}
          </div>
          <h1>Scan report</h1>
          {result && (
            <p>
              {result.repository || result.project}
              {result.reference ? ` : ${result.reference}` : ''}
              {result.tenant ? ` — ${result.tenant}` : ''}
            </p>
          )}
        </div>

        {result?.policy_evaluation && (
          <div className={`verdict ${result.policy_evaluation.status.toLowerCase()}`}>
            <span className="verdict-badge">
              {result.policy_evaluation.status === 'PASS' ? '✓' : '✕'}
              {result.policy_evaluation.status === 'PASS' ? 'Policy passed' : 'Policy failed'}
            </span>
            {result.policy_evaluation.reason && (
              <span className="verdict-reason">{result.policy_evaluation.reason}</span>
            )}
            {fixable > 0 && (
              <span className="verdict-fixable">
                <b>{fixable}</b>
                fixable now
              </span>
            )}
          </div>
        )}

        {result && <SeverityBar summary={result.summary} />}

        {result ? (
          <>
            <div className="tiles">
              <button
                className={`tile total ${filter === 'all' ? 'active' : ''}`}
                onClick={() => setFilter('all')}
              >
                <span className="lbl">Total</span>
                <span className="num tabular">{total}</span>
              </button>
              {SEVERITIES.map((k) => (
                <button
                  key={k}
                  className={`tile ${k} ${filter === k ? 'active' : ''}`}
                  onClick={() => setFilter(filter === k ? 'all' : k)}
                  aria-pressed={filter === k}
                >
                  <span className="lbl">{k}</span>
                  <span className="num tabular">{result.summary[k] ?? 0}</span>
                </button>
              ))}
            </div>

            <div className="card">
              <div className="card-head">
                <h2>Findings</h2>
                <span className="sub">
                  {filter === 'all' ? `${visible.length} shown` : `${visible.length} ${filter}`}
                </span>
              </div>
              {visible.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th className="cvss">CVSS</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed</th>
                        <th>Layer</th>
                        <th>Summary</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visible.map((v) => (
                        <tr key={`${v.id}-${v.package}`} className={v.suppressed ? 'suppressed' : ''}>
                          <td className="id"><code>{v.id}</code></td>
                          <td><SevBadge severity={v.severity} /></td>
                          <td className="cvss">
                            {typeof v.cvss_score === 'number'
                              ? <span className="cvss-val">{v.cvss_score.toFixed(1)}</span>
                              : <span className="muted">—</span>}
                          </td>
                          <td>{v.package}</td>
                          <td><code>{v.installed_version}</code></td>
                          <td>{v.fixed_version ? <code>{v.fixed_version}</code> : <span className="muted">—</span>}</td>
                          <td>
                            {v.layer_digest ? (
                              <code title={v.layer_digest}>{v.layer_digest.slice(7, 19)}</code>
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </td>
                          <td className="muted">{v.summary || ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">
                  <h3>Nothing to show</h3>
                  <p>
                    {total === 0
                      ? 'No vulnerabilities were found in this image.'
                      : `No ${filter} findings — clear the filter to see all ${total}.`}
                  </p>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="card">
            <div className="empty">
              <h3>{statusClass === 'error' ? 'Scan unavailable' : 'Waiting for scan data…'}</h3>
              <p>
                {statusClass === 'error'
                  ? 'The scan stream could not be reached. Check the digest and your connection.'
                  : 'Streaming results as the scanner processes each layer.'}
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
