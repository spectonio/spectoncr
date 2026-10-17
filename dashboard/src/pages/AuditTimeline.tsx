import { FormEvent, useEffect, useState } from 'react';
import { AuditRowView, getAudit } from '../api';

export function AuditTimeline() {
  const [limit, setLimit] = useState('100');
  const [tenant, setTenant] = useState('');
  const [category, setCategory] = useState('');
  const [eventType, setEventType] = useState('');
  const [subject, setSubject] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<AuditRowView[]>([]);
  const [source, setSource] = useState<string>('');

  async function load(params?: Record<string, string>) {
    setLoading(true);
    setError(null);
    try {
      const resp = await getAudit(params ?? buildParams());
      setRows(resp.rows);
      setSource(resp.source);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setRows([]);
    } finally {
      setLoading(false);
    }
  }

  function buildParams(): Record<string, string> {
    const p: Record<string, string> = { limit };
    if (tenant.trim()) p.tenant = tenant.trim();
    if (category.trim()) p.category = category.trim();
    if (eventType.trim()) p.type = eventType.trim();
    if (subject.trim()) p.subject = subject.trim();
    return p;
  }

  useEffect(() => {
    void load({ limit });
  }, []);

  function onFilter(e: FormEvent) {
    e.preventDefault();
    load(buildParams());
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>Audit timeline</h1>
        <p>
          Read-only view of registry activity. Uses chained <code>/v2/_audit</code> when your token
          has admin scope, otherwise the dashboard ring buffer at <code>/api/audit</code>.
        </p>
      </div>

      <div className="card rule-top" style={{ marginBottom: 18 }}>
        <div className="card-body">
          <form className="filter-row" onSubmit={onFilter}>
            <label>
              <span>Limit</span>
              <input value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              <span>Tenant</span>
              <input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="optional" />
            </label>
            <label>
              <span>Category</span>
              <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="push, pull, …" />
            </label>
            <label>
              <span>Event type</span>
              <input
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                placeholder="manifest.push"
              />
            </label>
            <label>
              <span>Subject</span>
              <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="optional" />
            </label>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Loading…' : 'Apply'}
            </button>
          </form>
        </div>
      </div>

      {source && (
        <p className="muted" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
          Source: <code>{source}</code> · {rows.length} event{rows.length === 1 ? '' : 's'}
        </p>
      )}

      {error && (
        <div className="card">
          <div className="empty">
            <h3>Audit unavailable</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {!error && !loading && rows.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No events</h3>
            <p>Nothing matched your filters.</p>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type / action</th>
                  <th>Actor</th>
                  <th>Tenant</th>
                  <th>Subject</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td className="muted tabular" style={{ whiteSpace: 'nowrap' }}>
                      {r.at}
                    </td>
                    <td>
                      <code>{r.action}</code>
                    </td>
                    <td className="muted">{r.actor || '—'}</td>
                    <td>{r.tenant || '—'}</td>
                    <td className="muted">{r.subject || '—'}</td>
                    <td>{r.outcome || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </main>
  );
}
