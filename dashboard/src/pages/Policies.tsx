import { FormEvent, useState } from 'react';
import { AdmissionPolicy, getAdmissionPolicies } from '../api';

export function Policies() {
  const [tenant, setTenant] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<AdmissionPolicy[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [searched, setSearched] = useState(false);

  async function load(e?: FormEvent) {
    e?.preventDefault();
    const t = tenant.trim();
    if (!t) {
      setError('Enter a tenant name to list admission policies.');
      return;
    }
    setLoading(true);
    setError(null);
    setNote(null);
    setSearched(true);
    try {
      const rows = await getAdmissionPolicies(t);
      setItems(rows);
      setNote(
        'Signing verification policies are fetched per name via /v2/_signing/policies/{tenant}/{name}; no list API yet.',
      );
    } catch (err) {
      setItems([]);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page">
      <div className="page-head">
        <h1>Policies</h1>
        <p>
          Read-only admission policies (<code>GET /v2/_admit/policies</code>). Requires admin role and
          admission enabled on the registry.
        </p>
      </div>

      <div className="card rule-top" style={{ marginBottom: 18 }}>
        <div className="card-body">
          <form className="filter-row" onSubmit={load}>
            <label>
              <span>Tenant</span>
              <input
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
                placeholder="e.g. demo"
                aria-label="Tenant"
              />
            </label>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Loading…' : 'Load policies'}
            </button>
          </form>
        </div>
      </div>

      {note && (
        <p className="muted" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
          {note}
        </p>
      )}

      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not load policies</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {searched && !error && !loading && items.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No policies</h3>
            <p>No admission policies returned for this tenant.</p>
          </div>
        </div>
      )}

      {items.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h2>Admission policies</h2>
            <span className="sub">{items.length} item{items.length === 1 ? '' : 's'}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Enabled</th>
                  <th>Signature required</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <code>{p.name}</code>
                    </td>
                    <td>{p.enabled ? 'yes' : 'no'}</td>
                    <td>{p.spec.signature_required ? 'yes' : 'no'}</td>
                    <td className="muted">{p.updated_at}</td>
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
