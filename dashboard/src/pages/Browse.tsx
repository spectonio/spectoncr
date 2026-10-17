import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { getCatalog, getImages, parseRepository } from '../api';

/** Tenant overview — cards grouped from catalog or /api/images. */
export function Browse() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tenants, setTenants] = useState<Array<{ tenant: string; repos: number }>>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const counts = new Map<string, number>();
        try {
          const cat = await getCatalog();
          for (const repo of cat.repositories) {
            const p = parseRepository(repo);
            if (!p) continue;
            counts.set(p.tenant, (counts.get(p.tenant) ?? 0) + 1);
          }
        } catch {
          const imgs = await getImages({ limit: '1000' });
          for (const img of imgs.images) {
            counts.set(img.tenant, (counts.get(img.tenant) ?? 0) + 1);
          }
        }
        if (cancelled) return;
        const rows = [...counts.entries()]
          .map(([tenant, repos]) => ({ tenant, repos }))
          .sort((a, b) => a.tenant.localeCompare(b.tenant));
        setTenants(rows);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setTenants([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const totalRepos = useMemo(() => tenants.reduce((n, t) => n + t.repos, 0), [tenants]);

  return (
    <main className="page">
      <div className="page-head">
        <h1>Browse registry</h1>
        <p>
          Tenants visible to your token. Open a tenant to drill into projects, repositories, tags,
          and manifests.
        </p>
      </div>

      {loading && (
        <div className="grid-cards">
          {[0, 1, 2].map((i) => (
            <div key={i} className="card nav-card">
              <div className="skeleton" style={{ height: 18, width: '55%' }} />
              <div className="skeleton" style={{ height: 12, width: '40%', marginTop: 14 }} />
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not load catalog</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {!loading && !error && tenants.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No repositories</h3>
            <p>Nothing showed up in the catalog for this API key. Push an image or widen token scope.</p>
          </div>
        </div>
      )}

      {!loading && !error && tenants.length > 0 && (
        <>
          <p className="muted" style={{ margin: '0 0 14px', fontSize: 12.5 }}>
            {tenants.length} tenant{tenants.length === 1 ? '' : 's'} · {totalRepos} repositor
            {totalRepos === 1 ? 'y' : 'ies'}
          </p>
          <div className="grid-cards">
            {tenants.map((t) => (
              <Link key={t.tenant} to={`/t/${encodeURIComponent(t.tenant)}`} className="card nav-card">
                <h2>{t.tenant}</h2>
                <p className="muted">
                  {t.repos} repositor{t.repos === 1 ? 'y' : 'ies'}
                </p>
              </Link>
            ))}
          </div>
        </>
      )}
    </main>
  );
}
