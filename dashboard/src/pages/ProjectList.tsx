import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getCatalog, getImages, parseRepository } from '../api';

export function ProjectList() {
  const { tenant = '' } = useParams<{ tenant: string }>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projects, setProjects] = useState<Array<{ project: string; repos: number }>>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const counts = new Map<string, number>();
        const ingest = (full: string) => {
          const p = parseRepository(full);
          if (!p || p.tenant !== tenant) return;
          counts.set(p.project, (counts.get(p.project) ?? 0) + 1);
        };
        try {
          const cat = await getCatalog();
          cat.repositories.forEach(ingest);
        } catch {
          const imgs = await getImages({ q: tenant, limit: '1000' });
          for (const img of imgs.images) {
            if (img.tenant === tenant) {
              counts.set(img.project, (counts.get(img.project) ?? 0) + 1);
            }
          }
        }
        if (cancelled) return;
        setProjects(
          [...counts.entries()]
            .map(([project, repos]) => ({ project, repos }))
            .sort((a, b) => a.project.localeCompare(b.project)),
        );
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setProjects([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tenant]);

  const total = useMemo(() => projects.reduce((n, p) => n + p.repos, 0), [projects]);

  return (
    <main className="page">
      <div className="page-head">
        <div className="crumb">
          <Link to="/browse">Browse</Link>
          <span>/</span>
          <code>{tenant}</code>
        </div>
        <h1>Projects</h1>
        <p>Repositories grouped by project under tenant <code>{tenant}</code>.</p>
      </div>

      {loading && <p className="muted">Loading…</p>}
      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not list projects</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {!loading && !error && projects.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No projects</h3>
            <p>No repositories found for this tenant.</p>
          </div>
        </div>
      )}

      {!loading && !error && projects.length > 0 && (
        <>
          <p className="muted" style={{ margin: '0 0 14px', fontSize: 12.5 }}>
            {projects.length} project{projects.length === 1 ? '' : 's'} · {total} repositor
            {total === 1 ? 'y' : 'ies'}
          </p>
          <div className="grid-cards">
            {projects.map((p) => (
              <Link
                key={p.project}
                to={`/t/${encodeURIComponent(tenant)}/${encodeURIComponent(p.project)}`}
                className="card nav-card"
              >
                <h2>{p.project}</h2>
                <p className="muted">
                  {p.repos} repositor{p.repos === 1 ? 'y' : 'ies'}
                </p>
              </Link>
            ))}
          </div>
        </>
      )}
    </main>
  );
}
