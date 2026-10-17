import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getCatalog, getImages, parseRepository } from '../api';

export function RepoList() {
  const { tenant = '', project = '' } = useParams<{ tenant: string; project: string }>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [repos, setRepos] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const names: string[] = [];
        const prefix = `${tenant}/${project}/`;
        try {
          const cat = await getCatalog();
          for (const repo of cat.repositories) {
            const p = parseRepository(repo);
            if (p && p.tenant === tenant && p.project === project) {
              names.push(p.repo);
            }
          }
        } catch {
          const imgs = await getImages({ q: prefix, limit: '1000' });
          for (const img of imgs.images) {
            if (img.tenant === tenant && img.project === project) {
              names.push(img.name);
            }
          }
        }
        if (cancelled) return;
        setRepos([...new Set(names)].sort((a, b) => a.localeCompare(b)));
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setRepos([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tenant, project]);

  return (
    <main className="page">
      <div className="page-head">
        <div className="crumb">
          <Link to="/browse">Browse</Link>
          <span>/</span>
          <Link to={`/t/${encodeURIComponent(tenant)}`}>{tenant}</Link>
          <span>/</span>
          <code>{project}</code>
        </div>
        <h1>Repositories</h1>
        <p>
          Image repositories in <code>{tenant}/{project}</code>.
        </p>
      </div>

      {loading && <p className="muted">Loading…</p>}
      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not list repositories</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {!loading && !error && repos.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No repositories</h3>
            <p>Nothing matched this project path.</p>
          </div>
        </div>
      )}

      {!loading && !error && repos.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h2>{repos.length} repositor{repos.length === 1 ? 'y' : 'ies'}</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {repos.map((name) => (
                  <tr key={name}>
                    <td>
                      <Link
                        to={`/t/${encodeURIComponent(tenant)}/${encodeURIComponent(project)}/${encodeURIComponent(name)}`}
                      >
                        <code>{name}</code>
                      </Link>
                    </td>
                    <td>
                      <Link
                        to={`/t/${encodeURIComponent(tenant)}/${encodeURIComponent(project)}/${encodeURIComponent(name)}`}
                        className="btn btn-ghost"
                        style={{ height: 32, padding: '0 12px', fontSize: 12.5 }}
                      >
                        View tags
                      </Link>
                    </td>
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
