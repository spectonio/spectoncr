import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { headManifestDigest, listTags } from '../api';

type TagRow = { tag: string; digest: string | null; resolving: boolean };

export function TagList() {
  const { tenant = '', project = '', repo = '' } = useParams<{
    tenant: string;
    project: string;
    repo: string;
  }>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<TagRow[]>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const tl = await listTags(tenant, project, repo);
        if (cancelled) return;
        const initial = tl.tags.map((tag) => ({ tag, digest: null, resolving: true }));
        setRows(initial);
        setLoading(false);

        for (let i = 0; i < tl.tags.length; i++) {
          if (cancelled) return;
          const tag = tl.tags[i];
          const digest = await headManifestDigest(tenant, project, repo, tag).catch(() => null);
          if (cancelled) return;
          setRows((prev) =>
            prev.map((r) => (r.tag === tag ? { ...r, digest, resolving: false } : r)),
          );
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setRows([]);
          setLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tenant, project, repo]);

  const base = `/t/${encodeURIComponent(tenant)}/${encodeURIComponent(project)}/${encodeURIComponent(repo)}`;

  return (
    <main className="page">
      <div className="page-head">
        <div className="crumb">
          <Link to="/browse">Browse</Link>
          <span>/</span>
          <Link to={`/t/${encodeURIComponent(tenant)}`}>{tenant}</Link>
          <span>/</span>
          <Link to={`/t/${encodeURIComponent(tenant)}/${encodeURIComponent(project)}`}>{project}</Link>
          <span>/</span>
          <code>{repo}</code>
        </div>
        <h1>Tags</h1>
        <p>
          Tags for <code>{tenant}/{project}/{repo}</code>. Open a manifest or jump to the live scan
          for its digest.
        </p>
      </div>

      {loading && <p className="muted">Loading tags…</p>}
      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not list tags</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {!loading && !error && rows.length === 0 && (
        <div className="card">
          <div className="empty">
            <h3>No tags</h3>
            <p>This repository has no tag links yet.</p>
          </div>
        </div>
      )}

      {!loading && !error && rows.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h2>{rows.length} tag{rows.length === 1 ? '' : 's'}</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tag</th>
                  <th>Digest</th>
                  <th>Manifest</th>
                  <th>Scan</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.tag}>
                    <td>
                      <code>{r.tag}</code>
                    </td>
                    <td className="muted">
                      {r.resolving ? '…' : r.digest ? (
                        <code title={r.digest}>{r.digest.slice(7, 19)}…</code>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      <Link to={`${base}/manifest/${encodeURIComponent(r.tag)}`}>Manifest</Link>
                    </td>
                    <td>
                      {r.digest ? (
                        <Link to={`/scan/${encodeURIComponent(r.digest)}`}>Scan</Link>
                      ) : r.resolving ? (
                        <span className="muted">…</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
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
