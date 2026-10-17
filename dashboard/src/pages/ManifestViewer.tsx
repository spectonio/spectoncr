import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getManifest, ManifestView } from '../api';
import { CopyButton } from '../ui';

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

export function ManifestViewer() {
  const { tenant = '', project = '', repo = '', ref = '' } = useParams<{
    tenant: string;
    project: string;
    repo: string;
    ref: string;
  }>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [manifest, setManifest] = useState<ManifestView | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const m = await getManifest(tenant, project, repo, ref);
        if (!cancelled) setManifest(m);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setManifest(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tenant, project, repo, ref]);

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
          <Link to={base}>{repo}</Link>
          <span>/</span>
          <code>{ref}</code>
        </div>
        <h1>Manifest</h1>
        <p>
          OCI / Docker v2 manifest for <code>{ref}</code>.
        </p>
      </div>

      {loading && <p className="muted">Loading manifest…</p>}
      {error && (
        <div className="card">
          <div className="empty">
            <h3>Could not load manifest</h3>
            <p>{error}</p>
          </div>
        </div>
      )}

      {manifest && (
        <>
          <div className="card rule-top" style={{ marginBottom: 18 }}>
            <div className="card-body meta-grid">
              <div>
                <span className="meta-lbl">Media type</span>
                <code>{manifest.mediaType}</code>
              </div>
              <div>
                <span className="meta-lbl">Digest</span>
                <span className="meta-val">
                  <code>{manifest.digest}</code>
                  <CopyButton value={manifest.digest} label="digest" />
                </span>
              </div>
              {manifest.config && (
                <div>
                  <span className="meta-lbl">Config</span>
                  <code title={manifest.config.digest}>
                    {manifest.config.digest.slice(0, 24)}… ({formatBytes(manifest.config.size)})
                  </code>
                </div>
              )}
              <div>
                <span className="meta-lbl">Scan</span>
                <Link to={`/scan/${encodeURIComponent(manifest.digest)}`}>Open scan report</Link>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-head">
              <h2>Layers</h2>
              <span className="sub">{manifest.layers.length} layer{manifest.layers.length === 1 ? '' : 's'}</span>
            </div>
            {manifest.layers.length === 0 ? (
              <div className="empty">
                <p>No layers in this manifest (index or attestation-only).</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Digest</th>
                      <th>Size</th>
                      <th>Media type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {manifest.layers.map((layer, i) => (
                      <tr key={layer.digest}>
                        <td className="muted tabular">{i + 1}</td>
                        <td>
                          <code title={layer.digest}>{layer.digest}</code>
                        </td>
                        <td className="tabular">{formatBytes(layer.size)}</td>
                        <td className="muted">{layer.mediaType || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </main>
  );
}
