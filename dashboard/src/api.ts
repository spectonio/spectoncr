// Thin wrapper around the scanner's v2 HTTP API. Auth is via an API key
// the operator pastes into the header bar; the value is kept in memory only
// so a page refresh clears it (the dashboard never persists credentials).

let apiKey: string | null = null;

export function setApiKey(v: string) {
  apiKey = v || null;
}

export function getApiKey() {
  return apiKey;
}

function headers(extra: Record<string, string> = {}): HeadersInit {
  const h: Record<string, string> = { Accept: 'application/json', ...extra };
  if (apiKey) h.Authorization = `Bearer ${apiKey}`;
  return h;
}

export async function fetchLiveScan(digest: string): Promise<LiveScanResponse> {
  const r = await fetch(`/v2/scan/live/${encodeURIComponent(digest)}`, {
    headers: headers(),
  });
  if (!r.ok) throw new Error(`live scan: ${r.status}`);
  return r.json();
}

export async function searchCves(params: Record<string, string>): Promise<CveSearchResp> {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(`/v2/cve/search?${qs}`, { headers: headers() });
  if (!r.ok) throw new Error(`cve search: ${r.status}`);
  return r.json();
}

export interface Vulnerability {
  id: string;
  package: string;
  ecosystem: string;
  installed_version: string;
  fixed_version?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvss_score?: number;
  summary?: string;
  layer_digest?: string;
  suppressed: boolean;
}

export interface ScanResult {
  id: string;
  digest: string;
  tenant: string;
  project: string;
  repository: string;
  reference: string;
  status: 'queued' | 'in_progress' | 'completed' | 'failed';
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  vulnerabilities: Vulnerability[];
  policy_evaluation?: {
    status: 'PASS' | 'FAIL';
    reason?: string;
  };
}

export interface LiveScanResponse {
  status: string;
  digest: string;
  result?: ScanResult;
}

export interface CveHit {
  id: string;
  source: string;
  severity?: string;
  cvss_score?: number;
  summary?: string;
  affected: Array<{ ecosystem: string; package: string; fixed?: string }>;
}

export interface CveSearchResp {
  total: number;
  limit: number;
  offset: number;
  results: CveHit[];
}

export interface PilotChatMessage {
  role: string;
  content: string;
  tool_name?: string;
  tool_use_id?: string;
}

export interface PilotChatResp {
  reply: string;
  messages: PilotChatMessage[];
  tool_rounds: number;
  session_id?: string;
  backend: string;
}

/** POST /v2/_pilot/chat — requires [pilot] enabled on the registry. */
export async function postPilotChat(body: {
  message: string;
  history?: PilotChatMessage[];
  dry_run?: boolean;
  tenant?: string;
}): Promise<PilotChatResp> {
  const r = await fetch('/v2/_pilot/chat', {
    method: 'POST',
    headers: headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      message: body.message,
      history: body.history ?? [],
      dry_run: body.dry_run ?? true,
      tenant: body.tenant,
    }),
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`pilot chat: ${r.status} ${text}`);
  }
  return r.json();
}

// ── Registry browse (007) ───────────────────────────────────────────────────

export interface Catalog {
  repositories: string[];
}

export interface TagListResponse {
  name: string;
  tags: string[];
}

export interface ImageEntry {
  repository: string;
  tenant: string;
  project: string;
  name: string;
  tags: string[];
  tag_count: number;
  total_size_bytes: number;
  total_size: string;
  blob_count: number;
  manifest_count: number;
  last_pushed?: string;
}

export interface ImageListResponse {
  images: ImageEntry[];
  total: number;
}

export interface RepoSummary {
  repository: string;
  tag_count: number;
  last_pushed?: string;
  total_size?: string;
}

export interface ManifestDescriptor {
  digest: string;
  size: number;
  mediaType?: string;
}

export interface ManifestView {
  mediaType: string;
  digest: string;
  config?: ManifestDescriptor;
  layers: ManifestDescriptor[];
}

export interface AdmissionPolicySpec {
  signature_required?: boolean;
  scope?: { projects?: string[]; repositories?: string[] };
}

export interface AdmissionPolicy {
  id: string;
  name: string;
  tenant: string;
  spec: AdmissionPolicySpec;
  enabled: boolean;
  updated_at: string;
}

export interface AuditRowView {
  id: string;
  at: string;
  action: string;
  actor: string;
  tenant: string;
  subject: string;
  outcome: string;
}

export interface AuditListResponse {
  source: 'chained' | 'dashboard';
  rows: AuditRowView[];
}

/** Split `tenant/project/repo` paths returned by the catalog. */
export function parseRepository(full: string): { tenant: string; project: string; repo: string } | null {
  const parts = full.split('/').filter(Boolean);
  if (parts.length < 3) return null;
  return {
    tenant: parts[0],
    project: parts[1],
    repo: parts.slice(2).join('/'),
  };
}

function v2RepoPath(tenant: string, project: string, repo: string): string {
  return `/v2/${encodeURIComponent(tenant)}/${encodeURIComponent(project)}/${encodeURIComponent(repo)}`;
}

export async function getCatalog(params?: { n?: string; last?: string }): Promise<Catalog> {
  const qs = new URLSearchParams(params as Record<string, string>).toString();
  const r = await fetch(`/v2/_catalog${qs ? `?${qs}` : ''}`, { headers: headers() });
  if (!r.ok) throw new Error(`catalog: ${r.status}`);
  return r.json();
}

export async function getImages(params?: Record<string, string>): Promise<ImageListResponse> {
  const qs = new URLSearchParams(params ?? {}).toString();
  const r = await fetch(`/api/images?${qs}`, { headers: headers() });
  if (!r.ok) throw new Error(`images: ${r.status}`);
  return r.json();
}

export async function listTags(
  tenant: string,
  project: string,
  repo: string,
  params?: { n?: string; last?: string },
): Promise<TagListResponse> {
  const qs = new URLSearchParams(params as Record<string, string>).toString();
  const r = await fetch(`${v2RepoPath(tenant, project, repo)}/tags/list${qs ? `?${qs}` : ''}`, {
    headers: headers(),
  });
  if (!r.ok) throw new Error(`tags: ${r.status}`);
  return r.json();
}

export async function headManifestDigest(
  tenant: string,
  project: string,
  repo: string,
  ref: string,
): Promise<string | null> {
  const r = await fetch(
    `${v2RepoPath(tenant, project, repo)}/manifests/${encodeURIComponent(ref)}`,
    { method: 'HEAD', headers: headers() },
  );
  if (!r.ok) return null;
  return r.headers.get('Docker-Content-Digest');
}

interface RawManifest {
  mediaType?: string;
  config?: ManifestDescriptor;
  layers?: ManifestDescriptor[];
  manifests?: Array<{ digest: string; size?: number; mediaType?: string }>;
}

export async function getManifest(
  tenant: string,
  project: string,
  repo: string,
  ref: string,
): Promise<ManifestView> {
  const url = `${v2RepoPath(tenant, project, repo)}/manifests/${encodeURIComponent(ref)}`;
  const r = await fetch(url, {
    headers: headers({
      Accept:
        'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json',
    }),
  });
  if (!r.ok) throw new Error(`manifest: ${r.status}`);
  const digest = r.headers.get('Docker-Content-Digest') ?? ref;
  const raw = (await r.json()) as RawManifest;
  const mediaType = raw.mediaType ?? r.headers.get('Content-Type') ?? 'unknown';
  let layers: ManifestDescriptor[] = raw.layers ?? [];
  if (layers.length === 0 && raw.manifests) {
    layers = raw.manifests.map((m) => ({
      digest: m.digest,
      size: m.size ?? 0,
      mediaType: m.mediaType,
    }));
  }
  return {
    mediaType,
    digest,
    config: raw.config,
    layers,
  };
}

/** Aggregated repo stats — uses /api/ui/repo-summary when present, else /api/images. */
export async function getRepoSummary(tenant: string, project: string, repo: string): Promise<RepoSummary> {
  const repository = `${tenant}/${project}/${repo}`;
  try {
    const qs = new URLSearchParams({ repo: repository }).toString();
    const r = await fetch(`/api/ui/repo-summary?${qs}`, { headers: headers() });
    if (r.ok) return r.json();
  } catch {
    /* compose below */
  }
  const imgs = await getImages({ q: repository, limit: '50' });
  const hit = imgs.images.find((i) => i.repository === repository);
  if (hit) {
    return {
      repository,
      tag_count: hit.tag_count,
      last_pushed: hit.last_pushed,
      total_size: hit.total_size,
    };
  }
  const tags = await listTags(tenant, project, repo);
  return { repository, tag_count: tags.tags.length };
}

export async function getAdmissionPolicies(tenant: string): Promise<AdmissionPolicy[]> {
  const qs = new URLSearchParams({ tenant }).toString();
  const r = await fetch(`/v2/_admit/policies?${qs}`, { headers: headers() });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`admission policies: ${r.status} ${text}`);
  }
  const data = (await r.json()) as { items?: AdmissionPolicy[] };
  return data.items ?? [];
}

function mapDashboardAudit(events: Array<Record<string, unknown>>): AuditRowView[] {
  return events.map((ev, i) => ({
    id: String(i),
    at: String(ev.timestamp ?? ''),
    action: String(ev.event_type ?? ''),
    actor: String(ev.subject ?? ''),
    tenant: String(ev.tenant ?? ''),
    subject: [ev.repository, ev.reference].filter(Boolean).join(':') || String(ev.digest ?? ''),
    outcome: String(ev.status_code ?? ''),
  }));
}

function mapChainedAudit(rows: Array<{ id?: number; event?: Record<string, unknown>; tenant?: string }>): AuditRowView[] {
  return rows.map((row) => {
    const ev = row.event ?? {};
    const actor = (ev.actor as { id?: string } | undefined)?.id ?? '';
    const subject = (ev.subject as { ref?: string; digest?: string } | undefined);
    const subj = subject?.ref ?? subject?.digest ?? '';
    const outcome = (ev.outcome as { type?: string } | undefined)?.type ?? '';
    return {
      id: String(row.id ?? ''),
      at: String(ev.at ?? ''),
      action: String(ev.action ?? ''),
      actor,
      tenant: String(row.tenant ?? ''),
      subject: subj,
      outcome,
    };
  });
}

/** Prefer chained audit; fall back to dashboard ring buffer. */
export async function getAudit(params: Record<string, string>): Promise<AuditListResponse> {
  const qs = new URLSearchParams(params).toString();
  const chained = await fetch(`/v2/_audit?${qs}`, { headers: headers() });
  if (chained.ok) {
    const data = (await chained.json()) as { events?: unknown[] };
    return {
      source: 'chained',
      rows: mapChainedAudit((data.events ?? []) as Array<{ id?: number; event?: Record<string, unknown>; tenant?: string }>),
    };
  }
  const dashQs = new URLSearchParams(params);
  if (params.type) {
    dashQs.set('type', params.type);
  }
  const dash = await fetch(`/api/audit?${dashQs.toString()}`, { headers: headers() });
  if (!dash.ok) throw new Error(`audit: ${chained.status} / ${dash.status}`);
  const data = (await dash.json()) as { audit_events?: Array<Record<string, unknown>> };
  return {
    source: 'dashboard',
    rows: mapDashboardAudit(data.audit_events ?? []),
  };
}
