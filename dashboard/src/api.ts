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
