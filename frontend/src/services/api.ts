export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export type Investigation = { id: string; title: string; description: string; status: string; created_at: string; owner_id: string }
export type Agent = { id: string; hostname: string; platform: string; version: string; last_seen: string }
export type Job = { id: string; investigation_id: string; agent_id: string; capability: string; status: string; created_at: string; completed_at: string | null; error: string | null }
export type Evidence = { id: string; investigation_id: string; job_id: string; capability: string; sha256: string; size_bytes: number; collected_at: string; details: Record<string, string>; blockchain_tx_id: string | null }
export type Finding = { id: string; investigation_id: string; category: string; severity: string; title: string; description: string; evidence_ids: string[]; confidence: number; created_at?: string }
export type BlockchainRecord = { id: string; evidence_id: string; sha256: string; blockchain_tx_id: string; verification_status: string; mode: string; custodian: string; verified_at: string | null }
export type Verification = { evidence_id: string; status: string; actual_sha256: string; registered_sha256: string; metadata_sha256: string; mode: string; verified_at: string }
export type EvidenceBatch = { id: string; investigation_id: string; root: string; algorithm: string; mode: string; blockchain_tx_id: string; created_at: string; evidence_count: number }
export type BatchVerification = { id: string; status: string; algorithm: string; stored_root: string; current_root: string; registered_root: string; mode: string; proofs: { evidence_id: string; valid: boolean }[] }
export type BatchManifest = EvidenceBatch & { evidence: { evidence_id: string; sha256: string; proof: { side: 'left' | 'right'; hash: string }[] }[] }
export type CustodyEvent = { id: string; evidence_id: string; event_type: string; from_entity: string | null; to_entity: string; blockchain_tx_id: string | null; created_at: string }
export type CaseDetail = { investigation: Investigation; agents: Agent[]; jobs: Job[]; evidence: Evidence[]; findings: Finding[] }
export type EditorResult = { success: boolean; output: string; errors: string; ir: string; mode: string }
export type Report = { id: string; investigation_id: string; title: string; created_at: string; content: { evidence_count: number; evidence: { id: string; capability: string; sha256: string }[] } }

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message) }
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(body.detail || `Request failed (${response.status})`, response.status)
  }
  return response.json() as Promise<T>
}

export const api = {
  login: (email: string, password: string) => request<{ access_token: string }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  investigations: (token: string) => request<Investigation[]>('/api/investigations', {}, token),
  createInvestigation: (token: string, title: string, description: string, agent_ids: string[] = []) => request<Investigation>('/api/investigations', { method: 'POST', body: JSON.stringify({ title, description, agent_ids }) }, token),
  updateInvestigation: (token: string, id: string, status: 'open' | 'closed') => request<Investigation>(`/api/investigations/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }, token),
  agents: (token: string) => request<Agent[]>('/api/agents', {}, token),
  jobs: (token: string) => request<Job[]>('/api/jobs', {}, token),
  createJob: (token: string, investigation_id: string, agent_id: string, capability: string) => request<Job>('/api/jobs', { method: 'POST', body: JSON.stringify({ investigation_id, agent_id, capability }) }, token),
  evidence: (token: string) => request<Evidence[]>('/api/evidence', {}, token),
  evidenceContent: (token: string, id: string) => request<unknown>(`/api/evidence/${id}/content`, {}, token),
  reports: (token: string) => request<Report[]>('/api/reports', {}, token),
  createReport: (token: string, investigation_id: string, title: string) => request<Report>('/api/reports', { method: 'POST', body: JSON.stringify({ investigation_id, title }) }, token),
  findings: (token: string) => request<Finding[]>('/api/findings', {}, token),
  caseDetail: (token: string, id: string) => request<CaseDetail>(`/api/investigations/${id}`, {}, token),
  blockchainRecords: (token: string) => request<BlockchainRecord[]>('/api/blockchain/records', {}, token),
  registerEvidence: (token: string, evidence_id: string) => request<BlockchainRecord>('/api/blockchain/register', { method: 'POST', body: JSON.stringify({ evidence_id }) }, token),
  verifyEvidence: (token: string, id: string) => request<Verification>(`/api/blockchain/verify/${id}`, {}, token),
  evidenceBatches: (token: string) => request<EvidenceBatch[]>('/api/blockchain/batches', {}, token),
  registerBatch: (token: string, investigation_id: string, evidence_ids: string[]) => request<EvidenceBatch & { evidence: unknown[] }>('/api/blockchain/batches', { method: 'POST', body: JSON.stringify({ investigation_id, evidence_ids }) }, token),
  evidenceBatchManifest: (token: string, id: string) => request<BatchManifest>(`/api/blockchain/batches/${id}`, {}, token),
  verifyBatch: (token: string, id: string) => request<BatchVerification>(`/api/blockchain/batches/${id}/verify`, {}, token),
  custodyHistory: (token: string, id: string) => request<CustodyEvent[]>(`/api/custody/history?evidence_id=${encodeURIComponent(id)}`, {}, token),
  custodyRecipients: (token: string) => request<{ id: string; email: string }[]>('/api/custody/recipients', {}, token),
  transferCustody: (token: string, evidence_id: string, from_entity: string, to_entity: string) => request<CustodyEvent>('/api/custody/transfer', { method: 'POST', body: JSON.stringify({ evidence_id, from_entity, to_entity }) }, token),
  editor: (token: string, action: 'check' | 'run' | 'compile', source: string) => request<EditorResult>(`/api/editor/${action}`, { method: 'POST', body: JSON.stringify({ source }) }, token),
  reportPdf: async (token: string, id: string) => {
    const response = await fetch(`${API_URL}/api/reports/${id}/pdf`, { headers: { Authorization: `Bearer ${token}` } })
    if (!response.ok) throw new ApiError('PDF generation failed', response.status)
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a'); link.href = url; link.download = `jocky-${id}.pdf`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 10000)
  },
}
