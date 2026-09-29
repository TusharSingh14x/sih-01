import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Activity, ArrowRight, ClipboardList, Database, FileText, HardDrive, LogOut, Plus, RefreshCw, Search, ShieldCheck, X } from 'lucide-react'
import { api, ApiError, type Agent, type Evidence, type Investigation, type Job, type Report } from './services/api'
import { BlockchainPage, CustodyPage, FindingsPage, EditorPage, CaseDialog, PdfDownloads } from './Workbench'
import './workbench.css'

type Section = 'Overview' | 'Investigations' | 'Agents' | 'Jobs' | 'Evidence' | 'Reports' | 'Blockchain' | 'Custody' | 'Findings' | 'Editor'
type Modal = 'investigation' | 'job' | 'report' | null

const sections: { label: Section; icon: typeof Activity }[] = [
  { label: 'Overview', icon: Activity },
  { label: 'Investigations', icon: ClipboardList },
  { label: 'Agents', icon: HardDrive },
  { label: 'Jobs', icon: RefreshCw },
  { label: 'Evidence', icon: Database },
  { label: 'Reports', icon: FileText },
  { label: 'Blockchain', icon: ShieldCheck },
  { label: 'Custody', icon: ClipboardList },
  { label: 'Findings', icon: Search },
  { label: 'Editor', icon: FileText },
]

function date(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [email, setEmail] = useState('analyst@jocky.local')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try { onLogin((await api.login(email, password)).access_token) }
    catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  return <div className="login-shell">
    <div className="login-brand"><div className="brand-mark"><ShieldCheck size={22} /></div><strong>JOCKY</strong><span>INVESTIGATION PLATFORM</span></div>
    <main className="login-panel">
      <p className="eyebrow">SECURE WORKSPACE</p>
      <h1>Sign in</h1>
      <p className="muted">Access your investigations and collection records.</p>
      <form onSubmit={submit} className="form-stack">
        <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} required /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary full" disabled={busy}>{busy ? 'Signing in...' : 'Sign in'} <ArrowRight size={16} /></button>
      </form>
    </main>
  </div>
}

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('jocky-token') || '')
  const [section, setSection] = useState<Section>('Overview')
  const [modal, setModal] = useState<Modal>(null)
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [search, setSearch] = useState('')
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [selectedInvestigation, setSelectedInvestigation] = useState('')
  const [selectedAgent, setSelectedAgent] = useState('')
  const [capability, setCapability] = useState('system.info')
  const [processPid, setProcessPid] = useState('')
  const [preview, setPreview] = useState<unknown>(null)
  const [caseId, setCaseId] = useState('')
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])

  const refresh = useCallback(async () => {
    if (!token) return
    try {
      const [i, a, j, e, r] = await Promise.all([api.investigations(token), api.agents(token), api.jobs(token), api.evidence(token), api.reports(token)])
      setInvestigations(i); setAgents(a); setJobs(j); setEvidence(e); setReports(r); setError('')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { sessionStorage.removeItem('jocky-token'); setToken('') }
      setError((err as Error).message)
    }
  }, [token])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => { if (!token) return; const id = window.setInterval(() => void refresh(), 15000); return () => clearInterval(id) }, [refresh, token])

  function signIn(value: string) { sessionStorage.setItem('jocky-token', value); setToken(value) }
  function signOut() { sessionStorage.removeItem('jocky-token'); setToken('') }
  const activeAgents = agents.filter(agent => Date.now() - new Date(agent.last_seen).getTime() < 120000).length
  const openCases = investigations.filter(item => item.status === 'open')
  const recentJobs = jobs.slice(0, 5)
  const filteredInvestigations = useMemo(() => investigations.filter(item => `${item.title} ${item.description}`.toLowerCase().includes(search.toLowerCase())), [investigations, search])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!token || !modal) return
    setBusy(true); setError('')
    try {
      if (modal === 'investigation') { await api.createInvestigation(token, title, description, selectedAgents); setSelectedAgents([]) }
      if (modal === 'job') await api.createJob(token, selectedInvestigation, selectedAgent, capability === 'process.modules' ? `process.modules:${processPid}` : capability)
      if (modal === 'report') await api.createReport(token, selectedInvestigation, title)
      setModal(null); setTitle(''); setDescription(''); await refresh()
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }

  async function openEvidence(item: Evidence) {
    try { setPreview(await api.evidenceContent(token, item.id)) }
    catch (err) { setError((err as Error).message) }
  }

  async function toggleInvestigation(item: Investigation) {
    try {
      await api.updateInvestigation(token, item.id, item.status === 'open' ? 'closed' : 'open')
      await refresh()
    } catch (err) { setError((err as Error).message) }
  }

  if (!token) return <Login onLogin={signIn} />
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={20} /></div><div><strong>JOCKY</strong><small>FORENSICS</small></div></div>
      <nav aria-label="Main navigation">{sections.map(({ label, icon: Icon }) => <button key={label} className={`nav-item ${section === label ? 'active' : ''}`} onClick={() => setSection(label)}><Icon size={18} strokeWidth={1.8} />{label}</button>)}</nav>
      <div className="sidebar-bottom"><span className="connection-dot" /> Connected to workspace<button onClick={signOut} title="Sign out" aria-label="Sign out"><LogOut size={17} /></button></div>
    </aside>
    <div className="main-area">
      <header className="topbar"><div className="mobile-brand">JOCKY</div><span>Investigation workspace</span><div className="topbar-actions"><span className="analyst-badge">ANALYST</span><button className="icon-button" title="Refresh data" aria-label="Refresh data" onClick={() => void refresh()}><RefreshCw size={17} /></button></div></header>
      <main className="content">
        <div className="page-heading"><div><p className="eyebrow">WORKSPACE / {section.toUpperCase()}</p><h1>{section}</h1></div><div className="heading-actions">{section === 'Overview' || section === 'Investigations' ? <button className="primary" onClick={() => setModal('investigation')}><Plus size={16} /> New investigation</button> : null}{section === 'Jobs' && <button className="primary" disabled={!agents.length || !openCases.length} onClick={() => { setSelectedInvestigation(openCases[0]?.id || ''); setSelectedAgent(agents[0]?.id || ''); setModal('job') }}><Plus size={16} /> Schedule collection</button>}{section === 'Reports' && <button className="primary" disabled={!investigations.length} onClick={() => { setSelectedInvestigation(investigations[0]?.id || ''); setModal('report') }}><Plus size={16} /> Generate report</button>}</div></div>
        {error && <div className="alert" role="alert">{error}<button aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button></div>}
        {section === 'Blockchain' && <BlockchainPage token={token} evidence={evidence} investigations={investigations} refresh={refresh} />}
        {section === 'Custody' && <CustodyPage token={token} evidence={evidence} />}
        {section === 'Findings' && <FindingsPage token={token} />}
        {section === 'Editor' && <EditorPage token={token} />}
        {section === 'Reports' && <PdfDownloads token={token} reports={reports} />}
        {section === 'Investigations' && <div className="workbench-toolbar">{filteredInvestigations.map(item => <button className="secondary wrap" key={item.id} onClick={() => setCaseId(item.id)}><ClipboardList size={16} />{item.title}<ArrowRight size={14} /></button>)}</div>}
        {section === 'Overview' && <>
          <div className="stat-grid"><Stat icon={ClipboardList} label="Open investigations" value={investigations.filter(x => x.status === 'open').length} /><Stat icon={HardDrive} label="Active agents" value={activeAgents} /><Stat icon={RefreshCw} label="Queued jobs" value={jobs.filter(x => x.status === 'queued').length} /><Stat icon={Database} label="Evidence items" value={evidence.length} /></div>
          <div className="overview-grid"><section className="workspace-section"><div className="section-heading"><h2>Recent investigations</h2><button className="text-button" onClick={() => setSection('Investigations')}>View all <ArrowRight size={15} /></button></div>{investigations.length ? <div className="item-list">{investigations.slice(0, 5).map(item => <div className="list-row" key={item.id}><div className="row-symbol"><ClipboardList size={17} /></div><div className="row-main"><strong>{item.title}</strong><small>{item.description || 'No description'}</small></div><Status value={item.status} /><span className="row-date">{date(item.created_at)}</span></div>)}</div> : <Empty text="No investigations yet" />}</section><section className="workspace-section"><div className="section-heading"><h2>Collection activity</h2><button className="text-button" onClick={() => setSection('Jobs')}>View jobs <ArrowRight size={15} /></button></div>{recentJobs.length ? <div className="activity-list">{recentJobs.map(job => <div key={job.id} className="activity-row"><span className={`activity-dot ${job.status}`} /><div><strong>{job.capability}</strong><small>{job.agent_id} · {date(job.created_at)}</small></div><Status value={job.status} /></div>)}</div> : <Empty text="No collection jobs yet" />}</section></div>
        </>}
        {section === 'Investigations' && <section className="workspace-section"><div className="section-heading"><h2>Case register</h2><label className="search"><Search size={16} /><input aria-label="Search investigations" placeholder="Search investigations" value={search} onChange={e => setSearch(e.target.value)} /></label></div><div className="table-wrap"><table><thead><tr><th>Investigation</th><th>Status</th><th>Created</th><th>Evidence</th><th></th></tr></thead><tbody>{filteredInvestigations.map(item => <tr key={item.id}><td><strong>{item.title}</strong><small>{item.description}</small></td><td><Status value={item.status} /></td><td>{date(item.created_at)}</td><td>{evidence.filter(x => x.investigation_id === item.id).length}</td><td><button className="text-button" onClick={() => void toggleInvestigation(item)}>{item.status === 'open' ? 'Close' : 'Reopen'}</button></td></tr>)}</tbody></table>{!filteredInvestigations.length && <Empty text="No matching investigations" />}</div></section>}
        {section === 'Agents' && <section className="workspace-section"><div className="section-heading"><h2>Managed endpoints</h2><span className="count">{agents.length} registered</span></div><div className="table-wrap"><table><thead><tr><th>Hostname</th><th>Agent ID</th><th>Platform</th><th>Last seen</th><th>Status</th></tr></thead><tbody>{agents.map(agent => <tr key={agent.id}><td><strong>{agent.hostname}</strong></td><td className="mono">{agent.id}</td><td>{agent.platform}</td><td>{date(agent.last_seen)}</td><td><Status value={Date.now() - new Date(agent.last_seen).getTime() < 120000 ? 'online' : 'offline'} /></td></tr>)}</tbody></table>{!agents.length && <Empty text="Waiting for an agent to register" />}</div></section>}
        {section === 'Jobs' && <section className="workspace-section"><div className="section-heading"><h2>Collection queue</h2><span className="count">{jobs.length} jobs</span></div><div className="table-wrap"><table><thead><tr><th>Capability</th><th>Agent</th><th>Investigation</th><th>Created</th><th>Status</th></tr></thead><tbody>{jobs.map(job => <tr key={job.id}><td><strong>{job.capability}</strong>{job.error && <small className="error">{job.error}</small>}</td><td className="mono">{job.agent_id}</td><td>{investigations.find(x => x.id === job.investigation_id)?.title || job.investigation_id}</td><td>{date(job.created_at)}</td><td><Status value={job.status} /></td></tr>)}</tbody></table>{!jobs.length && <Empty text="No collection jobs scheduled" />}</div></section>}
        {section === 'Evidence' && <section className="workspace-section"><div className="section-heading"><h2>Evidence inventory</h2><span className="count">SHA-256 verified on access</span></div><div className="table-wrap"><table><thead><tr><th>Capability</th><th>Investigation</th><th>SHA-256</th><th>Collected</th><th></th></tr></thead><tbody>{evidence.map(item => <tr key={item.id}><td><strong>{item.capability}</strong><small>{item.size_bytes} bytes</small></td><td>{investigations.find(x => x.id === item.investigation_id)?.title || item.investigation_id}</td><td className="mono hash">{item.sha256}</td><td>{date(item.collected_at)}</td><td><button className="text-button" onClick={() => void openEvidence(item)}>View</button></td></tr>)}</tbody></table>{!evidence.length && <Empty text="No evidence collected yet" />}</div></section>}
        {section === 'Reports' && <section className="workspace-section"><div className="section-heading"><h2>Forensic reports</h2><span className="count">{reports.length} generated</span></div><div className="table-wrap"><table><thead><tr><th>Report</th><th>Investigation</th><th>Evidence items</th><th>Generated</th><th></th></tr></thead><tbody>{reports.map(item => <tr key={item.id}><td><strong>{item.title}</strong></td><td>{investigations.find(x => x.id === item.investigation_id)?.title || item.investigation_id}</td><td>{item.content.evidence_count}</td><td>{date(item.created_at)}</td><td><button className="text-button" onClick={() => setPreview(item.content)}>View</button></td></tr>)}</tbody></table>{!reports.length && <Empty text="No reports generated yet" />}</div></section>}
      </main>
    </div>
    {modal && <div className="modal-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) setModal(null) }}>
      <section className="modal" role="dialog" aria-modal="true" aria-label={modal}>
        <div className="modal-heading"><h2>{modal === 'investigation' ? 'New investigation' : modal === 'job' ? 'Schedule collection' : 'Generate report'}</h2><button className="icon-button" title="Close" aria-label="Close" onClick={() => setModal(null)}><X size={18} /></button></div>
        <form onSubmit={submit} className="form-stack">
          {modal !== 'job' && <label>Title<input value={title} onChange={e => setTitle(e.target.value)} minLength={3} maxLength={200} required autoFocus /></label>}
          {modal === 'investigation' && <><label>Description<textarea value={description} onChange={e => setDescription(e.target.value)} rows={4} maxLength={5000} /></label><fieldset className="agent-picker"><legend>Assign machines</legend>{agents.map(a => <label key={a.id}><input type="checkbox" checked={selectedAgents.includes(a.id)} onChange={e => setSelectedAgents(current => e.target.checked ? [...current, a.id] : current.filter(id => id !== a.id))} />{a.hostname}</label>)}{!agents.length && <span>No agents registered</span>}</fieldset></>}
          {modal !== 'investigation' && <label>Investigation<select value={selectedInvestigation} onChange={e => setSelectedInvestigation(e.target.value)} required>{(modal === 'job' ? openCases : investigations).map(item => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label>}
          {modal === 'job' && <><label>Agent<select value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)} required>{agents.map(item => <option key={item.id} value={item.id}>{item.hostname} ({item.platform})</option>)}</select></label><label>Collection capability<select value={capability} onChange={e => setCapability(e.target.value)}><option value="system.info">System information</option><option value="system.drivers">Loaded driver or kernel module inventory</option><option value="process.list">Process list</option><option value="process.modules">Loaded modules for a process</option><option value="network.connections">Network connections</option><option value="logs.system">Recent system logs</option></select></label>{capability === 'process.modules' && <label>Process ID<input type="number" min="1" max="4294967295" value={processPid} onChange={event => setProcessPid(event.target.value)} required /></label>}</>}
          {error && <p className="error" role="alert">{error}</p>}
          <div className="modal-actions"><button type="button" className="secondary" onClick={() => setModal(null)}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Working...' : modal === 'job' ? 'Schedule' : modal === 'report' ? 'Generate' : 'Create'}</button></div>
        </form>
      </section>
    </div>}
    {caseId && <CaseDialog token={token} id={caseId} close={() => setCaseId('')} />}
    {preview !== null && <div className="modal-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) setPreview(null) }}><section className="modal preview" role="dialog" aria-modal="true" aria-label="Evidence preview"><div className="modal-heading"><h2>Record preview</h2><button className="icon-button" title="Close" aria-label="Close" onClick={() => setPreview(null)}><X size={18} /></button></div><pre>{JSON.stringify(preview, null, 2)}</pre></section></div>}
  </div>
}

function Status({ value }: { value: string }) { return <span className={`status ${value}`}>{value}</span> }
function Empty({ text }: { text: string }) { return <div className="empty"><Database size={23} strokeWidth={1.5} /><span>{text}</span></div> }
function Stat({ icon: Icon, label, value }: { icon: typeof Activity; label: string; value: number }) { return <div className="stat"><span className="stat-icon"><Icon size={18} /></span><div><span className="stat-label">{label}</span><strong>{value}</strong></div></div> }
