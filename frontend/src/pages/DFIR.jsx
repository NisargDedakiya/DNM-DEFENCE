import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listDfirCases, createDfirCase, updateDfirCase,
  listDfirEvidence, uploadDfirEvidence, addDfirCustodyEntry,
  listDfirIocs, addDfirIoc,
  listDfirTimeline, addDfirTimelineEntry,
  getDfirExecutiveReport, getDfirTechnicalReport,
  getDfirRetainer, upsertDfirRetainer,
  listDfirLogAnalysisJobs, uploadDfirLogForAnalysis,
  downloadAuthenticatedFile,
} from '../api/client.js'

const STATUSES = ['active', 'contained', 'closed']
const SEVERITIES = ['low', 'medium', 'high', 'critical']
const TABS = ['Evidence', 'IoCs', 'Timeline', 'Log Analysis', 'Reports']
const LOG_TYPES = ['cloudtrail', 'azure', 'gcp', 'syslog', 'web_access', 'paloalto', 'evtx']

export default function DFIR() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const [form, setForm] = useState({ case_number: '', incident_type: '', severity: 'medium' })

  const { data: cases, isLoading } = useQuery({ queryKey: ['dfir-cases', clientId], queryFn: () => listDfirCases(clientId) })
  const create = useMutation({
    mutationFn: () => createDfirCase(clientId, form),
    onSuccess: (c) => { qc.invalidateQueries({ queryKey: ['dfir-cases', clientId] }); setForm({ case_number: '', incident_type: '', severity: 'medium' }); setSelectedCaseId(c.id) },
  })

  const selectedCase = cases?.find((c) => c.id === selectedCaseId)

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Digital Forensics &amp; Incident Response</h2>
        <p className="text-muted text-sm">Case management, evidence chain-of-custody, IoC tracking &amp; export, forensic log analysis, and IR retainer dashboard.</p>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-4 gap-3 mb-6">
        <input required placeholder="Case number (e.g. DFIR-2026-0001)" value={form.case_number} onChange={(e) => setForm({ ...form, case_number: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Incident type" value={form.incident_type} onChange={(e) => setForm({ ...form, incident_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button type="submit" disabled={create.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">New Case</button>
      </form>

      <RetainerBanner clientId={clientId} />

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : cases?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No cases yet.</div>
      ) : (
        <div className="flex gap-2 mb-6 flex-wrap">
          {cases?.map((c) => (
            <button key={c.id} onClick={() => setSelectedCaseId(c.id)}
              className={`px-3 py-2 rounded-md text-sm font-mono border ${selectedCaseId === c.id ? 'border-signal text-signal' : 'border-border text-muted hover:text-ink'}`}>
              {c.case_number} <span className="text-[10px] uppercase ml-1">({c.status})</span>
              <span className={`ml-1 text-[10px] uppercase ${c.severity === 'critical' ? 'text-critical' : 'text-muted'}`}>· {c.severity}</span>
            </button>
          ))}
        </div>
      )}

      {selectedCase && <CaseWorkspace clientId={clientId} caseData={selectedCase} />}
    </div>
  )
}

function RetainerBanner({ clientId }) {
  const qc = useQueryClient()
  const { data: retainer } = useQuery({ queryKey: ['dfir-retainer', clientId], queryFn: () => getDfirRetainer(clientId), retry: false })
  const upsert = useMutation({
    mutationFn: (payload) => upsertDfirRetainer(clientId, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dfir-retainer', clientId] }),
  })

  const editRetainer = () => {
    const tier = window.prompt('Retainer tier (e.g. Gold)?', retainer?.tier || '')
    if (tier === null) return
    const hoursIncluded = Number(window.prompt('Hours included per year?', retainer?.hours_included_per_year ?? 0) || 0)
    const hoursUsed = Number(window.prompt('Hours used so far?', retainer?.hours_used ?? 0) || 0)
    const sla = Number(window.prompt('Response SLA (hours)?', retainer?.response_sla_hours ?? 4) || 0)
    upsert.mutate({ tier, hours_included_per_year: hoursIncluded, hours_used: hoursUsed, response_sla_hours: sla })
  }

  if (!retainer) {
    return (
      <button onClick={editRetainer} className="mb-4 text-xs px-3 py-1.5 rounded border border-dashed border-border hover:border-signal/50 font-mono">
        Set up IR retainer
      </button>
    )
  }

  return (
    <div className="bg-panel2 rounded-md p-3 mb-4 text-xs flex items-center gap-6">
      <span>Retainer: <span className="font-mono">{retainer.tier}</span></span>
      <span>Hours used: <span className="font-mono">{retainer.hours_used}/{retainer.hours_included_per_year}</span></span>
      {retainer.response_sla_hours && <span>SLA: <span className="font-mono">{retainer.response_sla_hours}h</span></span>}
      <button onClick={editRetainer} className="ml-auto px-2 py-1 rounded border border-border hover:border-signal/50 font-mono text-[10px]">Edit</button>
    </div>
  )
}

function CaseWorkspace({ clientId, caseData }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState(TABS[0])
  const updateStatus = useMutation({
    mutationFn: (status) => updateDfirCase(clientId, caseData.id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dfir-cases', clientId] }),
  })

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-semibold">{caseData.case_number} — {caseData.incident_type || 'Unclassified incident'}</h3>
          <p className="text-xs text-muted mt-0.5">
            Initial vector: {caseData.initial_vector || 'unknown'} · Systems: {caseData.affected_systems?.join(', ') || 'none recorded'}
            {caseData.data_exfiltrated && <span className="text-critical"> · Data exfiltrated</span>}
          </p>
        </div>
        <select value={caseData.status} onChange={(e) => updateStatus.mutate(e.target.value)}
          className="bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal">
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="flex gap-2 mb-4 border-b border-border flex-wrap">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'Evidence' && <EvidencePanel clientId={clientId} caseId={caseData.id} />}
      {tab === 'IoCs' && <IocsPanel clientId={clientId} caseId={caseData.id} />}
      {tab === 'Timeline' && <TimelinePanel clientId={clientId} caseId={caseData.id} />}
      {tab === 'Log Analysis' && <LogAnalysisPanel clientId={clientId} caseId={caseData.id} />}
      {tab === 'Reports' && <ReportsPanel clientId={clientId} caseId={caseData.id} />}
    </div>
  )
}

function EvidencePanel({ clientId, caseId }) {
  const qc = useQueryClient()
  const [meta, setMeta] = useState({ evidence_type: '', source_host: '', acquisition_tool: '', acquired_by_name: '' })
  const { data: evidence, isLoading } = useQuery({ queryKey: ['dfir-evidence', caseId], queryFn: () => listDfirEvidence(clientId, caseId) })
  const upload = useMutation({
    mutationFn: (file) => uploadDfirEvidence(clientId, caseId, file, meta),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dfir-evidence', caseId] }),
  })
  const custody = useMutation({
    mutationFn: ({ evidenceId, custodian, action }) => addDfirCustodyEntry(clientId, caseId, evidenceId, { custodian, action }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dfir-evidence', caseId] }),
  })

  return (
    <div>
      <div className="grid grid-cols-4 gap-2 mb-4">
        <input placeholder="Evidence type (e.g. disk image)" value={meta.evidence_type} onChange={(e) => setMeta({ ...meta, evidence_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Source host" value={meta.source_host} onChange={(e) => setMeta({ ...meta, source_host: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Acquisition tool" value={meta.acquisition_tool} onChange={(e) => setMeta({ ...meta, acquisition_tool: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Acquired by" value={meta.acquired_by_name} onChange={(e) => setMeta({ ...meta, acquired_by_name: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
      </div>
      <label className="inline-block bg-panel2 border border-dashed border-border rounded-lg p-4 text-center cursor-pointer hover:border-signal/50 mb-4">
        <span className="text-xs px-3 py-1.5 rounded border border-border font-mono inline-block">
          {upload.isPending ? 'Hashing & uploading…' : 'Upload evidence file'}
        </span>
        <input type="file" className="hidden" onChange={(e) => e.target.files[0] && upload.mutate(e.target.files[0])} />
      </label>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {evidence?.map((e) => (
            <div key={e.id} className="bg-panel2 rounded-md p-3 text-xs">
              <p className="font-mono">{e.evidence_type} — {e.source_host} ({e.acquisition_tool})</p>
              <p className="text-muted mt-1 break-all">MD5: {e.md5_hash} · SHA256: {e.sha256_hash} · {e.file_size_bytes} bytes</p>
              <p className="text-muted mt-1">Custody chain: {e.chain_of_custody.map((c) => `${c.custodian} (${c.action})`).join(' → ')}</p>
              <button onClick={() => {
                const custodian = window.prompt('New custodian name?')
                const action = custodian && window.prompt('Action (e.g. transferred to lab)?')
                if (custodian && action) custody.mutate({ evidenceId: e.id, custodian, action })
              }} className="mt-2 px-2 py-1 rounded border border-border hover:border-signal/50 font-mono text-[10px]">
                Add custody entry
              </button>
            </div>
          ))}
          {evidence?.length === 0 && <p className="text-muted text-sm">No evidence acquired yet.</p>}
        </div>
      )}
    </div>
  )
}

function IocsPanel({ clientId, caseId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ ioc_type: 'ip', value: '', confidence: 'medium', context: '' })
  const { data: iocs, isLoading } = useQuery({ queryKey: ['dfir-iocs', caseId], queryFn: () => listDfirIocs(clientId, caseId) })
  const add = useMutation({
    mutationFn: () => addDfirIoc(clientId, caseId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dfir-iocs', caseId] }); setForm({ ...form, value: '', context: '' }) },
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-5 gap-2 mb-4">
        <select value={form.ioc_type} onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {['ip', 'domain', 'hash', 'email', 'url'].map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input required placeholder="Value" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <select value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {['low', 'medium', 'high'].map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Add IoC</button>
      </form>

      <div className="flex gap-2 mb-4">
        <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/dfir/cases/${caseId}/iocs/export/stix`, 'iocs-stix.json')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Export STIX</button>
        <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/dfir/cases/${caseId}/iocs/export/sigma`, 'iocs-sigma.yml')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Export Sigma</button>
        <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/dfir/cases/${caseId}/iocs/export/csv`, 'iocs.csv')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Export CSV</button>
      </div>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {iocs?.map((i) => (
            <div key={i.id} className="bg-panel2 rounded-md p-3 text-xs">
              <span className="uppercase text-[10px] px-1.5 py-0.5 bg-panel rounded mr-2">{i.ioc_type}</span>
              <span className="font-mono">{i.value}</span> <span className="text-muted ml-2">confidence: {i.confidence}</span>
            </div>
          ))}
          {iocs?.length === 0 && <p className="text-muted text-sm">No IoCs recorded yet.</p>}
        </div>
      )}
    </div>
  )
}

function TimelinePanel({ clientId, caseId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ timestamp: '', event_description: '', host: '' })
  const { data: entries, isLoading } = useQuery({ queryKey: ['dfir-timeline', caseId], queryFn: () => listDfirTimeline(clientId, caseId) })
  const add = useMutation({
    mutationFn: () => addDfirTimelineEntry(clientId, caseId, { ...form, timestamp: new Date(form.timestamp).toISOString() }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dfir-timeline', caseId] }); setForm({ timestamp: '', event_description: '', host: '' }) },
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-4 gap-2 mb-4">
        <input required type="datetime-local" value={form.timestamp} onChange={(e) => setForm({ ...form, timestamp: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input required placeholder="Event description" value={form.event_description} onChange={(e) => setForm({ ...form, event_description: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <input placeholder="Host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs col-span-4">Add timeline entry</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {entries?.map((e) => (
            <div key={e.id} className="bg-panel2 rounded-md p-3 text-xs">
              <span className="font-mono text-muted">{new Date(e.timestamp).toLocaleString()}</span>
              <p>{e.event_description}{e.host && ` — ${e.host}`}</p>
            </div>
          ))}
          {entries?.length === 0 && <p className="text-muted text-sm">No timeline entries yet.</p>}
        </div>
      )}
    </div>
  )
}

function LogAnalysisPanel({ clientId, caseId }) {
  const qc = useQueryClient()
  const [logType, setLogType] = useState(LOG_TYPES[0])
  const { data: jobs, isLoading } = useQuery({ queryKey: ['dfir-log-jobs', caseId], queryFn: () => listDfirLogAnalysisJobs(clientId, caseId) })
  const upload = useMutation({
    mutationFn: (file) => uploadDfirLogForAnalysis(clientId, caseId, file, logType),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dfir-log-jobs', caseId] }),
  })

  return (
    <div>
      <div className="flex gap-2 mb-4">
        <select value={logType} onChange={(e) => setLogType(e.target.value)}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {LOG_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <label className="inline-block bg-panel2 border border-dashed border-border rounded-lg px-4 py-1.5 text-center cursor-pointer hover:border-signal/50">
          <span className="text-xs font-mono">{upload.isPending ? 'Parsing…' : 'Upload log file'}</span>
          <input type="file" className="hidden" onChange={(e) => e.target.files[0] && upload.mutate(e.target.files[0])} />
        </label>
      </div>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-3">
          {jobs?.map((j) => (
            <div key={j.id} className="bg-panel2 rounded-md p-3 text-xs">
              <p className="font-mono">{j.original_filename} ({j.log_type}) — {j.events_count} event(s)</p>
              {j.error_message ? <p className="text-critical mt-1">{j.error_message}</p> : (
                <>
                  {j.anomalies?.length > 0 && (
                    <ul className="mt-2 space-y-1">
                      {j.anomalies.map((a, i) => <li key={i} className="text-medium">⚠ {a.detail}</li>)}
                    </ul>
                  )}
                  {j.narrative && <p className="mt-2 text-muted whitespace-pre-wrap">{j.narrative}</p>}
                </>
              )}
            </div>
          ))}
          {jobs?.length === 0 && <p className="text-muted text-sm">No logs analyzed yet.</p>}
        </div>
      )}
    </div>
  )
}

function ReportsPanel({ clientId, caseId }) {
  const executive = useMutation({ mutationFn: () => getDfirExecutiveReport(clientId, caseId) })
  const technical = useMutation({ mutationFn: () => getDfirTechnicalReport(clientId, caseId) })

  return (
    <div>
      <div className="flex gap-2 mb-4">
        <button onClick={() => executive.mutate()} disabled={executive.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          {executive.isPending ? 'Generating…' : 'Generate executive summary'}
        </button>
        <button onClick={() => technical.mutate()} disabled={technical.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          {technical.isPending ? 'Generating…' : 'Generate technical report'}
        </button>
      </div>
      {executive.data && <div className="bg-panel2 rounded-md p-4 text-sm whitespace-pre-wrap mb-4">{executive.data}</div>}
      {technical.data && <div className="bg-panel2 rounded-md p-4 text-sm whitespace-pre-wrap">{technical.data}</div>}
    </div>
  )
}
