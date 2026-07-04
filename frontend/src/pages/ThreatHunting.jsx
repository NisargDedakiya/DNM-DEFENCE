import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listHuntHypotheses, seedHuntHypotheses, createHuntHypothesis, generateHuntHypothesis,
  listHunts, createHunt, updateHunt,
  listHuntFindings, addHuntFinding, getHuntReport,
  getThreatHuntingCoverage, enrichIoc,
  listSiemConnections, registerSiemConnection,
} from '../api/client.js'

const TABS = ['Hypothesis Library', 'Active Hunts', 'SIEM Connections', 'IoC Enrichment', 'Coverage']
const HUNT_STATUSES = ['planned', 'active', 'complete']
const OUTCOMES = ['threat_found', 'negative', 'inconclusive']

export default function ThreatHunting() {
  const { clientId } = useParams()
  const [tab, setTab] = useState(TABS[0])

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Continuous Threat Hunting</h2>
        <p className="text-muted text-sm">
          Shared hypothesis library, client-scoped hunt operations, real SIEM/EDR querying, IoC enrichment, and ATT&amp;CK coverage tracking.
        </p>
      </div>

      <div className="flex gap-2 mb-6 border-b border-border flex-wrap">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'Hypothesis Library' && <HypothesisLibraryPanel />}
      {tab === 'Active Hunts' && <HuntsPanel clientId={clientId} />}
      {tab === 'SIEM Connections' && <SiemConnectionsPanel clientId={clientId} />}
      {tab === 'IoC Enrichment' && <IocEnrichmentPanel clientId={clientId} />}
      {tab === 'Coverage' && <CoveragePanel clientId={clientId} />}
    </div>
  )
}

function HypothesisLibraryPanel() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ title: '', attack_technique: '', description: '' })
  const [genIndustry, setGenIndustry] = useState('')
  const { data: hypotheses, isLoading } = useQuery({ queryKey: ['hunt-hypotheses'], queryFn: listHuntHypotheses })
  const seed = useMutation({ mutationFn: seedHuntHypotheses, onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-hypotheses'] }) })
  const create = useMutation({
    mutationFn: () => createHuntHypothesis(form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['hunt-hypotheses'] }); setForm({ title: '', attack_technique: '', description: '' }) },
  })
  const generate = useMutation({
    mutationFn: () => generateHuntHypothesis({ client_industry: genIndustry }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-hypotheses'] }),
  })

  return (
    <div>
      <div className="flex gap-3 mb-4">
        <button onClick={() => seed.mutate()} disabled={seed.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          {seed.isPending ? 'Seeding…' : 'Seed starter library'}
        </button>
        <input placeholder="Industry (for AI generation)" value={genIndustry} onChange={(e) => setGenIndustry(e.target.value)}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button onClick={() => generate.mutate()} disabled={generate.isPending || !genIndustry}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          {generate.isPending ? 'Generating…' : 'AI-generate hypothesis'}
        </button>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-4 gap-2 mb-6">
        <input required placeholder="Title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <input placeholder="ATT&CK technique" value={form.attack_technique} onChange={(e) => setForm({ ...form, attack_technique: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Add hypothesis</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {hypotheses?.map((h) => (
            <div key={h.id} className="bg-panel2 rounded-md p-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono">{h.title}</span>
                <span className="text-[10px] uppercase text-muted">{h.source}</span>
              </div>
              <p className="text-muted mt-1">{h.description}</p>
              <div className="mt-1 flex gap-2 flex-wrap">
                {h.attack_technique && <span className="px-1.5 py-0.5 bg-panel rounded text-[10px] font-mono">{h.attack_technique}</span>}
                {h.data_sources?.map((d, i) => <span key={i} className="px-1.5 py-0.5 bg-panel rounded text-[10px]">{d}</span>)}
                <span className="text-muted">hunted {h.hunt_count}×</span>
              </div>
            </div>
          ))}
          {hypotheses?.length === 0 && <p className="text-muted text-sm">No hypotheses yet — seed the starter library or add one.</p>}
        </div>
      )}
    </div>
  )
}

function HuntsPanel({ clientId }) {
  const qc = useQueryClient()
  const [selectedHypothesisId, setSelectedHypothesisId] = useState('')
  const [selectedHuntId, setSelectedHuntId] = useState(null)
  const { data: hypotheses } = useQuery({ queryKey: ['hunt-hypotheses'], queryFn: listHuntHypotheses })
  const { data: hunts, isLoading } = useQuery({ queryKey: ['hunts', clientId], queryFn: () => listHunts(clientId) })
  const create = useMutation({
    mutationFn: () => createHunt(clientId, { hypothesis_id: selectedHypothesisId }),
    onSuccess: (h) => { qc.invalidateQueries({ queryKey: ['hunts', clientId] }); setSelectedHuntId(h.id) },
  })
  const update = useMutation({
    mutationFn: ({ huntId, payload }) => updateHunt(clientId, huntId, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunts', clientId] }),
  })

  const selectedHunt = hunts?.find((h) => h.id === selectedHuntId)

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2 mb-6">
        <select required value={selectedHypothesisId} onChange={(e) => setSelectedHypothesisId(e.target.value)}
          className="flex-1 bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          <option value="">Select a hypothesis to hunt…</option>
          {hypotheses?.map((h) => <option key={h.id} value={h.id}>{h.title}</option>)}
        </select>
        <button type="submit" disabled={create.isPending || !selectedHypothesisId} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">
          Start hunt
        </button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : hunts?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No hunts started yet.</div>
      ) : (
        <div className="flex gap-2 mb-6 flex-wrap">
          {hunts?.map((h) => (
            <button key={h.id} onClick={() => setSelectedHuntId(h.id)}
              className={`px-3 py-2 rounded-md text-sm font-mono border ${selectedHuntId === h.id ? 'border-signal text-signal' : 'border-border text-muted hover:text-ink'}`}>
              {hypotheses?.find((hy) => hy.id === h.hypothesis_id)?.title || h.hypothesis_id}
              <span className="text-[10px] uppercase ml-1">({h.status})</span>
            </button>
          ))}
        </div>
      )}

      {selectedHunt && (
        <div className="bg-panel border border-border rounded-lg p-5">
          <div className="flex items-center gap-2 mb-4">
            <select value={selectedHunt.status} onChange={(e) => update.mutate({ huntId: selectedHunt.id, payload: { status: e.target.value } })}
              className="bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal">
              {HUNT_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={selectedHunt.outcome || ''} onChange={(e) => update.mutate({ huntId: selectedHunt.id, payload: { outcome: e.target.value } })}
              className="bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal">
              <option value="">no outcome yet</option>
              {OUTCOMES.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
            <input type="number" placeholder="Hours spent" defaultValue={selectedHunt.hours_spent}
              onBlur={(e) => update.mutate({ huntId: selectedHunt.id, payload: { hours_spent: Number(e.target.value) } })}
              className="w-28 bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal" />
          </div>
          <HuntFindingsSection clientId={clientId} huntId={selectedHunt.id} />
        </div>
      )}
    </div>
  )
}

function HuntFindingsSection({ clientId, huntId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ title: '', severity: 'medium', description: '' })
  const { data: findings, isLoading } = useQuery({ queryKey: ['hunt-findings', huntId], queryFn: () => listHuntFindings(clientId, huntId) })
  const add = useMutation({
    mutationFn: () => addHuntFinding(clientId, huntId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['hunt-findings', huntId] }); setForm({ title: '', severity: 'medium', description: '' }) },
  })
  const report = useMutation({ mutationFn: () => getHuntReport(clientId, huntId) })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-4 gap-2 mb-4">
        <input required placeholder="Finding title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Add finding</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2 mb-4">
          {findings?.map((f) => (
            <div key={f.id} className="bg-panel2 rounded-md p-3 text-xs">
              <span className="uppercase text-[10px] mr-2">{f.severity}</span>{f.title}
              {f.escalated_to_ir && <span className="ml-2 text-critical">→ escalated to IR</span>}
            </div>
          ))}
          {findings?.length === 0 && <p className="text-muted text-sm">No findings yet.</p>}
        </div>
      )}

      <button onClick={() => report.mutate()} disabled={report.isPending}
        className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
        {report.isPending ? 'Generating…' : 'Generate hunt report'}
      </button>
      {report.data && <div className="mt-3 bg-panel2 rounded-md p-3 text-xs whitespace-pre-wrap">{report.data}</div>}
    </div>
  )
}

function SiemConnectionsPanel({ clientId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ provider: 'elastic', base_url: '', api_key: '', username: '', password: '', client_id_cred: '', client_secret: '' })
  const { data: connections, isLoading } = useQuery({ queryKey: ['siem-connections', clientId], queryFn: () => listSiemConnections(clientId) })
  const register = useMutation({
    mutationFn: () => registerSiemConnection(clientId, form),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['siem-connections', clientId] }),
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); register.mutate() }} className="grid grid-cols-3 gap-2 mb-6">
        <select value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {['elastic', 'splunk', 'crowdstrike', 'sentinelone'].map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input placeholder="Base URL" value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        {form.provider === 'elastic' && (
          <input placeholder="API key" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })}
            className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-3" />
        )}
        {form.provider === 'splunk' && (
          <>
            <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })}
              className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
            <input placeholder="Password" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
          </>
        )}
        {form.provider === 'crowdstrike' && (
          <>
            <input placeholder="Client ID" value={form.client_id_cred} onChange={(e) => setForm({ ...form, client_id_cred: e.target.value })}
              className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
            <input placeholder="Client secret" type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
              className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
          </>
        )}
        <button type="submit" disabled={register.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs col-span-3">
          Register connection
        </button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {connections?.map((c) => (
            <div key={c.id} className="bg-panel2 rounded-md p-3 text-xs">
              <span className="uppercase text-[10px] px-1.5 py-0.5 bg-panel rounded mr-2">{c.provider}</span>
              <span className="font-mono">{c.base_url}</span>
            </div>
          ))}
          {connections?.length === 0 && <p className="text-muted text-sm">No SIEM/EDR connections registered yet.</p>}
        </div>
      )}
    </div>
  )
}

function IocEnrichmentPanel({ clientId }) {
  const [ioc, setIoc] = useState({ ioc_value: '', ioc_type: 'ip' })
  const enrich = useMutation({ mutationFn: () => enrichIoc(clientId, ioc) })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); enrich.mutate() }} className="flex gap-2 mb-4">
        <select value={ioc.ioc_type} onChange={(e) => setIoc({ ...ioc, ioc_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {['ip', 'domain', 'hash', 'email', 'url'].map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input required placeholder="IoC value" value={ioc.ioc_value} onChange={(e) => setIoc({ ...ioc, ioc_value: e.target.value })}
          className="flex-1 bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={enrich.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">
          {enrich.isPending ? 'Enriching…' : 'Enrich'}
        </button>
      </form>

      {enrich.data && (
        <div className="bg-panel2 rounded-md p-4 text-xs">
          {enrich.data.enriched ? (
            <>
              <p className={enrich.data.flagged ? 'text-critical' : 'text-good'}>
                {enrich.data.flagged ? 'Flagged by threat intel sources' : 'No hits from Shodan/Censys/blocklists'}
              </p>
              <pre className="mt-2 whitespace-pre-wrap">{JSON.stringify(enrich.data, null, 2)}</pre>
            </>
          ) : <p className="text-muted">{enrich.data.note}</p>}
        </div>
      )}
    </div>
  )
}

function CoveragePanel({ clientId }) {
  const { data: coverage, isLoading } = useQuery({ queryKey: ['th-coverage', clientId], queryFn: () => getThreatHuntingCoverage(clientId) })

  if (isLoading) return <p className="text-muted text-sm">Loading…</p>
  return (
    <div>
      {coverage?.techniques.length === 0 ? (
        <p className="text-muted text-sm">No completed hunts yet — coverage will appear here once hunts finish.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {coverage?.techniques.map((t) => (
            <span key={t.techniqueID} className="px-2 py-1 bg-panel2 rounded text-xs font-mono" title={t.comment}>
              {t.techniqueID} <span className="text-signal">×{t.score}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
