import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listRedTeamOps, createRedTeamOp, updateRedTeamOp,
  listRedTeamTimeline, addRedTeamTimelineEntry,
  listRedTeamImplants, addRedTeamImplant, updateRedTeamImplant,
  listRedTeamInfra, addRedTeamInfra, checkRedTeamInfraExposure,
  getRedTeamHeatmap, getRedTeamNarrative, downloadAuthenticatedFile,
} from '../api/client.js'

const STATUSES = ['planning', 'active', 'complete']
const PHASES = ['recon', 'initial_access', 'lateral_movement', 'persistence', 'exfiltration', 'objective']
const DETECTION_STATES = ['not_detected', 'detected', 'partial']
const INFRA_TYPES = ['c2_server', 'phishing_domain', 'payload_host', 'redirector']
const TABS = ['Timeline', 'Implants', 'Infrastructure', 'Heatmap & Narrative']

export default function RedTeam() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [selectedOpId, setSelectedOpId] = useState(null)
  const [name, setName] = useState('')
  const [objective, setObjective] = useState('')
  const [threatActor, setThreatActor] = useState('')

  const { data: operations, isLoading } = useQuery({ queryKey: ['red-team-ops', clientId], queryFn: () => listRedTeamOps(clientId) })
  const create = useMutation({
    mutationFn: () => createRedTeamOp(clientId, { name, objective, threat_actor: threatActor }),
    onSuccess: (op) => { qc.invalidateQueries({ queryKey: ['red-team-ops', clientId] }); setName(''); setObjective(''); setThreatActor(''); setSelectedOpId(op.id) },
  })

  const selectedOp = operations?.find((o) => o.id === selectedOpId)

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Red Team Operations</h2>
        <p className="text-muted text-sm">
          Tracking &amp; logging workspace only — this platform does not run a C2 server or execute attacks.
          Log what your operator did in real tooling (Cobalt Strike, Havoc, etc.) here for reporting and ATT&amp;CK coverage.
        </p>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-4 gap-3 mb-6">
        <input required placeholder="Operation name" value={name} onChange={(e) => setName(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Objective" value={objective} onChange={(e) => setObjective(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Emulated threat actor (e.g. FIN7)" value={threatActor} onChange={(e) => setThreatActor(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">
          New Operation
        </button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : operations?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No operations yet.</div>
      ) : (
        <div className="flex gap-2 mb-6 flex-wrap">
          {operations?.map((op) => (
            <button key={op.id} onClick={() => setSelectedOpId(op.id)}
              className={`px-3 py-2 rounded-md text-sm font-mono border ${selectedOpId === op.id ? 'border-signal text-signal' : 'border-border text-muted hover:text-ink'}`}>
              {op.name} <span className="text-[10px] uppercase ml-1">({op.status})</span>
            </button>
          ))}
        </div>
      )}

      {selectedOp && <OperationWorkspace clientId={clientId} operation={selectedOp} />}
    </div>
  )
}

function OperationWorkspace({ clientId, operation }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState(TABS[0])
  const updateStatus = useMutation({
    mutationFn: (status) => updateRedTeamOp(clientId, operation.id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['red-team-ops', clientId] }),
  })
  const toggleRoe = useMutation({
    mutationFn: () => updateRedTeamOp(clientId, operation.id, { roe_signed: !operation.roe_signed }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['red-team-ops', clientId] }),
  })

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-semibold">{operation.name}</h3>
          <p className="text-xs text-muted mt-0.5">{operation.objective || 'No objective set'} · Actor: {operation.threat_actor || 'n/a'}</p>
        </div>
        <div className="flex items-center gap-2">
          <select value={operation.status} onChange={(e) => updateStatus.mutate(e.target.value)}
            className="bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal">
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button onClick={() => toggleRoe.mutate()}
            className={`text-xs px-3 py-1.5 rounded border font-mono ${operation.roe_signed ? 'border-good text-good' : 'border-border text-muted'}`}>
            RoE {operation.roe_signed ? 'signed' : 'unsigned'}
          </button>
        </div>
      </div>

      <div className="flex gap-2 mb-4 border-b border-border flex-wrap">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'Timeline' && <TimelinePanel clientId={clientId} opId={operation.id} />}
      {tab === 'Implants' && <ImplantsPanel clientId={clientId} opId={operation.id} />}
      {tab === 'Infrastructure' && <InfrastructurePanel clientId={clientId} opId={operation.id} />}
      {tab === 'Heatmap & Narrative' && <HeatmapNarrativePanel clientId={clientId} opId={operation.id} />}
    </div>
  )
}

function TimelinePanel({ clientId, opId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ timestamp: '', phase: PHASES[0], action: '', host: '', tool_used: '', outcome: '', detected: 'not_detected', attack_technique_id: '' })
  const { data: entries, isLoading } = useQuery({ queryKey: ['red-team-timeline', opId], queryFn: () => listRedTeamTimeline(clientId, opId) })
  const add = useMutation({
    mutationFn: () => addRedTeamTimelineEntry(clientId, opId, { ...form, timestamp: new Date(form.timestamp).toISOString() }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-timeline', opId] }); setForm({ ...form, action: '', host: '', tool_used: '', outcome: '', attack_technique_id: '' }) },
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-4 gap-2 mb-4">
        <input required type="datetime-local" value={form.timestamp} onChange={(e) => setForm({ ...form, timestamp: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <select value={form.phase} onChange={(e) => setForm({ ...form, phase: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {PHASES.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input required placeholder="Action" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <input placeholder="Host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Tool used" value={form.tool_used} onChange={(e) => setForm({ ...form, tool_used: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Outcome" value={form.outcome} onChange={(e) => setForm({ ...form, outcome: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <select value={form.detected} onChange={(e) => setForm({ ...form, detected: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {DETECTION_STATES.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        <input placeholder="ATT&CK ID (e.g. T1566.001)" value={form.attack_technique_id} onChange={(e) => setForm({ ...form, attack_technique_id: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Log entry</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {entries?.map((e) => (
            <div key={e.id} className="bg-panel2 rounded-md p-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-muted">{new Date(e.timestamp).toLocaleString()} · {e.phase}</span>
                <span className={`font-mono uppercase ${e.detected === 'detected' ? 'text-critical' : e.detected === 'partial' ? 'text-medium' : 'text-good'}`}>{e.detected}</span>
              </div>
              <p className="mt-1">{e.action}{e.host && ` — ${e.host}`}{e.tool_used && ` (${e.tool_used})`}</p>
              {e.outcome && <p className="text-muted mt-0.5">Outcome: {e.outcome}</p>}
              {e.attack_technique_id && <span className="inline-block mt-1 px-1.5 py-0.5 bg-panel rounded text-[10px] font-mono">{e.attack_technique_id}</span>}
            </div>
          ))}
          {entries?.length === 0 && <p className="text-muted text-sm">No timeline entries logged yet.</p>}
        </div>
      )}
    </div>
  )
}

function ImplantsPanel({ clientId, opId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ host: '', ip_address: '', username: '', implant_type: '', persistence: '' })
  const { data: implants, isLoading } = useQuery({ queryKey: ['red-team-implants', opId], queryFn: () => listRedTeamImplants(clientId, opId) })
  const add = useMutation({
    mutationFn: () => addRedTeamImplant(clientId, opId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-implants', opId] }); setForm({ host: '', ip_address: '', username: '', implant_type: '', persistence: '' }) },
  })
  const toggle = useMutation({
    mutationFn: ({ id, is_active }) => updateRedTeamImplant(clientId, opId, id, { is_active: !is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['red-team-implants', opId] }),
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-5 gap-2 mb-4">
        <input required placeholder="Host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="IP address" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Implant type" value={form.implant_type} onChange={(e) => setForm({ ...form, implant_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Add implant</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {implants?.map((i) => (
            <div key={i.id} className="bg-panel2 rounded-md p-3 flex items-center justify-between text-xs">
              <div>
                <span className="font-mono">{i.host}</span> {i.ip_address && <span className="text-muted">({i.ip_address})</span>}
                {i.username && <span className="text-muted"> · {i.username}</span>} {i.implant_type && <span className="text-muted"> · {i.implant_type}</span>}
              </div>
              <button onClick={() => toggle.mutate(i)} className={`px-2 py-1 rounded border font-mono text-[10px] uppercase ${i.is_active ? 'border-good text-good' : 'border-muted text-muted'}`}>
                {i.is_active ? 'active' : 'inactive'}
              </button>
            </div>
          ))}
          {implants?.length === 0 && <p className="text-muted text-sm">No implants tracked yet.</p>}
        </div>
      )}
    </div>
  )
}

function InfrastructurePanel({ clientId, opId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ infra_type: INFRA_TYPES[0], identifier: '', provider: '' })
  const { data: infra, isLoading } = useQuery({ queryKey: ['red-team-infra', opId], queryFn: () => listRedTeamInfra(clientId, opId) })
  const add = useMutation({
    mutationFn: () => addRedTeamInfra(clientId, opId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['red-team-infra', opId] }); setForm({ infra_type: INFRA_TYPES[0], identifier: '', provider: '' }) },
  })
  const exposureCheck = useMutation({ mutationFn: () => checkRedTeamInfraExposure(clientId, opId) })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-4 gap-2 mb-4">
        <select value={form.infra_type} onChange={(e) => setForm({ ...form, infra_type: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {INFRA_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input required placeholder="IP / domain / hostname" value={form.identifier} onChange={(e) => setForm({ ...form, identifier: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <input placeholder="Provider (e.g. DigitalOcean)" value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Track infra</button>
      </form>

      <button onClick={() => exposureCheck.mutate()} disabled={exposureCheck.isPending}
        className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono mb-4">
        {exposureCheck.isPending ? 'Checking Shodan…' : 'Check exposure (Shodan)'}
      </button>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2 mb-4">
          {infra?.map((i) => (
            <div key={i.id} className="bg-panel2 rounded-md p-3 text-xs">
              <span className="font-mono uppercase text-[10px] px-1.5 py-0.5 bg-panel rounded mr-2">{i.infra_type}</span>
              <span className="font-mono">{i.identifier}</span> {i.provider && <span className="text-muted">· {i.provider}</span>}
            </div>
          ))}
          {infra?.length === 0 && <p className="text-muted text-sm">No infrastructure tracked yet.</p>}
        </div>
      )}

      {exposureCheck.data && (
        <div className="bg-panel2 rounded-md p-3 text-xs">
          {exposureCheck.data.exposure.length === 0 ? (
            <p className="text-good">No tracked infra IPs were found on Shodan.</p>
          ) : (
            exposureCheck.data.exposure.map((hit, i) => <p key={i} className="text-medium">⚠ {hit.ip || hit.ip_str}: {hit.org || 'fingerprinted'}</p>)
          )}
        </div>
      )}
    </div>
  )
}

function HeatmapNarrativePanel({ clientId, opId }) {
  const { data: heatmap, isLoading } = useQuery({ queryKey: ['red-team-heatmap', opId], queryFn: () => getRedTeamHeatmap(clientId, opId) })
  const narrative = useMutation({ mutationFn: () => getRedTeamNarrative(clientId, opId) })

  return (
    <div>
      <div className="mb-6">
        <h4 className="text-sm font-semibold mb-2">ATT&amp;CK Technique Coverage</h4>
        {isLoading ? <p className="text-muted text-sm">Loading…</p> : heatmap?.techniques.length === 0 ? (
          <p className="text-muted text-sm">No ATT&amp;CK-tagged timeline entries yet.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {heatmap?.techniques.map((t) => (
              <span key={t.techniqueID} className="px-2 py-1 bg-panel2 rounded text-xs font-mono" title={t.comment}>
                {t.techniqueID} <span className="text-signal">×{t.score}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="flex gap-2 mb-3">
        <button onClick={() => narrative.mutate()} disabled={narrative.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          {narrative.isPending ? 'Generating…' : 'Generate AI narrative'}
        </button>
        <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/red-team/operations/${opId}/purple-team-export`, 'purple-team-debrief.md')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
          Download purple team export
        </button>
      </div>

      {narrative.data && <div className="bg-panel2 rounded-md p-4 text-sm whitespace-pre-wrap">{narrative.data}</div>}
    </div>
  )
}
