import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listResearchTargets, createResearchTarget, updateResearchTarget,
  listResearchFindings, createResearchFinding, updateResearchFinding,
  lookupFindingCve, getFindingAdvisory,
  listFuzzingJobs, createFuzzingJob, updateFuzzingJob,
} from '../api/client.js'

const STATUSES = ['identified', 'active', 'paused', 'complete']
const FINDING_STATUSES = ['researching', 'confirmed', 'disclosed', 'published']
const SEVERITIES = ['low', 'medium', 'high', 'critical']
const TABS = ['Findings', 'Fuzzing Jobs']

export default function ZeroDayResearch() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState(null)
  const [form, setForm] = useState({ name: '', vendor: '', version: '', bug_bounty_url: '', max_bounty: '' })

  const { data: targets, isLoading } = useQuery({ queryKey: ['research-targets'], queryFn: listResearchTargets })
  const create = useMutation({
    mutationFn: () => createResearchTarget({ ...form, max_bounty: form.max_bounty ? Number(form.max_bounty) : null }),
    onSuccess: (t) => { qc.invalidateQueries({ queryKey: ['research-targets'] }); setForm({ name: '', vendor: '', version: '', bug_bounty_url: '', max_bounty: '' }); setSelectedId(t.id) },
  })

  const selected = targets?.find((t) => t.id === selectedId)

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Zero Day Research &amp; Responsible Disclosure</h2>
        <p className="text-muted text-sm">
          Research target board, disclosure tracker with a 90-day countdown, real CVE/NVD lookups, and bounty submission tracking.
          Fuzzing jobs are analyst-updated records of campaigns run outside this platform — not live orchestration.
        </p>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-5 gap-3 mb-6">
        <input required placeholder="Target name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Vendor" value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Version" value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Max bounty (USD)" type="number" value={form.max_bounty} onChange={(e) => setForm({ ...form, max_bounty: e.target.value })}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">
          New Target
        </button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : targets?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No research targets yet.</div>
      ) : (
        <div className="flex gap-2 mb-6 flex-wrap">
          {targets?.map((t) => (
            <button key={t.id} onClick={() => setSelectedId(t.id)}
              className={`px-3 py-2 rounded-md text-sm font-mono border ${selectedId === t.id ? 'border-signal text-signal' : 'border-border text-muted hover:text-ink'}`}>
              {t.name} <span className="text-[10px] uppercase ml-1">({t.status})</span>
              {!t.client_id && <span className="text-[10px] ml-1 text-muted">· independent</span>}
            </button>
          ))}
        </div>
      )}

      {selected && <TargetWorkspace target={selected} />}
    </div>
  )
}

function TargetWorkspace({ target }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState(TABS[0])
  const updateStatus = useMutation({
    mutationFn: (status) => updateResearchTarget(target.id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['research-targets'] }),
  })

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-semibold">{target.name}</h3>
          <p className="text-xs text-muted mt-0.5">
            {target.vendor} {target.version} · Max bounty: {target.max_bounty ? `$${target.max_bounty}` : 'n/a'} ·
            Earned so far: ${target.total_earned} · {target.total_hours}h logged
          </p>
        </div>
        <select value={target.status} onChange={(e) => updateStatus.mutate(e.target.value)}
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

      {tab === 'Findings' && <FindingsPanel targetId={target.id} />}
      {tab === 'Fuzzing Jobs' && <FuzzingJobsPanel targetId={target.id} />}
    </div>
  )
}

function FindingsPanel({ targetId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ title: '', cve_id: '', vuln_class: '', severity: 'medium', description: '' })
  const [expanded, setExpanded] = useState(null)
  const { data: findings, isLoading } = useQuery({ queryKey: ['research-findings', targetId], queryFn: () => listResearchFindings(targetId) })
  const add = useMutation({
    mutationFn: () => createResearchFinding(targetId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['research-findings', targetId] }); setForm({ title: '', cve_id: '', vuln_class: '', severity: 'medium', description: '' }) },
  })
  const update = useMutation({
    mutationFn: ({ id, payload }) => updateResearchFinding(targetId, id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['research-findings', targetId] }),
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-5 gap-2 mb-4">
        <input required placeholder="Title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <input placeholder="CVE ID (if assigned)" value={form.cve_id} onChange={(e) => setForm({ ...form, cve_id: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal" />
        <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Log finding</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {findings?.map((f) => (
            <FindingRow key={f.id} finding={f} targetId={targetId}
              expanded={expanded === f.id} onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
              onUpdateStatus={(status) => update.mutate({ id: f.id, payload: { status } })} />
          ))}
          {findings?.length === 0 && <p className="text-muted text-sm">No findings logged yet.</p>}
        </div>
      )}
    </div>
  )
}

function FindingRow({ finding, targetId, expanded, onToggle, onUpdateStatus }) {
  const cveLookup = useMutation({ mutationFn: () => lookupFindingCve(finding.id) })
  const advisory = useMutation({ mutationFn: () => getFindingAdvisory(finding.id) })

  return (
    <div className="bg-panel2 rounded-md p-3 text-xs">
      <div className="flex items-center justify-between cursor-pointer" onClick={onToggle}>
        <div>
          <span className="font-mono">{finding.title}</span>
          {finding.cve_id && <span className="ml-2 px-1.5 py-0.5 bg-panel rounded text-[10px] font-mono">{finding.cve_id}</span>}
          {finding.severity && <span className="ml-2 uppercase text-[10px] text-muted">{finding.severity}</span>}
        </div>
        <div className="flex items-center gap-2">
          {finding.days_until_deadline !== null && finding.days_until_deadline !== undefined && (
            <span className={`font-mono ${finding.days_until_deadline < 14 ? 'text-critical' : 'text-muted'}`}>
              {finding.days_until_deadline}d to disclosure
            </span>
          )}
          <select value={finding.status} onClick={(e) => e.stopPropagation()} onChange={(e) => onUpdateStatus(e.target.value)}
            className="bg-panel border border-border rounded px-2 py-1 text-[10px] outline-none focus:border-signal">
            {FINDING_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {expanded && (
        <div className="mt-3 pt-3 border-t border-border">
          <p className="text-muted mb-2">{finding.description || 'No description recorded.'}</p>
          <div className="flex gap-2">
            {finding.cve_id && (
              <button onClick={() => cveLookup.mutate()} disabled={cveLookup.isPending}
                className="px-2 py-1 rounded border border-border hover:border-signal/50 font-mono text-[10px]">
                {cveLookup.isPending ? 'Looking up…' : 'Lookup CVE (NVD)'}
              </button>
            )}
            <button onClick={() => advisory.mutate()} disabled={advisory.isPending}
              className="px-2 py-1 rounded border border-border hover:border-signal/50 font-mono text-[10px]">
              {advisory.isPending ? 'Generating…' : 'Generate disclosure advisory'}
            </button>
          </div>
          {cveLookup.data && (
            <div className="mt-2 text-[11px]">
              {cveLookup.data.exists ? (
                <p>CVSS {cveLookup.data.detail?.cvss_score ?? '—'} · {cveLookup.data.detail?.description}</p>
              ) : <p className="text-medium">CVE not found in NVD.</p>}
            </div>
          )}
          {advisory.data && <div className="mt-2 bg-panel rounded p-3 whitespace-pre-wrap">{advisory.data}</div>}
        </div>
      )}
    </div>
  )
}

function FuzzingJobsPanel({ targetId }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ fuzzer: 'afl++', target_binary_path: '', corpus_path: '' })
  const { data: jobs, isLoading } = useQuery({ queryKey: ['fuzzing-jobs', targetId], queryFn: () => listFuzzingJobs(targetId) })
  const add = useMutation({
    mutationFn: () => createFuzzingJob(targetId, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['fuzzing-jobs', targetId] }); setForm({ fuzzer: 'afl++', target_binary_path: '', corpus_path: '' }) },
  })
  const update = useMutation({
    mutationFn: ({ id, payload }) => updateFuzzingJob(targetId, id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fuzzing-jobs', targetId] }),
  })

  return (
    <div>
      <p className="text-xs text-muted mb-3">Tracked campaigns run outside this platform — update status/crashes here as the analyst monitors AFL++/LibFuzzer/Boofuzz directly.</p>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid grid-cols-4 gap-2 mb-4">
        <select value={form.fuzzer} onChange={(e) => setForm({ ...form, fuzzer: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal">
          <option value="afl++">AFL++</option>
          <option value="libfuzzer">LibFuzzer</option>
          <option value="boofuzz">Boofuzz</option>
        </select>
        <input placeholder="Target binary path" value={form.target_binary_path} onChange={(e) => setForm({ ...form, target_binary_path: e.target.value })}
          className="bg-panel2 border border-border rounded px-2 py-1.5 text-xs outline-none focus:border-signal col-span-2" />
        <button type="submit" disabled={add.isPending} className="px-3 py-1.5 bg-signal text-base font-medium rounded-md text-xs">Track job</button>
      </form>

      {isLoading ? <p className="text-muted text-sm">Loading…</p> : (
        <div className="space-y-2">
          {jobs?.map((j) => (
            <div key={j.id} className="bg-panel2 rounded-md p-3 flex items-center justify-between text-xs">
              <div>
                <span className="font-mono">{j.fuzzer}</span> {j.target_binary_path && <span className="text-muted">· {j.target_binary_path}</span>}
                <span className="ml-2 text-muted">{j.crashes_found} crash(es)</span>
              </div>
              <select value={j.status} onChange={(e) => update.mutate({ id: j.id, payload: { status: e.target.value } })}
                className="bg-panel border border-border rounded px-2 py-1 text-[10px] outline-none focus:border-signal">
                <option value="queued">queued</option>
                <option value="running">running</option>
                <option value="stopped">stopped</option>
                <option value="completed">completed</option>
              </select>
            </div>
          ))}
          {jobs?.length === 0 && <p className="text-muted text-sm">No fuzzing jobs tracked yet.</p>}
        </div>
      )}
    </div>
  )
}
