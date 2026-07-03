import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  registerPipeline, listPipelines, deployGate, pollPipeline,
  triageSarif, triageTrivy, triageOwaspDc,
  getScorecard, snapshotScorecard, downloadAuthenticatedFile,
  runIacScan,
} from '../api/client.js'

const TABS = ['Pipeline Gates', 'Finding Triage', 'Developer Scorecard', 'IaC Scanner']
const TEMPLATES = ['python_fastapi', 'node_express', 'react', 'go', 'java_spring']

export default function DevSecOps() {
  const [tab, setTab] = useState(TABS[0])
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">DevSecOps Pipeline &amp; CI/CD Security</h2>
        <p className="text-muted text-sm">Pipeline security gates, scanner-output triage, developer scorecard, and IaC scanning.</p>
      </div>
      <div className="flex gap-2 mb-6 border-b border-border flex-wrap">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === 'Pipeline Gates' && <PipelinesPanel />}
      {tab === 'Finding Triage' && <TriagePanel />}
      {tab === 'Developer Scorecard' && <ScorecardPanel />}
      {tab === 'IaC Scanner' && <IacScanPanel />}
    </div>
  )
}

function PipelinesPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [repo, setRepo] = useState('')
  const [template, setTemplate] = useState(TEMPLATES[0])

  const { data: pipelines, isLoading } = useQuery({ queryKey: ['pipelines', clientId], queryFn: () => listPipelines(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['pipelines', clientId] })
  const register = useMutation({
    mutationFn: () => registerPipeline(clientId, { repo_full_name: repo, template }),
    onSuccess: () => { invalidate(); setRepo('') },
  })
  const deploy = useMutation({ mutationFn: (id) => deployGate(clientId, id) })
  const poll = useMutation({ mutationFn: (id) => pollPipeline(clientId, id) })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); register.mutate() }} className="flex gap-3 mb-6">
        <input required placeholder="owner/repo" value={repo} onChange={(e) => setRepo(e.target.value)}
          className="flex-1 bg-panel2 border border-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-signal" />
        <select value={template} onChange={(e) => setTemplate(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal">
          {TEMPLATES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <button type="submit" disabled={register.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">Register</button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : pipelines?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No repos registered yet.</div>
      ) : (
        <div className="space-y-3">
          {pipelines?.map((p) => (
            <div key={p.id} className="bg-panel border border-border rounded-lg p-5 flex items-center justify-between">
              <div>
                <h3 className="font-mono text-sm">{p.repo_full_name}</h3>
                <p className="text-xs text-muted mt-0.5">{p.gate_config.template} · block on {p.gate_config.block_on_severity}</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => deploy.mutate(p.id)} disabled={deploy.isPending}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Deploy gate</button>
                <button onClick={() => poll.mutate(p.id)} disabled={poll.isPending}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Poll runs</button>
              </div>
            </div>
          ))}
        </div>
      )}
      {deploy.data && <p className="text-xs text-good mt-3 font-mono">Gate workflow {deploy.data.action} at {deploy.data.path}</p>}
      {poll.data && <p className="text-xs text-muted mt-3 font-mono">{poll.data.runs_seen} run(s) seen, {poll.data.new_findings} new finding(s)</p>}
    </div>
  )
}

function TriagePanel() {
  const { clientId } = useParams()
  const [result, setResult] = useState(null)

  const upload = useMutation({
    mutationFn: ({ kind, file }) => {
      if (kind === 'sarif') return triageSarif(clientId, file)
      if (kind === 'trivy') return triageTrivy(clientId, file)
      return triageOwaspDc(clientId, file)
    },
    onSuccess: setResult,
  })

  return (
    <div>
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[['sarif', 'SARIF (Semgrep/CodeQL/etc)'], ['trivy', 'Trivy JSON'], ['owasp-dc', 'OWASP Dependency-Check XML']].map(([kind, label]) => (
          <label key={kind} className="bg-panel border border-border rounded-lg p-4 text-center cursor-pointer hover:border-signal/50">
            <p className="text-sm mb-2">{label}</p>
            <span className="text-xs px-3 py-1.5 rounded border border-border font-mono inline-block">Upload</span>
            <input type="file" className="hidden" onChange={(e) => e.target.files[0] && upload.mutate({ kind, file: e.target.files[0] })} />
          </label>
        ))}
      </div>
      {upload.isPending && <p className="text-muted text-sm">Parsing + triaging…</p>}
      {result && (
        <div className="bg-panel border border-border rounded-lg p-5">
          <p className="text-sm mb-2">{result.parsed} finding(s) parsed, {result.new_findings} new</p>
          <ul className="text-xs space-y-1">
            {result.findings?.map((f, i) => (
              <li key={i}>[{f.recalibrated_severity || f.severity}] {f.tool}/{f.check_id}: {f.message}
                {f.ai_verdict === 'FALSE_POSITIVE' && <span className="text-muted italic"> (AI: false positive)</span>}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ScorecardPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const { data: metrics, isLoading } = useQuery({ queryKey: ['scorecard', clientId], queryFn: () => getScorecard(clientId) })
  const snapshot = useMutation({ mutationFn: () => snapshotScorecard(clientId), onSuccess: () => qc.invalidateQueries({ queryKey: ['scorecard', clientId] }) })

  return (
    <div>
      <div className="flex gap-2 mb-4">
        <button onClick={() => snapshot.mutate()} disabled={snapshot.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Snapshot now</button>
        <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/devsecops/scorecard/export/pdf`, 'scorecard.pdf')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Download PDF</button>
      </div>
      {isLoading ? <p className="text-muted text-sm">Loading…</p> : metrics && (
        <div className="grid grid-cols-5 gap-3">
          <Metric label="Pipeline Health" value={`${metrics.pipeline_health_score}/100`} />
          <Metric label="Vulns Blocked" value={metrics.vulnerabilities_blocked} />
          <Metric label="Secrets Blocked" value={metrics.secrets_blocked} />
          <Metric label="MTTR (hrs)" value={metrics.mttr_hours ?? '—'} />
          <Metric label="Open Findings" value={metrics.open_pipeline_findings} />
        </div>
      )}
    </div>
  )
}

function Metric({ label, value }) {
  return (
    <div className="text-center bg-panel2 rounded-md py-3">
      <div className="text-lg font-mono font-semibold">{value}</div>
      <div className="text-[10px] text-muted uppercase mt-1 font-mono">{label}</div>
    </div>
  )
}

function IacScanPanel() {
  const { clientId } = useParams()
  const [result, setResult] = useState(null)
  const scan = useMutation({ mutationFn: (file) => runIacScan(clientId, file), onSuccess: setResult })

  return (
    <div>
      <label className="inline-block bg-panel border border-dashed border-border rounded-lg p-6 text-center cursor-pointer hover:border-signal/50 mb-6">
        <p className="text-sm mb-2">Upload a Terraform/CloudFormation/Kubernetes/Dockerfile/Compose file</p>
        <span className="text-xs px-3 py-1.5 rounded border border-border font-mono inline-block">
          {scan.isPending ? 'Scanning…' : 'Upload & scan'}
        </span>
        <input type="file" className="hidden" onChange={(e) => e.target.files[0] && scan.mutate(e.target.files[0])} />
      </label>

      {result && (
        <div className="bg-panel border border-border rounded-lg p-5">
          <p className="text-sm mb-2">{result.parsed} finding(s), {result.new_findings} new</p>
          <ul className="text-xs space-y-1">
            {result.findings?.map((f, i) => (
              <li key={i}>[{f.severity}] {f.check_id} — {f.resource}: {f.description}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
