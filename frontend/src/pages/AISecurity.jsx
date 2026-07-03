import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  createPromptInjectionTest, listPromptInjectionTests, createAiFeature, listAiFeatures, runAiCveCheck, getAiPostureBrief,
} from '../api/client.js'

const TABS = ['Prompt Injection Testing', 'AI Security Posture']

export default function AISecurity() {
  const [tab, setTab] = useState(TABS[0])
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">AI/ML Model Security</h2>
        <p className="text-muted text-sm">Prompt injection testing and AI feature inventory with CVE/OWASP LLM Top 10 tracking.</p>
      </div>
      <div className="flex gap-2 mb-6 border-b border-border">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === 'Prompt Injection Testing' && <PromptInjectionPanel />}
      {tab === 'AI Security Posture' && <PosturePanel />}
    </div>
  )
}

function PromptInjectionPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [targetUrl, setTargetUrl] = useState('')

  const { data: tests, isLoading } = useQuery({ queryKey: ['prompt-injection', clientId], queryFn: () => listPromptInjectionTests(clientId) })
  const run = useMutation({
    mutationFn: () => createPromptInjectionTest(clientId, { target_url: targetUrl }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['prompt-injection', clientId] }); setTargetUrl('') },
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); run.mutate() }} className="flex gap-3 mb-6">
        <input required placeholder='Target endpoint URL (accepts {"message": "..."})' value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="flex-1 bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button type="submit" disabled={run.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
          {run.isPending ? 'Running ~40 payloads…' : 'Run test suite'}
        </button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : tests?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No prompt injection tests run yet.</div>
      ) : (
        <div className="space-y-3">
          {tests?.map((t) => (
            <div key={t.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-mono text-sm">{t.target_url}</h3>
                <span className={`text-xs font-mono ${t.success_count > 0 ? 'text-critical' : 'text-good'}`}>
                  {t.success_count}/{t.results.length} succeeded
                </span>
              </div>
              {t.success_count > 0 && (
                <ul className="text-xs space-y-1">
                  {t.results.filter((r) => r.classification.success).slice(0, 10).map((r, i) => (
                    <li key={i} className="text-critical">[{r.payload.category}] {r.classification.reason}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PosturePanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [type, setType] = useState('')
  const [libStack, setLibStack] = useState('langchain=0.1.0, openai=1.40.0')
  const [cveHits, setCveHits] = useState(null)
  const [brief, setBrief] = useState('')

  const { data: features, isLoading } = useQuery({ queryKey: ['ai-features', clientId], queryFn: () => listAiFeatures(clientId) })
  const create = useMutation({
    mutationFn: () => {
      const library_stack = Object.fromEntries(
        libStack.split(',').map((s) => s.trim()).filter(Boolean).map((s) => s.split('=').map((x) => x.trim()))
      )
      return createAiFeature(clientId, { feature_name: name, feature_type: type || null, library_stack })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ai-features', clientId] }); setName(''); setType('') },
  })
  const cveCheck = useMutation({ mutationFn: () => runAiCveCheck(clientId), onSuccess: (d) => setCveHits(d.hits) })
  const postureBrief = useMutation({ mutationFn: () => getAiPostureBrief(clientId), onSuccess: (d) => setBrief(d.brief) })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="bg-panel border border-border rounded-lg p-5 mb-6 grid grid-cols-3 gap-3">
        <input required placeholder="Feature name (e.g. Support chatbot)" value={name} onChange={(e) => setName(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Feature type (e.g. chatbot, rag_pipeline)" value={type} onChange={(e) => setType(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="lib=version, lib2=version2" value={libStack} onChange={(e) => setLibStack(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending} className="col-span-3 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
          Add AI feature
        </button>
      </form>

      <div className="flex gap-2 mb-4">
        <button onClick={() => cveCheck.mutate()} disabled={cveCheck.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Run CVE check</button>
        <button onClick={() => postureBrief.mutate()} disabled={postureBrief.isPending}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">Generate posture brief (AI)</button>
      </div>

      {cveHits && (
        <div className="mb-4 text-xs">
          {cveHits.length === 0 ? <p className="text-good">No CVE matches found.</p> : (
            <ul className="space-y-1">
              {cveHits.map((h, i) => <li key={i} className="text-critical">{h.cve_id}: {h.library} {h.version}</li>)}
            </ul>
          )}
        </div>
      )}
      {brief && <p className="text-sm bg-panel2 rounded-md p-3 mb-4 whitespace-pre-wrap">{brief}</p>}

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : features?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No AI features in inventory yet.</div>
      ) : (
        <div className="space-y-2">
          {features?.map((f) => (
            <div key={f.id} className="bg-panel border border-border rounded-lg p-4">
              <h3 className="font-medium text-sm">{f.feature_name} {f.feature_type && <span className="text-muted text-xs">({f.feature_type})</span>}</h3>
              <p className="text-xs text-muted font-mono mt-1">{Object.entries(f.library_stack).map(([k, v]) => `${k}@${v}`).join(', ')}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
