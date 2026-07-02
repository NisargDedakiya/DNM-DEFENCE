import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listFindings, updateFindingStatus } from '../api/client.js'
import SeverityBadge from '../components/SeverityBadge.jsx'

// Mirrors backend ALLOWED_TRANSITIONS in app/api/findings.py -- keep in sync.
const ALLOWED_TRANSITIONS = {
  new: ['acknowledged', 'disputed'],
  acknowledged: ['in_remediation', 'disputed'],
  in_remediation: ['resolved', 'disputed'],
  resolved: ['verified', 'disputed'],
  verified: ['disputed'],
  disputed: ['acknowledged', 'new'],
}

// Cloud findings are titled "[AWS] ...", "[GCP] ...", "[AZURE] ..." by cspm.py's
// sync_cloud_findings_to_db -- client-side grouping on that prefix gives a
// unified multi-cloud view without a separate backend endpoint.
const CLOUD_PROVIDER_PREFIX = /^\[(AWS|GCP|AZURE)\]/

export default function Findings() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [severityFilter, setSeverityFilter] = useState('')
  const [providerFilter, setProviderFilter] = useState('')
  const [expanded, setExpanded] = useState(null)

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', clientId, severityFilter],
    queryFn: () => listFindings(clientId, severityFilter ? { severity: severityFilter } : {}),
  })

  const updateStatus = useMutation({
    mutationFn: ({ findingId, status }) => updateFindingStatus(clientId, findingId, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', clientId] }),
  })

  const visibleFindings = (findings || []).filter((f) => {
    if (!providerFilter) return true
    const match = f.title.match(CLOUD_PROVIDER_PREFIX)
    return providerFilter === 'other' ? !match : match?.[1] === providerFilter
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Vulnerability Tracker</h2>
          <p className="text-muted text-sm">All open and resolved findings across every scan type.</p>
        </div>
        <div className="flex gap-2">
          <select
            value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal"
          >
            <option value="">All sources</option>
            <option value="AWS">AWS (CSPM)</option>
            <option value="GCP">GCP (CSPM)</option>
            <option value="AZURE">Azure (CSPM)</option>
            <option value="other">Non-cloud</option>
          </select>
          <select
            value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : visibleFindings.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">
          No findings match this filter. Run a vulnerability, dark web, or cloud scan from the Overview tab.
        </div>
      ) : (
        <div className="space-y-2">
          {visibleFindings.map((f) => (
            <div key={f.id} className="bg-panel border border-border rounded-lg overflow-hidden">
              <button
                onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                className="w-full flex items-center justify-between px-4 py-3 text-left"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <SeverityBadge severity={f.severity} />
                  <span className="truncate text-sm">{f.title}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 pl-3">
                  <span className="text-xs text-muted font-mono">CVSS {f.cvss_score ?? '—'}</span>
                  <span className="text-xs text-muted font-mono uppercase">{f.status.replace('_', ' ')}</span>
                </div>
              </button>

              {expanded === f.id && (
                <div className="px-4 pb-4 border-t border-border/60 pt-3">
                  {f.description && <p className="text-sm text-muted mb-3">{f.description}</p>}
                  {f.remediation_steps && (
                    <div className="mb-3">
                      <h4 className="text-[10px] text-muted uppercase font-mono mb-1">Remediation</h4>
                      <p className="text-sm">{f.remediation_steps}</p>
                    </div>
                  )}
                  <div className="flex items-center gap-2 mt-3">
                    <span className="text-[10px] text-muted uppercase font-mono">Set status:</span>
                    <span className={`text-xs px-2 py-1 rounded border font-mono border-signal text-signal bg-signal/10`}>
                      {f.status.replace('_', ' ')}
                    </span>
                    {(ALLOWED_TRANSITIONS[f.status] || []).map((s) => (
                      <button
                        key={s}
                        onClick={() => updateStatus.mutate({ findingId: f.id, status: s })}
                        className="text-xs px-2 py-1 rounded border font-mono border-border text-muted hover:border-signal/50 hover:text-ink"
                      >
                        &rarr; {s.replace('_', ' ')}
                      </button>
                    ))}
                    {updateStatus.isError && (
                      <span className="text-xs text-red-400 font-mono">
                        {updateStatus.error?.response?.data?.detail || 'Update failed'}
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
