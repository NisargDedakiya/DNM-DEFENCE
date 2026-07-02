import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listComplianceControls, getComplianceSummary, updateComplianceControl,
  uploadComplianceEvidence, downloadAuthenticatedFile,
} from '../api/client.js'

const FRAMEWORKS = [
  { key: 'soc2', label: 'SOC 2' },
  { key: 'iso27001', label: 'ISO 27001' },
  { key: 'india_dpdp', label: 'India DPDP Act' },
]

const STATUS_STYLES = {
  implemented: 'text-good bg-good/10 border-good/40',
  in_progress: 'text-medium bg-medium/10 border-medium/40',
  missing: 'text-muted bg-panel2 border-border',
}

export default function Compliance() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [framework, setFramework] = useState('soc2')

  const { data: controls, isLoading } = useQuery({
    queryKey: ['compliance', clientId, framework],
    queryFn: () => listComplianceControls(clientId, framework),
  })
  const { data: summary } = useQuery({
    queryKey: ['compliance-summary', clientId],
    queryFn: () => getComplianceSummary(clientId),
  })

  const update = useMutation({
    mutationFn: ({ controlId, status }) => updateComplianceControl(clientId, controlId, { status }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['compliance', clientId] })
      qc.invalidateQueries({ queryKey: ['compliance-summary', clientId] })
    },
  })
  const uploadEvidence = useMutation({
    mutationFn: ({ controlId, file }) => uploadComplianceEvidence(clientId, controlId, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance', clientId] }),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <h2 className="text-2xl font-semibold">Compliance Center</h2>
        <button
          onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/compliance/export/pdf`, 'compliance-report.pdf')}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono"
        >
          Export report for auditors
        </button>
      </div>
      <p className="text-muted text-sm mb-6">Track control implementation across frameworks. Starter checklist — expand with your auditor.</p>

      <div className="grid grid-cols-3 gap-4 mb-6">
        {FRAMEWORKS.map((fw) => {
          const s = summary?.[fw.key]
          return (
            <button
              key={fw.key}
              onClick={() => setFramework(fw.key)}
              className={`text-left p-4 rounded-lg border transition ${
                framework === fw.key ? 'border-signal bg-panel2' : 'border-border bg-panel hover:border-signal/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium text-sm">{fw.label}</span>
                <span className="font-mono text-lg font-semibold">{s?.percent_implemented ?? 0}%</span>
              </div>
              <div className="w-full h-1.5 bg-panel2 rounded-full mt-2 overflow-hidden">
                <div className="h-full bg-good" style={{ width: `${s?.percent_implemented ?? 0}%` }} />
              </div>
              <p className="text-[11px] text-muted mt-2 font-mono">
                {s ? `${s.implemented}/${s.total} implemented` : '—'}
              </p>
            </button>
          )
        })}
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : (
        <div className="bg-panel border border-border rounded-lg divide-y divide-border/60">
          {controls?.map((c) => (
            <div key={c.id} className="flex items-center justify-between px-4 py-3">
              <div className="min-w-0 pr-4">
                <span className="font-mono text-xs text-muted mr-2">{c.control_id}</span>
                <span className="text-sm">{c.control_name}</span>
              </div>
              <div className="flex gap-1.5 shrink-0 items-center">
                {['missing', 'in_progress', 'implemented'].map((s) => (
                  <button
                    key={s}
                    onClick={() => update.mutate({ controlId: c.id, status: s })}
                    className={`text-[11px] px-2 py-1 rounded border font-mono ${
                      c.status === s ? STATUS_STYLES[s] : 'border-border text-muted hover:text-ink'
                    }`}
                  >
                    {s.replace('_', ' ')}
                  </button>
                ))}
                {c.has_evidence ? (
                  <button
                    onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/compliance/${c.id}/evidence`, `evidence-${c.control_id}`)}
                    className="text-[11px] px-2 py-1 rounded border border-signal/40 text-signal font-mono"
                  >
                    evidence ↓
                  </button>
                ) : (
                  <label className="text-[11px] px-2 py-1 rounded border border-border text-muted hover:text-ink font-mono cursor-pointer">
                    + evidence
                    <input
                      type="file" className="hidden"
                      onChange={(e) => e.target.files[0] && uploadEvidence.mutate({ controlId: c.id, file: e.target.files[0] })}
                    />
                  </label>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
