import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  uploadMobileApp, listMobileScans, analyzeMobileScan, importMobileTraffic, listMobileTrafficImports,
} from '../api/client.js'

const SEVERITY_TONE = { critical: 'text-critical', high: 'text-high', medium: 'text-signal', low: 'text-muted' }

export default function MobileSecurity() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(null)

  const { data: scans, isLoading } = useQuery({ queryKey: ['mobile-scans', clientId], queryFn: () => listMobileScans(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['mobile-scans', clientId] })
  const upload = useMutation({ mutationFn: (file) => uploadMobileApp(clientId, file), onSuccess: invalidate })
  const analyze = useMutation({ mutationFn: (id) => analyzeMobileScan(clientId, id), onSuccess: invalidate })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Mobile App Security</h2>
          <p className="text-muted text-sm">Static analysis (MASVS L1/L2), HAR traffic import, and compliance scoring for Android/iOS apps.</p>
        </div>
        <label className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm cursor-pointer hover:brightness-110">
          {upload.isPending ? 'Uploading…' : '+ Upload .apk/.ipa'}
          <input type="file" accept=".apk,.ipa" className="hidden"
            onChange={(e) => e.target.files[0] && upload.mutate(e.target.files[0])} />
        </label>
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : scans?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No mobile apps uploaded yet.</div>
      ) : (
        <div className="space-y-3">
          {scans?.map((s) => (
            <div key={s.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="font-medium">{s.app_label || s.original_filename}</h3>
                  <p className="text-xs text-muted mt-0.5">{s.platform.toUpperCase()} &middot; {s.original_filename}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {s.masvs_score != null && (
                    <span className="text-xs font-mono">MASVS <span className={s.masvs_score >= 80 ? 'text-good' : s.masvs_score >= 50 ? 'text-signal' : 'text-critical'}>{s.masvs_score}%</span></span>
                  )}
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${
                    s.status === 'completed' ? 'text-good bg-good/10' : s.status === 'failed' ? 'text-critical bg-critical/10' : 'text-muted bg-panel2'
                  }`}>{s.status}</span>
                  {s.status === 'queued' && (
                    <button onClick={() => analyze.mutate(s.id)} disabled={analyze.isPending}
                      className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                      Run analysis
                    </button>
                  )}
                </div>
              </div>

              {s.executive_summary && <p className="text-sm text-muted mb-2">{s.executive_summary}</p>}
              {s.error_message && <p className="text-xs text-critical mb-2">{s.error_message}</p>}

              {s.findings?.length > 0 && (
                <ul className="text-xs space-y-1 mb-2">
                  {s.findings.map((f, i) => (
                    <li key={i}>
                      <span className={`font-mono uppercase ${SEVERITY_TONE[f.severity] || 'text-ink'}`}>[{f.severity}]</span>{' '}
                      <span className="font-mono text-muted">{f.masvs_control}</span> — {f.description}
                    </li>
                  ))}
                </ul>
              )}

              <button onClick={() => setExpanded(expanded === s.id ? null : s.id)} className="text-xs text-signal hover:underline">
                {expanded === s.id ? 'Hide traffic import' : 'Import HAR traffic capture'}
              </button>
              {expanded === s.id && <TrafficImportPanel clientId={clientId} scanId={s.id} />}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function TrafficImportPanel({ clientId, scanId }) {
  const qc = useQueryClient()
  const { data: imports } = useQuery({
    queryKey: ['mobile-traffic', clientId, scanId],
    queryFn: () => listMobileTrafficImports(clientId, scanId),
  })
  const importHar = useMutation({
    mutationFn: (file) => importMobileTraffic(clientId, scanId, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mobile-traffic', clientId, scanId] }),
  })

  return (
    <div className="mt-3 pt-3 border-t border-border/60">
      <label className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono cursor-pointer">
        {importHar.isPending ? 'Importing…' : 'Upload HAR file'}
        <input type="file" accept=".har,application/json" className="hidden"
          onChange={(e) => e.target.files[0] && importHar.mutate(e.target.files[0])} />
      </label>
      <p className="text-[10px] text-muted mt-1 italic">Export a HAR from Burp Suite, Chrome DevTools, mitmproxy, or Charles while the app is running.</p>

      {imports?.map((imp) => (
        <div key={imp.id} className="mt-3 text-xs">
          <p className="text-muted mb-1">{imp.discovered_endpoints.length} endpoint(s) discovered &middot; {imp.sensitive_data_hits.length} sensitive-data hit(s)</p>
          {imp.sensitive_data_hits.length > 0 && (
            <ul className="space-y-0.5">
              {imp.sensitive_data_hits.slice(0, 10).map((h, i) => (
                <li key={i} className="text-critical font-mono">{h.type} in {h.location} — {h.url}</li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  )
}
