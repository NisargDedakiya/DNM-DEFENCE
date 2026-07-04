import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listFirmwareScans, uploadFirmware, analyzeFirmwareScan } from '../api/client.js'

export default function HardwareIoT() {
  const { clientId } = useParams()
  const qc = useQueryClient()

  const { data: scans, isLoading } = useQuery({ queryKey: ['firmware-scans', clientId], queryFn: () => listFirmwareScans(clientId) })
  const upload = useMutation({
    mutationFn: (file) => uploadFirmware(clientId, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firmware-scans', clientId] }),
  })
  const analyze = useMutation({
    mutationFn: (scanId) => analyzeFirmwareScan(clientId, scanId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firmware-scans', clientId] }),
  })

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Hardware &amp; IoT Security Testing</h2>
        <p className="text-muted text-sm">
          Firmware extraction (binwalk), component identification, hardcoded-secret scanning, NVD CVE matching,
          and optional binary hardening (checksec) enrichment.
        </p>
      </div>

      <label className="inline-block bg-panel border border-dashed border-border rounded-lg p-6 text-center cursor-pointer hover:border-signal/50 mb-6">
        <p className="text-sm mb-2">Upload a firmware image</p>
        <span className="text-xs px-3 py-1.5 rounded border border-border font-mono inline-block">
          {upload.isPending ? 'Uploading…' : 'Upload firmware'}
        </span>
        <input type="file" className="hidden" onChange={(e) => e.target.files[0] && upload.mutate(e.target.files[0])} />
      </label>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : scans?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No firmware images uploaded yet.</div>
      ) : (
        <div className="space-y-3">
          {scans?.map((s) => (
            <ScanCard key={s.id} scan={s} onAnalyze={() => analyze.mutate(s.id)} analyzing={analyze.isPending} />
          ))}
        </div>
      )}
    </div>
  )
}

function ScanCard({ scan, onAnalyze, analyzing }) {
  const findings = scan.findings || {}
  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h3 className="font-mono text-sm">{scan.original_filename}</h3>
          <p className="text-xs text-muted mt-0.5 uppercase">{scan.status}</p>
        </div>
        {scan.status === 'queued' && (
          <button onClick={onAnalyze} disabled={analyzing}
            className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
            {analyzing ? 'Analyzing…' : 'Run analysis'}
          </button>
        )}
      </div>

      {scan.status === 'failed' && <p className="text-critical text-xs mt-2">{scan.error_message}</p>}

      {scan.status === 'completed' && (
        <div className="mt-3 space-y-3 text-xs">
          {!findings.extracted && (
            <p className="text-medium">binwalk extraction unavailable — analysis ran against raw firmware bytes.</p>
          )}

          {Object.keys(scan.component_summary || {}).length > 0 && (
            <div>
              <p className="text-muted uppercase text-[10px] mb-1">Identified components</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(scan.component_summary).map(([name, version]) => (
                  <span key={name} className="px-2 py-1 bg-panel2 rounded font-mono">{name} {version}</span>
                ))}
              </div>
            </div>
          )}

          {findings.secrets?.length > 0 && (
            <div>
              <p className="text-muted uppercase text-[10px] mb-1">Hardcoded secrets ({findings.secrets.length})</p>
              <ul className="space-y-1">
                {findings.secrets.map((s, i) => <li key={i} className="text-critical">{s.type} — {s.file}</li>)}
              </ul>
            </div>
          )}

          {findings.cves?.length > 0 && (
            <div>
              <p className="text-muted uppercase text-[10px] mb-1">Matched CVEs ({findings.cves.length})</p>
              <ul className="space-y-1">
                {findings.cves.map((c, i) => <li key={i}>{c.cve_id} — {c.component} {c.version}: {c.description?.slice(0, 100)}</li>)}
              </ul>
            </div>
          )}

          {findings.checksec?.length > 0 && (
            <div>
              <p className="text-muted uppercase text-[10px] mb-1">Binary hardening (checksec)</p>
              <ul className="space-y-1">
                {findings.checksec.map((c, i) => <li key={i} className="font-mono">{c.binary}: {JSON.stringify(c.result)}</li>)}
              </ul>
            </div>
          )}

          {scan.executive_summary && (
            <div className="bg-panel2 rounded-md p-3 whitespace-pre-wrap">{scan.executive_summary}</div>
          )}
        </div>
      )}
    </div>
  )
}
