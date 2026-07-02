import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listReports, triggerReportGeneration, downloadAuthenticatedFile, uploadPentestReport, getPentestSchedule } from '../api/client.js'

export default function Reports() {
  const { clientId } = useParams()
  const qc = useQueryClient()

  const { data: reports, isLoading } = useQuery({ queryKey: ['reports', clientId], queryFn: () => listReports(clientId) })
  const { data: pentestSchedule } = useQuery({ queryKey: ['pentest-schedule', clientId], queryFn: () => getPentestSchedule(clientId) })
  const generate = useMutation({
    mutationFn: () => triggerReportGeneration(clientId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports', clientId] }),
  })
  const uploadReport = useMutation({
    mutationFn: (file) => uploadPentestReport(clientId, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pentest-schedule', clientId] }),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Report Library</h2>
          <p className="text-muted text-sm">Monthly security reports, generated automatically with an AI-drafted executive summary.</p>
        </div>
        <button
          onClick={() => generate.mutate()}
          disabled={generate.isPending}
          className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm hover:brightness-110 transition disabled:opacity-50"
        >
          {generate.isPending ? 'Generating…' : 'Generate report now'}
        </button>
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : reports?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">
          No reports generated yet. Reports are auto-generated on the 1st of each month, or generate one now.
        </div>
      ) : (
        <div className="space-y-3">
          {reports?.map((r) => (
            <div key={r.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-medium">
                    {new Date(r.period_start).toLocaleDateString(undefined, { month: 'long', year: 'numeric' })}
                  </h3>
                  <p className="text-xs text-muted font-mono mt-1">
                    generated {new Date(r.created_at).toLocaleDateString()} · risk score {r.risk_score ?? '—'}/100
                  </p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/reports/${r.id}/pdf`, `report-${r.id}.pdf`)}
                    className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                    PDF
                  </button>
                  <button
                    onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/reports/${r.id}/docx`, `report-${r.id}.docx`)}
                    className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                    DOCX
                  </button>
                </div>
              </div>
              {r.executive_summary && <p className="text-sm text-muted mt-3">{r.executive_summary}</p>}
              {r.share_token && (
                <p className="text-[11px] text-muted font-mono mt-3 truncate">
                  share link: /api/shared-reports/{r.share_token}/pdf
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 bg-panel border border-border rounded-lg p-5">
        <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono mb-3">Pentest report archive</h3>
        {pentestSchedule?.report_file_path ? (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted">Report from the last completed engagement is on file.</p>
            <button
              onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/pentest-schedule/report`, `pentest-report.pdf`)}
              className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
              Download
            </button>
          </div>
        ) : (
          <p className="text-sm text-muted mb-3">No pentest report uploaded yet.</p>
        )}
        <label className="inline-block mt-3 text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono cursor-pointer">
          {uploadReport.isPending ? 'Uploading…' : 'Upload report (PDF/DOCX)'}
          <input
            type="file" accept=".pdf,.docx" className="hidden"
            onChange={(e) => e.target.files[0] && uploadReport.mutate(e.target.files[0])}
          />
        </label>
        {uploadReport.isError && (
          <p className="text-xs text-red-400 mt-2">{uploadReport.error?.response?.data?.detail || 'Upload failed'}</p>
        )}
      </div>
    </div>
  )
}
