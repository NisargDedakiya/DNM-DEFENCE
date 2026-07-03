import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  generateOsintProfile, listOsintProfiles,
  createVishingEngagement, listVishingEngagements, uploadVishingRecording, analyzeVishingEngagement,
  createPhysicalAssessment, listPhysicalAssessments, updatePhysicalAssessment, updatePhysicalChecklistItem,
  downloadAuthenticatedFile,
} from '../api/client.js'

const TABS = ['OSINT Profiling', 'Vishing Analyser', 'Physical Security']

export default function SocialEngineering() {
  const [tab, setTab] = useState(TABS[0])

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Social Engineering &amp; Physical Security</h2>
        <p className="text-muted text-sm">OSINT reconnaissance, vishing call analysis, and physical assessment tracking.</p>
      </div>

      <div className="flex gap-2 mb-6 border-b border-border">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'OSINT Profiling' && <OsintPanel />}
      {tab === 'Vishing Analyser' && <VishingPanel />}
      {tab === 'Physical Security' && <PhysicalSecurityPanel />}
    </div>
  )
}

function OsintPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [employeeNames, setEmployeeNames] = useState('')
  const [careersUrl, setCareersUrl] = useState('')

  const { data: profiles, isLoading } = useQuery({ queryKey: ['osint', clientId], queryFn: () => listOsintProfiles(clientId) })
  const generate = useMutation({
    mutationFn: () => generateOsintProfile(clientId, {
      employee_names: employeeNames.split(',').map((s) => s.trim()).filter(Boolean),
      careers_page_url: careersUrl || null,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['osint', clientId] }),
  })

  return (
    <div>
      <div className="bg-panel border border-border rounded-lg p-5 mb-6 grid grid-cols-2 gap-4">
        <input placeholder="Employee names, comma-separated (for email-pattern guessing)" value={employeeNames}
          onChange={(e) => setEmployeeNames(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Careers page URL (optional, for tech-stack analysis)" value={careersUrl}
          onChange={(e) => setCareersUrl(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button onClick={() => generate.mutate()} disabled={generate.isPending}
          className="col-span-2 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
          {generate.isPending ? 'Generating…' : 'Generate OSINT profile'}
        </button>
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : profiles?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No OSINT profiles generated yet.</div>
      ) : (
        <div className="space-y-3">
          {profiles?.map((p) => (
            <div key={p.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted font-mono">{new Date(p.generated_at).toLocaleString()}</span>
                <button
                  onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/osint/${p.id}/export/pdf`, `osint-profile-${p.id}.pdf`)}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                  Download PDF
                </button>
              </div>
              <p className="text-sm">{p.findings?.narrative}</p>
              <p className="text-[10px] text-muted mt-2 italic">{p.findings?.linkedin_note}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function VishingPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [scenario, setScenario] = useState('')
  const [transcript, setTranscript] = useState('')

  const { data: engagements, isLoading } = useQuery({ queryKey: ['vishing', clientId], queryFn: () => listVishingEngagements(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['vishing', clientId] })
  const create = useMutation({
    mutationFn: () => createVishingEngagement(clientId, { scenario, transcript: transcript || null }),
    onSuccess: () => { invalidate(); setScenario(''); setTranscript('') },
  })
  const analyze = useMutation({ mutationFn: (id) => analyzeVishingEngagement(clientId, id), onSuccess: invalidate })
  const upload = useMutation({
    mutationFn: ({ id, file }) => uploadVishingRecording(clientId, id, file),
    onSuccess: invalidate,
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }}
        className="bg-panel border border-border rounded-lg p-5 mb-6 grid grid-cols-2 gap-4">
        <input required placeholder="Scenario / pretext (e.g. IT helpdesk password reset)" value={scenario}
          onChange={(e) => setScenario(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <input placeholder="Transcript (optional if uploading a recording)" value={transcript}
          onChange={(e) => setTranscript(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending}
          className="col-span-2 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
          Log new vishing engagement
        </button>
      </form>
      <p className="text-xs text-muted mb-4 italic">
        Calls are placed by an analyst under the engagement's own consent process — this tool analyses a recording or transcript afterward, it does not place calls itself.
      </p>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : engagements?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No vishing engagements logged yet.</div>
      ) : (
        <div className="space-y-3">
          {engagements?.map((e) => (
            <div key={e.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium text-sm">{e.scenario}</h3>
                {e.risk_rating && (
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${
                    e.risk_rating === 'critical' || e.risk_rating === 'high' ? 'text-critical bg-critical/10' : 'text-muted bg-panel2'
                  }`}>{e.risk_rating}</span>
                )}
              </div>
              {e.analysis?.summary && <p className="text-sm text-muted mb-2">{e.analysis.summary}</p>}
              {e.analysis?.techniques_identified?.length > 0 && (
                <p className="text-xs mb-1"><span className="text-muted font-mono">Techniques: </span>{e.analysis.techniques_identified.join(', ')}</p>
              )}
              {e.analysis?.disclosures?.length > 0 && (
                <p className="text-xs mb-2"><span className="text-muted font-mono">Disclosed: </span>{e.analysis.disclosures.join(', ')}</p>
              )}
              <div className="flex items-center gap-2 mt-2">
                <label className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono cursor-pointer">
                  Upload recording
                  <input type="file" accept="audio/*" className="hidden"
                    onChange={(ev) => ev.target.files[0] && upload.mutate({ id: e.id, file: ev.target.files[0] })} />
                </label>
                <button onClick={() => analyze.mutate(e.id)} disabled={analyze.isPending}
                  className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                  Run analysis
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PhysicalSecurityPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [siteName, setSiteName] = useState('')

  const { data: assessments, isLoading } = useQuery({ queryKey: ['physec', clientId], queryFn: () => listPhysicalAssessments(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['physec', clientId] })
  const create = useMutation({
    mutationFn: () => createPhysicalAssessment(clientId, { site_name: siteName }),
    onSuccess: () => { invalidate(); setSiteName('') },
  })
  const updateItem = useMutation({
    mutationFn: ({ assessmentId, itemId, payload }) => updatePhysicalChecklistItem(clientId, assessmentId, itemId, payload),
    onSuccess: invalidate,
  })
  const updateAssessment = useMutation({
    mutationFn: ({ id, payload }) => updatePhysicalAssessment(clientId, id, payload),
    onSuccess: invalidate,
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-3 mb-6">
        <input required placeholder="Site name" value={siteName} onChange={(e) => setSiteName(e.target.value)}
          className="flex-1 bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        <button type="submit" disabled={create.isPending}
          className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">New assessment</button>
      </form>
      <p className="text-xs text-muted mb-4 italic">
        Tailgating, badge cloning, dumpster diving, and USB-drop tests require an in-person analyst — this is an engagement checklist tracker, not automation.
      </p>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : assessments?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No physical security assessments scheduled yet.</div>
      ) : (
        <div className="space-y-4">
          {assessments?.map((a) => (
            <div key={a.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-medium">{a.site_name}</h3>
                <select value={a.status} onChange={(e) => updateAssessment.mutate({ id: a.id, payload: { status: e.target.value } })}
                  className="bg-panel2 border border-border rounded px-2 py-1 text-xs font-mono">
                  <option value="scheduled">Scheduled</option>
                  <option value="in_progress">In progress</option>
                  <option value="completed">Completed</option>
                </select>
              </div>
              <table className="w-full text-xs">
                <thead className="text-muted uppercase font-mono">
                  <tr><th className="text-left py-1">Test type</th><th className="text-left py-1">Attempted</th><th className="text-left py-1">Notes</th></tr>
                </thead>
                <tbody>
                  {a.checklist_items?.map((item) => (
                    <tr key={item.id} className="border-t border-border/40">
                      <td className="py-1.5 font-mono">{item.test_type.replace('_', ' ')}</td>
                      <td>
                        <input type="checkbox" checked={item.attempted}
                          onChange={(e) => updateItem.mutate({ assessmentId: a.id, itemId: item.id, payload: { attempted: e.target.checked } })} />
                      </td>
                      <td>
                        <input defaultValue={item.outcome_notes || ''} placeholder="Outcome notes"
                          onBlur={(e) => updateItem.mutate({ assessmentId: a.id, itemId: item.id, payload: { outcome_notes: e.target.value } })}
                          className="w-full bg-panel2 border border-border rounded px-2 py-1 text-xs outline-none focus:border-signal" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
