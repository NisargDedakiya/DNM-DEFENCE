import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listPhishingCampaigns, createPhishingCampaign, startPhishingCampaign, getPhishingTrend,
  getPhishingResults, getTrainingCompletion,
} from '../api/client.js'

const rate = (n, total) => (total ? Math.round((100 * n) / total) : 0)

export default function Phishing() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [expanded, setExpanded] = useState(null)
  const [form, setForm] = useState({ name: '', template_name: '', target_count: 0 })

  const { data: campaigns, isLoading } = useQuery({ queryKey: ['phishing', clientId], queryFn: () => listPhishingCampaigns(clientId) })
  const { data: trend } = useQuery({ queryKey: ['phishing-trend', clientId], queryFn: () => getPhishingTrend(clientId) })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['phishing', clientId] })
  const create = useMutation({
    mutationFn: () => createPhishingCampaign(clientId, { ...form, target_count: Number(form.target_count) }),
    onSuccess: () => { invalidate(); setShowForm(false); setForm({ name: '', template_name: '', target_count: 0 }) },
  })
  const start = useMutation({ mutationFn: (id) => startPhishingCampaign(clientId, id), onSuccess: invalidate })

  const improving = trend && trend.length >= 2 && trend[trend.length - 1].click_rate < trend[0].click_rate

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Phishing Simulation Dashboard</h2>
          <p className="text-muted text-sm">Campaign history and employee security awareness trend.</p>
        </div>
        <button onClick={() => setShowForm((s) => !s)}
          className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm hover:brightness-110 transition">
          + New campaign
        </button>
      </div>

      {trend && trend.length >= 2 && (
        <div className="bg-panel border border-border rounded-lg p-5 mb-6">
          <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono mb-3">Awareness trend</h3>
          <p className="text-sm">
            Click rate is <span className={improving ? 'text-good' : 'text-high'}>
              {improving ? 'improving' : 'not improving'}
            </span> across the last {trend.length} campaigns
            ({trend[0].click_rate ?? 0}% → {trend[trend.length - 1].click_rate ?? 0}%).
          </p>
        </div>
      )}

      {showForm && (
        <form onSubmit={(e) => { e.preventDefault(); create.mutate() }}
          className="mb-6 p-5 bg-panel border border-border rounded-lg grid grid-cols-3 gap-4">
          <input required placeholder="Campaign name" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input placeholder="Template (e.g. IT password reset)" value={form.template_name}
            onChange={(e) => setForm({ ...form, template_name: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input required type="number" placeholder="Target employee count" value={form.target_count}
            onChange={(e) => setForm({ ...form, target_count: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <button type="submit" disabled={create.isPending}
            className="col-span-3 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
            Create campaign
          </button>
        </form>
      )}

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : campaigns?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">
          No campaigns yet. Results are recorded via an external phishing tool posting back to this campaign's API.
        </div>
      ) : (
        <div className="space-y-3">
          {campaigns?.map((c) => (
            <div key={c.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="font-medium">{c.name}</h3>
                  {c.template_name && <p className="text-xs text-muted mt-0.5">{c.template_name}</p>}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    c.status === 'completed' ? 'text-good bg-good/10' : c.status === 'running' ? 'text-signal bg-signal/10' : 'text-muted bg-panel2'
                  }`}>{c.status.toUpperCase()}</span>
                  {c.status === 'draft' && (
                    <button onClick={() => start.mutate(c.id)}
                      className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                      Start
                    </button>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-5 gap-3">
                <Metric label="Sent" value={c.sent_count} />
                <Metric label="Opened" value={`${rate(c.opened_count, c.sent_count)}%`} />
                <Metric label="Clicked" value={`${rate(c.clicked_count, c.sent_count)}%`} tone="high" />
                <Metric label="Reported" value={`${rate(c.reported_count, c.sent_count)}%`} tone="good" />
                <Metric label="Creds submitted" value={`${rate(c.credential_submitted_count, c.sent_count)}%`} tone="critical" />
              </div>
              <button
                onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                className="text-xs text-signal hover:underline mt-3"
              >
                {expanded === c.id ? 'Hide employee results' : 'Show employee results & training completion'}
              </button>
              {expanded === c.id && <CampaignDetail clientId={clientId} campaignId={c.id} />}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Metric({ label, value, tone }) {
  const cls = { high: 'text-high', good: 'text-good', critical: 'text-critical' }[tone] || 'text-ink'
  return (
    <div className="text-center bg-panel2 rounded-md py-3">
      <div className={`text-lg font-mono font-semibold ${cls}`}>{value}</div>
      <div className="text-[10px] text-muted uppercase mt-1 font-mono">{label}</div>
    </div>
  )
}

function CampaignDetail({ clientId, campaignId }) {
  const { data: results, isLoading: resultsLoading } = useQuery({
    queryKey: ['phishing-results', clientId, campaignId],
    queryFn: () => getPhishingResults(clientId, campaignId),
  })
  const { data: training } = useQuery({
    queryKey: ['training-completion', clientId, campaignId],
    queryFn: () => getTrainingCompletion(clientId, campaignId),
  })

  return (
    <div className="mt-4 pt-4 border-t border-border/60">
      {training && (
        <p className="text-xs text-muted mb-3">
          Training completion: <span className="text-ink font-mono">{training.percent_completed}%</span>
          {' '}({training.completed}/{training.total_employees} employees)
        </p>
      )}
      {resultsLoading ? (
        <p className="text-muted text-xs">Loading results…</p>
      ) : results?.length === 0 ? (
        <p className="text-muted text-xs">No individual results recorded yet.</p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-muted uppercase font-mono">
            <tr>
              <th className="text-left py-1">Employee</th>
              <th className="text-left py-1">Clicked</th>
              <th className="text-left py-1">Reported</th>
              <th className="text-left py-1">Creds submitted</th>
              <th className="text-left py-1">Training</th>
            </tr>
          </thead>
          <tbody>
            {results?.map((r) => (
              <tr key={r.id} className="border-t border-border/40">
                <td className="py-1.5 font-mono">{r.employee_identifier}</td>
                <td className={r.clicked ? 'text-high' : 'text-muted'}>{r.clicked ? 'Yes' : 'No'}</td>
                <td className={r.reported ? 'text-good' : 'text-muted'}>{r.reported ? 'Yes' : 'No'}</td>
                <td className={r.submitted_credentials ? 'text-critical' : 'text-muted'}>{r.submitted_credentials ? 'Yes' : 'No'}</td>
                <td className={r.training_completed ? 'text-good' : 'text-muted'}>{r.training_completed ? 'Done' : 'Pending'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
