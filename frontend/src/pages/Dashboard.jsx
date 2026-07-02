import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import {
  getClient, listFindings, listAssets, listScans, getFindingsTrend,
  triggerSubdomainEnum, triggerVulnScan, triggerDarkWebScan,
} from '../api/client.js'
import RiskScoreRadial from '../components/RiskScoreRadial.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import PentestWidget from '../components/PentestWidget.jsx'

const riskScore = (counts) => Math.min(100, counts.critical * 25 + counts.high * 10 + counts.medium * 3 + counts.low * 1)

export default function Dashboard() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [trendMonths, setTrendMonths] = useState(3)

  const { data: client } = useQuery({ queryKey: ['client', clientId], queryFn: () => getClient(clientId) })
  const { data: findings } = useQuery({ queryKey: ['findings', clientId], queryFn: () => listFindings(clientId) })
  const { data: assets } = useQuery({ queryKey: ['assets', clientId], queryFn: () => listAssets(clientId) })
  const { data: scans } = useQuery({ queryKey: ['scans', clientId], queryFn: () => listScans(clientId) })
  const { data: trend } = useQuery({
    queryKey: ['findings-trend', clientId, trendMonths],
    queryFn: () => getFindingsTrend(clientId, trendMonths),
  })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['scans', clientId] })
  const runRecon = useMutation({ mutationFn: () => triggerSubdomainEnum(clientId), onSuccess: invalidate })
  const runVuln = useMutation({ mutationFn: () => triggerVulnScan(clientId), onSuccess: invalidate })
  const runIntel = useMutation({ mutationFn: () => triggerDarkWebScan(clientId), onSuccess: invalidate })

  const open = (findings || []).filter((f) => !['resolved', 'verified'].includes(f.status))
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  open.forEach((f) => { if (counts[f.severity] !== undefined) counts[f.severity]++ })
  const score = riskScore(counts)
  const recentAlerts = [...(findings || [])].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 10)
  const trendData = (trend || []).map((p) => ({
    date: new Date(p.snapshot_date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    risk_score: p.risk_score,
  }))

  if (!client) return <p className="text-muted text-sm">Loading…</p>

  return (
    <div>
      <div className="mb-8">
        <h2 className="text-2xl font-semibold">{client.name}</h2>
        <p className="text-muted text-sm font-mono mt-1">{client.root_domain}</p>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-panel border border-border rounded-lg p-6 flex items-center justify-center">
          <RiskScoreRadial score={score} />
        </div>

        <div className="col-span-2 bg-panel border border-border rounded-lg p-6">
          <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">Open findings</h3>
          <div className="grid grid-cols-4 gap-3">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <div key={s} className="text-center bg-panel2 rounded-md py-4">
                <div className="text-2xl font-mono font-semibold"><SeverityCount count={counts[s]} severity={s} /></div>
                <div className="text-[10px] text-muted uppercase mt-1 font-mono">{s}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-3 gap-3 mt-6 text-sm">
            <button onClick={() => runRecon.mutate()} disabled={runRecon.isPending}
              className="py-2 rounded-md border border-border hover:border-signal/50 text-xs font-mono disabled:opacity-50">
              {runRecon.isPending ? 'Queuing…' : 'Run recon scan'}
            </button>
            <button onClick={() => runVuln.mutate()} disabled={runVuln.isPending}
              className="py-2 rounded-md border border-border hover:border-signal/50 text-xs font-mono disabled:opacity-50">
              {runVuln.isPending ? 'Queuing…' : 'Run vuln scan'}
            </button>
            <button onClick={() => runIntel.mutate()} disabled={runIntel.isPending}
              className="py-2 rounded-md border border-border hover:border-signal/50 text-xs font-mono disabled:opacity-50">
              {runIntel.isPending ? 'Queuing…' : 'Run intel scan'}
            </button>
          </div>
        </div>
      </div>

      <div className="bg-panel border border-border rounded-lg p-6 mb-8">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono">Risk score trend</h3>
          <div className="flex gap-1">
            {[3, 6, 12].map((m) => (
              <button
                key={m} onClick={() => setTrendMonths(m)}
                className={`text-xs px-2 py-1 rounded border font-mono ${
                  trendMonths === m ? 'border-signal text-signal bg-signal/10' : 'border-border text-muted hover:border-signal/50'
                }`}
              >
                {m}mo
              </button>
            ))}
          </div>
        </div>
        {trendData.length < 2 ? (
          <p className="text-muted text-sm py-8 text-center">
            Not enough history yet to show a trend — check back after a few days of scanning.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3d" />
              <XAxis dataKey="date" stroke="#888" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#888" fontSize={11} />
              <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #2a2a3d', fontSize: 12 }} />
              <Line type="monotone" dataKey="risk_score" stroke="#f5a623" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="bg-panel border border-border rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono">Recent alerts</h3>
            <Link to={`/clients/${clientId}/findings`} className="text-xs text-signal hover:underline">View all →</Link>
          </div>
          <ul className="space-y-2">
            {recentAlerts.length === 0 && <li className="text-muted text-sm">No findings yet — run a scan to populate this.</li>}
            {recentAlerts.map((f) => (
              <li key={f.id} className="flex items-center justify-between text-sm py-2 border-b border-border/60 last:border-0">
                <span className="truncate pr-3">{f.title}</span>
                <SeverityBadge severity={f.severity} />
              </li>
            ))}
          </ul>
        </div>

        <div className="bg-panel border border-border rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono">Asset inventory</h3>
            <Link to={`/clients/${clientId}/assets`} className="text-xs text-signal hover:underline">View all →</Link>
          </div>
          <p className="text-3xl font-mono font-semibold">{assets?.length ?? 0}</p>
          <p className="text-muted text-xs mt-1">discovered assets · {assets?.filter(a => a.is_alive).length ?? 0} currently alive</p>

          <h4 className="text-[10px] text-muted uppercase tracking-wide font-mono mt-5 mb-2">Recent scans</h4>
          <ul className="space-y-1.5">
            {(scans || []).slice(0, 4).map((s) => (
              <li key={s.id} className="flex items-center justify-between text-xs">
                <span className="text-muted font-mono">{s.scan_type.replace('_', ' ')}</span>
                <span className={`font-mono ${s.status === 'completed' ? 'text-good' : s.status === 'failed' ? 'text-critical' : 'text-muted'}`}>
                  {s.status}
                </span>
              </li>
            ))}
            {(!scans || scans.length === 0) && <li className="text-muted text-xs">No scans run yet.</li>}
          </ul>
        </div>

        <PentestWidget />
      </div>
    </div>
  )
}

function SeverityCount({ count, severity }) {
  const colorClass = { critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low' }[severity]
  return <span className={colorClass}>{count}</span>
}
