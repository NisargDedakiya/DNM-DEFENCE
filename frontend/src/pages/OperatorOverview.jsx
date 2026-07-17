import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getOperatorOverview } from '../api/client.js'

const SEV_COLOR = { critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low' }

function Stat({ label, value, accent }) {
  return (
    <div className="bg-panel2 rounded-md py-4 px-3 text-center">
      <div className={`text-2xl font-mono font-semibold ${accent || ''}`}>{value}</div>
      <div className="text-[10px] text-muted uppercase mt-1 font-mono tracking-wide">{label}</div>
    </div>
  )
}

export default function OperatorOverview() {
  const navigate = useNavigate()
  const { data, isLoading, error } = useQuery({
    queryKey: ['operator-overview'],
    queryFn: getOperatorOverview,
    refetchInterval: 30000,
  })

  if (isLoading) return <p className="text-muted text-sm">Loading…</p>
  if (error) return <p className="text-critical text-sm">Could not load the operator overview — the API may be down.</p>

  const sev = data.open_findings.by_severity

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Operator Overview</h2>
        <p className="text-muted text-sm">Your whole book of business at a glance — every client, live. Auto-refreshes every 30s.</p>
      </div>

      {/* System status banner */}
      <div className={`rounded-lg border p-4 mb-6 text-sm font-mono ${
        data.system_healthy ? 'bg-good/10 border-good/30 text-good' : 'bg-critical/10 border-critical/30 text-critical'
      }`}>
        {data.system_healthy
          ? 'All systems operational — scans and reports can run normally.'
          : `Attention needed — ${data.system_warnings.length} system warning(s). See System Health.`}
      </div>

      {/* Top-line stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Stat label="Clients" value={`${data.clients.active}/${data.clients.total}`} />
        <Stat label="Open findings" value={data.open_findings.total} />
        <Stat label="Scans running" value={data.scans.running} accent={data.scans.running ? 'text-signal' : ''} />
        <Stat label="Failed (24h)" value={data.scans.failed_24h} accent={data.scans.failed_24h ? 'text-critical' : 'text-good'} />
      </div>

      {/* Open findings by severity */}
      <div className="bg-panel border border-border rounded-lg p-6 mb-6">
        <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">Open findings by severity — all clients</h3>
        <div className="grid grid-cols-4 gap-3">
          {['critical', 'high', 'medium', 'low'].map((s) => (
            <div key={s} className="text-center bg-panel2 rounded-md py-4">
              <div className={`text-2xl font-mono font-semibold ${SEV_COLOR[s]}`}>{sev[s]}</div>
              <div className="text-[10px] text-muted uppercase mt-1 font-mono">{s}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Risk leaderboard */}
        <div className="bg-panel border border-border rounded-lg p-6">
          <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">Clients needing attention</h3>
          {data.risk_leaderboard.length === 0 && <p className="text-muted text-sm">No clients yet.</p>}
          <ul className="space-y-2">
            {data.risk_leaderboard.map((c) => (
              <li key={c.client_id}>
                <button onClick={() => navigate(`/clients/${c.client_id}`)}
                  className="w-full flex items-center justify-between text-sm py-2 border-b border-border/60 last:border-0 hover:text-signal">
                  <span className="truncate pr-3">{c.client_name}</span>
                  <span className="flex items-center gap-3 shrink-0 font-mono text-xs">
                    {c.critical > 0 && <span className="text-critical">{c.critical} crit</span>}
                    {c.high > 0 && <span className="text-high">{c.high} high</span>}
                    <span className="text-muted">risk {c.risk_score}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        {/* Recent scan failures */}
        <div className="bg-panel border border-border rounded-lg p-6">
          <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">Recent scan failures (7d)</h3>
          {data.recent_failures.length === 0
            ? <p className="text-good text-sm font-mono">None — every scan completed cleanly.</p>
            : (
              <ul className="space-y-2">
                {data.recent_failures.map((f, i) => (
                  <li key={i} className="text-sm py-2 border-b border-border/60 last:border-0">
                    <button onClick={() => navigate(`/clients/${f.client_id}`)} className="hover:text-signal text-left w-full">
                      <div className="flex items-center justify-between">
                        <span className="font-medium truncate pr-3">{f.client_name}</span>
                        <span className="text-[10px] text-muted font-mono shrink-0">{f.scan_type}</span>
                      </div>
                      {f.error && <div className="text-[11px] text-critical/80 font-mono truncate mt-0.5">{f.error}</div>}
                    </button>
                  </li>
                ))}
              </ul>
            )}
        </div>
      </div>
    </div>
  )
}
