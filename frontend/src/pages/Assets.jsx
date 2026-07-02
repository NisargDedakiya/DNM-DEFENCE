import { useState, Fragment } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { listAssets } from '../api/client.js'

function riskColor(score) {
  if (score >= 60) return 'text-critical'
  if (score >= 35) return 'text-high'
  if (score >= 15) return 'text-medium'
  return 'text-muted'
}

export default function Assets() {
  const { clientId } = useParams()
  const [expanded, setExpanded] = useState(null)
  const { data: assets, isLoading } = useQuery({ queryKey: ['assets', clientId], queryFn: () => listAssets(clientId) })

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-1">Asset Inventory</h2>
      <p className="text-muted text-sm mb-6">Every domain, subdomain, and cloud resource discovered for this client.</p>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : assets?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">
          No assets discovered yet. Run a recon scan from the Overview tab.
        </div>
      ) : (
        <div className="bg-panel border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-panel2 text-muted text-xs uppercase font-mono">
              <tr>
                <th className="text-left px-4 py-3">Asset</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Source</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Risk</th>
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {assets?.map((a) => (
                <Fragment key={a.id}>
                  <tr
                    onClick={() => setExpanded(expanded === a.id ? null : a.id)}
                    className="border-t border-border/60 cursor-pointer hover:bg-panel2/50"
                  >
                    <td className="px-4 py-3 font-mono">{a.value}</td>
                    <td className="px-4 py-3 text-muted">{a.asset_type}</td>
                    <td className="px-4 py-3 text-muted">{a.source || '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded ${a.is_alive ? 'text-good bg-good/10' : 'text-muted bg-panel2'}`}>
                        {a.is_alive ? 'ALIVE' : 'DEAD'}
                      </span>
                    </td>
                    <td className={`px-4 py-3 font-mono ${riskColor(a.risk_score)}`}>{Math.round(a.risk_score)}</td>
                    <td className="px-4 py-3 text-muted font-mono text-xs">{new Date(a.last_seen).toLocaleDateString()}</td>
                  </tr>
                  {expanded === a.id && (
                    <tr className="bg-panel2/30">
                      <td colSpan={6} className="px-4 py-4">
                        <div className="grid grid-cols-2 gap-6">
                          <div>
                            <h4 className="text-[10px] text-muted uppercase font-mono mb-2">Tech stack</h4>
                            {Object.keys(a.tech_stack || {}).length === 0 ? (
                              <p className="text-muted text-xs">No fingerprint data yet.</p>
                            ) : (
                              <ul className="text-xs space-y-1 font-mono">
                                {Object.entries(a.tech_stack).map(([k, v]) => (
                                  <li key={k}><span className="text-muted">{k}:</span> {String(v)}</li>
                                ))}
                              </ul>
                            )}
                            <h4 className="text-[10px] text-muted uppercase font-mono mt-4 mb-1">History</h4>
                            <p className="text-xs text-muted">First discovered {new Date(a.first_seen).toLocaleDateString()}</p>
                          </div>
                          <div>
                            <h4 className="text-[10px] text-muted uppercase font-mono mb-2">Open ports</h4>
                            {(a.ports || []).length === 0 ? (
                              <p className="text-muted text-xs">No ports recorded.</p>
                            ) : (
                              <ul className="text-xs space-y-1 font-mono">
                                {a.ports.map((p) => (
                                  <li key={p.port_number} className={p.is_dangerous ? 'text-critical' : ''}>
                                    {p.port_number}/{p.protocol} {p.service_name || ''} {p.service_version || ''}
                                    {p.is_dangerous && ' — dangerous'}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
