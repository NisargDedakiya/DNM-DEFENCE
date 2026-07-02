import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { listAssets } from '../api/client.js'

export default function Assets() {
  const { clientId } = useParams()
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
                <th className="text-left px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {assets?.map((a) => (
                <tr key={a.id} className="border-t border-border/60">
                  <td className="px-4 py-3 font-mono">{a.value}</td>
                  <td className="px-4 py-3 text-muted">{a.asset_type}</td>
                  <td className="px-4 py-3 text-muted">{a.source || '—'}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded ${a.is_alive ? 'text-good bg-good/10' : 'text-muted bg-panel2'}`}>
                      {a.is_alive ? 'ALIVE' : 'DEAD'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted font-mono text-xs">{new Date(a.last_seen).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
