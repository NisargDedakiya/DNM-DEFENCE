import { useQuery } from '@tanstack/react-query'
import { getSystemDiagnostics } from '../api/client.js'

function StatusPill({ ok, okLabel = 'OK', badLabel = 'DOWN' }) {
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase tracking-wide ${
      ok ? 'bg-good/10 text-good' : 'bg-critical/10 text-critical'
    }`}>
      {ok ? okLabel : badLabel}
    </span>
  )
}

function ToolRow({ name, present }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border/60 last:border-0">
      <span className="text-sm font-mono">{name}</span>
      <StatusPill ok={present} okLabel="installed" badLabel="missing" />
    </div>
  )
}

export default function SystemHealth() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['system-diagnostics'],
    queryFn: getSystemDiagnostics,
    refetchInterval: 30000,
  })

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold mb-1">System Health</h2>
          <p className="text-muted text-sm">
            Is the platform actually able to do work right now? Scans queue via Celery — if the worker isn't
            running or can't reach the same Redis/DB as the API, a scan will sit at "running" forever with no
            error shown anywhere else. This page exists to catch that.
          </p>
        </div>
        <button onClick={() => refetch()} disabled={isFetching}
          className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono disabled:opacity-50 whitespace-nowrap">
          {isFetching ? 'Checking…' : 'Re-check now'}
        </button>
      </div>

      {isLoading && <p className="text-muted text-sm">Checking…</p>}
      {error && <p className="text-critical text-sm">Could not reach the diagnostics endpoint — the API itself may be down.</p>}

      {data && (
        <div className="space-y-6">
          <div className={`rounded-lg border p-4 text-sm font-mono ${
            data.healthy ? 'bg-good/10 border-good/30 text-good' : 'bg-critical/10 border-critical/30 text-critical'
          }`}>
            {data.healthy ? 'All required systems are up. Scans should run normally.' : 'One or more required systems are down — see warnings below.'}
          </div>

          {data.warnings.length > 0 && (
            <div className="bg-panel border border-border rounded-lg p-6">
              <h3 className="text-sm font-medium text-muted mb-3 uppercase tracking-wide font-mono">Warnings</h3>
              <ul className="space-y-2">
                {data.warnings.map((w, i) => (
                  <li key={i} className="text-sm flex gap-2">
                    <span className="text-critical shrink-0">⚠</span>
                    <span>{w}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-3 gap-6">
            <div className="bg-panel border border-border rounded-lg p-6">
              <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">Core infrastructure</h3>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Database</span>
                  <StatusPill ok={data.database.ok} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Redis</span>
                  <StatusPill ok={data.redis.ok} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Celery worker</span>
                  <StatusPill ok={data.celery.reachable} okLabel={`${data.celery.worker_count} up`} badLabel="unreachable" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">AI reports (Anthropic key)</span>
                  <StatusPill ok={data.ai_reports_configured} okLabel="configured" badLabel="not set" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Stuck scans (&gt;6h running)</span>
                  <StatusPill ok={data.stuck_scans === 0} okLabel="none" badLabel={`${data.stuck_scans}`} />
                </div>
              </div>
            </div>

            <div className="bg-panel border border-border rounded-lg p-6">
              <h3 className="text-sm font-medium text-muted mb-2 uppercase tracking-wide font-mono">Required recon tools</h3>
              <p className="text-muted text-xs mb-3">Module 1 asset discovery depends on these — missing any of them means scans complete but return empty results.</p>
              {Object.entries(data.required_recon_tools).map(([name, present]) => (
                <ToolRow key={name} name={name} present={present} />
              ))}
            </div>

            <div className="bg-panel border border-border rounded-lg p-6">
              <h3 className="text-sm font-medium text-muted mb-2 uppercase tracking-wide font-mono">Optional enrichment tools</h3>
              <p className="text-muted text-xs mb-3">Expanded/Advanced services degrade gracefully without these — not required for core functionality.</p>
              {Object.entries(data.optional_tools).map(([name, present]) => (
                <ToolRow key={name} name={name} present={present} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
