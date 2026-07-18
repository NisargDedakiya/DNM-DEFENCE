import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getPosture } from '../api/client.js'

const GRADE_COLOR = {
  A: 'text-good border-good/40 bg-good/10',
  B: 'text-good border-good/40 bg-good/10',
  C: 'text-medium border-medium/40 bg-medium/10',
  D: 'text-high border-high/40 bg-high/10',
  F: 'text-critical border-critical/40 bg-critical/10',
}
const SEV_COLOR = { critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low', info: 'text-muted' }
const BAR_COLOR = (score) => (score >= 80 ? 'bg-good' : score >= 70 ? 'bg-medium' : score >= 60 ? 'bg-high' : 'bg-critical')

function ActionItem({ item }) {
  const [open, setOpen] = useState(item.priority <= 3)
  return (
    <li className="border border-border rounded-lg overflow-hidden">
      <button onClick={() => setOpen((o) => !o)} className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-panel2/40">
        <span className="text-xs font-mono text-muted w-5 shrink-0">{item.priority}</span>
        <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded shrink-0 ${SEV_COLOR[item.severity]}`}>{item.severity}</span>
        <span className="flex-1 text-sm truncate">{item.title}</span>
        <span className="text-muted text-xs shrink-0">{open ? '−' : '+'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 space-y-2 border-t border-border/60">
          <p className="text-xs text-muted">{item.domain}</p>
          <div>
            <p className="text-[11px] uppercase font-mono text-muted tracking-wide">Why it matters</p>
            <p className="text-sm">{item.why_it_matters}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase font-mono text-muted tracking-wide">How to fix it</p>
            <p className="text-sm whitespace-pre-wrap">{item.how_to_fix}</p>
          </div>
        </div>
      )}
    </li>
  )
}

export default function SecurityScorecard() {
  const { clientId } = useParams()
  const { data, isLoading, error } = useQuery({ queryKey: ['posture', clientId], queryFn: () => getPosture(clientId) })

  if (isLoading) return <p className="text-muted text-sm">Loading your security report…</p>
  if (error) return <p className="text-critical text-sm">Could not load the scorecard.</p>

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Security Report Card</h2>
        <p className="text-muted text-sm">Your security posture in plain English — where you stand and exactly what to do next.</p>
      </div>

      {!data.assessment_ready && (
        <div className="mb-6 rounded-lg border border-medium/40 bg-medium/10 p-4 text-sm text-medium font-mono">
          No scan has completed yet — this grade will fill in once your baseline assessment finishes.
        </div>
      )}

      {/* Grade + summary */}
      <div className="grid grid-cols-3 gap-6 mb-6">
        <div className={`rounded-lg border p-6 flex flex-col items-center justify-center ${GRADE_COLOR[data.grade]}`}>
          <div className="text-6xl font-mono font-bold">{data.grade}</div>
          <div className="text-xs font-mono mt-1 opacity-80">{data.score}/100</div>
        </div>
        <div className="col-span-2 bg-panel border border-border rounded-lg p-6 flex flex-col justify-center">
          <p className="text-sm mb-3">{data.grade_meaning}</p>
          {data.summary && <p className="text-sm text-muted border-t border-border/60 pt-3">{data.summary}</p>}
          <div className="grid grid-cols-4 gap-3 mt-4">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <div key={s} className="text-center bg-panel2 rounded-md py-2">
                <div className={`text-lg font-mono font-semibold ${SEV_COLOR[s]}`}>{data.open_by_severity[s]}</div>
                <div className="text-[10px] text-muted uppercase font-mono">{s}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Action plan */}
        <div className="col-span-2 bg-panel border border-border rounded-lg p-6">
          <h3 className="text-sm font-medium text-muted mb-1 uppercase tracking-wide font-mono">Your action plan</h3>
          <p className="text-muted text-xs mb-4">The highest-impact fixes, in order. Start at the top.</p>
          {data.action_plan.length === 0 ? (
            <p className="text-good text-sm font-mono">Nothing urgent right now — no open issues to action. 🎉</p>
          ) : (
            <ul className="space-y-2">
              {data.action_plan.map((item) => <ActionItem key={item.finding_id} item={item} />)}
            </ul>
          )}
        </div>

        <div className="space-y-6">
          {/* Weakest areas */}
          <div className="bg-panel border border-border rounded-lg p-6">
            <h3 className="text-sm font-medium text-muted mb-4 uppercase tracking-wide font-mono">By area</h3>
            {data.domains.length === 0 ? (
              <p className="text-muted text-sm">No weak areas — clean across the board.</p>
            ) : (
              <ul className="space-y-3">
                {data.domains.map((d) => (
                  <li key={d.domain}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="truncate pr-2">{d.domain}</span>
                      <span className="font-mono text-muted shrink-0">{d.score}</span>
                    </div>
                    <div className="h-1.5 rounded bg-panel2 overflow-hidden">
                      <div className={`h-full ${BAR_COLOR(d.score)}`} style={{ width: `${d.score}%` }} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* SOC 2 readiness */}
          <div className="bg-panel border border-border rounded-lg p-6">
            <h3 className="text-sm font-medium text-muted mb-1 uppercase tracking-wide font-mono">SOC 2 readiness</h3>
            <p className="text-muted text-xs mb-3">How ready you are to pass a customer's security review.</p>
            <div className="flex items-end gap-2 mb-2">
              <span className="text-3xl font-mono font-semibold">{data.soc2_readiness.percent_ready}%</span>
              <span className="text-muted text-xs mb-1">ready</span>
            </div>
            <div className="h-1.5 rounded bg-panel2 overflow-hidden mb-3">
              <div className={`h-full ${BAR_COLOR(data.soc2_readiness.percent_ready)}`} style={{ width: `${data.soc2_readiness.percent_ready}%` }} />
            </div>
            <div className="text-xs text-muted font-mono space-y-0.5">
              <div>{data.soc2_readiness.controls_ready} ready</div>
              <div>{data.soc2_readiness.controls_in_progress} in progress</div>
              <div>{data.soc2_readiness.controls_missing} not started</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
