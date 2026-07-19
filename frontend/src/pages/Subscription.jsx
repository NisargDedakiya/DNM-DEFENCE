import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listPlans, getSubscription, setSubscription, getMe } from '../api/client.js'

const TIER_ACCENT = {
  essential: 'border-border',
  growth: 'border-signal/50',
  enterprise: 'border-good/50',
}

export default function Subscription() {
  const { clientId } = useParams()
  const qc = useQueryClient()

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: getMe })
  const isStaff = me?.role === 'admin' || me?.role === 'analyst'
  const { data: plans } = useQuery({ queryKey: ['plans'], queryFn: listPlans })
  const { data: sub } = useQuery({ queryKey: ['subscription', clientId], queryFn: () => getSubscription(clientId) })

  const change = useMutation({
    mutationFn: (plan) => setSubscription(clientId, plan),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['subscription', clientId] })
      qc.invalidateQueries({ queryKey: ['client', clientId] })
      qc.invalidateQueries({ queryKey: ['entitlements', clientId] })
    },
  })

  if (!plans || !sub) return <p className="text-muted text-sm">Loading plans…</p>

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Subscription</h2>
        <p className="text-muted text-sm">
          You're on the <span className="text-ink font-medium">{sub.plan_name}</span> plan
          {' '}(${sub.price_monthly_usd.toLocaleString()}/mo). {isStaff ? 'Change a client’s tier below.' : 'Contact us to change your plan.'}
        </p>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {plans.map((p) => {
          const current = p.tier === sub.plan
          return (
            <div key={p.tier} className={`bg-panel border rounded-lg p-6 flex flex-col ${current ? 'border-signal' : TIER_ACCENT[p.tier]}`}>
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-lg font-semibold">{p.name}</h3>
                {current && <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-signal/15 text-signal">Current</span>}
              </div>
              <div className="text-2xl font-mono font-bold mb-1">${p.price_monthly_usd.toLocaleString()}<span className="text-sm text-muted font-normal">/mo</span></div>
              <p className="text-muted text-xs mb-3">{p.tagline}</p>
              <p className="text-[11px] text-muted font-mono border-t border-border/60 pt-3 mb-3">{p.scan_cadence}</p>
              <p className="text-[11px] text-muted mb-3">Critical SLA: {p.sla_hours_critical}h · High SLA: {p.sla_hours_high}h</p>

              <ul className="space-y-1.5 flex-1 mb-4">
                {p.features.map((f) => (
                  <li key={f.key} className={`text-xs flex items-start gap-2 ${f.included ? '' : 'text-muted/50 line-through'}`}>
                    <span className={f.included ? 'text-good' : 'text-muted/40'}>{f.included ? '✓' : '·'}</span>
                    <span>{f.label}</span>
                  </li>
                ))}
              </ul>

              {isStaff && (
                <button
                  onClick={() => change.mutate(p.tier)}
                  disabled={current || change.isPending}
                  className={`w-full py-2 rounded-md text-sm font-medium transition ${
                    current ? 'bg-panel2 text-muted cursor-default'
                    : 'bg-signal text-base hover:brightness-110 disabled:opacity-50'
                  }`}
                >
                  {current ? 'Current plan' : change.isPending ? 'Updating…' : `Switch to ${p.name}`}
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
