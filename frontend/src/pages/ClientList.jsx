import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { listClients, createClient } from '../api/client.js'

export default function ClientList() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', root_domain: '', contact_email: '', industry: '', plan: 'essential' })

  const { data: clients, isLoading } = useQuery({ queryKey: ['clients'], queryFn: listClients })

  const onboard = useMutation({
    mutationFn: createClient,
    onSuccess: (client) => {
      qc.invalidateQueries({ queryKey: ['clients'] })
      setShowForm(false)
      navigate(`/clients/${client.id}`)
    },
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-semibold">Clients</h2>
          <p className="text-muted text-sm mt-1">Every client under active managed security delivery.</p>
        </div>
        <button
          onClick={() => setShowForm((s) => !s)}
          className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm hover:brightness-110 transition"
        >
          + Onboard client
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={(e) => { e.preventDefault(); onboard.mutate(form) }}
          className="mb-8 p-5 bg-panel border border-border rounded-lg grid grid-cols-2 gap-4"
        >
          <input required placeholder="Client name" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input required placeholder="Root domain (example.com)" value={form.root_domain}
            onChange={(e) => setForm({ ...form, root_domain: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input required type="email" placeholder="Contact email" value={form.contact_email}
            onChange={(e) => setForm({ ...form, contact_email: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input placeholder="Industry (optional)" value={form.industry}
            onChange={(e) => setForm({ ...form, industry: e.target.value })}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}
            className="col-span-2 bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal">
            <option value="essential">Essential — $499/mo (core monitoring)</option>
            <option value="growth">Growth — $1,499/mo (+ cloud, threat intel, phishing)</option>
            <option value="enterprise">Enterprise — $4,999/mo (every service, tightest SLAs)</option>
          </select>
          <button type="submit" disabled={onboard.isPending}
            className="col-span-2 py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
            {onboard.isPending ? 'Onboarding — triggering baseline scan…' : 'Onboard and start baseline scan'}
          </button>
        </form>
      )}

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : clients?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">
          No clients yet. Onboarding a client automatically triggers a baseline recon scan.
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {clients?.map((c) => (
            <button
              key={c.id}
              onClick={() => navigate(`/clients/${c.id}`)}
              className="text-left p-5 bg-panel border border-border rounded-lg hover:border-signal/50 transition"
            >
              <div className="flex items-center justify-between">
                <h3 className="font-semibold">{c.name}</h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${c.is_active ? 'text-good bg-good/10' : 'text-muted bg-panel2'}`}>
                  {c.is_active ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>
              <p className="text-muted text-sm font-mono mt-1">{c.root_domain}</p>
              {c.industry && <p className="text-muted text-xs mt-2">{c.industry}</p>}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
