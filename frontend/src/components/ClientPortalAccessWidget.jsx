import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listClientUsers, createClientUser, updateClientUser } from '../api/client.js'

/**
 * Staff-only. Connects a login (a user's id/password) to this client record
 * so their team can sign into their own scoped portal -- onboarding a client
 * only creates the client record; someone still has to provision the account
 * that can actually log in and see it.
 */
export default function ClientPortalAccessWidget() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ email: '', password: '' })

  const { data: users, isLoading } = useQuery({ queryKey: ['client-users', clientId], queryFn: () => listClientUsers(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['client-users', clientId] })

  const create = useMutation({
    mutationFn: () => createClientUser(clientId, form),
    onSuccess: () => { invalidate(); setShowForm(false); setForm({ email: '', password: '' }) },
  })
  const toggle = useMutation({
    mutationFn: ({ userId, is_active }) => updateClientUser(clientId, userId, { is_active }),
    onSuccess: invalidate,
  })

  return (
    <div className="bg-panel border border-border rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-muted uppercase tracking-wide font-mono">Client portal access</h3>
        <button onClick={() => setShowForm((s) => !s)} className="text-xs text-signal hover:underline">
          {showForm ? 'Cancel' : '+ Add login'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="space-y-2 mb-4">
          <input required type="email" placeholder="Email" value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            className="w-full bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input required type="password" minLength={8} placeholder="Temporary password (min 8 chars)" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            className="w-full bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <button type="submit" disabled={create.isPending}
            className="w-full py-2 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
            {create.isPending ? 'Creating…' : 'Create login for this client'}
          </button>
          {create.isError && (
            <p className="text-xs text-critical">{create.error?.response?.data?.detail || 'Could not create login'}</p>
          )}
        </form>
      )}

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : users?.length === 0 ? (
        <p className="text-muted text-sm">No portal logins yet — this client's team can't sign in until you add one.</p>
      ) : (
        <ul className="space-y-2">
          {users?.map((u) => (
            <li key={u.id} className="flex items-center justify-between text-sm py-2 border-b border-border/60 last:border-0">
              <span className="truncate pr-3 font-mono text-xs">{u.email}</span>
              <div className="flex items-center gap-2 shrink-0">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${u.is_active ? 'text-good bg-good/10' : 'text-muted bg-panel2'}`}>
                  {u.is_active ? 'ACTIVE' : 'REVOKED'}
                </span>
                <button
                  onClick={() => toggle.mutate({ userId: u.id, is_active: !u.is_active })}
                  disabled={toggle.isPending}
                  className="text-[11px] px-2 py-1 rounded border border-border hover:border-signal/50 font-mono"
                >
                  {u.is_active ? 'Revoke' : 'Restore'}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
