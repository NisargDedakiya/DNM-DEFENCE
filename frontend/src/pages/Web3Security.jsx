import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  createContractAudit, listContractAudits, createOnchainMonitor, listOnchainMonitors, updateOnchainMonitor,
  downloadAuthenticatedFile,
} from '../api/client.js'

const SEVERITY_TONE = { critical: 'text-critical', high: 'text-high', medium: 'text-signal', low: 'text-muted', info: 'text-muted' }
const TABS = ['Smart Contract Audits', 'On-Chain Monitoring']

export default function Web3Security() {
  const [tab, setTab] = useState(TABS[0])
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Blockchain &amp; Web3 Security</h2>
        <p className="text-muted text-sm">Smart contract static analysis and interval-based on-chain transaction monitoring.</p>
      </div>
      <div className="flex gap-2 mb-6 border-b border-border">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm font-mono ${tab === t ? 'text-signal border-b-2 border-signal' : 'text-muted hover:text-ink'}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === 'Smart Contract Audits' && <ContractAuditsPanel />}
      {tab === 'On-Chain Monitoring' && <OnchainMonitorsPanel />}
    </div>
  )
}

function ContractAuditsPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [contractName, setContractName] = useState('')
  const [network, setNetwork] = useState('ethereum')
  const [source, setSource] = useState('')

  const { data: audits, isLoading } = useQuery({ queryKey: ['web3-audits', clientId], queryFn: () => listContractAudits(clientId) })
  const create = useMutation({
    mutationFn: () => createContractAudit(clientId, { contract_name: contractName, contract_source: source, network }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['web3-audits', clientId] }); setContractName(''); setSource('') },
  })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="bg-panel border border-border rounded-lg p-5 mb-6">
        <div className="grid grid-cols-2 gap-3 mb-3">
          <input required placeholder="Contract name" value={contractName} onChange={(e) => setContractName(e.target.value)}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <select value={network} onChange={(e) => setNetwork(e.target.value)}
            className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal">
            <option value="ethereum">Ethereum</option>
            <option value="polygon">Polygon</option>
            <option value="bsc">BNB Chain</option>
            <option value="arbitrum">Arbitrum</option>
          </select>
        </div>
        <textarea required placeholder="Paste Solidity source here (pragma solidity ...; contract ... { ... })"
          value={source} onChange={(e) => setSource(e.target.value)} rows={6}
          className="w-full bg-panel2 border border-border rounded px-3 py-2 text-xs font-mono outline-none focus:border-signal mb-3" />
        <button type="submit" disabled={create.isPending} className="py-2 px-4 bg-signal text-base font-medium rounded-md text-sm disabled:opacity-50">
          {create.isPending ? 'Scanning (Slither + Semgrep)…' : 'Run scan'}
        </button>
      </form>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : audits?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No contract audits yet.</div>
      ) : (
        <div className="space-y-3">
          {audits?.map((a) => (
            <div key={a.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="font-medium">{a.contract_name}</h3>
                  <p className="text-xs text-muted mt-0.5">{a.network} {a.solc_version_hint && `· solc ${a.solc_version_hint}`}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${
                    a.status === 'completed' ? 'text-good bg-good/10' : a.status === 'failed' ? 'text-critical bg-critical/10' : 'text-muted bg-panel2'
                  }`}>{a.status}</span>
                  {a.status === 'completed' && (
                    <button onClick={() => downloadAuthenticatedFile(`/clients/${clientId}/web3/contract-audits/${a.id}/export/pdf`, `${a.contract_name}-audit.pdf`)}
                      className="text-xs px-3 py-1.5 rounded border border-border hover:border-signal/50 font-mono">
                      PDF
                    </button>
                  )}
                </div>
              </div>
              {a.error_message && <p className="text-xs text-critical mb-2">{a.error_message}</p>}
              {a.findings?.length > 0 ? (
                <ul className="text-xs space-y-1">
                  {a.findings.map((f, i) => (
                    <li key={i}>
                      <span className={`font-mono uppercase ${SEVERITY_TONE[f.severity] || 'text-ink'}`}>[{f.severity}]</span>{' '}
                      <span className="font-mono text-muted">{f.tool}/{f.check}</span> — {f.description}
                      {f.ai_verdict === 'LIKELY_FALSE_POSITIVE' && <span className="text-muted italic"> (AI: likely false positive)</span>}
                    </li>
                  ))}
                </ul>
              ) : a.status === 'completed' && <p className="text-xs text-good">No findings from Slither/Semgrep.</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function OnchainMonitorsPanel() {
  const { clientId } = useParams()
  const qc = useQueryClient()
  const [address, setAddress] = useState('')
  const [network, setNetwork] = useState('ethereum')

  const { data: monitors, isLoading } = useQuery({ queryKey: ['web3-monitors', clientId], queryFn: () => listOnchainMonitors(clientId) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['web3-monitors', clientId] })
  const create = useMutation({
    mutationFn: () => createOnchainMonitor(clientId, { contract_address: address, network }),
    onSuccess: () => { invalidate(); setAddress('') },
  })
  const toggle = useMutation({ mutationFn: ({ id, active }) => updateOnchainMonitor(clientId, id, active), onSuccess: invalidate })

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-3 mb-6">
        <input required placeholder="Contract address (0x...)" value={address} onChange={(e) => setAddress(e.target.value)}
          className="flex-1 bg-panel2 border border-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-signal" />
        <select value={network} onChange={(e) => setNetwork(e.target.value)}
          className="bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal">
          <option value="ethereum">Ethereum</option>
          <option value="polygon">Polygon</option>
        </select>
        <button type="submit" disabled={create.isPending} className="px-4 py-2 bg-signal text-base font-medium rounded-md text-sm">Add monitor</button>
      </form>
      <p className="text-xs text-muted mb-4 italic">Polls every few minutes (configurable), not block-by-block. Requires ETHERSCAN_API_KEY server-side.</p>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : monitors?.length === 0 ? (
        <div className="border border-dashed border-border rounded-lg p-10 text-center text-muted">No contracts under monitoring yet.</div>
      ) : (
        <div className="space-y-3">
          {monitors?.map((m) => (
            <div key={m.id} className="bg-panel border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="font-mono text-sm">{m.contract_address}</h3>
                  <p className="text-xs text-muted mt-0.5">{m.network} &middot; last checked block {m.last_checked_block ?? '—'}</p>
                </div>
                <button onClick={() => toggle.mutate({ id: m.id, active: !m.is_active })}
                  className={`text-xs px-3 py-1.5 rounded border font-mono ${m.is_active ? 'border-good/50 text-good' : 'border-border text-muted'}`}>
                  {m.is_active ? 'Active' : 'Paused'}
                </button>
              </div>
              {m.last_alerts?.length > 0 && (
                <ul className="text-xs space-y-1">
                  {m.last_alerts.map((a, i) => <li key={i} className="text-high">{a.note}</li>)}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
