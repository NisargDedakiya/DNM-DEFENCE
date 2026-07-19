import { NavLink, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getSubscription } from '../api/client.js'

const navItem = ({ isActive }) =>
  `block px-3 py-2 rounded-md text-sm transition-colors ${
    isActive ? 'bg-panel2 text-ink border-l-2 border-signal' : 'text-muted hover:text-ink hover:bg-panel2/50'
  }`

export default function Sidebar({ user, onLogout }) {
  // Sidebar is rendered as a sibling of <Routes> in App.jsx, not inside the
  // matched route's subtree, so useParams() (which reads from Routes'
  // RouteContext) always returns {} here. useLocation() is a Router-level
  // context available everywhere, so the client id is parsed from the
  // pathname directly instead.
  const location = useLocation()
  const clientId = location.pathname.match(/^\/clients\/([^/]+)/)?.[1]
  const isStaff = user?.role === 'admin' || user?.role === 'analyst'

  // Entitlements gate what a *client-role* user sees in the nav, so a plan
  // never shows features it doesn't include. Staff see every service (they
  // deliver them regardless of the client's tier), so we skip the fetch.
  const { data: sub } = useQuery({
    queryKey: ['entitlements', clientId],
    queryFn: () => getSubscription(clientId),
    enabled: !!clientId && !isStaff,
  })
  const ent = sub?.entitlements
  // Staff (no ent fetched) => everything visible; client-role => gate on ent.
  const can = (feature) => isStaff || !ent || ent[feature]

  return (
    <aside className="w-64 fixed inset-y-0 left-0 bg-panel border-r border-border flex flex-col">
      <div className="px-5 py-6 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-signal" />
          <span className="font-mono text-xs tracking-widest text-muted uppercase">Track 1</span>
        </div>
        <h1 className="text-lg font-semibold mt-1">Security Portal</h1>
      </div>

      <nav className="flex-1 min-h-0 overflow-y-auto px-3 py-4 space-y-1">
        {isStaff && <NavLink to="/operator" className={navItem}>Operator Overview</NavLink>}
        {isStaff && <NavLink to="/" end className={navItem}>All Clients</NavLink>}
        {isStaff && <NavLink to="/zero-day-research" className={navItem}>Zero Day Research</NavLink>}
        {isStaff && <NavLink to="/system-health" className={navItem}>System Health</NavLink>}

        {clientId && (
          <>
            <div className="px-3 pt-4 pb-1 text-[10px] uppercase tracking-widest text-muted font-mono">This Client</div>
            <NavLink to={`/clients/${clientId}`} end className={navItem}>Overview</NavLink>
            <NavLink to={`/clients/${clientId}/scorecard`} className={navItem}>Security Report Card</NavLink>
            <NavLink to={`/clients/${clientId}/assets`} className={navItem}>Asset Inventory</NavLink>
            <NavLink to={`/clients/${clientId}/findings`} className={navItem}>Vulnerability Tracker</NavLink>
            <NavLink to={`/clients/${clientId}/compliance`} className={navItem}>Compliance Center</NavLink>
            {can('phishing_simulations') && <NavLink to={`/clients/${clientId}/phishing`} className={navItem}>Phishing Simulations</NavLink>}
            <NavLink to={`/clients/${clientId}/reports`} className={navItem}>Report Library</NavLink>
            <NavLink to={`/clients/${clientId}/subscription`} className={navItem}>Subscription</NavLink>

            {(isStaff || can('phishing_simulations') || can('mobile_security') || can('web3_security') || can('ai_security') || can('devsecops')) && (
              <div className="px-3 pt-4 pb-1 text-[10px] uppercase tracking-widest text-muted font-mono">Expanded Services</div>
            )}
            {can('phishing_simulations') && <NavLink to={`/clients/${clientId}/social-engineering`} className={navItem}>Social Engineering</NavLink>}
            {can('mobile_security') && <NavLink to={`/clients/${clientId}/mobile-security`} className={navItem}>Mobile App Security</NavLink>}
            {can('web3_security') && <NavLink to={`/clients/${clientId}/web3-security`} className={navItem}>Web3 &amp; Blockchain</NavLink>}
            {can('ai_security') && <NavLink to={`/clients/${clientId}/ai-security`} className={navItem}>AI/ML Security</NavLink>}
            {can('devsecops') && <NavLink to={`/clients/${clientId}/devsecops`} className={navItem}>DevSecOps</NavLink>}
          </>
        )}

        {isStaff && clientId && (
          <>
            <div className="px-3 pt-4 pb-1 text-[10px] uppercase tracking-widest text-muted font-mono">Advanced Services</div>
            <NavLink to={`/clients/${clientId}/red-team`} className={navItem}>Red Team Operations</NavLink>
            <NavLink to={`/clients/${clientId}/dfir`} className={navItem}>DFIR</NavLink>
            <NavLink to={`/clients/${clientId}/hardware-iot`} className={navItem}>Hardware &amp; IoT Security</NavLink>
            <NavLink to={`/clients/${clientId}/threat-hunting`} className={navItem}>Threat Hunting</NavLink>
          </>
        )}
      </nav>

      <div className="px-5 py-4 border-t border-border">
        <p className="text-xs text-muted truncate mb-2">{user?.email}</p>
        <button onClick={onLogout} className="text-[11px] text-muted hover:text-ink font-mono">Sign out</button>
      </div>
    </aside>
  )
}
