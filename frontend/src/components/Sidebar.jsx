import { NavLink, useLocation } from 'react-router-dom'

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
            <NavLink to={`/clients/${clientId}/assets`} className={navItem}>Asset Inventory</NavLink>
            <NavLink to={`/clients/${clientId}/findings`} className={navItem}>Vulnerability Tracker</NavLink>
            <NavLink to={`/clients/${clientId}/compliance`} className={navItem}>Compliance Center</NavLink>
            <NavLink to={`/clients/${clientId}/phishing`} className={navItem}>Phishing Simulations</NavLink>
            <NavLink to={`/clients/${clientId}/reports`} className={navItem}>Report Library</NavLink>

            <div className="px-3 pt-4 pb-1 text-[10px] uppercase tracking-widest text-muted font-mono">Expanded Services</div>
            <NavLink to={`/clients/${clientId}/social-engineering`} className={navItem}>Social Engineering</NavLink>
            <NavLink to={`/clients/${clientId}/mobile-security`} className={navItem}>Mobile App Security</NavLink>
            <NavLink to={`/clients/${clientId}/web3-security`} className={navItem}>Web3 &amp; Blockchain</NavLink>
            <NavLink to={`/clients/${clientId}/ai-security`} className={navItem}>AI/ML Security</NavLink>
            <NavLink to={`/clients/${clientId}/devsecops`} className={navItem}>DevSecOps</NavLink>
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
