import { NavLink, useParams } from 'react-router-dom'

const navItem = ({ isActive }) =>
  `block px-3 py-2 rounded-md text-sm transition-colors ${
    isActive ? 'bg-panel2 text-ink border-l-2 border-signal' : 'text-muted hover:text-ink hover:bg-panel2/50'
  }`

export default function Sidebar({ user, onLogout }) {
  const { clientId } = useParams()
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

      <nav className="flex-1 px-3 py-4 space-y-1">
        {isStaff && <NavLink to="/" end className={navItem}>All Clients</NavLink>}

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
