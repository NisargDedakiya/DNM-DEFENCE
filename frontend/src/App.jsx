import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar.jsx'
import Login from './pages/Login.jsx'
import ClientList from './pages/ClientList.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Assets from './pages/Assets.jsx'
import Findings from './pages/Findings.jsx'
import Reports from './pages/Reports.jsx'
import Compliance from './pages/Compliance.jsx'
import Phishing from './pages/Phishing.jsx'
import SocialEngineering from './pages/SocialEngineering.jsx'
import MobileSecurity from './pages/MobileSecurity.jsx'
import Web3Security from './pages/Web3Security.jsx'
import AISecurity from './pages/AISecurity.jsx'
import DevSecOps from './pages/DevSecOps.jsx'
import RedTeam from './pages/RedTeam.jsx'
import ZeroDayResearch from './pages/ZeroDayResearch.jsx'
import DFIR from './pages/DFIR.jsx'
import { getMe } from './api/client.js'

export default function App() {
  const [user, setUser] = useState(undefined) // undefined = checking, null = logged out

  useEffect(() => {
    const token = localStorage.getItem('track1_token')
    if (!token) { setUser(null); return }
    getMe().then(setUser).catch(() => { localStorage.removeItem('track1_token'); setUser(null) })
  }, [])

  if (user === undefined) {
    return <div className="min-h-screen flex items-center justify-center text-muted text-sm">Loading…</div>
  }

  if (!user) {
    return (
      <Routes>
        <Route path="*" element={<Login onLoggedIn={() => getMe().then(setUser)} />} />
      </Routes>
    )
  }

  const logout = () => { localStorage.removeItem('track1_token'); setUser(null) }
  const homePath = user.role === 'client' ? `/clients/${user.client_id}` : '/'

  return (
    <div className="min-h-screen flex">
      <Sidebar user={user} onLogout={logout} />
      <main className="flex-1 ml-64 p-8 max-w-6xl">
        <Routes>
          <Route path="/" element={user.role === 'client' ? <Navigate to={homePath} replace /> : <ClientList />} />
          <Route path="/zero-day-research" element={<ZeroDayResearch />} />
          <Route path="/clients/:clientId" element={<Dashboard />} />
          <Route path="/clients/:clientId/assets" element={<Assets />} />
          <Route path="/clients/:clientId/findings" element={<Findings />} />
          <Route path="/clients/:clientId/compliance" element={<Compliance />} />
          <Route path="/clients/:clientId/phishing" element={<Phishing />} />
          <Route path="/clients/:clientId/social-engineering" element={<SocialEngineering />} />
          <Route path="/clients/:clientId/mobile-security" element={<MobileSecurity />} />
          <Route path="/clients/:clientId/web3-security" element={<Web3Security />} />
          <Route path="/clients/:clientId/ai-security" element={<AISecurity />} />
          <Route path="/clients/:clientId/devsecops" element={<DevSecOps />} />
          <Route path="/clients/:clientId/red-team" element={<RedTeam />} />
          <Route path="/clients/:clientId/dfir" element={<DFIR />} />
          <Route path="/clients/:clientId/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to={homePath} replace />} />
        </Routes>
      </main>
    </div>
  )
}
