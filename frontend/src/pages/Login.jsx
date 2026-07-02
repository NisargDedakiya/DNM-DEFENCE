import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api/client.js'

export default function Login({ onLoggedIn }) {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { access_token } = await login(email, password)
      localStorage.setItem('track1_token', access_token)
      onLoggedIn()
      navigate('/')
    } catch {
      setError('Incorrect email or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-base">
      <form onSubmit={submit} className="w-full max-w-sm bg-panel border border-border rounded-lg p-8">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-2 h-2 rounded-full bg-signal" />
          <span className="font-mono text-xs tracking-widest text-muted uppercase">Track 1</span>
        </div>
        <h1 className="text-xl font-semibold mb-6">Sign in to Security Portal</h1>

        <div className="space-y-3">
          <input required type="email" placeholder="Email" value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
          <input required type="password" placeholder="Password" value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-panel2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-signal" />
        </div>

        {error && <p className="text-critical text-sm mt-3">{error}</p>}

        <button type="submit" disabled={loading}
          className="w-full mt-5 py-2 bg-signal text-base font-medium rounded-md text-sm hover:brightness-110 transition disabled:opacity-50">
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
