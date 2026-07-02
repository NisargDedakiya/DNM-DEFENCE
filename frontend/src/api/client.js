import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('track1_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('track1_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const login = (email, password) => {
  const form = new URLSearchParams()
  form.append('username', email)
  form.append('password', password)
  return axios.post('/api/auth/login', form, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
    .then(r => r.data)
}
export const getMe = () => api.get('/auth/me').then(r => r.data)

export const listClients = () => api.get('/clients').then(r => r.data)
export const getClient = (id) => api.get(`/clients/${id}`).then(r => r.data)
export const createClient = (payload) => api.post('/clients', payload).then(r => r.data)

export const listAssets = (clientId) => api.get(`/clients/${clientId}/assets`).then(r => r.data)
export const listScans = (clientId) => api.get(`/clients/${clientId}/scans`).then(r => r.data)
export const triggerSubdomainEnum = (clientId) => api.post(`/clients/${clientId}/scans/subdomain-enum`).then(r => r.data)
export const triggerPortScan = (clientId) => api.post(`/clients/${clientId}/scans/port-scan`).then(r => r.data)

export const listFindings = (clientId, params = {}) =>
  api.get(`/clients/${clientId}/findings`, { params }).then(r => r.data)
export const updateFindingStatus = (clientId, findingId, status) =>
  api.patch(`/clients/${clientId}/findings/${findingId}`, { status }).then(r => r.data)
export const triggerVulnScan = (clientId) => api.post(`/clients/${clientId}/findings/scan`).then(r => r.data)
export const triggerDarkWebScan = (clientId) => api.post(`/clients/${clientId}/findings/dark-web-scan`).then(r => r.data)

export const listCloudAccounts = (clientId) => api.get(`/clients/${clientId}/cloud-accounts`).then(r => r.data)
export const triggerCloudAudit = (clientId) => api.post(`/clients/${clientId}/cloud-accounts/audit`).then(r => r.data)

export const listReports = (clientId) => api.get(`/clients/${clientId}/reports`).then(r => r.data)
export const triggerReportGeneration = (clientId) => api.post(`/clients/${clientId}/reports/generate`).then(r => r.data)

export const listComplianceControls = (clientId, framework) =>
  api.get(`/clients/${clientId}/compliance`, { params: framework ? { framework } : {} }).then(r => r.data)
export const getComplianceSummary = (clientId) => api.get(`/clients/${clientId}/compliance/summary`).then(r => r.data)
export const updateComplianceControl = (clientId, controlId, payload) =>
  api.patch(`/clients/${clientId}/compliance/${controlId}`, payload).then(r => r.data)

export const listPhishingCampaigns = (clientId) => api.get(`/clients/${clientId}/phishing-campaigns`).then(r => r.data)
export const createPhishingCampaign = (clientId, payload) => api.post(`/clients/${clientId}/phishing-campaigns`, payload).then(r => r.data)
export const startPhishingCampaign = (clientId, campaignId) => api.post(`/clients/${clientId}/phishing-campaigns/${campaignId}/start`).then(r => r.data)
export const getPhishingTrend = (clientId) => api.get(`/clients/${clientId}/phishing-campaigns/trend`).then(r => r.data)

export const getPentestSchedule = (clientId) => api.get(`/clients/${clientId}/pentest-schedule`).then(r => r.data)
export const createPentestSchedule = (clientId, payload) => api.post(`/clients/${clientId}/pentest-schedule`, payload).then(r => r.data)
export const completePentestEngagement = (clientId, payload = {}) =>
  api.post(`/clients/${clientId}/pentest-schedule/complete`, payload).then(r => r.data)

export default api
