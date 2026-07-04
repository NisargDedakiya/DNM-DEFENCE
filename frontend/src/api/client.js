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

export const listClientUsers = (clientId) => api.get(`/clients/${clientId}/users`).then(r => r.data)
export const createClientUser = (clientId, payload) => api.post(`/clients/${clientId}/users`, payload).then(r => r.data)
export const updateClientUser = (clientId, userId, payload) => api.patch(`/clients/${clientId}/users/${userId}`, payload).then(r => r.data)

export const listAssets = (clientId) => api.get(`/clients/${clientId}/assets`).then(r => r.data)
export const listScans = (clientId) => api.get(`/clients/${clientId}/scans`).then(r => r.data)
export const triggerSubdomainEnum = (clientId) => api.post(`/clients/${clientId}/scans/subdomain-enum`).then(r => r.data)
export const triggerPortScan = (clientId) => api.post(`/clients/${clientId}/scans/port-scan`).then(r => r.data)

export const listFindings = (clientId, params = {}) =>
  api.get(`/clients/${clientId}/findings`, { params }).then(r => r.data)
export const updateFindingStatus = (clientId, findingId, status) =>
  api.patch(`/clients/${clientId}/findings/${findingId}`, { status }).then(r => r.data)
export const assignFinding = (clientId, findingId, assignedTo) =>
  api.patch(`/clients/${clientId}/findings/${findingId}/assign`, { assigned_to: assignedTo }).then(r => r.data)
export const getFindingsTrend = (clientId, months = 3) =>
  api.get(`/clients/${clientId}/findings/trend`, { params: { months } }).then(r => r.data)
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
export const getPhishingResults = (clientId, campaignId) =>
  api.get(`/clients/${clientId}/phishing-campaigns/${campaignId}/results`).then(r => r.data)
export const getTrainingCompletion = (clientId, campaignId) =>
  api.get(`/clients/${clientId}/phishing-campaigns/${campaignId}/training-completion`).then(r => r.data)

export const getPentestSchedule = (clientId) => api.get(`/clients/${clientId}/pentest-schedule`).then(r => r.data)
export const createPentestSchedule = (clientId, payload) => api.post(`/clients/${clientId}/pentest-schedule`, payload).then(r => r.data)
export const completePentestEngagement = (clientId, payload = {}) =>
  api.post(`/clients/${clientId}/pentest-schedule/complete`, payload).then(r => r.data)
export const uploadPentestReport = (clientId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/pentest-schedule/report`, form).then(r => r.data)
}

export const uploadComplianceEvidence = (clientId, controlId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/compliance/${controlId}/evidence`, form).then(r => r.data)
}

// --- SE-1/SE-2/SE-3 Social Engineering & Physical Security ---
export const generateOsintProfile = (clientId, payload) => api.post(`/clients/${clientId}/osint/generate`, payload).then(r => r.data)
export const listOsintProfiles = (clientId) => api.get(`/clients/${clientId}/osint`).then(r => r.data)

export const importPhishingTargets = (clientId, campaignId, rows) =>
  api.post(`/clients/${clientId}/phishing-campaigns/${campaignId}/targets/import`, rows).then(r => r.data)
export const listPhishingTargets = (clientId, campaignId) =>
  api.get(`/clients/${clientId}/phishing-campaigns/${campaignId}/targets`).then(r => r.data)
export const setPhishingTemplate = (clientId, campaignId, payload) =>
  api.patch(`/clients/${clientId}/phishing-campaigns/${campaignId}/template`, payload).then(r => r.data)
export const sendPhishingCampaign = (clientId, campaignId) =>
  api.post(`/clients/${clientId}/phishing-campaigns/${campaignId}/send`).then(r => r.data)
export const getPhishingDebrief = (clientId, campaignId) =>
  api.get(`/clients/${clientId}/phishing-campaigns/${campaignId}/debrief`).then(r => r.data)

export const createVishingEngagement = (clientId, payload) =>
  api.post(`/clients/${clientId}/vishing-engagements`, payload).then(r => r.data)
export const listVishingEngagements = (clientId) => api.get(`/clients/${clientId}/vishing-engagements`).then(r => r.data)
export const uploadVishingRecording = (clientId, engagementId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/vishing-engagements/${engagementId}/recording`, form).then(r => r.data)
}
export const analyzeVishingEngagement = (clientId, engagementId) =>
  api.post(`/clients/${clientId}/vishing-engagements/${engagementId}/analyze`).then(r => r.data)

export const createPhysicalAssessment = (clientId, payload) =>
  api.post(`/clients/${clientId}/physical-security`, payload).then(r => r.data)
export const listPhysicalAssessments = (clientId) => api.get(`/clients/${clientId}/physical-security`).then(r => r.data)
export const updatePhysicalAssessment = (clientId, assessmentId, payload) =>
  api.patch(`/clients/${clientId}/physical-security/${assessmentId}`, payload).then(r => r.data)
export const updatePhysicalChecklistItem = (clientId, assessmentId, itemId, payload) =>
  api.patch(`/clients/${clientId}/physical-security/${assessmentId}/checklist/${itemId}`, payload).then(r => r.data)

// --- MOB-1/MOB-2/MOB-3 Mobile App Security ---
export const uploadMobileApp = (clientId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/mobile-scans`, form).then(r => r.data)
}
export const listMobileScans = (clientId) => api.get(`/clients/${clientId}/mobile-scans`).then(r => r.data)
export const analyzeMobileScan = (clientId, scanId) => api.post(`/clients/${clientId}/mobile-scans/${scanId}/analyze`).then(r => r.data)
export const importMobileTraffic = (clientId, scanId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/mobile-scans/${scanId}/traffic-import`, form).then(r => r.data)
}
export const listMobileTrafficImports = (clientId, scanId) =>
  api.get(`/clients/${clientId}/mobile-scans/${scanId}/traffic-imports`).then(r => r.data)

// --- WEB3-1/WEB3-2/WEB3-3 Blockchain & Web3 Security ---
export const createContractAudit = (clientId, payload) => api.post(`/clients/${clientId}/web3/contract-audits`, payload).then(r => r.data)
export const listContractAudits = (clientId) => api.get(`/clients/${clientId}/web3/contract-audits`).then(r => r.data)
export const createOnchainMonitor = (clientId, payload) => api.post(`/clients/${clientId}/web3/onchain-monitors`, payload).then(r => r.data)
export const listOnchainMonitors = (clientId) => api.get(`/clients/${clientId}/web3/onchain-monitors`).then(r => r.data)
export const updateOnchainMonitor = (clientId, monitorId, isActive) =>
  api.patch(`/clients/${clientId}/web3/onchain-monitors/${monitorId}`, null, { params: { is_active: isActive } }).then(r => r.data)

// --- AI-1/AI-2 AI/ML Security ---
export const createPromptInjectionTest = (clientId, payload) =>
  api.post(`/clients/${clientId}/ai-security/prompt-injection-tests`, payload).then(r => r.data)
export const listPromptInjectionTests = (clientId) => api.get(`/clients/${clientId}/ai-security/prompt-injection-tests`).then(r => r.data)
export const createAiFeature = (clientId, payload) => api.post(`/clients/${clientId}/ai-security/feature-inventory`, payload).then(r => r.data)
export const listAiFeatures = (clientId) => api.get(`/clients/${clientId}/ai-security/feature-inventory`).then(r => r.data)
export const runAiCveCheck = (clientId) => api.get(`/clients/${clientId}/ai-security/cve-check`).then(r => r.data)
export const getAiPostureBrief = (clientId) => api.get(`/clients/${clientId}/ai-security/posture-brief`).then(r => r.data)

// --- DSO-1/2/3/4 DevSecOps ---
export const registerPipeline = (clientId, payload) => api.post(`/clients/${clientId}/devsecops/pipelines`, payload).then(r => r.data)
export const listPipelines = (clientId) => api.get(`/clients/${clientId}/devsecops/pipelines`).then(r => r.data)
export const deployGate = (clientId, pipelineId) => api.post(`/clients/${clientId}/devsecops/pipelines/${pipelineId}/deploy-gate`).then(r => r.data)
export const pollPipeline = (clientId, pipelineId) => api.post(`/clients/${clientId}/devsecops/pipelines/${pipelineId}/poll`).then(r => r.data)

export const triageSarif = (clientId, file) => {
  const form = new FormData(); form.append('file', file)
  return api.post(`/clients/${clientId}/devsecops/triage/sarif`, form).then(r => r.data)
}
export const triageTrivy = (clientId, file) => {
  const form = new FormData(); form.append('file', file)
  return api.post(`/clients/${clientId}/devsecops/triage/trivy`, form).then(r => r.data)
}
export const triageOwaspDc = (clientId, file) => {
  const form = new FormData(); form.append('file', file)
  return api.post(`/clients/${clientId}/devsecops/triage/owasp-dependency-check`, form).then(r => r.data)
}

export const getScorecard = (clientId) => api.get(`/clients/${clientId}/devsecops/scorecard`).then(r => r.data)
export const getScorecardTrend = (clientId) => api.get(`/clients/${clientId}/devsecops/scorecard/trend`).then(r => r.data)
export const snapshotScorecard = (clientId) => api.post(`/clients/${clientId}/devsecops/scorecard/snapshot`).then(r => r.data)

export const runIacScan = (clientId, file) => {
  const form = new FormData(); form.append('file', file)
  return api.post(`/clients/${clientId}/devsecops/iac-scan`, form).then(r => r.data)
}

// --- RT-1 Red Team Operations (analyst/admin only) ---
export const listRedTeamOps = (clientId) => api.get(`/clients/${clientId}/red-team/operations`).then(r => r.data)
export const createRedTeamOp = (clientId, payload) => api.post(`/clients/${clientId}/red-team/operations`, payload).then(r => r.data)
export const getRedTeamOp = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}`).then(r => r.data)
export const updateRedTeamOp = (clientId, opId, payload) => api.patch(`/clients/${clientId}/red-team/operations/${opId}`, payload).then(r => r.data)
export const deleteRedTeamOp = (clientId, opId) => api.delete(`/clients/${clientId}/red-team/operations/${opId}`).then(r => r.data)

export const listRedTeamTimeline = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/timeline`).then(r => r.data)
export const addRedTeamTimelineEntry = (clientId, opId, payload) => api.post(`/clients/${clientId}/red-team/operations/${opId}/timeline`, payload).then(r => r.data)
export const uploadRedTeamEvidence = (clientId, opId, entryId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/red-team/operations/${opId}/timeline/${entryId}/evidence`, form).then(r => r.data)
}

export const listRedTeamImplants = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/implants`).then(r => r.data)
export const addRedTeamImplant = (clientId, opId, payload) => api.post(`/clients/${clientId}/red-team/operations/${opId}/implants`, payload).then(r => r.data)
export const updateRedTeamImplant = (clientId, opId, implantId, payload) => api.patch(`/clients/${clientId}/red-team/operations/${opId}/implants/${implantId}`, payload).then(r => r.data)

export const listRedTeamInfra = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/infrastructure`).then(r => r.data)
export const addRedTeamInfra = (clientId, opId, payload) => api.post(`/clients/${clientId}/red-team/operations/${opId}/infrastructure`, payload).then(r => r.data)
export const checkRedTeamInfraExposure = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/infrastructure/exposure-check`).then(r => r.data)

export const getRedTeamHeatmap = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/heatmap`).then(r => r.data)
export const getRedTeamNarrative = (clientId, opId) => api.get(`/clients/${clientId}/red-team/operations/${opId}/narrative`).then(r => r.data)

// --- ZD-1 Zero Day Research (analyst/admin only, not client-scoped) ---
export const listResearchTargets = () => api.get('/zero-day/targets').then(r => r.data)
export const createResearchTarget = (payload) => api.post('/zero-day/targets', payload).then(r => r.data)
export const updateResearchTarget = (targetId, payload) => api.patch(`/zero-day/targets/${targetId}`, payload).then(r => r.data)
export const deleteResearchTarget = (targetId) => api.delete(`/zero-day/targets/${targetId}`).then(r => r.data)

export const listResearchFindings = (targetId) => api.get(`/zero-day/targets/${targetId}/findings`).then(r => r.data)
export const createResearchFinding = (targetId, payload) => api.post(`/zero-day/targets/${targetId}/findings`, payload).then(r => r.data)
export const updateResearchFinding = (targetId, findingId, payload) => api.patch(`/zero-day/targets/${targetId}/findings/${findingId}`, payload).then(r => r.data)
export const uploadResearchPoc = (targetId, findingId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/zero-day/targets/${targetId}/findings/${findingId}/poc`, form).then(r => r.data)
}
export const lookupFindingCve = (findingId) => api.get(`/zero-day/findings/${findingId}/lookup-cve`).then(r => r.data)
export const getFindingAdvisory = (findingId) => api.get(`/zero-day/findings/${findingId}/advisory`).then(r => r.data)
export const submitFindingHackerOne = (findingId, payload) => api.post(`/zero-day/findings/${findingId}/submit/hackerone`, payload).then(r => r.data)
export const submitFindingBugcrowd = (findingId, payload) => api.post(`/zero-day/findings/${findingId}/submit/bugcrowd`, payload).then(r => r.data)
export const publishFindingAdvisory = (findingId, payload) => api.post(`/zero-day/findings/${findingId}/publish-advisory`, payload).then(r => r.data)

export const listFuzzingJobs = (targetId) => api.get(`/zero-day/targets/${targetId}/fuzzing-jobs`).then(r => r.data)
export const createFuzzingJob = (targetId, payload) => api.post(`/zero-day/targets/${targetId}/fuzzing-jobs`, payload).then(r => r.data)
export const updateFuzzingJob = (targetId, jobId, payload) => api.patch(`/zero-day/targets/${targetId}/fuzzing-jobs/${jobId}`, payload).then(r => r.data)

// --- DFIR-1/DFIR-2 Incident Response Case Manager & Log Analyzer (analyst/admin only) ---
export const listDfirCases = (clientId) => api.get(`/clients/${clientId}/dfir/cases`).then(r => r.data)
export const createDfirCase = (clientId, payload) => api.post(`/clients/${clientId}/dfir/cases`, payload).then(r => r.data)
export const updateDfirCase = (clientId, caseId, payload) => api.patch(`/clients/${clientId}/dfir/cases/${caseId}`, payload).then(r => r.data)

export const listDfirEvidence = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/evidence`).then(r => r.data)
export const uploadDfirEvidence = (clientId, caseId, file, meta) => {
  const form = new FormData()
  form.append('file', file)
  Object.entries(meta).forEach(([k, v]) => form.append(k, v))
  return api.post(`/clients/${clientId}/dfir/cases/${caseId}/evidence`, form).then(r => r.data)
}
export const addDfirCustodyEntry = (clientId, caseId, evidenceId, payload) =>
  api.post(`/clients/${clientId}/dfir/cases/${caseId}/evidence/${evidenceId}/custody`, payload).then(r => r.data)

export const listDfirIocs = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/iocs`).then(r => r.data)
export const addDfirIoc = (clientId, caseId, payload) => api.post(`/clients/${clientId}/dfir/cases/${caseId}/iocs`, payload).then(r => r.data)

export const listDfirTimeline = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/timeline`).then(r => r.data)
export const addDfirTimelineEntry = (clientId, caseId, payload) => api.post(`/clients/${clientId}/dfir/cases/${caseId}/timeline`, payload).then(r => r.data)

export const getDfirExecutiveReport = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/reports/executive`).then(r => r.data)
export const getDfirTechnicalReport = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/reports/technical`).then(r => r.data)

export const getDfirRetainer = (clientId) => api.get(`/clients/${clientId}/dfir/retainer`).then(r => r.data)
export const upsertDfirRetainer = (clientId, payload) => api.put(`/clients/${clientId}/dfir/retainer`, payload).then(r => r.data)

export const listDfirLogAnalysisJobs = (clientId, caseId) => api.get(`/clients/${clientId}/dfir/cases/${caseId}/log-analysis`).then(r => r.data)
export const uploadDfirLogForAnalysis = (clientId, caseId, file, logType) => {
  const form = new FormData()
  form.append('file', file)
  form.append('log_type', logType)
  return api.post(`/clients/${clientId}/dfir/cases/${caseId}/log-analysis/upload`, form).then(r => r.data)
}

// --- IOT-1 Hardware & IoT Firmware Analyzer (analyst/admin only) ---
export const listFirmwareScans = (clientId) => api.get(`/clients/${clientId}/firmware-scans`).then(r => r.data)
export const uploadFirmware = (clientId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/clients/${clientId}/firmware-scans`, form).then(r => r.data)
}
export const analyzeFirmwareScan = (clientId, scanId) => api.post(`/clients/${clientId}/firmware-scans/${scanId}/analyze`).then(r => r.data)

// Authenticated file downloads must go through axios (so the Bearer token
// header is attached) rather than a plain <a href> -- this app has no
// cookie-based session, so a bare anchor tag hitting an authenticated
// endpoint would 401. Fetches as a blob, then triggers a normal browser
// save-as via a throwaway object URL.
export const downloadAuthenticatedFile = async (url, filename) => {
  const res = await api.get(url, { responseType: 'blob' })
  const blobUrl = window.URL.createObjectURL(res.data)
  const link = document.createElement('a')
  link.href = blobUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(blobUrl)
}

export default api
