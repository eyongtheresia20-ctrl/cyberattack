import axios from 'axios';

const API_BASE = '/api/v1';

// Automatically inject JWT token into all outgoing Axios requests
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishguard_token');
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

export const api = {
  // Threat Analysis
  analyzeUrl: (url, modelChoice = 'rf') => axios.post(`${API_BASE}/analyze/url`, { url, model_choice: modelChoice }),
  analyzeText: (text, sender = '', analysis_type = 'MESSAGE') => 
    axios.post(`${API_BASE}/analyze/text`, { text, sender, analysis_type }),
  getAnalysisStats: () => axios.get(`${API_BASE}/analyze/stats`),
  getAnalysisHistory: () => axios.get(`${API_BASE}/analyze/history`),
  deleteHistoryItem: (recordId) => axios.delete(`${API_BASE}/analyze/history/${recordId}`),

  // Security Monitoring
  ingestLog: (logData) => axios.post(`${API_BASE}/monitor/ingest`, logData),
  getSecurityEvents: (limit = 50) => axios.get(`${API_BASE}/monitor/events?limit=${limit}`),
  seedDemoLogs: () => axios.post(`${API_BASE}/monitor/seed-demo-logs`),
  auditDomain: (domain) => axios.post(`${API_BASE}/monitor/site-audit`, { domain }),

  // Incidents
  getIncidents: () => axios.get(`${API_BASE}/incidents`),
  getIncidentDetails: (id) => axios.get(`${API_BASE}/incidents/${id}`),
  createIncident: (data) => axios.post(`${API_BASE}/incidents/create`, data),
  updateIncidentStatus: (id, status, notes = '') => 
    axios.patch(`${API_BASE}/incidents/${id}/status`, { status, notes }),
  generateReport: (incidentId, reporter) => 
    axios.post(`${API_BASE}/incidents/${incidentId}/generate-report?reporter_name=${encodeURIComponent(reporter)}`),

  // Verification
  verifyReport: (lookupCode, providedHash = '') => 
    axios.post(`${API_BASE}/verify/check`, { lookup_code: lookupCode, provided_hash: providedHash }),

  // AI Assistant
  chatAssistant: (message, contextType = null, contextData = null) => 
    axios.post(`${API_BASE}/assistant/chat`, { message, context_type: contextType, context_data: contextData })
};

