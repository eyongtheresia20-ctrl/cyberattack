import axios from 'axios';

const API_BASE = '/api/v1';

export const api = {
  // Threat Analysis
  analyzeUrl: (url) => axios.post(`${API_BASE}/analyze/url`, { url }),
  analyzeText: (text, sender, analysis_type = 'MESSAGE') => 
    axios.post(`${API_BASE}/analyze/text`, { text, sender, analysis_type }),

  // Security Monitoring
  ingestLog: (logData) => axios.post(`${API_BASE}/monitor/ingest`, logData),
  getSecurityEvents: (limit = 50) => axios.get(`${API_BASE}/monitor/events?limit=${limit}`),
  seedDemoLogs: () => axios.post(`${API_BASE}/monitor/seed-demo-logs`),
  auditDomain: (domain) => axios.post(`${API_BASE}/monitor/site-audit`, { domain }),

  // Incidents
  getIncidents: () => axios.get(`${API_BASE}/incidents`),
  getIncidentDetails: (id) => axios.get(`${API_BASE}/incidents/${id}`),
  createIncident: (data) => axios.post(`${API_BASE}/incidents/create`, data),
  generateReport: (incidentId, reporter) => 
    axios.post(`${API_BASE}/incidents/${incidentId}/generate-report?reporter_name=${encodeURIComponent(reporter)}`),

  // Verification
  verifyReport: (lookupCode, providedHash = '') => 
    axios.post(`${API_BASE}/verify/check`, { lookup_code: lookupCode, provided_hash: providedHash }),

  // AI Assistant
  chatAssistant: (message, contextType = null, contextData = null) => 
    axios.post(`${API_BASE}/assistant/chat`, { message, context_type: contextType, context_data: contextData })
};
