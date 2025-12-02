// 使用相对路径，让Nginx处理代理
const API_BASE_URL = '/api';

// 通用的错误处理函数
const handleResponse = (res, defaultErrorMessage) => {
  if (!res.ok) {
    return res.json().then(err => Promise.reject(new Error(err.error || defaultErrorMessage)));
  }
  return res.json();
};

// 通用的文本响应处理函数
const handleTextResponse = (res, defaultErrorMessage) => {
  if (!res.ok) {
    return res.text().then(err => Promise.reject(new Error(err || defaultErrorMessage)));
  }
  return res.text();
};

export const api = {
  // Authentication
  login: (username, password) => fetch(`${API_BASE_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  }).then(res => handleResponse(res, 'Login failed')),

  changePassword: (username, currentPassword, newPassword) => fetch(`${API_BASE_URL}/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, current_password: currentPassword, new_password: newPassword })
  }).then(res => handleResponse(res, 'Failed to change password')),

  // Servers
  getServers: () => fetch(`${API_BASE_URL}/servers`).then(res => res.json()),
  createServer: (server) => fetch(`${API_BASE_URL}/servers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(server)
  }).then(res => handleResponse(res, 'Failed to create server')),
  updateServer: (id, server) => fetch(`${API_BASE_URL}/servers/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(server)
  }).then(res => handleResponse(res, 'Failed to update server')),
  deleteServer: (id) => fetch(`${API_BASE_URL}/servers/${id}`, {
    method: 'DELETE'
  }),
  toggleServer: (interfaceName, action) => fetch(`${API_BASE_URL}/${action}/${interfaceName}`, {
    method: 'POST'
  }).then(res => handleTextResponse(res, `Failed to ${action} server`)),

  restartServer: (interfaceName) => fetch(`${API_BASE_URL}/restart/${interfaceName}`, {
    method: 'POST'
  }).then(res => handleTextResponse(res, `Failed to restart server`)),

  // Clients
  getClients: () => fetch(`${API_BASE_URL}/clients`).then(res => res.json()),
  searchClients: (query) => fetch(`${API_BASE_URL}/clients/search?q=${encodeURIComponent(query)}`).then(res => res.json()),
  createClient: (client) => fetch(`${API_BASE_URL}/clients`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(client)
  }).then(res => handleResponse(res, 'Failed to create client')),
  updateClient: (id, client) => fetch(`${API_BASE_URL}/clients/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(client)
  }).then(res => handleResponse(res, 'Failed to update client')),
  deleteClient: (id) => fetch(`${API_BASE_URL}/clients/${id}`, {
    method: 'DELETE'
  }),
  toggleClient: (id, action) => fetch(`${API_BASE_URL}/clients/${id}/${action}`, {
    method: 'POST'
  }),
  sendClientConfig: (id, email, language = 'en') => fetch(`${API_BASE_URL}/clients/${id}/send-config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, language })
  }).then(res => handleResponse(res, 'Failed to send configuration')),

  // Status
  getStatus: () => fetch(`${API_BASE_URL}/status`).then(res => res.text()),
  getOnlineClients: () => fetch(`${API_BASE_URL}/online-clients`).then(res => res.json()),

  // Traffic
  getTraffic: () => fetch(`${API_BASE_URL}/traffic`).then(res => res.json()),
  getDetailedTraffic: () => fetch(`${API_BASE_URL}/detailed-traffic`).then(res => res.json()),

  // Interfaces
  getInterfaces: () => fetch(`${API_BASE_URL}/interfaces`).then(res => res.json()),

  // Access Logs
  getAccessLogs: () => fetch(`${API_BASE_URL}/access-logs`).then(res => res.json()),
  searchAccessLogs: (params) => {
    const queryParams = new URLSearchParams(params).toString();
    return fetch(`${API_BASE_URL}/access-logs/search?${queryParams}`).then(res => res.json());
  },
};