import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';

const Clients = () => {
  const [clients, setClients] = useState([]);
  const [servers, setServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingClient, setEditingClient] = useState(null);
  const [expandedServers, setExpandedServers] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [showSearchIframe, setShowSearchIframe] = useState(false);
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [emailFormData, setEmailFormData] = useState({
    clientId: null,
    clientName: '',
    email: ''
  });

  const { language } = useLanguage();
  const [emailSending, setEmailSending] = useState(false);
  const [emailMessage, setEmailMessage] = useState('');
  const [emailError, setEmailError] = useState('');
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    address: '',
    private_key: '',
    public_key: '',
    preshared_key: '',
    allowed_ips: '',
    server_allowed_ips: '',
    client_allowed_ips: '',
    server_id: '',
    autoGenerateKeys: true,
    autoGeneratePresharedKey: false, // 默认不自动生成预共享密钥
    persistent_keepalive: 25, // 默认值为25秒
    dns: '',
    mtu: ''
  });

  // 分页状态
  const [currentPage, setCurrentPage] = useState({});

  useEffect(() => {
    fetchClients();
    fetchServers();
  }, []);

  const fetchClients = async () => {
    try {
      const data = await api.getClients();
      setClients(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching clients:', error);
      setLoading(false);
    }
  };

  const fetchServers = async () => {
    try {
      const data = await api.getServers();
      setServers(data);
    } catch (error) {
      console.error('Error fetching servers:', error);
    }
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      alert('Please enter a search query');
      return;
    }

    try {
      const results = await api.searchClients(searchQuery);
      setSearchResults(results);
      setShowSearchResults(true);
      setShowSearchIframe(true); // 使用iframe模式显示搜索结果
    } catch (error) {
      console.error('Error searching clients:', error);
      alert('Error searching clients: ' + error.message);
    }
  };

  const closeSearchIframe = () => {
    setShowSearchIframe(false);
    setSearchResults([]);
    setShowSearchResults(false);
  };

  // 打开发送邮件模态框或直接发送邮件
  const openEmailModal = async (clientId, clientName) => {
    // 首先查找客户端是否有配置的邮箱
    const client = [...clients, ...searchResults].find(c => c.id === clientId);
    if (client && client.email) {
      // 如果客户端有配置邮箱，直接发送邮件
      setEmailSending(true);
      setEmailError('');
      setEmailMessage('');

      try {
        await api.sendClientConfig(clientId, client.email, language);
        alert(`已发送至${client.email}`);
        setEmailSending(false);
      } catch (error) {
        setEmailError('Failed to send configuration: ' + error.message);
        setEmailSending(false);
        // 如果发送失败，还是显示输入框让用户手动输入
        setEmailFormData({
          clientId,
          clientName,
          email: client.email || ''
        });
        setEmailMessage('');
        setEmailError('');
        setShowEmailModal(true);
      }
    } else {
      // 如果没有配置邮箱，显示输入框
      setEmailFormData({
        clientId,
        clientName,
        email: ''
      });
      setEmailMessage('');
      setEmailError('');
      setShowEmailModal(true);
    }
  };

  // 关闭发送邮件模态框
  const closeEmailModal = () => {
    setShowEmailModal(false);
    setEmailFormData({
      clientId: null,
      clientName: '',
      email: ''
    });
    setEmailMessage('');
    setEmailError('');
  };

  // 处理邮箱输入变化
  const handleEmailChange = (e) => {
    setEmailFormData(prev => ({
      ...prev,
      email: e.target.value
    }));
  };

  // 验证邮箱格式
  const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  // 发送配置文件到邮箱
  const sendConfigToEmail = async (e) => {
    e.preventDefault();

    // 验证邮箱格式
    if (!validateEmail(emailFormData.email)) {
      setEmailError('Please enter a valid email address');
      return;
    }

    setEmailSending(true);
    setEmailError('');
    setEmailMessage('');

    try {
      await api.sendClientConfig(emailFormData.clientId, emailFormData.email, language);
      setEmailMessage(`Configuration for ${emailFormData.clientName} sent successfully to ${emailFormData.email}`);
      setEmailSending(false);

      // 3秒后自动关闭模态框
      setTimeout(() => {
        closeEmailModal();
      }, 3000);
    } catch (error) {
      setEmailError('Failed to send configuration: ' + error.message);
      setEmailSending(false);
    }
  };

  const clearSearch = () => {
    setSearchQuery('');
    setSearchResults([]);
    setShowSearchResults(false);
  };

  // 验证DNS格式
  const validateDNS = (dns) => {
    if (!dns) return true; // 空值是允许的

    const dnsAddresses = dns.split(',');
    for (let dnsAddr of dnsAddresses) {
      dnsAddr = dnsAddr.trim();
      // 检查是否是有效的IP地址或域名
      // 简单的验证：不为空且不包含非法字符
      if (!dnsAddr || dnsAddr.length === 0) {
        return false;
      }
    }

    return true;
  };

  // 验证MTU值
  const validateMTU = (mtu) => {
    if (!mtu) return true; // 空值是允许的

    const mtuValue = parseInt(mtu, 10);
    return mtuValue > 0 && mtuValue < 1600;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // 前端验证DNS和MTU
    if (formData.dns && !validateDNS(formData.dns)) {
      alert('DNS地址格式不正确，每个DNS地址不能为空，多个地址用英文逗号分隔');
      return;
    }

    if (formData.mtu && !validateMTU(formData.mtu)) {
      alert('MTU值必须大于0且小于1600');
      return;
    }

    try {
      // 如果选择了自动生成密钥，则从表单数据中移除密钥字段
      let submitData = { ...formData };
      // 转换 server_id 为整数类型
      submitData.server_id = parseInt(submitData.server_id, 10);
      // 转换 MTU 为整数类型，如果为空则设置为0
      if (submitData.mtu === '' || submitData.mtu === null || submitData.mtu === undefined) {
        submitData.mtu = 0;
      } else {
        submitData.mtu = parseInt(submitData.mtu, 10);
        if (isNaN(submitData.mtu)) {
          submitData.mtu = 0;
        }
      }
      // 在创建模式下，如果选择了自动生成密钥，则移除密钥字段
      // 在编辑模式下，始终保留密钥字段
      if (!editingClient && submitData.autoGenerateKeys) {
        delete submitData.private_key;
        delete submitData.public_key;
      }
      // 在创建模式下，如果选择了自动生成预共享密钥，则移除预共享密钥字段
      // 在编辑模式下，始终保留预共享密钥字段
      if (!editingClient && submitData.autoGeneratePresharedKey) {
        delete submitData.preshared_key;
      }
      delete submitData.autoGenerateKeys;
      // Note: autoGeneratePresharedKey is NOT deleted because it needs to be sent to backend
      // to indicate that the backend should auto-generate the preshared key

      if (editingClient) {
        await api.updateClient(editingClient.id, submitData);
      } else {
        await api.createClient(submitData);
      }
      fetchClients();
      resetForm();
    } catch (error) {
      console.error('Error saving client:', error);
      alert('Error: ' + error.message); // 直接显示错误信息
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this client?')) {
      try {
        await api.deleteClient(id);
        // 重置分页状态，确保不会出现错误的分页显示
        setCurrentPage({});
        fetchClients();

        // 从搜索结果中移除已删除的客户端
        setSearchResults(prevResults =>
          prevResults.filter(client => client.id !== id)
        );

        // 如果搜索结果为空，关闭搜索界面
        setSearchResults(prevResults => {
          const newResults = prevResults.filter(client => client.id !== id);
          if (newResults.length === 0) {
            setShowSearchResults(false);
            setShowSearchIframe(false);
          }
          return newResults;
        });
      } catch (error) {
        console.error('Error deleting client:', error);
      }
    }
  };

  const downloadClientConfig = async (id) => {
    try {
      // 创建一个临时的iframe来触发下载
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = `/api/clients/${id}/config`;
      document.body.appendChild(iframe);

      // 下载完成后移除iframe
      setTimeout(() => {
        document.body.removeChild(iframe);
      }, 1000);
    } catch (error) {
      console.error('Error downloading client config:', error);
      alert('Error downloading client config: ' + error.message);
    }
  };

  const toggleClient = async (id, currentlyEnabled) => {
    try {
      if (currentlyEnabled) {
        await fetch(`/api/clients/${id}/disable`, { method: 'POST' });
      } else {
        await fetch(`/api/clients/${id}/enable`, { method: 'POST' });
      }
      fetchClients();

      // 更新搜索结果中的客户端状态
      setSearchResults(prevResults =>
        prevResults.map(client =>
          client.id === id
            ? { ...client, enabled: currentlyEnabled ? 0 : 1 }
            : client
        )
      );
    } catch (error) {
      console.error('Error toggling client:', error);
      alert('Error toggling client: ' + error.message);
    }
  };

  const toggleServerExpansion = (serverId) => {
    setExpandedServers(prev => ({
      ...prev,
      [serverId]: !prev[serverId]
    }));
  };

  const resetForm = () => {
    setFormData({
      name: '',
      email: '',
      address: '',
      private_key: '',
      public_key: '',
      preshared_key: '',
      allowed_ips: '',
      server_allowed_ips: '',
      client_allowed_ips: '',
      server_id: '',
      autoGenerateKeys: true,
      autoGeneratePresharedKey: false, // 默认不自动生成预共享密钥
      persistent_keepalive: 25, // 默认值为25秒
      dns: '',
      mtu: ''
    });
    setEditingClient(null);
    setShowForm(false);
  };

  const startEdit = (client) => {
    setFormData({
      ...client,
      // 处理可能为null的字段，防止它们被发送到后端时造成问题
      server_allowed_ips: client.server_allowed_ips || '',
      client_allowed_ips: client.client_allowed_ips || '',
      // 保持其他字段不变
      autoGeneratePresharedKey: false // 在编辑模式下，默认不自动生成预共享密钥
    });
    setEditingClient(client);
    setShowForm(true);
    // 关闭搜索界面
    setShowSearchIframe(false);
    setShowSearchResults(false);
  };

  if (loading) return <div>Loading clients...</div>;

  return (
    <div className="clients-container">
      <div className="header">
        <h2>{t('clients.title', language)}</h2>
        <button className="btn-primary" onClick={() => setShowForm(true)}>
          {t('clients.create', language)}
        </button>
      </div>

      {/* 搜索表单 */}
      <div className="search-container">
        <form onSubmit={handleSearch} className="search-form">
          <div className="search-row">
            <div className="search-group">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('clients.searchPlaceholder', language)}
                className="search-input"
              />
            </div>
            <div className="search-actions">
              <button type="submit" className="btn-primary search-button">
                {t('clients.search', language)}
              </button>
              {showSearchResults && (
                <button type="button" className="btn-secondary clear-search-button" onClick={clearSearch}>
                  {t('clients.clearSearch', language)}
                </button>
              )}
            </div>
          </div>
        </form>
      </div>

      {/* 搜索结果iframe展示 */}
      {showSearchIframe && (
        <div className="modal-overlay">
          <div className="modal-content" style={{width: '90%', maxWidth: '1200px'}}>
            <div className="modal-header">
              <h3>{t('clients.searchResults', language, { count: searchResults.length })}</h3>
              <button className="modal-close" onClick={closeSearchIframe}>
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="clients-list">
                {searchResults.map(client => {
                  const server = servers.find(s => s.id == client.server_id) || { name: `Server ${client.server_id}` };
                  return (
                    <div key={client.id} className="client-card">
                      <div className="client-header">
                        <h4>{client.name}</h4>
                        <span className={`status-badge ${client.status}`}>{client.status}</span>
                      </div>
                      <div className="client-details">
                        <p><strong>{t('clients.server', language)}:</strong> {server.name}</p>
                        <p><strong>{t('clients.address', language)}:</strong> {client.address}</p>
                      </div>
                      <div className="client-actions" style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <button className="btn-download" onClick={() => downloadClientConfig(client.id)}>
                          {t('clients.download', language)}
                        </button>
                        <button className="btn-info" onClick={() => openEmailModal(client.id, client.name)}>
                          {t('clients.sendEmail', language)}
                        </button>
                        <button className="btn-secondary" onClick={() => startEdit(client)}>
                          {t('clients.edit', language)}
                        </button>
                        <button
                          className={client.enabled ? 'btn-toggle' : 'btn-toggle disabled'}
                          onClick={() => toggleClient(client.id, client.enabled)}
                        >
                          {client.enabled ? t('clients.disable', language) : t('clients.enable', language)}
                        </button>
                        <button className="btn-danger" onClick={() => handleDelete(client.id)}>
                          {t('clients.delete', language)}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 邮箱发送模态框 */}
      {showEmailModal && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ width: '400px' }}>
            <div className="modal-header">
              <h3>{t('clients.sendEmailTitle', language)}</h3>
              <button className="modal-close" onClick={closeEmailModal}>
                ×
              </button>
            </div>
            <form onSubmit={sendConfigToEmail}>
              <div className="modal-body">
                <div className="form-group">
                  <label>{t('clients.clientName', language)}</label>
                  <input
                    type="text"
                    value={emailFormData.clientName}
                    disabled
                    className="form-control"
                    style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
                  />
                </div>
                <div className="form-group">
                  <label>{t('clients.emailAddress', language)}</label>
                  <input
                    type="email"
                    value={emailFormData.email}
                    onChange={handleEmailChange}
                    placeholder={t('clients.emailPlaceholder', language)}
                    className="form-control"
                    style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
                    required
                  />
                </div>
                {emailError && (
                  <div className="error-message" style={{ color: '#e74c3c', marginBottom: '10px' }}>
                    {emailError}
                  </div>
                )}
                {emailMessage && (
                  <div className="success-message" style={{ color: '#27ae60', marginBottom: '10px' }}>
                    {emailMessage}
                  </div>
                )}
              </div>
              <div className="modal-footer">
                <button type="button" className="btn-secondary" onClick={closeEmailModal} disabled={emailSending}>
                  {t('clients.cancel', language)}
                </button>
                <button type="submit" className="btn-primary" disabled={emailSending}>
                  {emailSending ? t('clients.sending', language) : t('clients.sendConfiguration', language)}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showForm && (
        <form className="form" onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="form-group">
              <label>{t('clients.name', language)}</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                required
              />
            </div>

            <div className="form-group">
              <label>{t('clients.email', language)}</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                placeholder={t('clients.emailOptional', language)}
                pattern="^[^\s@]+@[^\s@]+\.[^\s@]+$"
                title={t('clients.emailTitle', language)}
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>{t('clients.address', language)}</label>
              <input
                type="text"
                value={formData.address}
                onChange={(e) => setFormData({...formData, address: e.target.value})}
                placeholder={t('clients.addressPlaceholder', language)}
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$|(^$)"
                title={t('clients.addressTitle', language)}
              />
            </div>

            <div className="form-group">
              <label>{t('clients.server', language)}</label>
              <select
                value={formData.server_id}
                onChange={(e) => setFormData({...formData, server_id: e.target.value})}
                required
              >
                <option value="">{t('clients.selectServer', language)}</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>
                    {server.name} (ID: {server.id})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>{t('clients.serverAllowedIPs', language)}</label>
              <input
                type="text"
                value={formData.server_allowed_ips}
                onChange={(e) => setFormData({...formData, server_allowed_ips: e.target.value})}
                placeholder={t('clients.serverAllowedIPsPlaceholder', language)}
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(,([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})*$|(^$)"
                title={t('clients.serverAllowedIPsTitle', language)}
              />
            </div>

            <div className="form-group">
              <label>{t('clients.clientAllowedIPs', language)}</label>
              <input
                type="text"
                value={formData.client_allowed_ips}
                onChange={(e) => setFormData({...formData, client_allowed_ips: e.target.value})}
                placeholder={t('clients.clientAllowedIPsPlaceholder', language)}
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(,([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})*$|(^$)"
                title={t('clients.clientAllowedIPsTitle', language)}
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>{t('clients.persistentKeepalive', language)}</label>
              <input
                type="number"
                value={formData.persistent_keepalive}
                onChange={(e) => setFormData({...formData, persistent_keepalive: parseInt(e.target.value) || 0})}
                min="0"
                placeholder="25"
                title={t('clients.persistentKeepaliveTitle', language)}
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>DNS</label>
              <input
                type="text"
                value={formData.dns}
                onChange={(e) => setFormData({...formData, dns: e.target.value})}
                placeholder={t('clients.dnsPlaceholder', language)}
                title={t('clients.dnsTitle', language)}
              />
            </div>

            <div className="form-group">
              <label>MTU</label>
              <input
                type="number"
                value={formData.mtu || ''}
                onChange={(e) => {
                  const value = e.target.value;
                  setFormData({...formData, mtu: value === '' ? 0 : parseInt(value) || 0});
                }}
                min="0"
                max="1599"
                placeholder={t('clients.mtuPlaceholder', language)}
                title={t('clients.mtuTitle', language)}
              />
            </div>
          </div>

          {/* 在创建模式下显示Auto-generate preshared key复选框 */}
          {!editingClient && (
            <div className="form-group" style={{ display: 'flex', alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, flexDirection: 'row-reverse', justifyContent: 'flex-end', whiteSpace: 'nowrap' }}>
                {t('clients.autoGeneratePresharedKey', language)}
                <input
                  type="checkbox"
                  checked={formData.autoGeneratePresharedKey}
                  onChange={(e) => setFormData({...formData, autoGeneratePresharedKey: e.target.checked})}
                  style={{ marginLeft: '0.5rem' }}
                />
              </label>
            </div>
          )}

          {/* 在创建模式下显示Auto-generate key pair复选框 */}
          {!editingClient && (
            <div className="form-group" style={{ display: 'flex', alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, flexDirection: 'row-reverse', justifyContent: 'flex-end', whiteSpace: 'nowrap' }}>
                {t('clients.autoGenerateKeyPair', language)}
                <input
                  type="checkbox"
                  checked={formData.autoGenerateKeys}
                  onChange={(e) => setFormData({...formData, autoGenerateKeys: e.target.checked})}
                  style={{ marginLeft: '0.5rem' }}
                />
              </label>
            </div>
          )}

          {/* 在创建模式下，仅当不自动生成密钥时显示密钥字段 */}
          {/* 在编辑模式下，始终显示密钥字段并设为只读 */}
          {(!editingClient && !formData.autoGenerateKeys) || editingClient ? (
            <>
              <div className="form-row">
                <div className="form-group">
                  <label>{t('clients.privateKey', language)}</label>
                  <textarea
                    value={formData.private_key}
                    onChange={(e) => setFormData({...formData, private_key: e.target.value})}
                    required={!editingClient && !formData.autoGenerateKeys}
                    readOnly={!!editingClient}
                    style={editingClient ? { backgroundColor: '#f5f5f5', cursor: 'not-allowed' } : {}}
                  />
                </div>
                <div className="form-group">
                  <label>{t('clients.publicKey', language)}</label>
                  <textarea
                    value={formData.public_key}
                    onChange={(e) => setFormData({...formData, public_key: e.target.value})}
                    required={!editingClient && !formData.autoGenerateKeys}
                    readOnly={!!editingClient}
                    style={editingClient ? { backgroundColor: '#f5f5f5', cursor: 'not-allowed' } : {}}
                  />
                </div>
              </div>

              {/* Preshared Key字段 - 仅在编辑模式下或选择了自动生成预共享密钥时显示 */}
              {editingClient || formData.autoGeneratePresharedKey ? (
                <div className="form-group">
                  <label>{t('clients.presharedKey', language)}</label>
                  <textarea
                    value={formData.preshared_key}
                    onChange={(e) => setFormData({...formData, preshared_key: e.target.value})}
                    readOnly={!!editingClient || formData.autoGeneratePresharedKey}
                    placeholder={editingClient ? "" : (formData.autoGeneratePresharedKey ? t('clients.autoGenerated', language) : t('clients.presharedKeyPlaceholder', language))}
                    style={editingClient || formData.autoGeneratePresharedKey ? { backgroundColor: '#f5f5f5', cursor: 'not-allowed' } : {}}
                  />
                  {editingClient && (
                    <small className="form-text text-muted">
                    </small>
                  )}
                </div>
              ) : null}
            </>
          ) : null}

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={resetForm}>
              {t('clients.cancel', language)}
            </button>
            <button type="submit" className="btn-primary">
              {editingClient ? t('clients.update', language) : t('clients.create', language)}
            </button>
          </div>
        </form>
      )}

      {/* 只有在没有显示搜索结果时才显示所有客户端列表 */}
      {!showSearchResults && (
        <div className="clients-list">
          {/* 按服务器ID对客户端进行分组 */}
          {(() => {
            // 创建服务器到客户端的映射
            const serverClientMap = {};
            clients.forEach(client => {
              if (!serverClientMap[client.server_id]) {
                serverClientMap[client.server_id] = [];
              }
              serverClientMap[client.server_id].push(client);
            });

            // 获取唯一的服务器ID列表
            const serverIds = Object.keys(serverClientMap);

            return serverIds.map(serverId => {
              const serverClients = serverClientMap[serverId];
              const server = servers.find(s => s.id == serverId) || { name: `Server ${serverId}` };
              const isExpanded = expandedServers[serverId];

              return (
                <div key={serverId} className="server-group-card">
                  <div className="server-group-header">
                    <div className="server-group-info">
                      <h3>{server.name}</h3>
                      <p>{t('clients.serverId', language)}: {serverId}</p>
                    </div>
                    <button
                      className={`expand-toggle ${isExpanded ? 'expanded' : ''}`}
                      onClick={() => toggleServerExpansion(serverId)}
                    >
                      ▼
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="clients-container-list">
                      {/* 分页实现，每页显示5个客户端卡片 */}
                      {(() => {
                        const clientsPerPage = 5;
                        const serverCurrentPage = currentPage[serverId] || 1;
                        const startIndex = (serverCurrentPage - 1) * clientsPerPage;
                        const endIndex = startIndex + clientsPerPage;
                        const currentClients = serverClients.slice(startIndex, endIndex);
                        const totalPages = Math.ceil(serverClients.length / clientsPerPage);

                        return (
                          <>
                            {currentClients.map(client => (
                              <div key={client.id} className="nested-client-card">
                                <div className="nested-client-header">
                                  <h4>{client.name}</h4>
                                </div>
                                <div className="nested-client-details">
                                  <p><strong>{t('clients.address', language)}:</strong> {client.address}</p>
                                </div>
                                <div className="nested-client-actions">
                                  <button className="btn-download" onClick={() => downloadClientConfig(client.id)}>
                                    {t('clients.download', language)}
                                  </button>
                                  <button className="btn-info" onClick={() => openEmailModal(client.id, client.name)}>
                                    {t('clients.sendEmail', language)}
                                  </button>
                                  <button className="btn-secondary" onClick={() => startEdit(client)}>
                                    {t('clients.edit', language)}
                                  </button>
                                  <button
                                    className={client.enabled ? 'btn-toggle' : 'btn-toggle disabled'}
                                    onClick={() => toggleClient(client.id, client.enabled)}
                                  >
                                    {client.enabled ? t('clients.disable', language) : t('clients.enable', language)}
                                  </button>
                                  <button className="btn-danger" onClick={() => handleDelete(client.id)}>
                                    {t('clients.delete', language)}
                                  </button>
                                </div>
                              </div>
                            ))}
                            {/* 分页控件 */}
                            {totalPages > 1 && (
                              <div className="pagination">
                                <button
                                  className="btn-primary"
                                  onClick={() => setCurrentPage(prev => ({
                                    ...prev,
                                    [serverId]: Math.max((prev[serverId] || 1) - 1, 1)
                                  }))}
                                  disabled={serverCurrentPage === 1}
                                >
                                  {t('clients.previous', language)}
                                </button>
                                <span className="page-info">
                                  {t('clients.pageInfo', language, { current: serverCurrentPage, total: totalPages })}
                                </span>
                                <button
                                  className="btn-primary"
                                  onClick={() => setCurrentPage(prev => ({
                                    ...prev,
                                    [serverId]: Math.min((prev[serverId] || 1) + 1, totalPages)
                                  }))}
                                  disabled={serverCurrentPage === totalPages}
                                >
                                  {t('clients.next', language)}
                                </button>
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  )}
                </div>
              );
            })
          })()}
        </div>
      )}
    </div>
  );
};

export default Clients;
