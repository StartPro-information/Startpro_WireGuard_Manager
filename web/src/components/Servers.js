import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';

const Servers = () => {
  const [servers, setServers] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingServer, setEditingServer] = useState(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configContent, setConfigContent] = useState('');
  const [formData, setFormData] = useState({
    name: '',
    address: '',
    listen_port: 51820,
    private_key: '',
    public_key: '',
    dns: '',
    mtu: 1420,
    interface: 'eth0',
    public_ip_port: '',
    autoGenerateKeys: true
  });
  const { language } = useLanguage();

  useEffect(() => {
    fetchServers();
    fetchInterfaces();
  }, []);

  const fetchInterfaces = async () => {
    try {
      const data = await api.getInterfaces();
      setInterfaces(data);
      // 如果表单中的interface不在可用接口列表中，设置为第一个可用接口
      if (data.length > 0 && !data.includes(formData.interface)) {
        setFormData(prev => ({ ...prev, interface: data[0] }));
      }
    } catch (error) {
      console.error('Error fetching interfaces:', error);
    }
  };

  const fetchServers = async () => {
    try {
      const data = await api.getServers();
      setServers(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching servers:', error);
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      let submitData = { ...formData };

      // 在创建模式下，如果选择了自动生成密钥，则移除密钥字段
      // 在编辑模式下，始终保留密钥字段
      if (!editingServer && submitData.autoGenerateKeys) {
        delete submitData.private_key;
        delete submitData.public_key;
      }
      delete submitData.autoGenerateKeys;

      if (editingServer) {
        await api.updateServer(editingServer.id, submitData);
      } else {
        await api.createServer(submitData);
      }
      fetchServers();
      resetForm();
    } catch (error) {
      console.error('Error saving server:', error);
      alert('Error: ' + error.message);
    }
  };

  const handleDelete = async (id, serverStatus) => {
    // 检查服务器状态，如果为"up"则不允许删除
    if (serverStatus === 'up') {
      alert('Cannot delete server while it is running. Please stop the server first.');
      return;
    }

    if (window.confirm('Are you sure you want to delete this server?')) {
      try {
        await api.deleteServer(id);
        fetchServers();
      } catch (error) {
        console.error('Error deleting server:', error);
      }
    }
  };

  const showServerConfig = async (id) => {
    try {
      const response = await fetch(`/api/servers/${id}/config`);
      const data = await response.json();
      setConfigContent(data.content);
      setShowConfigModal(true);
    } catch (error) {
      console.error('Error fetching server config:', error);
      alert('Error fetching server config: ' + error.message);
    }
  };

  const closeConfigModal = () => {
    setShowConfigModal(false);
    setConfigContent('');
  };

  const handleToggle = async (interfaceName, action) => {
    try {
      await api.toggleServer(interfaceName, action);
      fetchServers();
    } catch (error) {
      console.error(`Error ${action} server:`, error);
      alert(`Error: ${error.message}`);
    }
  };

  const handleRestart = async (interfaceName) => {
    if (window.confirm('Are you sure you want to restart this server?')) {
      try {
        await api.restartServer(interfaceName);
        fetchServers();
        alert('Server restarted successfully');
      } catch (error) {
        console.error('Error restarting server:', error);
        alert(`Error: ${error.message}`);
      }
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      address: '',
      listen_port: 51820,
      private_key: '',
      public_key: '',
      dns: '',
      mtu: 1420,
      interface: interfaces.length > 0 ? interfaces[0] : 'eth0',
      public_ip_port: '',
      autoGenerateKeys: true
    });
    setEditingServer(null);
    setShowForm(false);
  };

  const startEdit = (server) => {
    setFormData(server);
    setEditingServer(server);
    setShowForm(true);
  };

  if (loading) return <div>Loading servers...</div>;

  return (
    <div className="servers-container">
      {/* 配置文件查看模态框 */}
      {showConfigModal && (
        <div className="modal-overlay" onClick={closeConfigModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{t('servers.config', language)}</h3>
              <button className="modal-close" onClick={closeConfigModal}>&times;</button>
            </div>
            <div className="modal-body">
              <pre className="config-content">{configContent}</pre>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={closeConfigModal}>{t('common.close', language)}</button>
            </div>
          </div>
        </div>
      )}

      <div className="header">
        <h2>{t('servers.title', language)}</h2>
        <button className="btn-primary" onClick={() => setShowForm(true)}>
          {t('servers.create', language)}
        </button>
      </div>

      {showForm && (
        <form className="form" onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="form-group">
              <label>{t('servers.name', language)}</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                required
              />
            </div>
            <div className="form-group">
              <label>{t('servers.address', language)}</label>
              <input
                type="text"
                value={formData.address}
                onChange={(e) => setFormData({...formData, address: e.target.value})}
                required
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"
                title="请输入有效的CIDR格式地址，例如: 192.168.1.1/24"
              />
            </div>
          </div>
          
          <div className="form-row">
            <div className="form-group">
              <label>{t('servers.port', language)} (UDP)</label>
              <input
                type="number"
                value={formData.listen_port}
                onChange={(e) => setFormData({...formData, listen_port: parseInt(e.target.value)})}
                required
                min="1024"
                max="65535"
                title={t('servers.portTitle', language)}
              />
            </div>
            
            <div className="form-group">
              <label>{t('servers.remote', language)}</label>
              <input
                type="text"
                value={formData.public_ip_port}
                onChange={(e) => setFormData({...formData, public_ip_port: e.target.value})}
                placeholder={t('servers.remotePlaceholder', language)}
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}:[0-9]{1,5}$|(^$)"
                title={t('servers.remoteTitle', language)}
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
                placeholder={t('servers.dnsPlaceholder', language)}
                pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}(,([0-9]{1,3}\.){3}[0-9]{1,3})?$"
                title={t('servers.dnsTitle', language)}
              />
            </div>
            <div className="form-group">
              <label>MTU</label>
              <input
                type="number"
                value={formData.mtu}
                onChange={(e) => setFormData({...formData, mtu: parseInt(e.target.value) || 0})}
                min="1200"
                max="1600"
                title={t('servers.mtuTitle', language)}
              />
            </div>
          </div>
          
          <div className="form-group">
            <label>{t('servers.networkInterface', language)}</label>
            <select
              value={formData.interface}
              onChange={(e) => setFormData({...formData, interface: e.target.value})}
            >
              {interfaces.map((iface) => (
                <option key={iface} value={iface}>
                  {iface}
                </option>
              ))}
            </select>
          </div>

          {/* 在创建模式下显示Auto-generate keys复选框 */}
          {!editingServer && (
            <div className="form-group" style={{ display: 'flex', alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, flexDirection: 'row-reverse', justifyContent: 'flex-end', whiteSpace: 'nowrap' }}>
                {t('servers.autoGenerateKeys', language)}
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
          {(!editingServer && !formData.autoGenerateKeys) || editingServer ? (
            <>
              <div className="form-group">
                <label>{t('servers.privateKey', language)}</label>
                <textarea
                  value={formData.private_key}
                  onChange={(e) => setFormData({...formData, private_key: e.target.value})}
                  required={!editingServer && !formData.autoGenerateKeys}
                  readOnly={!!editingServer}
                  placeholder={editingServer ? "" : t('servers.privateKeyPlaceholder', language)}
                />
              </div>

              <div className="form-group">
                <label>{t('servers.publicKey', language)}</label>
                <textarea
                  value={formData.public_key}
                  onChange={(e) => setFormData({...formData, public_key: e.target.value})}
                  required={!editingServer && !formData.autoGenerateKeys}
                  readOnly={!!editingServer}
                  placeholder={editingServer ? "" : t('servers.publicKeyPlaceholder', language)}
                />
              </div>
            </>
          ) : null}
          
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={resetForm}>
              {t('common.cancel', language)}
            </button>
            <button type="submit" className="btn-primary">
              {editingServer ? t('servers.update', language) : t('servers.create', language)}
            </button>
          </div>
        </form>
      )}

      <div className="servers-list">
        {servers.map((server) => (
          <div key={server.id} className="server-card">
            <div className="server-header">
              <h3>{server.name}</h3>
              <div className={`server-status ${server.status}`}>
                {server.status}
              </div>
            </div>
            <div className="server-details">
              <p><strong>{t('servers.serverId', language)}:</strong> {server.id}</p>
              <p><strong>{t('servers.address', language)}:</strong> {server.address}</p>
              <p><strong>{t('servers.port', language)}:</strong> {server.listen_port}</p>
              {server.public_ip_port && <p><strong>{t('servers.remote', language)}:</strong> {server.public_ip_port}</p>}
              <p><strong>{t('servers.interface', language)}:</strong> {server.interface}</p>
            </div>
            <div className="server-actions">
              <button className="btn-secondary" onClick={() => startEdit(server)}>
                {t('servers.edit', language)}
              </button>
              <button className="btn-info" onClick={() => showServerConfig(server.id)}>
                {t('servers.config', language)}
              </button>
              <button className="btn-primary" onClick={() => handleRestart(`wg${server.id}`)}>
                {t('servers.restart', language)}
              </button>
              <button
                className={server.status === 'up' ? 'btn-warning' : 'btn-success'}
                onClick={() => handleToggle(`wg${server.id}`, server.status === 'up' ? 'down' : 'up')}
              >
                {server.status === 'up' ? t('servers.stop', language) : t('servers.start', language)}
              </button>
              <button className="btn-danger" onClick={() => handleDelete(server.id, server.status)}>
                {t('servers.delete', language)}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Servers;
