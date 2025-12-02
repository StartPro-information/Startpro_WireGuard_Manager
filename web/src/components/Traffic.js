import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';

const Traffic = () => {
  const [detailedTraffic, setDetailedTraffic] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedServers, setExpandedServers] = useState({});
  const { language } = useLanguage();

  // 格式化流量数据为可读格式 (输入为KiB)
  const formatTraffic = (kibibytes) => {
    const bytes = kibibytes * 1024;
    if (bytes >= 1024 * 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`;
    } else if (bytes >= 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    } else if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    } else {
      return `${bytes.toFixed(2)} B`;
    }
  };

  // 获取详细流量数据
  const fetchDetailedTraffic = async () => {
    try {
      const data = await api.getDetailedTraffic();
      setDetailedTraffic(data);
    } catch (error) {
      console.error('Error fetching detailed traffic:', error);
    } finally {
      setLoading(false);
    }
  };

  // 初始化数据获取
  useEffect(() => {
    fetchDetailedTraffic();

    // 每30秒刷新一次数据
    const interval = setInterval(() => {
      fetchDetailedTraffic();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // 切换服务器展开/收缩状态
  const toggleServerExpansion = (serverId) => {
    setExpandedServers(prev => ({
      ...prev,
      [serverId]: !prev[serverId]
    }));
  };

  if (loading) return <div>Loading traffic data...</div>;

  const trafficData = detailedTraffic || { servers: [], global_total_received: 0, global_total_sent: 0 };

  return (
    <div className="traffic-container">
      <div className="header">
        <h2>{t('traffic.title', language)}</h2>
        <button className="btn-primary" onClick={fetchDetailedTraffic}>
          {t('common.refresh', language)}
        </button>
      </div>

      {/* 平台总流量统计 */}
      <div className="traffic-summary">
        <div className="traffic-card">
          <h3>{t('traffic.received', language)}</h3>
          <p className="traffic-value">{formatTraffic(trafficData.global_total_received)}</p>
        </div>
        <div className="traffic-card">
          <h3>{t('traffic.sent', language)}</h3>
          <p className="traffic-value">{formatTraffic(trafficData.global_total_sent)}</p>
        </div>
        <div className="traffic-card">
          <h3>{t('traffic.total', language)}</h3>
          <p className="traffic-value">{formatTraffic(trafficData.global_total_received + trafficData.global_total_sent)}</p>
        </div>
      </div>

      {/* 服务器流量统计 */}
      <div className="servers-traffic">
        <h3>{t('traffic.serverTraffic', language)}</h3>
        {trafficData.servers.map((server) => (
          <div key={server.id} className="server-card" style={{ marginBottom: '20px' }}>
            <div
              className="server-header"
              onClick={() => toggleServerExpansion(server.id)}
              style={{
                background: 'white',
                padding: '15px',
                borderRadius: '8px',
                cursor: 'pointer',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <h4 style={{ margin: 0 }}>{server.name}</h4>
              <div style={{ textAlign: 'right', display: 'flex', alignItems: 'center' }}>
                <div style={{ marginRight: '20px' }}>
                  <p style={{ margin: '0 0 5px 0' }}>Received: {formatTraffic(server.server_total_received)}</p>
                  <p style={{ margin: 0 }}>Sent: {formatTraffic(server.server_total_sent)}</p>
                </div>
                <button
                  style={{
                    background: 'transparent',
                    border: 'none',
                    fontSize: '18px',
                    cursor: 'pointer',
                    padding: '5px 10px',
                    borderRadius: '4px',
                    transition: 'background-color 0.2s'
                  }}
                  onMouseEnter={(e) => e.target.style.backgroundColor = '#f0f0f0'}
                  onMouseLeave={(e) => e.target.style.backgroundColor = 'transparent'}
                >
                  {expandedServers[server.id] ? '▲' : '▼'}
                </button>
              </div>
            </div>

            {expandedServers[server.id] && server.clients.length > 0 && (
              <div className="server-clients" style={{
                border: '1px solid #ddd',
                borderRadius: '0 0 8px 8px',
                maxHeight: '300px',
                overflowY: 'auto'
              }}>
                <table className="traffic-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ background: '#f8f9fa' }}>
                      <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>{t('traffic.client', language)}</th>
                      <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>{t('traffic.received', language)}</th>
                      <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #ddd' }}>{t('traffic.sent', language)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {server.clients.map((client) => (
                      <tr
                        key={client.id}
                        style={{
                          borderBottom: '1px solid #eee',
                          backgroundColor: client.status === 'online' ? 'white' : '#f8f9fa'
                        }}
                      >
                        <td style={{ padding: '12px' }}>
                          {client.name}
                          <span style={{
                            fontSize: '0.8em',
                            color: client.status === 'online' ? '#28a745' : '#6c757d',
                            marginLeft: '8px',
                            fontStyle: 'italic'
                          }}>
                            ({client.status === 'online' ? t('status.online', language) : t('status.offline', language)})
                          </span>
                        </td>
                        <td style={{ padding: '12px' }}>{formatTraffic(client.client_total_received)}</td>
                        <td style={{ padding: '12px' }}>{formatTraffic(client.client_total_sent)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Traffic;
