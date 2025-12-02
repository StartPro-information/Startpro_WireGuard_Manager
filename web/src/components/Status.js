import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';

const ClientStatus = () => {
  const [clients, setClients] = useState([]);
  const [detailedTraffic, setDetailedTraffic] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filteredClients, setFilteredClients] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const clientsPerPage = 10;
  const { language } = useLanguage();

  // 格式化在线时间（秒）为可读格式
  const formatOnlineTime = (seconds) => {
    if (seconds < 60) {
      return `${seconds} seconds`;
    } else if (seconds < 3600) {
      const minutes = Math.floor(seconds / 60);
      return `${minutes} minutes`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      if (minutes > 0) {
        return `${hours} hours ${minutes} minutes`;
      }
      return `${hours} hours`;
    }
  };

  // 格式化流量数据为可读格式 (输入为KiB)
  const formatTraffic = (kibibytes) => {
    const bytes = kibibytes * 1024;
    if (bytes >= 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    } else if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    } else {
      return `${bytes.toFixed(2)} B`;
    }
  };

  // 获取在线客户端数据和详细流量数据
  const fetchOnlineClients = async () => {
    try {
      setLoading(true);
      const [clientsData, trafficData] = await Promise.all([
        api.getOnlineClients(),
        api.getDetailedTraffic()
      ]);
      setClients(clientsData);
      setFilteredClients(clientsData);
      setDetailedTraffic(trafficData);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch online clients or traffic data:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  // 处理搜索
  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setFilteredClients(clients);
      return;
    }

    const filtered = clients.filter(client => {
      const nameMatch = client.name.toLowerCase().includes(searchQuery.toLowerCase());
      const ipMatch = client.address.toLowerCase().includes(searchQuery.toLowerCase());
      const serverMatch = client.server_name.toLowerCase().includes(searchQuery.toLowerCase());
      return nameMatch || ipMatch || serverMatch;
    });

    setFilteredClients(filtered);
  };


  // 设置定时刷新
  useEffect(() => {
    // 首次加载
    fetchOnlineClients();

    // 每30秒刷新一次
    const interval = setInterval(() => {
      fetchOnlineClients();
    }, 30000);

    // 清理定时器
    return () => clearInterval(interval);
  }, []);

  if (loading && clients.length === 0) return <div>Loading client status...</div>;
  if (error) return <div className="error">Error: {error.message}</div>;

  return (
    <div className="status-container">
      <div className="header">
        <h2>{t('status.title', language)}</h2>
        <button className="btn-primary" onClick={fetchOnlineClients}>
          {t('common.refresh', language)}
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
                placeholder={t('status.searchPlaceholder', language)}
                className="search-input"
              />
            </div>
            <div className="search-actions">
              <button type="submit" className="btn-primary search-button">
                {t('common.search', language)}
              </button>
            </div>
          </div>
        </form>
      </div>

      {filteredClients.length === 0 ? (
        <div className="no-clients">
          <p>{t('status.noClients', language)}</p>
        </div>
      ) : (
        <>
          <div className="table-container">
            {/* 创建客户端ID到流量数据的映射 */}
            {(detailedTraffic && detailedTraffic.servers) && (
              <></>
            )}
            <table className="status-table">
              <thead>
                <tr>
                  <th>{t('status.name', language)}</th>
                  <th>IP</th>
                  <th>{t('status.server', language)}</th>
                  <th>{t('status.status', language)}</th>
                  <th>{t('status.onlineTime', language)}</th>
                  <th>{t('status.traffic30s', language)}</th>
                  <th>{t('status.totalTraffic', language)}</th>
                </tr>
              </thead>
              <tbody>
                {filteredClients.slice((currentPage - 1) * clientsPerPage, currentPage * clientsPerPage).map((client) => {
                  // 创建客户端ID到流量数据的映射
                  const clientTrafficMap = {};
                  if (detailedTraffic && detailedTraffic.servers) {
                    detailedTraffic.servers.forEach(server => {
                      server.clients.forEach(trafficClient => {
                        clientTrafficMap[trafficClient.id] = trafficClient;
                      });
                    });
                  }

                  // 获取该客户端的流量数据
                  const trafficData = clientTrafficMap[client.id] || {};

                  return (
                    <tr key={client.id}>
                      <td>{client.name}</td>
                      <td>{client.address.split('/')[0]}</td>
                      <td>{client.server_name}</td>
                      <td>
                        <span className={`status-badge status-${client.status}`}>
                          {client.status}
                        </span>
                      </td>
                      <td>{formatOnlineTime(client.online_time)}</td>
                      <td>
                        {trafficData.received_30s !== undefined && trafficData.sent_30s !== undefined ? (
                          <div>
                            <span>↑ {formatTraffic(trafficData.received_30s)}</span><br />
                            <span>↓ {formatTraffic(trafficData.sent_30s)}</span>
                          </div>
                        ) : '-'}
                      </td>
                      <td>
                        {trafficData.online_received !== undefined && trafficData.online_sent !== undefined ? (
                          <div>
                            <span>↑ {formatTraffic(trafficData.online_received)}</span><br />
                            <span>↓ {formatTraffic(trafficData.online_sent)}</span>
                          </div>
                        ) : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {/* 分页控件 */}
          <div className="pagination">
            <button
              className="btn-primary"
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
            >
              {t('common.previous', language)}
            </button>
            <span className="page-info">
              {t('common.pageInfo', language, { current: currentPage, total: Math.ceil(filteredClients.length / clientsPerPage) })}
            </span>
            <button
              className="btn-primary"
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, Math.ceil(filteredClients.length / clientsPerPage)))}
              disabled={currentPage === Math.ceil(filteredClients.length / clientsPerPage)}
            >
              {t('common.next', language)}
            </button>
          </div>
        </>
      )}
    </div>
  );
};

export default ClientStatus;
