// AccessLog.js - Full featured access log component with pagination, search, and all data fields
import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import './AccessLog.css';

const AccessLog = () => {
  const [logs, setLogs] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchParams, setSearchParams] = useState({
    q: '',
    start_time: '',
    end_time: ''
  });
  const [isSearching, setIsSearching] = useState(false);
  const logsPerPage = 10;
  const { language } = useLanguage();

  // Format traffic data for readability (input in KiB)
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

  // Format online time (seconds) for readability
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

  // Get access logs data
  const fetchAccessLogs = async () => {
    try {
      setLoading(true);
      console.log('Fetching all access logs');
      const data = await api.getAccessLogs();
      console.log('Fetched', data.length, 'logs');
      setLogs(data);
      setCurrentPage(1); // Reset to first page when new data is loaded
      setError(null);
    } catch (err) {
      console.error('Failed to fetch access logs:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  // Search access logs
  const searchAccessLogs = async () => {
    try {
      setIsSearching(true);
      setError(null); // Clear any previous errors

      // Build search parameters - only send non-empty values
      const searchParamsToSend = {};

      // Always include the general search term as 'q'
      if (searchParams.q && searchParams.q.trim() !== '') {
        searchParamsToSend.q = searchParams.q.trim();
      }

      // Include time range parameters if set
      if (searchParams.start_time && searchParams.start_time !== '') {
        searchParamsToSend.start_time = searchParams.start_time;
      }

      if (searchParams.end_time && searchParams.end_time !== '') {
        searchParamsToSend.end_time = searchParams.end_time;
      }

      console.log('Search parameters to send:', searchParamsToSend);

      const data = await api.searchAccessLogs(searchParamsToSend);
      console.log('Search results:', data);

      // Check if data is an array before using it
      if (Array.isArray(data)) {
        console.log('Search results length:', data.length);
        // Update state with search results
        setLogs(data);
        setCurrentPage(1); // Reset to first page when new data is loaded
      } else {
        // Handle case where data is not an array (e.g., error response)
        console.error('Search returned non-array data:', data);
        setLogs([]); // Set empty array when search returns non-array data
        setCurrentPage(1);
      }
    } catch (err) {
      console.error('Failed to search access logs:', err);
      setError(err);
      setLogs([]); // Ensure logs state is reset to empty array on error
      setCurrentPage(1);
    } finally {
      setIsSearching(false);
    }
  };

  // Handle search parameter changes
  const handleSearchParamChange = (key, value) => {
    setSearchParams(prev => ({
      ...prev,
      [key]: value
    }));
  };

  // Reset search
  const resetSearch = () => {
    setSearchParams({
      q: '',
      start_time: '',
      end_time: ''
    });
    fetchAccessLogs();
  };

  // Handle search form submission
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    console.log('Search form submitted');
    searchAccessLogs();
  };

  // Calculate pagination
  const totalPages = Math.ceil(logs.length / logsPerPage);
  const startIndex = (currentPage - 1) * logsPerPage;
  const endIndex = Math.min(startIndex + logsPerPage, logs.length);
  const currentLogs = logs.slice(startIndex, endIndex);

  // Handle page change
  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
    }
  };

  // Ensure valid page when data changes
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [logs, currentPage, totalPages]);

  // Set up initial load
  useEffect(() => {
    fetchAccessLogs();
  }, []);

  if (loading && logs.length === 0) {
    return <div>Loading access logs...</div>;
  }

  if (error) {
    return <div className="error">Error: {error.message}</div>;
  }

  return (
    <div className="access-log-container">
      <div className="header">
        <h2>{t('accessLog.title', language)}</h2>
        <button className="btn-primary" onClick={fetchAccessLogs}>
          {t('common.refresh', language)}
        </button>
      </div>

      {/* Search form */}
      <div className="search-container">
        <form onSubmit={handleSearchSubmit} className="search-form">
          <div className="search-row">
            <div className="search-group">
              <label>{t('accessLog.generalSearch', language)}:</label>
              <input
                type="text"
                value={searchParams.q}
                onChange={(e) => handleSearchParamChange('q', e.target.value)}
                placeholder={t('accessLog.searchPlaceholder', language)}
                className="search-input"
              />
            </div>
            <div className="search-group">
              <label>{t('accessLog.startTime', language)}:</label>
              <input
                type="datetime-local"
                value={searchParams.start_time}
                onChange={(e) => handleSearchParamChange('start_time', e.target.value)}
                className="search-input"
              />
            </div>
            <div className="search-group">
              <label>{t('accessLog.endTime', language)}:</label>
              <input
                type="datetime-local"
                value={searchParams.end_time}
                onChange={(e) => handleSearchParamChange('end_time', e.target.value)}
                className="search-input"
              />
            </div>
            <div className="search-actions">
              <button type="submit" className="btn-primary" disabled={isSearching}>
                {isSearching ? t('accessLog.searching', language) : t('common.search', language)}
              </button>
              <button type="button" className="btn-secondary" onClick={resetSearch}>
                {t('common.reset', language)}
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Results container with pagination info */}
      <div style={{marginTop: '20px'}}>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px'}}>
          <h3>{t('accessLog.results', language, { count: logs.length })}</h3>
          <div style={{backgroundColor: '#f0f0f0', padding: '5px 10px', borderRadius: '4px', fontSize: '14px'}}>
            {t('accessLog.showing', language, { start: startIndex + 1, end: endIndex, total: logs.length })}
          </div>
        </div>

        {logs.length === 0 ? (
          <div className="no-logs">
            <p>{t('accessLog.noLogs', language)}</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="access-log-table">
              <thead>
                <tr>
                  <th>{t('accessLog.clientName', language)}</th>
                  <th>{t('accessLog.clientIP', language)}</th>
                  <th>{t('accessLog.server', language)}</th>
                  <th>{t('accessLog.eventType', language)}</th>
                  <th>{t('accessLog.eventTime', language)}</th>
                  <th>{t('accessLog.onlineDuration', language)}</th>
                  <th>{t('accessLog.sentTraffic', language)}</th>
                  <th>{t('accessLog.receivedTraffic', language)}</th>
                </tr>
              </thead>
              <tbody>
                {currentLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{log.client_name}</td>
                    <td>{log.client_ip.split('/')[0]}</td>
                    <td>{log.server_name}</td>
                    <td>
                      <span className={`status-badge status-${log.event_type}`}>
                        {log.event_type}
                      </span>
                    </td>
                    <td>{new Date(log.event_time).toLocaleString()}</td>
                    <td>
                      {log.event_type === 'offline'
                        ? formatOnlineTime(log.online_duration)
                        : '-'}
                    </td>
                    <td>
                      {log.event_type === 'offline'
                        ? formatTraffic(log.sent_traffic)
                        : '-'}
                    </td>
                    <td>
                      {log.event_type === 'offline'
                        ? formatTraffic(log.received_traffic)
                        : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination controls */}
      {totalPages > 1 && (
        <div className="pagination">
          <button
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={currentPage === 1}
          >
            {t('common.previous', language)}
          </button>

          <span className="page-info">
            {t('common.pageInfo', language, { current: currentPage, total: totalPages })}
          </span>

          <button
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={currentPage === totalPages}
          >
            {t('common.next', language)}
          </button>
        </div>
      )}

      {/* Page numbers */}
      {totalPages > 1 && (
        <div style={{marginTop: '10px', textAlign: 'center'}}>
          {(() => {
            const pages = [];
            const maxVisiblePages = 10;

            let startPage, endPage;
            if (totalPages <= maxVisiblePages) {
              // Less than maxVisiblePages: show all pages
              startPage = 1;
              endPage = totalPages;
            } else {
              // More than maxVisiblePages: show current page in the middle
              const maxPagesBeforeCurrent = Math.floor(maxVisiblePages / 2);
              const maxPagesAfterCurrent = Math.ceil(maxVisiblePages / 2) - 1;

              startPage = Math.max(1, currentPage - maxPagesBeforeCurrent);
              endPage = Math.min(totalPages, currentPage + maxPagesAfterCurrent);

              // Adjust if we're near the start or end of the page range
              if (startPage === 1) {
                endPage = Math.min(totalPages, maxVisiblePages);
              } else if (endPage === totalPages) {
                startPage = Math.max(1, totalPages - maxVisiblePages + 1);
              }
            }

            for (let i = startPage; i <= endPage; i++) {
              pages.push(
                <button
                  key={i}
                  onClick={() => handlePageChange(i)}
                  className={`page-number ${currentPage === i ? 'active' : ''}`}
                  style={{
                    margin: '0 2px',
                    padding: '4px 8px',
                    backgroundColor: currentPage === i ? '#007bff' : '#f0f0f0',
                    color: currentPage === i ? 'white' : 'black',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    cursor: 'pointer'
                  }}
                >
                  {i}
                </button>
              );
            }

            return pages;
          })()}
        </div>
      )}
    </div>
  );
};

export default AccessLog;
