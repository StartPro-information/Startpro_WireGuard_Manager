import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import './EmailConfig.css';

const EmailConfig = () => {
  const [config, setConfig] = useState({
    smtp_host: '',
    smtp_port: 587,
    username: '',
    password: '',
    from_email: '',
    from_name: 'WireGuard Manager',
    enabled: false
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const { language } = useLanguage();

  // 获取当前邮件配置
  useEffect(() => {
    const fetchEmailConfig = async () => {
      try {
        const response = await fetch('/api/email-config');
        const data = await response.json();
        setConfig({
          smtp_host: data.smtp_host || '',
          smtp_port: data.smtp_port || 587,
          username: data.username || '',
          password: data.password || '',
          from_email: data.from_email || '',
          from_name: data.from_name || 'WireGuard Manager',
          enabled: data.enabled === 1
        });
      } catch (err) {
        console.error('Failed to fetch email config:', err);
      }
    };

    fetchEmailConfig();
  }, []);

  // 处理表单输入变化
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  // 处理表单提交
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const response = await fetch('/api/email-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          smtp_host: config.smtp_host,
          smtp_port: config.smtp_port,
          username: config.username,
          password: config.password,
          from_email: config.from_email,
          from_name: config.from_name,
          enabled: config.enabled ? 1 : 0
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('messages.emailConfigSaved');
      } else {
        setError(data.error || 'errors.emailConfigSaveFailed');
      }
      setLoading(false);
    } catch (err) {
      setError('errors.emailConfigSaveFailed');
      setLoading(false);
    }
  };

  // 测试邮件配置
  const handleTestEmail = async () => {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const response = await fetch('/api/test-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('messages.testEmailSent');
      } else {
        setError(data.error || 'errors.testEmailSendFailed');
      }
      setLoading(false);
    } catch (err) {
      setError('errors.testEmailSendFailed');
      setLoading(false);
    }
  };

  return (
    <div className="email-config-container">
      <div className="header">
        <h2>{t('email.title', language)}</h2>
      </div>

      {message && <div className="success-message">{t(message, language)}</div>}
      {error && <div className="error-message">{t(error, language)}</div>}

      <form className="form" onSubmit={handleSubmit}>
        <div className="form-group" style={{ display: 'flex', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, flexDirection: 'row-reverse', justifyContent: 'flex-end', whiteSpace: 'nowrap' }}>
            {t('email.enabled', language)}
            <input
              type="checkbox"
              name="enabled"
              checked={config.enabled}
              onChange={handleInputChange}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>{t('email.smtpHost', language)}</label>
            <input
              type="text"
              name="smtp_host"
              value={config.smtp_host}
              onChange={handleInputChange}
              placeholder={t('email.smtpHostPlaceholder', language)}
              required={config.enabled}
              disabled={!config.enabled}
            />
          </div>

          <div className="form-group">
            <label>{t('email.smtpPort', language)}</label>
            <input
              type="number"
              name="smtp_port"
              value={config.smtp_port}
              onChange={handleInputChange}
              placeholder="587"
              min="1"
              max="65535"
              required={config.enabled}
              disabled={!config.enabled}
            />
          </div>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>{t('email.username', language)}</label>
            <input
              type="text"
              name="username"
              value={config.username}
              onChange={handleInputChange}
              placeholder={t('email.usernamePlaceholder', language)}
              required={config.enabled}
              disabled={!config.enabled}
            />
          </div>

          <div className="form-group">
            <label>{t('email.password', language)}</label>
            <input
              type="password"
              name="password"
              value={config.password}
              onChange={handleInputChange}
              placeholder={t('email.passwordPlaceholder', language)}
              required={config.enabled}
              disabled={!config.enabled}
            />
          </div>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>{t('email.fromEmail', language)}</label>
            <input
              type="email"
              name="from_email"
              value={config.from_email}
              onChange={handleInputChange}
              placeholder={t('email.fromEmailPlaceholder', language)}
              required={config.enabled}
              disabled={!config.enabled}
            />
          </div>

          <div className="form-group">
            <label>{t('email.fromName', language)}</label>
            <input
              type="text"
              name="from_name"
              value={config.from_name}
              onChange={handleInputChange}
              placeholder={t('email.fromNamePlaceholder', language)}
              disabled={!config.enabled}
            />
          </div>
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="btn-secondary"
            onClick={handleTestEmail}
            disabled={loading || !config.enabled}
          >
            {loading ? t('email.sending', language) : t('email.test', language)}
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={loading}
          >
            {loading ? t('email.saving', language) : t('email.save', language)}
          </button>
        </div>
      </form>
    </div>
  );
};

export default EmailConfig;