import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import { api } from '../api.js';
import './ChangePassword.css';

function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const username = localStorage.getItem('username') || 'admin';
  const { language } = useLanguage();

  const handleChangePassword = async (e) => {
    e.preventDefault();

    // 重置消息
    setError('');
    setSuccess('');

    // 验证输入
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError(t('errors.allFieldsRequired', language));
      return;
    }

    // 检查新密码和确认密码是否匹配
    if (newPassword !== confirmPassword) {
      setError(t('errors.passwordMismatch', language));
      return;
    }

    // 检查新密码是否与当前密码相同
    if (newPassword === currentPassword) {
      setError(t('errors.passwordSameAsCurrent', language));
      return;
    }

    // 调用后端 API 来更改密码
    setLoading(true);
    try {
      await api.changePassword(username, currentPassword, newPassword);

      // 显示成功消息
      setSuccess(t('messages.passwordChanged', language));

      // 清空表单
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');

      // 3秒后返回主页面
      setTimeout(() => {
        navigate('/servers');
      }, 3000);
    } catch (err) {
      setError(err.message || t('errors.passwordChangeFailed', language));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="change-password-container">
      <div className="change-password-card">
        <div className="change-password-header">
          <h2>{t('changePassword.title', language)}</h2>
          <p>{t('changePassword.description', language)}</p>
        </div>

        <form onSubmit={handleChangePassword} className="change-password-form">
          <div className="form-group">
            <label htmlFor="currentPassword">{t('changePassword.currentPassword', language)}</label>
            <input
              type="password"
              id="currentPassword"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="newPassword">{t('changePassword.newPassword', language)}</label>
            <input
              type="password"
              id="newPassword"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">{t('changePassword.confirmPassword', language)}</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={() => navigate('/servers')} disabled={loading}>
              {t('common.cancel', language)}
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? t('changePassword.processing', language) : t('changePassword.change', language)}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default ChangePassword;
