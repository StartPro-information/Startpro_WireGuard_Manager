import React, { useState, useEffect } from 'react';
import { Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import Servers from './components/Servers.js';
import Clients from './components/Clients.js';
import Status from './components/Status.js';
import Traffic from './components/Traffic.js';
import Login from './components/Login.js';
import ChangePassword from './components/ChangePassword.js';
import AccessLog from './components/AccessLog.js';
import EmailConfig from './components/EmailConfig.js';
import Other from './components/Other.js';
import Help from './components/Help.js';
import LanguageSwitcher from './components/LanguageSwitcher.js';
import { LanguageProvider, useLanguage } from './contexts/LanguageContext.js';
import { t } from './translations.js';
import './App.css';
import './components/Components.css';
import './components/TrafficStatus.css';

function AppContent() {
  const location = useLocation();
  const navigate = useNavigate();
  const { language } = useLanguage();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState('');

  // 检查用户认证状态
  useEffect(() => {
    const authStatus = localStorage.getItem('isAuthenticated') === 'true';
    const storedUsername = localStorage.getItem('username') || '';
    setIsAuthenticated(authStatus);
    setUsername(storedUsername);

    // 如果用户未认证且不在登录页面，则重定向到登录页面
    if (!authStatus && location.pathname !== '/login') {
      navigate('/login');
    }

    // 如果用户已认证且在登录页面，则重定向到服务器页面
    if (authStatus && location.pathname === '/login') {
      navigate('/servers');
    }
  }, [location.pathname, navigate]);

  // 根据当前路径确定活动选项卡
  const getActiveTab = () => {
    switch (location.pathname) {
      case '/clients':
        return 'clients';
      case '/status':
        return 'status';
      case '/traffic':
        return 'traffic';
      case '/change-password':
      case '/system-log':
      case '/email-config':
      case '/other':
        return 'system';
      default:
        return 'servers';
    }
  };

  const activeTab = getActiveTab();

  // 处理导航点击
  const handleNavClick = (path) => {
    navigate(path);
  };

  // 处理注销
  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setUsername('');
    navigate('/login');
  };

  // 如果在登录页面，只显示登录组件
  if (location.pathname === '/login') {
    return (
      <div className="app">
        <Routes>
          <Route path="/login" element={<Login />} />
        </Routes>
      </div>
    );
  }

  // 如果未认证，重定向到登录页面
  if (!isAuthenticated) {
    return (
      <div className="app">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Login />} />
        </Routes>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>WireGuard Manager</h1>
          <div className="user-menu">
            <LanguageSwitcher />
            <button className="help-button" onClick={() => navigate('/help')}>
              {t('navigation.help', language)}
            </button>
            <button className="logout-button" onClick={handleLogout}>{t('navigation.logout', language)}</button>
          </div>
        </div>
      </header>

      <nav className="app-nav">
        <ul>
          <li className={activeTab === 'servers' ? 'active' : ''} onClick={() => handleNavClick('/servers')}>
            {t('navigation.servers', language)}
          </li>
          <li className={activeTab === 'clients' ? 'active' : ''} onClick={() => handleNavClick('/clients')}>
            {t('navigation.clients', language)}
          </li>
          <li className={activeTab === 'status' ? 'active' : ''} onClick={() => handleNavClick('/status')}>
            {t('navigation.status', language)}
          </li>
          <li className={activeTab === 'traffic' ? 'active' : ''} onClick={() => handleNavClick('/traffic')}>
            {t('navigation.traffic', language)}
          </li>
          <li className={activeTab === 'system' ? 'active' : ''}>
            <div className="dropdown">
              <button className="dropdown-toggle">{t('navigation.system', language)}</button>
              <div className="dropdown-menu">
                <button className="dropdown-item" onClick={() => navigate('/change-password')}>{t('navigation.passwd', language)}</button>
                <button className="dropdown-item" onClick={() => navigate('/system-log')}>{t('navigation.accessLog', language)}</button>
                <button className="dropdown-item" onClick={() => navigate('/email-config')}>{t('navigation.email', language)}</button>
                <button className="dropdown-item" onClick={() => navigate('/other')}>{t('navigation.other', language)}</button>
              </div>
            </div>
          </li>
        </ul>
      </nav>

      <main className="app-main">
        <Routes>
          <Route path="/servers" element={<Servers />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/status" element={<Status />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/change-password" element={<ChangePassword />} />
          <Route path="/system-log" element={<AccessLog />} />
          <Route path="/email-config" element={<EmailConfig />} />
          <Route path="/other" element={<Other />} />
          <Route path="/help" element={<Help />} />
          <Route path="/" element={<Servers />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <LanguageProvider>
      <AppContent />
    </LanguageProvider>
  );
}

export default App;
