import React, { useState } from 'react';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import './LanguageSwitcher.css';

const LanguageSwitcher = () => {
  const { language, changeLanguage } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);

  const handleLanguageChange = (newLanguage) => {
    changeLanguage(newLanguage);
    setIsOpen(false); // 关闭下拉菜单
  };

  const toggleDropdown = () => {
    setIsOpen(!isOpen);
  };

  // 点击外部关闭下拉菜单
  const handleOutsideClick = (e) => {
    if (isOpen && !e.target.closest('.language-switcher')) {
      setIsOpen(false);
    }
  };

  // 添加和移除外部点击监听器
  React.useEffect(() => {
    if (isOpen) {
      document.addEventListener('click', handleOutsideClick);
    } else {
      document.removeEventListener('click', handleOutsideClick);
    }

    return () => {
      document.removeEventListener('click', handleOutsideClick);
    };
  }, [isOpen]);

  return (
    <div className="language-switcher">
      <button
        className="language-dropdown-button"
        onClick={toggleDropdown}
      >
        {language === 'en' ? 'Language' : '语言'}
      </button>
      {isOpen && (
        <div className="language-dropdown-menu">
          <button
            className={`language-dropdown-item ${language === 'en' ? 'active' : ''}`}
            onClick={() => handleLanguageChange('en')}
          >
            English
          </button>
          <button
            className={`language-dropdown-item ${language === 'zh' ? 'active' : ''}`}
            onClick={() => handleLanguageChange('zh')}
          >
            中文
          </button>
        </div>
      )}
    </div>
  );
};

export default LanguageSwitcher;