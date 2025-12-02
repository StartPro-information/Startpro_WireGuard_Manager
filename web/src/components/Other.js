import React, { useState, useEffect } from 'react';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import './Other.css';

const Other = () => {
  const [message, setMessage] = useState('');
  const [additionalFileConfig, setAdditionalFileConfig] = useState({
    enabled: 0,
    file_path: '',
    file_name: ''
  });
  const [uploadEnabled, setUploadEnabled] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const { language } = useLanguage();

  // 获取附加文件配置
  useEffect(() => {
    fetchAdditionalFileConfig();
  }, []);

  const fetchAdditionalFileConfig = async () => {
    try {
      const response = await fetch('/api/additional-file-config');
      const data = await response.json();
      setAdditionalFileConfig(data);
      setUploadEnabled(!!data.enabled);
    } catch (error) {
      console.error('Error fetching additional file config:', error);
      setMessage('errors.additionalFileFetchFailed');
      setTimeout(() => setMessage(''), 5000);
    }
  };

  const toggleUploadEnabled = async () => {
    try {
      const response = await fetch('/api/additional-file-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          enabled: uploadEnabled ? 0 : 1
        }),
      });

      if (response.ok) {
        setUploadEnabled(!uploadEnabled);
        fetchAdditionalFileConfig();
        setMessage(uploadEnabled ? 'messages.additionalFileDisabled' : 'messages.additionalFileEnabled');
        setTimeout(() => setMessage(''), 3000);
      } else {
        const errorData = await response.json();
        setMessage('errors.additionalFileToggleFailed');
        setTimeout(() => setMessage(''), 5000);
      }
    } catch (error) {
      console.error('Error updating upload config:', error);
      setMessage('errors.additionalFileUpdateFailed');
      setTimeout(() => setMessage(''), 5000);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Check file size (20MB limit)
      if (file.size > 20 * 1024 * 1024) {
        setMessage('errors.fileSizeExceeded');
        setTimeout(() => setMessage(''), 5000);
        return;
      }
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setMessage('errors.noFileSelected');
      setTimeout(() => setMessage(''), 5000);
      return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile);

    setIsUploading(true);
    setUploadProgress('Uploading...');

    try {
      const response = await fetch('/api/upload-additional-file', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();

      if (response.ok) {
        setSelectedFile(null);
        fetchAdditionalFileConfig();
        setMessage('File uploaded successfully');
        setTimeout(() => setMessage(''), 5000);
      } else {
        setMessage(`Error: ${result.error}`);
        setTimeout(() => setMessage(''), 5000);
      }
    } catch (error) {
      console.error('Error uploading file:', error);
      setMessage('Failed to upload file');
      setTimeout(() => setMessage(''), 5000);
    } finally {
      setIsUploading(false);
      setUploadProgress(null);
    }
  };

  const handleDeleteFile = async () => {
    if (!window.confirm('Are you sure you want to delete the uploaded file?')) {
      return;
    }

    try {
      const response = await fetch('/api/delete-additional-file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        fetchAdditionalFileConfig();
        setMessage('File deleted successfully');
        setTimeout(() => setMessage(''), 5000);
      } else {
        const errorData = await response.json();
        setMessage(`Error: ${errorData.error}`);
        setTimeout(() => setMessage(''), 5000);
      }
    } catch (error) {
      console.error('Error deleting file:', error);
      setMessage('Failed to delete file');
      setTimeout(() => setMessage(''), 5000);
    }
  };

  return (
    <div className="other-container">
      <div className="header">
        <h2>{t('other.title', language)}</h2>
      </div>

      {message && <div className="success-message">{t(message, language)}</div>}

      {/* 新增附加文件上传功能 */}
      <div className="feature-card">
        <h3>{t('other.additionalFileTitle', language)}</h3>
        
        <div className="form-group" style={{ marginBottom: '15px', display: 'flex', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, flexDirection: 'row-reverse', justifyContent: 'flex-end', whiteSpace: 'nowrap' }}>
            {t('other.enableAttachment', language)}
            <input
              type="checkbox"
              checked={uploadEnabled}
              onChange={toggleUploadEnabled}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
        </div>

        {uploadEnabled && (
          <div style={{ marginBottom: '15px' }}>
            <div className="form-group" style={{ marginBottom: '15px' }}>
              <label htmlFor="file-upload">{t('other.selectFile', language)}</label>
              <input
                type="file"
                id="file-upload"
                onChange={handleFileChange}
                className="form-control"
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
              />
            </div>

            {selectedFile && (
              <div style={{
                marginBottom: '15px',
                padding: '10px',
                backgroundColor: '#f8f9fa',
                borderRadius: '4px',
                border: '1px solid #e9ecef'
              }}>
                <p><strong>{t('other.selectedFile', language)}:</strong> {selectedFile.name}</p>
                <p><strong>{t('other.size', language)}:</strong> {(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
              </div>
            )}

            {uploadProgress && (
              <div style={{
                marginBottom: '15px',
                padding: '10px',
                backgroundColor: '#d1ecf1',
                borderRadius: '4px',
                border: '1px solid #bee5eb',
                color: '#0c5460'
              }}>
                {t('other.uploading', language)}
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                className="btn-primary"
                onClick={handleUpload}
                disabled={isUploading || !selectedFile}
                style={{ minWidth: '100px' }}
              >
                {isUploading ? t('other.uploading', language) : t('other.uploadButton', language)}
              </button>

              {additionalFileConfig.file_name && (
                <button
                  className="btn-danger"
                  onClick={handleDeleteFile}
                  disabled={isUploading}
                >
                  {t('other.delete', language)}
                </button>
              )}
            </div>

            {additionalFileConfig.file_name && (
              <div style={{
                marginTop: '15px',
                padding: '10px',
                backgroundColor: '#e2e3e5',
                borderRadius: '4px',
                border: '1px solid #d6d8db'
              }}>
                <p><strong>{t('other.uploadedFile', language)}:</strong> {additionalFileConfig.file_name}</p>
                <p><strong>{t('other.status', language)}:</strong> {t('other.fileReady', language)}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Other;