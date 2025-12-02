import React from 'react';
import { useLanguage } from '../contexts/LanguageContext.js';
import { t } from '../translations.js';
import './Help.css';

const Help = () => {
  const { language } = useLanguage();

  const helpContent = {
    en: {
      title: 'WireGuard Manager Help',
      introduction: 'WireGuard Manager is a web-based management tool for WireGuard VPN servers and clients.',
      features: [
        'Server Management: Create, edit, and delete WireGuard servers,supports configuring multiple VPN instances',
        'Client Management: Manage WireGuard clients with automatic configuration generation,due to the characteristics of WireGuard, there may be a delay in the platform is determination of the client is online/offline status',
        'Real-time Status: Monitor server and client connection status',
        'Traffic Statistics: View data transfer statistics for all connections',
        'Access Logs: Track client connection and disconnection events',
	'Email function: Supports configuring SMTP email servers to send client configuration files via email, and can add additional files',
        'Multi-language Support: Interface available in English and Chinese'
      ],
      gettingStarted: {
        title: 'Getting Started',
        steps: [
          'Create a new server by clicking the "Create Server" button',
          'Configure server settings including IP address, port, and network interface',
          'Add clients to your server with automatic IP assignment',
          'Generate and download client configuration files',
          'Start the server to begin accepting client connections'
        ]
      },
      serverManagement: {
        title: 'Server Management',
        content: 'Servers represent WireGuard instances running on your system. Each server has its own configuration file and can support multiple clients. You can configure multiple VPN instances with different settings.',
        configItems: [
          { name: 'Name', description: 'Specify an easily recognizable name for the server instance, used to distinguish different server instances in the management interface' },
          { name: 'Address', description: 'Set the virtual network interface IP address and subnet mask for the server, in IP/mask format, e.g., 10.0.0.1/24, which defines the VPN network segment' },
          { name: 'Listen Port', description: 'Specify the UDP port on which the server listens for client connections, default is 51820, ensure this port is not occupied by other services' },
          { name: 'Private Key', description: 'Server authentication private key, automatically generated or manually entered, used for encrypted communication, must be kept confidential' },
          { name: 'Public Key', description: 'Public key paired with the private key, automatically generated from the private key, used for clients to verify server identity' },
          { name: 'DNS', description: 'Specify the DNS servers used by clients after connection, you can set one or two DNS server addresses separated by commas' },
          { name: 'MTU', description: 'Set the maximum transmission unit of the network interface, default is 1420, can be adjusted according to network environment to optimize performance' },
          { name: 'Interface', description: 'Specify the physical network interface to which the server is bound, e.g., eth0, used to determine the server\'s public IP address' },
          { name: 'Remote', description: 'Specify the address and port for clients to connect to the server, in IP/Domain name:port format, clients connect to the server through this address' }
        ]
      },
      clientManagement: {
        title: 'Client Management',
        content: 'Clients are devices that connect to your WireGuard servers. The system automatically generates configuration files for each client. Due to the characteristics of WireGuard, there may be a delay in the platform\'s determination of the client\'s online/offline status.',
        configItems: [
          { name: 'Name', description: 'Specify an easily recognizable name for the client, used to distinguish different clients in the management interface' },
          { name: 'Address', description: 'Virtual IP address assigned to the client, must be within the network segment defined by the server, in IP/32 format' },
          { name: 'Private Key', description: 'Client authentication private key, automatically generated or manually entered, used for encrypted communication, must be kept confidential' },
          { name: 'Public Key', description: 'Public key paired with the private key, automatically generated from the private key, used for server to verify client identity' },
          { name: 'Preshared Key', description: 'Provides an additional encryption layer, optional configuration, enhances security, server and client use the same key' },
          { name: 'Server Allowed IPs', description: 'Define the route for servers to access clients and control which network resources the server can access for clients' },
          { name: 'Client Allowed IPs', description: 'Define the route for client access to the server and control which network resources the client can access on the server' },
          { name: 'Persistent Keepalive', description: 'Maintains connection between client and server, sets heartbeat packet transmission interval (seconds), suitable for NAT environments' },
          { name: 'DNS', description: 'Specify the DNS server used by the client, prioritizes client configuration, if empty then uses server configuration' },
          { name: 'MTU', description: 'Set the maximum transmission unit of the client network interface, prioritizes client configuration, if 0 then uses server configuration' },
          { name: 'Email', description: 'Contact email for the client user, used to send configuration files and notifications' }
        ]
      },
      emailConfig: {
        title: 'Email Configuration',
        content: 'Configure SMTP settings to send client configuration files via email.',
        configItems: [
          { name: 'SMTP Host', description: 'SMTP server address, e.g., smtp.gmail.com' },
          { name: 'SMTP Port', description: 'SMTP server port, typically 587 (TLS) or 465 (SSL)' },
          { name: 'Username', description: 'SMTP account username, usually your email address' },
          { name: 'Password', description: 'SMTP account password or application-specific password' },
          { name: 'From Email', description: 'Email address from which to send emails' },
          { name: 'From Name', description: 'Sender name displayed when sending emails' },
          { name: 'Enabled', description: 'Enable or disable email sending functionality' }
        ]
      }
    },
    zh: {
      title: 'WireGuard Manager 帮助手册',
      introduction: 'WireGuard Manager 是一个基于Web的WireGuard VPN服务器和客户端管理工具。',
      features: [
        '服务器管理：创建、编辑和删除WireGuard服务器，支持配置多个VPN实例',
        '客户端管理：管理WireGuard客户端并自动生成配置文件',
        '实时状态：监控服务器和客户端连接状态，由于wireguard的特性，平台判断客户端在线/离线状态会有时差',
        '流量统计：查看所有连接的数据传输统计信息',
        '访问日志：跟踪客户端连接和断开连接事件',
	'邮箱功能：支持配置SMTP邮箱服务器，以通过电子邮件发送客户端配置文件，并且可添加附加文件',
        '多语言支持：界面支持英文和中文'
      ],
      gettingStarted: {
        title: '入门指南',
        steps: [
          '点击"创建服务器"按钮创建新服务器',
          '配置服务器设置，包括IP地址、端口和网络接口',
          '向服务器添加客户端并自动分配IP',
          '生成并下载客户端配置文件',
          '启动服务器以开始接受客户端连接'
        ]
      },
      serverManagement: {
        title: '服务器管理',
        content: '服务器代表系统上运行的WireGuard实例。每个服务器都有自己的配置文件，可以支持多个客户端。您可以配置多个具有不同设置的VPN实例。',
        configItems: [
          { name: '名称 (Name)', description: '为服务器实例指定一个易于识别的名称，用于在管理界面中区分不同的服务器实例' },
          { name: '地址 (Address)', description: '设置服务器的虚拟网络接口IP地址和子网掩码，格式为IP/掩码，例如：10.0.0.1/24，定义了VPN网络的网段' },
          { name: '监听端口 (Listen Port)', description: '指定服务器监听客户端连接的UDP端口，默认为51820，确保该端口未被其他服务占用' },
          { name: '私钥 (Private Key)', description: '服务器的身份验证私钥，自动生成或手动输入，用于加密通信，必须保密' },
          { name: '公钥 (Public Key)', description: '与私钥配对的公钥，自动根据私钥生成，用于客户端验证服务器身份' },
          { name: 'DNS', description: '指定客户端连接后使用的DNS服务器，可以设置一个或两个DNS服务器地址，用逗号分隔' },
          { name: 'MTU', description: '设置网络接口的最大传输单元，默认为1420，可根据网络环境调整以优化性能' },
          { name: '网络接口 (Interface)', description: '指定服务器绑定的物理网络接口，例如eth0，用于确定服务器的公网IP地址' },
          { name: '远程 (Remote)', description: '指定客户端连接服务器的地址和端口，格式为IP/域名:端口，客户端通过此地址连接到服务器' }
        ]
      },
      clientManagement: {
        title: '客户端管理',
        content: '客户端是连接到您的WireGuard服务器的设备。系统会为每个客户端自动生成配置文件。由于WireGuard的特性，平台判断客户端在线/离线状态可能会有时差。',
        configItems: [
          { name: '名称 (Name)', description: '为客户端指定一个易于识别的名称，用于在管理界面中区分不同的客户端' },
          { name: '地址 (Address)', description: '分配给客户端的虚拟IP地址，必须在服务器定义的网段内，格式为IP/32' },
          { name: '私钥 (Private Key)', description: '客户端的身份验证私钥，自动生成或手动输入，用于加密通信，必须保密' },
          { name: '公钥 (Public Key)', description: '与私钥配对的公钥，自动根据私钥生成，用于服务器验证客户端身份' },
          { name: '预共享密钥 (Preshared Key)', description: '提供额外的加密层，可选配置，增强安全性，服务器和客户端使用相同的密钥' },
          { name: '服务器允许的IP (Server Allowed IPs)', description: '定义服务器访问客户端的路由，控制服务器可以访问客户端的哪些网络资源' },
          { name: '客户端允许的IP (Client Allowed IPs)', description: '定义客户端访问服务器的路由，控制客户端可以访问服务端的哪些网络资源' },
          { name: '持久化连接 (Persistent Keepalive)', description: '维持客户端与服务器之间的连接，设置心跳包发送间隔（秒），适用于NAT环境' },
          { name: 'DNS', description: '指定客户端使用的DNS服务器，优先使用客户端配置，如果为空则使用服务器配置' },
          { name: 'MTU', description: '设置客户端网络接口的最大传输单元，优先使用客户端配置，如果为0则使用服务器配置' },
          { name: '电子邮件 (Email)', description: '客户端用户的联系邮箱，用于发送配置文件和通知' }
        ]
      },
      emailConfig: {
        title: '邮箱配置',
        content: '配置SMTP设置以通过电子邮件发送客户端配置文件。',
        configItems: [
          { name: 'SMTP主机 (SMTP Host)', description: 'SMTP服务器地址，例如smtp.gmail.com' },
          { name: 'SMTP端口 (SMTP Port)', description: 'SMTP服务器端口，通常为587（TLS）或465（SSL）' },
          { name: '用户名 (Username)', description: 'SMTP账户用户名，通常是您的邮箱地址' },
          { name: '密码 (Password)', description: 'SMTP账户密码或应用专用密码' },
          { name: '发件人邮箱 (From Email)', description: '发送邮件的邮箱地址' },
          { name: '发件人名称 (From Name)', description: '发送邮件显示的发件人名称' },
          { name: '启用 (Enabled)', description: '启用或禁用邮件发送功能' }
        ]
      }
    }
  };

  const content = helpContent[language] || helpContent.en;

  return (
    <div className="help-container">
      <h1>{content.title}</h1>

      <section className="help-section">
        <h2>{t('help.introduction', language)}</h2>
        <p>{content.introduction}</p>
      </section>

      <section className="help-section">
        <h2>{t('help.features', language)}</h2>
        <ul>
          {content.features.map((feature, index) => (
            <li key={index}>{feature}</li>
          ))}
        </ul>
      </section>

      <section className="help-section">
        <h2>{content.gettingStarted.title}</h2>
        <ol>
          {content.gettingStarted.steps.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      </section>

      <section className="help-section">
        <h2>{content.serverManagement.title}</h2>
        <p>{content.serverManagement.content}</p>
        <h3>{language === 'zh' ? '服务器配置项说明' : 'Server Configuration Items'}</h3>
        <ul>
          {content.serverManagement.configItems.map((item, index) => (
            <li key={index}><strong>{item.name}:</strong> {item.description}</li>
          ))}
        </ul>
      </section>

      <section className="help-section">
        <h2>{content.clientManagement.title}</h2>
        <p>{content.clientManagement.content}</p>
        <h3>{language === 'zh' ? '客户端配置项说明' : 'Client Configuration Items'}</h3>
        <ul>
          {content.clientManagement.configItems.map((item, index) => (
            <li key={index}><strong>{item.name}:</strong> {item.description}</li>
          ))}
        </ul>
      </section>

      <section className="help-section">
        <h2>{content.emailConfig.title}</h2>
        <p>{content.emailConfig.content}</p>
        <h3>{language === 'zh' ? '邮箱配置项说明' : 'Email Configuration Items'}</h3>
        <ul>
          {content.emailConfig.configItems.map((item, index) => (
            <li key={index}><strong>{item.name}:</strong> {item.description}</li>
          ))}
        </ul>
      </section>
    </div>
  );
};

export default Help;
