package main

import (
      "database/sql"
      "fmt"
      "log"
      "net"
      "net/http"
      "os"
      "os/exec"
      "path/filepath"
      "regexp"
      "strconv"
      "strings"
      "time"

      _ "github.com/go-sql-driver/mysql"
      "github.com/labstack/echo/v4"
      "github.com/labstack/echo/v4/middleware"
)

type Server struct {
      ID         int    `json:"id" db:"id"`
      Name       string `json:"name" db:"name"`
      Address    string `json:"address" db:"address"`
      ListenPort int    `json:"listen_port" db:"listen_port"`
      PrivateKey string `json:"private_key" db:"private_key"`
      PublicKey  string `json:"public_key" db:"public_key"`
      Status     string `json:"status" db:"-"`  // 不存储在数据库中，仅用于API响应
      DNS        string `json:"dns" db:"dns"`
      MTU        int    `json:"mtu" db:"mtu"`
      Interface  string `json:"interface" db:"interface"`
      PublicIpPort string `json:"public_ip_port" db:"public_ip_port"`
}

type Client struct {
      ID             int    `json:"id" db:"id"`
      ServerID       int    `json:"server_id" db:"server_id"`
      Name           string `json:"name" db:"name"`
      Address        string `json:"address" db:"address"`
      PrivateKey     string `json:"private_key" db:"private_key"`
      PublicKey      string `json:"public_key" db:"public_key"`
      PresharedKey   string `json:"preshared_key" db:"preshared_key"`
      AllowedIPs     string `json:"allowed_ips" db:"allowed_ips"`
      ServerAllowedIPs *string `json:"server_allowed_ips" db:"server_allowed_ips"`
      ClientAllowedIPs *string `json:"client_allowed_ips" db:"client_allowed_ips"`
      Status         string `json:"status" db:"status"`
      LatestHandshake *string `json:"latest_handshake" db:"latest_handshake"`
      TransferRx     int64  `json:"transfer_rx" db:"transfer_rx"`
      TransferTx     int64  `json:"transfer_tx" db:"transfer_tx"`
      Enabled        int    `json:"enabled" db:"enabled"`
      PersistentKeepalive int `json:"persistent_keepalive" db:"persistent_keepalive"`
      DNS            string `json:"dns" db:"dns"`
      MTU            int    `json:"mtu" db:"mtu"`
      OnlineTime     int    `json:"online_time" db:"online_time"`
      FirstOnline    *string `json:"first_online" db:"first_online"`
      Email          string `json:"email" db:"email"`
      AutoGeneratePresharedKey bool `json:"autoGeneratePresharedKey"` // 仅用于接收前端参数，不存储到数据库
}

type EmailConfig struct {
      ID        int    `json:"id" db:"id"`
      SMTPHost  string `json:"smtp_host" db:"smtp_host"`
      SMTPPort  int    `json:"smtp_port" db:"smtp_port"`
      Username  string `json:"username" db:"username"`
      Password  string `json:"password" db:"password"`
      FromEmail string `json:"from_email" db:"from_email"`
      FromName  string `json:"from_name" db:"from_name"`
      Enabled   int    `json:"enabled" db:"enabled"`
}

type AdditionalFileConfig struct {
      ID        int    `json:"id" db:"id"`
      FilePath  string `json:"file_path" db:"file_path"`
      FileName  string `json:"file_name" db:"file_name"`
      Enabled   int    `json:"enabled" db:"enabled"`
}

// 写入日志到文件
func writeLog(message string) {
      f, err := os.OpenFile("/var/log/wireguard-manager.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
      if err != nil {
        log.Println("Failed to open log file:", err)
        return
      }
      defer f.Close()

      timestamp := time.Now().Format("2006-01-02 15:04:05")
      logMessage := fmt.Sprintf("[%s] %s\n", timestamp, message)
      if _, err := f.WriteString(logMessage); err != nil {
        log.Println("Failed to write to log file:", err)
      }
}

func main() {
      writeLog("Starting WireGuard Manager main function")
      // 初始化主数据库连接
      db, err := initDBConnection()
      if err != nil {
        log.Fatal(err)
      }
      defer db.Close()

      // 为定时任务创建单独的数据库连接
      dbForTasks, err := initDBConnection()
      if err != nil {
        log.Fatal(err)
      }
      defer dbForTasks.Close()

      // 创建表
      initDB(db)

      // 创建日志目录
      os.MkdirAll("/var/log", 0755)

      // 创建Echo实例
      e := echo.New()

      // 中间件
      e.Use(middleware.Logger())
      e.Use(middleware.Recover())
      // 设置请求体大小限制为20MB，用于文件上传
      e.Use(middleware.BodyLimit("20M"))

      // 路由
      e.GET("/api/servers", getServers(db))
      e.POST("/api/servers", createServer(db))
      e.PUT("/api/servers/:id", updateServer(db))
      e.DELETE("/api/servers/:id", deleteServer(db))

      e.GET("/api/clients", getClients(db))
      e.GET("/api/clients/search", searchClients(db))
      e.POST("/api/clients", createClient(db))
      e.PUT("/api/clients/:id", updateClient(db))
      e.DELETE("/api/clients/:id", deleteClient(db))
      e.POST("/api/clients/:id/enable", enableClient(db))
      e.POST("/api/clients/:id/disable", disableClient(db))

      e.GET("/api/status", getWireGuardStatus)
      e.GET("/api/servers/:id/config", getServerConfig(db))
      e.GET("/api/clients/:id/config", getClientConfig(db))
      e.POST("/api/up/:interface", func(c echo.Context) error {
        return upWireGuardInterfaceHandler(c, db)
      })
      e.POST("/api/down/:interface", func(c echo.Context) error {
        return downWireGuardInterfaceHandler(c, db)
      })
      e.POST("/api/restart/:interface", func(c echo.Context) error {
        return restartWireGuardInterfaceHandler(c, db)
      })

      e.GET("/api/traffic", getTrafficStats(db))
      e.GET("/api/detailed-traffic", getDetailedTrafficStats(db))
      e.GET("/api/access-logs", getAccessLogs(db))
      e.GET("/api/access-logs/search", searchAccessLogs(db))
      e.GET("/api/interfaces", getNetworkInterfaces)
      e.GET("/api/online-clients", getOnlineClients(db))

      // 认证相关路由
      e.POST("/api/login", login(db))
      e.POST("/api/change-password", changePassword(db))
      e.GET("/api/check-auth", checkAuth)

      // 邮件配置相关路由
      e.GET("/api/email-config", getEmailConfig(db))
      e.POST("/api/email-config", updateEmailConfig(db))
      e.POST("/api/test-email", testEmailConfig(db))
      e.POST("/api/clients/:id/send-config", sendClientConfig(db))

      // 附加文件配置相关路由
      e.GET("/api/additional-file-config", getAdditionalFileConfig(db))
      e.POST("/api/additional-file-config", updateAdditionalFileConfig(db))
      e.POST("/api/upload-additional-file", uploadAdditionalFile(db))
      e.POST("/api/delete-additional-file", deleteAdditionalFile(db))

      // 记录启动日志
      writeLog("WireGuard Manager started")

      // 启动定时任务来更新客户端状态
      go func() {
              ticker := time.NewTicker(30 * time.Second)
              defer ticker.Stop()

              for {
                      <-ticker.C
                      writeLog("Running updateClientStatuses task")
                      updateClientStatuses(dbForTasks)
                      writeLog("Finished updateClientStatuses task")
              }
      }()

      // 启动定时任务来清理三个月前的访问日志
      go func() {
              // 每天检查一次（24小时）
              ticker := time.NewTicker(24 * time.Hour)
              defer ticker.Stop()

              for {
                      <-ticker.C
                      writeLog("Running cleanupOldAccessLogs task")
                      cleanupOldAccessLogs(dbForTasks)
                      writeLog("Finished cleanupOldAccessLogs task")
              }
      }()

      // 启动服务器，使用默认的8080端口
      e.Logger.Fatal(e.Start(":8080"))
}

// 创建VPN统计表
type VPNStats struct {
	ID            int     `json:"id"`
	TotalReceived float64 `json:"total_received"`
	TotalSent     float64 `json:"total_sent"`
}

func createVPNStatsTable(db *sql.DB) {
	// 使用SQL创建vpn_stats表(如果不存在)
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS vpn_stats (
			id INT PRIMARY KEY,
			total_received FLOAT DEFAULT 0,
			total_sent FLOAT DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		writeLog(fmt.Sprintf("Error creating vpn_stats table: %v", err))
	} else {
		writeLog("vpn_stats table created or already exists")
	}

	// 尝试插入初始记录(如果不存在)
	_, err = db.Exec("INSERT IGNORE INTO vpn_stats (id, total_received, total_sent) VALUES (1, 0, 0)")
	if err != nil {
		writeLog(fmt.Sprintf("Error inserting initial vpn_stats record: %v", err))
	} else {
		writeLog("Initial vpn_stats record created or already exists")
	}
}

func initDB(db *sql.DB) {
      // MySQL数据库表已经通过SQL脚本创建，这里只需要确保默认数据存在
      // 创建vpn_stats表（如果不存在）
      createVPNStatsTable(db)
      
      // 检查并插入默认用户
      insertDefaultUser(db)

      // 检查并插入默认邮件配置
      insertDefaultEmailConfig(db)

      // 检查并插入默认附加文件配置
      insertDefaultAdditionalFileConfig(db)
}

// 插入默认用户
func insertDefaultUser(db *sql.DB) {
      var count int
      err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
      if err != nil {
        log.Printf("Error checking default user: %v", err)
        return
      }

      if count == 0 {
        // 插入默认用户 admin/admin
        _, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "admin", "admin")
        if err != nil {
          log.Printf("Error inserting default user: %v", err)
        } else {
          log.Println("Default user 'admin' created")
        }
      }
}

// 插入默认邮件配置
func insertDefaultEmailConfig(db *sql.DB) {
      var count int
      err := db.QueryRow("SELECT COUNT(*) FROM email_config").Scan(&count)
      if err != nil {
        log.Printf("Error checking email config: %v", err)
        return
      }

      if count == 0 {
        // 插入默认邮件配置
        _, err = db.Exec("INSERT INTO email_config (smtp_host, smtp_port, username, password, from_email, from_name, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         "", 587, "", "", "", "WireGuard Manager", 0)
        if err != nil {
          log.Printf("Error inserting default email config: %v", err)
        } else {
          log.Println("Default email configuration created")
        }
      }
}

// 插入默认附加文件配置
func insertDefaultAdditionalFileConfig(db *sql.DB) {
      var count int
      err := db.QueryRow("SELECT COUNT(*) FROM additional_file_config").Scan(&count)
      if err != nil {
        log.Printf("Error checking additional file config: %v", err)
        return
      }

      if count == 0 {
        // 插入默认附加文件配置
        _, err = db.Exec("INSERT INTO additional_file_config (file_path, file_name, enabled) VALUES (?, ?, ?)",
                         "", "", 0)
        if err != nil {
          log.Printf("Error inserting default additional file config: %v", err)
        } else {
          log.Println("Default additional file configuration created")
        }
      }
}

// 为表添加列，如果列已存在则忽略错误
func addColumnsIfNotExists(db *sql.DB, columns []string) {
      for _, column := range columns {
        _, err := db.Exec(column)
        // 忽略"duplicate column name"错误，因为列可能已经存在
        if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
                log.Printf("Warning: %v", err)
        }
      }
}

// 生成WireGuard密钥对
func generateKeyPair() (privateKey, publicKey string, err error) {
      // 生成私钥
      cmd := exec.Command("wg", "genkey")
      privateKeyBytes, err := cmd.Output()
      if err != nil {
        return "", "", err
      }
      privateKey = strings.TrimSpace(string(privateKeyBytes))

      // 基于私钥生成公钥
      cmd = exec.Command("wg", "pubkey")
      cmd.Stdin = strings.NewReader(privateKey)
      publicKeyBytes, err := cmd.Output()
      if err != nil {
        return "", "", err
      }
      publicKey = strings.TrimSpace(string(publicKeyBytes))

      return privateKey, publicKey, nil
}

// 生成WireGuard预共享密钥
func generatePresharedKey() (presharedKey string, err error) {
      // 生成预共享密钥
      cmd := exec.Command("wg", "genpsk")
      presharedKeyBytes, err := cmd.Output()
      if err != nil {
        return "", err
      }
      presharedKey = strings.TrimSpace(string(presharedKeyBytes))

      return presharedKey, nil
}

// 获取下一个可用的服务器 ID
func getNextServerID(db *sql.DB) (int, error) {
      // 从 0 开始检查可用的 ID
      for id := 0; ; id++ {
        var count int
        err := db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ?", id).Scan(&count)
        if err != nil {
                writeLog(fmt.Sprintf("getNextServerID: Error querying ID %d: %v", id, err))
                return 0, err
        }

        writeLog(fmt.Sprintf("getNextServerID: Checking ID %d, count = %d", id, count))

        // 如果此 ID 不存在，则可以使用
        if count == 0 {
                writeLog(fmt.Sprintf("getNextServerID: Found available ID %d", id))
                return id, nil
        }

        // Safety check to prevent infinite loop
        if id > 1000 {
                writeLog("getNextServerID: Reached safety limit of 1000, returning error")
                return 0, fmt.Errorf("unable to find available server ID within reasonable range")
        }
      }
}

// 获取下一个可用的客户端 ID
func getNextClientID(db *sql.DB) (int, error) {
      // 从 0 开始检查可用的 ID
      for id := 0; ; id++ {
        var count int
        err := db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", id).Scan(&count)
        if err != nil {
                return 0, err
        }

        // 如果此 ID 不存在，则可以使用
        if count == 0 {
                return id, nil
        }
      }
}

// 重置客户端表的 AUTO_INCREMENT 值
func resetClientAutoIncrement(db *sql.DB, clientID int) {
      _, err := db.Exec(fmt.Sprintf("ALTER TABLE clients AUTO_INCREMENT = %d", clientID+1))
      if err != nil {
              writeLog(fmt.Sprintf("Failed to update clients auto increment value: %v", err))
              // 即使错误也继续执行
      }
}

// 通过接口名称获取服务器ID
func getServerIDByInterfaceName(interfaceName string, db *sql.DB) (int, error) {
      // 从接口名称"wg0"中提取数字部分作为服务器ID
      if len(interfaceName) > 2 && interfaceName[:2] == "wg" {
        id, err := strconv.Atoi(interfaceName[2:])
        if err != nil {
                return 0, err
        }
        
        // 验证服务器是否存在
        var count int
        err = db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ?", id).Scan(&count)
        if err != nil {
                return 0, err
        }
        
        if count > 0 {
                return id, nil
        }
      }
      
      return 0, fmt.Errorf("server not found for interface: %s", interfaceName)
}

// 生成WireGuard配置文件
func generateServerConfig(server Server, clients []Client) string {
      config := "[Interface]\n"
      // 添加本端服务器名称注释
      config += "#name = " + server.Name + "\n"
      config += "PrivateKey = " + server.PrivateKey + "\n"
      config += "Address = " + server.Address + "\n"
      config += "ListenPort = " + strconv.Itoa(server.ListenPort) + "\n"

      // 添加DNS配置（如果已设置）
      if server.DNS != "" {
        config += "DNS = " + server.DNS + "\n"
      }

      // 添加MTU配置（如果已设置且非0）
      if server.MTU != 0 {
        config += "MTU = " + strconv.Itoa(server.MTU) + "\n"
      }

      // 添加Public IP:Port注释
      config += "#Public IP:Port = " + server.PublicIpPort + "\n"

      // 添加PostUp和PostDown规则
      config += "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o " + server.Interface + " -j MASQUERADE\n"
      config += "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o " + server.Interface + " -j MASQUERADE\n\n"

      for _, client := range clients {
        config += "[Peer]\n"
        // 添加对端客户端名称注释
        config += "#name = " + client.Name + " --ip: " + strings.Split(client.Address, "/")[0] + "\n"
        config += "PublicKey = " + client.PublicKey + "\n"
        if client.PresharedKey != "" {
                config += "PresharedKey = " + client.PresharedKey + "\n"
        }
        serverAllowedIPs := ""
        if client.ServerAllowedIPs != nil {
                serverAllowedIPs = *client.ServerAllowedIPs
        }
        // 处理多个CIDR条目
        config += "AllowedIPs = " + processCIDRList(serverAllowedIPs) + "\n"
        if client.PersistentKeepalive > 0 {
                config += "PersistentKeepalive = " + strconv.Itoa(client.PersistentKeepalive) + "\n"
        }
        config += "\n"
      }

      return config
}

// 生成客户端配置文件
func generateClientConfig(client Client, server Server) string {
	config := "[Interface]\n"
	// 添加本端客户端名称注释
	config += "#name = " + client.Name + "\n"
	config += "PrivateKey = " + client.PrivateKey + "\n"

	// 处理客户端地址，添加24位掩码
	clientIP := strings.Split(client.Address, "/")[0]
	config += "Address = " + clientIP + "/24\n"

	// 添加DNS配置（优先使用客户端配置，如果为空则使用服务器配置）
	dnsConfig := client.DNS
	if dnsConfig == "" {
		dnsConfig = server.DNS
	}
	if dnsConfig != "" {
		config += "DNS = " + dnsConfig + "\n"
	}

	// 添加MTU配置（优先使用客户端配置，如果为0则使用服务器配置）
	mtuConfig := client.MTU
	if mtuConfig == 0 {
		mtuConfig = server.MTU
	}
	if mtuConfig != 0 {
		config += "MTU = " + strconv.Itoa(mtuConfig) + "\n"
	}

	config += "\n[Peer]\n"
	// 添加对端服务器名称注释
	config += "#name = " + server.Name + "\n"
	config += "PublicKey = " + server.PublicKey + "\n"

	// 添加Endpoint配置（服务器的公网IP和端口）- 必须设置
	config += "Endpoint = " + server.PublicIpPort + "\n"

	// 添加PresharedKey配置（如果存在）
	if client.PresharedKey != "" {
		config += "PresharedKey = " + client.PresharedKey + "\n"
	}

	// 添加Client Allowed IPs配置
	clientAllowedIPs := ""
	if client.ClientAllowedIPs != nil {
		clientAllowedIPs = *client.ClientAllowedIPs
	}
	// 处理多个CIDR条目
	config += "AllowedIPs = " + processCIDRList(clientAllowedIPs) + "\n"

	// 添加PersistentKeepalive配置
	if client.PersistentKeepalive > 0 {
		config += "PersistentKeepalive = " + strconv.Itoa(client.PersistentKeepalive) + "\n"
	}

	return config
}

// 保存客户端配置文件
func saveClientConfigFile(client Client, server Server) error {
	// 创建客户端配置目录
	interfaceName := "wg" + strconv.Itoa(server.ID)
	clientDir := filepath.Join("/etc/wireguard", "Clients", interfaceName+"_clients")
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		return err
	}

	// 生成客户端配置内容
	config := generateClientConfig(client, server)

	// 保存配置文件
	clientConfigPath := filepath.Join(clientDir, client.Name+".conf")
	return os.WriteFile(clientConfigPath, []byte(config), 0600)
}

// 删除客户端配置文件
func deleteClientConfigFile(client Client, server Server) error {
	interfaceName := "wg" + strconv.Itoa(server.ID)
	clientDir := filepath.Join("/etc/wireguard", "Clients", interfaceName+"_clients")
	clientConfigPath := filepath.Join(clientDir, client.Name+".conf")

	// 检查文件是否存在，如果存在则删除
	if _, err := os.Stat(clientConfigPath); err == nil {
		return os.Remove(clientConfigPath)
	}

	return nil
}

// 删除服务器对应的客户端配置目录
func deleteServerClientConfigDir(serverID int) error {
	interfaceName := "wg" + strconv.Itoa(serverID)
	clientDir := filepath.Join("/etc/wireguard", "Clients", interfaceName+"_clients")

	// 检查目录是否存在，如果存在则删除整个目录
	if _, err := os.Stat(clientDir); err == nil {
		return os.RemoveAll(clientDir)
	}

	return nil
}

// 更新服务器配置文件
func updateServerConfig(db *sql.DB, serverID int) error {
      // 获取服务器信息
      row := db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", serverID)
      server := Server{}
      err := row.Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
      if err != nil {
        return err
      }

      // 获取相关客户端信息(仅获取启用的客户端)
      clientRows, err := db.Query("SELECT id, server_id, name, address, private_key, public_key, preshared_key, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive FROM clients WHERE server_id=? AND enabled=1", serverID)
      if err != nil {
        return err
      }
      defer clientRows.Close()

      clients := []Client{}
      for clientRows.Next() {
        var cl Client
        err := clientRows.Scan(&cl.ID, &cl.ServerID, &cl.Name, &cl.Address, &cl.PrivateKey, &cl.PublicKey, &cl.PresharedKey, &cl.ServerAllowedIPs, &cl.ClientAllowedIPs, &cl.Status, &cl.LatestHandshake, &cl.TransferRx, &cl.TransferTx, &cl.PersistentKeepalive)
        if err != nil {
                return err
        }
        clients = append(clients, cl)
      }

      // 生成并保存配置文件
      config := generateServerConfig(server, clients)
      interfaceName := "wg" + strconv.Itoa(server.ID)
      err = saveConfigToFile(interfaceName, config)
      if err != nil {
        return err
      }
      
      // 更新所有相关客户端的配置文件以同步服务器信息（DNS、MTU、Name等）
      for _, client := range clients {
        if err := saveClientConfigFile(client, server); err != nil {
          writeLog(fmt.Sprintf("Failed to update client config file for client %s in updateServerConfig: %v", client.Name, err))
          // 继续处理其他客户端，不中断整个过程
        }
      }
      
      return nil
}

func saveConfigToFile(interfaceName, config string) error {
      filePath := filepath.Join("/etc/wireguard", interfaceName+".conf")
      return os.WriteFile(filePath, []byte(config), 0600)
}

// 服务器相关处理函数
func getServers(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        rows, err := db.Query("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers")
        if err != nil {
                return err
        }
        defer rows.Close()

        servers := []Server{}
        for rows.Next() {
                var s Server
                  err := rows.Scan(&s.ID, &s.Name, &s.Address, &s.ListenPort, &s.PrivateKey, &s.PublicKey, &s.DNS, &s.MTU, &s.Interface, &s.PublicIpPort)
                if err != nil {
                        return err
                }
                
                // 检查网卡实际状态
                interfaceName := fmt.Sprintf("wg%d", s.ID)
                if isInterfaceUp(interfaceName) {
                        s.Status = "up"
                } else {
                        s.Status = "down"
                }
                
                servers = append(servers, s)
        }

        return c.JSON(http.StatusOK, servers)
      }
}

// 服务器相关处理函数

func createServer(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        s := new(Server)
        if err := c.Bind(s); err != nil {
                writeLog(fmt.Sprintf("Failed to bind server data: %v", err))
                return err
        }

        // 检查服务器名称是否已存在
        var count int
        err := db.QueryRow("SELECT COUNT(*) FROM servers WHERE name=?", s.Name).Scan(&count)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to check server name uniqueness: %v", err))
                return err
        }
        if count > 0 {
                errorMsg := "Error: Name already exists"
                writeLog(errorMsg)
                return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
        }

        // 验证DNS格式（如果提供）
        if s.DNS != "" {
                // 分割多个DNS地址
                dnsAddresses := strings.Split(s.DNS, ",")
                // 最多允许两个DNS地址
                if len(dnsAddresses) > 2 {
                        writeLog(fmt.Sprintf("Too many DNS addresses: %d (maximum 2)", len(dnsAddresses)))
                        return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Too many DNS addresses: %d (maximum 2)", len(dnsAddresses))})
                }
                for _, dnsAddr := range dnsAddresses {
                        dnsAddr = strings.TrimSpace(dnsAddr)
                        ip := net.ParseIP(dnsAddr)
                        if ip == nil {
                                writeLog(fmt.Sprintf("Invalid DNS address format: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid DNS address format: %s", dnsAddr)})
                        }
                        // 只接受IPv4地址
                        if ip.To4() == nil {
                                writeLog(fmt.Sprintf("Only IPv4 DNS addresses are supported: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Only IPv4 DNS addresses are supported: %s", dnsAddr)})
                        }
                }
        }

        // 获取下一个可用的 ID
        id, err := getNextServerID(db)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get next server ID: %v", err))
                return err
        }
        s.ID = id
        writeLog(fmt.Sprintf("createServer: Using ID %d for server %s", s.ID, s.Name))

        // 设置默认值
        if s.MTU == 0 {
                s.MTU = 1420
        }
        if s.Interface == "" {
                s.Interface = "eth0"
        }
        // DNS设置为必选项，未选则默认为114.114.114.114
        if s.DNS == "" {
                s.DNS = "114.114.114.114"
        }
        // 如果Public IP:Port未提供，则自动设置为网卡IP:ListenPort
        if s.PublicIpPort == "" {
                ip, err := getInterfaceIPAddress(s.Interface)
                if err == nil {
                        s.PublicIpPort = fmt.Sprintf("%s:%d", ip, s.ListenPort)
                        writeLog(fmt.Sprintf("Auto-set Public IP:Port for server %s to %s", s.Name, s.PublicIpPort))
                } else {
                        writeLog(fmt.Sprintf("Failed to get IP address for interface %s: %v", s.Interface, err))
                }
        }

        // 如果没有提供密钥，则自动生成
        if s.PrivateKey == "" || s.PublicKey == "" {
                privateKey, publicKey, err := generateKeyPair()
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to generate key pair: %v", err))
                        return fmt.Errorf("failed to generate key pair: %v", err)
                }
                s.PrivateKey = privateKey
                s.PublicKey = publicKey
                writeLog(fmt.Sprintf("Generated key pair for server: %s", s.Name))
        }

        stmt, err := db.Prepare("INSERT INTO servers (id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        if err != nil {
                writeLog(fmt.Sprintf("Failed to prepare server insert statement: %v", err))
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(s.ID, s.Name, s.Address, s.ListenPort, s.PrivateKey, s.PublicKey, s.DNS, s.MTU, s.Interface, s.PublicIpPort)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to insert server: %v", err))
                return err
        }

        // 更新服务器表的auto_increment值，确保下次可以重用ID
        // 设置auto_increment为当前ID+1，这样下次可以重用之前的ID
        _, err = db.Exec(fmt.Sprintf("ALTER TABLE servers AUTO_INCREMENT = %d", s.ID+1))
        if err != nil {
                writeLog(fmt.Sprintf("Failed to update auto increment value: %v", err))
                // 即使错误也继续执行
        }

        // 生成并保存配置文件
        clients := []Client{}
        config := generateServerConfig(*s, clients)
        interfaceName := "wg" + strconv.Itoa(s.ID)
        if err := saveConfigToFile(interfaceName, config); err != nil {
                writeLog(fmt.Sprintf("Failed to save config file for server %s: %v", s.Name, err))
                return err
        }

        writeLog(fmt.Sprintf("Created server: %s (ID: %d)", s.Name, s.ID))
        return c.JSON(http.StatusCreated, s)
      }
}

func updateServer(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")
        s := new(Server)
        if err := c.Bind(s); err != nil {
                return err
        }

        // 检查服务器名称是否已存在（排除当前服务器）
        var count int
        err := db.QueryRow("SELECT COUNT(*) FROM servers WHERE name=? AND id!=?", s.Name, id).Scan(&count)
        if err != nil {
                return err
        }
        if count > 0 {
                errorMsg := "Error: Name already exists"
                writeLog(errorMsg)
                return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
        }

        // 验证DNS格式（如果提供）
        if s.DNS != "" {
                // 分割多个DNS地址
                dnsAddresses := strings.Split(s.DNS, ",")
                // 最多允许两个DNS地址
                if len(dnsAddresses) > 2 {
                        writeLog(fmt.Sprintf("Too many DNS addresses: %d (maximum 2)", len(dnsAddresses)))
                        return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Too many DNS addresses: %d (maximum 2)", len(dnsAddresses))})
                }
                for _, dnsAddr := range dnsAddresses {
                        dnsAddr = strings.TrimSpace(dnsAddr)
                        ip := net.ParseIP(dnsAddr)
                        if ip == nil {
                                writeLog(fmt.Sprintf("Invalid DNS address format: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid DNS address format: %s", dnsAddr)})
                        }
                        // 只接受IPv4地址
                        if ip.To4() == nil {
                                writeLog(fmt.Sprintf("Only IPv4 DNS addresses are supported: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Only IPv4 DNS addresses are supported: %s", dnsAddr)})
                        }
                }
        }

        // DNS设置为必选项，未选则默认为114.114.114.114
        if s.DNS == "" {
                s.DNS = "114.114.114.114"
        }
        // 如果Public IP:Port未提供，则自动设置为网卡IP:ListenPort
        if s.PublicIpPort == "" {
                ip, err := getInterfaceIPAddress(s.Interface)
                if err == nil {
                        s.PublicIpPort = fmt.Sprintf("%s:%d", ip, s.ListenPort)
                        writeLog(fmt.Sprintf("Auto-set Public IP:Port for server %s to %s", s.Name, s.PublicIpPort))
                } else {
                        writeLog(fmt.Sprintf("Failed to get IP address for interface %s: %v", s.Interface, err))
                }
        }

        stmt, err := db.Prepare("UPDATE servers SET name=?, address=?, listen_port=?, private_key=?, public_key=?, dns=?, mtu=?, interface=?, public_ip_port=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        if err != nil {
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(s.Name, s.Address, s.ListenPort, s.PrivateKey, s.PublicKey, s.DNS, s.MTU, s.Interface, s.PublicIpPort, id)
        if err != nil {
                return err
        }

        // 获取更新后的服务器信息
        row := db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", id)
        updatedServer := Server{}
        err = row.Scan(&updatedServer.ID, &updatedServer.Name, &updatedServer.Address, &updatedServer.ListenPort, &updatedServer.PrivateKey, &updatedServer.PublicKey, &updatedServer.DNS, &updatedServer.MTU, &updatedServer.Interface, &updatedServer.PublicIpPort)
        if err != nil {
                return err
        }

        // 获取相关客户端信息
        clientRows, err := db.Query("SELECT id, server_id, name, address, private_key, public_key, preshared_key, allowed_ips, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx FROM clients WHERE server_id=?", id)
        if err != nil {
                return err
        }
        defer clientRows.Close()

        clients := []Client{}
        for clientRows.Next() {
                var cl Client
                err := clientRows.Scan(&cl.ID, &cl.ServerID, &cl.Name, &cl.Address, &cl.PrivateKey, &cl.PublicKey, &cl.PresharedKey, &cl.AllowedIPs, &cl.ServerAllowedIPs, &cl.ClientAllowedIPs, &cl.Status, &cl.LatestHandshake, &cl.TransferRx, &cl.TransferTx)
                if err != nil {
                        return err
                }
                clients = append(clients, cl)
        }

        // 生成并保存配置文件
        config := generateServerConfig(updatedServer, clients)
        interfaceName := "wg" + id
        if err := saveConfigToFile(interfaceName, config); err != nil {
                return err
        }
        
        // 更新所有相关客户端的配置文件以同步服务器信息（DNS、MTU、Name等）
        for _, client := range clients {
                if err := saveClientConfigFile(client, updatedServer); err != nil {
                        writeLog(fmt.Sprintf("Failed to update client config file for client %s on server update: %v", client.Name, err))
                        // 继续处理其他客户端，不中断整个过程
                }
        }

        return c.JSON(http.StatusOK, s)
      }
}

func deleteServer(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")

        // 删除配置文件
        interfaceName := "wg" + id
        filePath := filepath.Join("/etc/wireguard", interfaceName+".conf")
        os.Remove(filePath)

        // 删除客户端配置目录
        serverID, err := strconv.Atoi(id)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to parse server ID %s: %v", id, err))
        } else {
                if err := deleteServerClientConfigDir(serverID); err != nil {
                        writeLog(fmt.Sprintf("Failed to delete client config directory for server ID %s: %v", id, err))
                } else {
                        writeLog(fmt.Sprintf("Deleted client config directory for server ID: %s", id))
                }
        }

        // 先删除关联的客户端
        clientStmt, err := db.Prepare("DELETE FROM clients WHERE server_id=?")
        if err != nil {
                writeLog(fmt.Sprintf("Failed to prepare client delete statement: %v", err))
                return err
        }
        defer clientStmt.Close()

        _, err = clientStmt.Exec(id)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to delete clients for server ID %s: %v", id, err))
                return err
        }

        // 重置客户端表的AUTO_INCREMENT值，确保ID可以被重用
        // 获取当前最大ID并设置AUTO_INCREMENT为该ID+1
        var maxID int
        err = db.QueryRow("SELECT COALESCE(MAX(id), -1) FROM clients").Scan(&maxID)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get max client ID: %v", err))
        } else {
                resetClientAutoIncrement(db, maxID)
        }

        // 再删除服务器
        stmt, err := db.Prepare("DELETE FROM servers WHERE id=?")
        if err != nil {
                writeLog(fmt.Sprintf("Failed to prepare server delete statement: %v", err))
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(id)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to delete server ID %s: %v", id, err))
                return err
        }

        // 重置服务器表的AUTO_INCREMENT值，确保ID可以被重用
        // 获取当前最大ID并设置AUTO_INCREMENT为该ID+1
        var maxServerID int
        err = db.QueryRow("SELECT COALESCE(MAX(id), -1) FROM servers").Scan(&maxServerID)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get max server ID: %v", err))
        } else {
                _, err = db.Exec(fmt.Sprintf("ALTER TABLE servers AUTO_INCREMENT = %d", maxServerID+1))
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to update servers auto increment value: %v", err))
                }
        }

        writeLog(fmt.Sprintf("Deleted server ID: %s and its associated clients", id))
        return c.NoContent(http.StatusNoContent)
      }
}

// 客户端相关处理函数
func getClients(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        // 查询所有客户端，包含服务器信息
        query := `
        SELECT
          c.id,
          c.server_id,
          c.name,
          c.address,
          c.private_key,
          c.public_key,
          c.preshared_key,
          c.allowed_ips,
          c.server_allowed_ips,
          c.client_allowed_ips,
          c.status,
          c.latest_handshake,
          c.transfer_rx,
          c.transfer_tx,
          c.enabled,
          c.persistent_keepalive,
          c.dns,
          c.mtu,
          c.online_time,
          c.first_online,
          c.email,
          s.name as server_name
        FROM clients c
        JOIN servers s ON c.server_id = s.id
        `
        rows, err := db.Query(query)
        if err != nil {
                return err
        }
        defer rows.Close()

        type ClientWithServerName struct {
                ID              int     `json:"id"`
                ServerID        int     `json:"server_id"`
                Name            string  `json:"name"`
                Address         string  `json:"address"`
                PrivateKey      string  `json:"private_key"`
                PublicKey       string  `json:"public_key"`
                PresharedKey    string  `json:"preshared_key"`
                AllowedIPs      string  `json:"allowed_ips"`
                ServerAllowedIPs *string `json:"server_allowed_ips"`
                ClientAllowedIPs *string `json:"client_allowed_ips"`
                Status          string  `json:"status"`
                LatestHandshake *string `json:"latest_handshake"`
                TransferRx      int64   `json:"transfer_rx"`
                TransferTx      int64   `json:"transfer_tx"`
                Enabled         int     `json:"enabled"`
                PersistentKeepalive int `json:"persistent_keepalive"`
                DNS             string  `json:"dns"`
                MTU             int     `json:"mtu"`
                OnlineTime      int     `json:"online_time"`
                FirstOnline     *string `json:"first_online"`
                Email           string  `json:"email"`
                ServerName      string  `json:"server_name"`
        }

        clients := []ClientWithServerName{}
        for rows.Next() {
                var c ClientWithServerName
                err := rows.Scan(&c.ID, &c.ServerID, &c.Name, &c.Address, &c.PrivateKey, &c.PublicKey, &c.PresharedKey, &c.AllowedIPs, &c.ServerAllowedIPs, &c.ClientAllowedIPs, &c.Status, &c.LatestHandshake, &c.TransferRx, &c.TransferTx, &c.Enabled, &c.PersistentKeepalive, &c.DNS, &c.MTU, &c.OnlineTime, &c.FirstOnline, &c.Email, &c.ServerName)
                if err != nil {
                        return err
                }
                clients = append(clients, c)
        }

        return c.JSON(http.StatusOK, clients)
      }
}

// 启用客户端
func enableClient(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")

        stmt, err := db.Prepare("UPDATE clients SET enabled=1 WHERE id=?")
        if err != nil {
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(id)
        if err != nil {
                return err
        }

        // 获取客户端信息以获取server_id
        var serverID int
        row := db.QueryRow("SELECT server_id FROM clients WHERE id=?", id)
        err = row.Scan(&serverID)
        if err != nil {
                return err
        }

        // 更新服务器配置文件
        updateServerConfig(db, serverID)

        return c.NoContent(http.StatusOK)
      }
}

// 禁用客户端
func disableClient(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")

        stmt, err := db.Prepare("UPDATE clients SET enabled=0 WHERE id=?")
        if err != nil {
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(id)
        if err != nil {
                return err
        }

        // 获取客户端信息以获取server_id
        var serverID int
        row := db.QueryRow("SELECT server_id FROM clients WHERE id=?", id)
        err = row.Scan(&serverID)
        if err != nil {
                return err
        }

        // 更新服务器配置文件
        updateServerConfig(db, serverID)

        return c.NoContent(http.StatusOK)
      }
}
      // 检查客户端名称是否在指定服务器下唯一
func isClientNameUnique(db *sql.DB, name string, serverID int, clientID int) (bool, error) {
        var count int
        var err error

        writeLog(fmt.Sprintf("Debug: isClientNameUnique called with name='%s', serverID=%d, clientID=%d", name, serverID, clientID))
        if clientID == -1 {
                // 创建新客户端时的检查
                writeLog(fmt.Sprintf("Debug: Creating new client, checking uniqueness with query: SELECT COUNT(*) FROM clients WHERE name='%s' AND server_id=%d", name, serverID))
                err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE name=? AND server_id=?", name, serverID).Scan(&count)
        } else {
                // 更新客户端时的检查（排除自己）
                writeLog(fmt.Sprintf("Debug: Updating existing client, checking uniqueness with query: SELECT COUNT(*) FROM clients WHERE name='%s' AND server_id=%d AND id!=%d", name, serverID, clientID))
                err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE name=? AND server_id=? AND id!=?", name, serverID, clientID).Scan(&count)
        }
        writeLog(fmt.Sprintf("Debug: isClientNameUnique result: count=%d", count))

        if err != nil {
                return false, err
        }

        return count == 0, nil
}

// 检查客户端地址是否与服务器在同一网段且无冲突
func validateClientAddress(db *sql.DB, address string, serverID int, clientID int) (bool, string, error) {
        // 获取服务器信息
        var server Server
        err := db.QueryRow("SELECT address FROM servers WHERE id=?", serverID).Scan(&server.Address)
        if err != nil {
                return false, "Failed to get server info", err
        }

        // 解析服务器地址和客户端地址
        _, serverIPNet, err := net.ParseCIDR(server.Address)
        if err != nil {
                return false, "Invalid server address format", err
        }

        clientIP, _, err := net.ParseCIDR(address)
        if err != nil {
                return false, "Invalid client address format", err
        }

        // 检查客户端地址是否在服务器网段内
        if !serverIPNet.Contains(clientIP) {
                return false, fmt.Sprintf("Client address %s is not in server network %s", address, server.Address), nil
        }

        // 检查客户端地址是否与服务器地址冲突
        serverIP, _, _ := net.ParseCIDR(server.Address)
        if clientIP.Equal(serverIP) {
                return false, fmt.Sprintf("Client address %s conflicts with server address %s", address, server.Address), nil
        }

        // 检查客户端地址是否与其他客户端地址冲突
        rows, err := db.Query("SELECT id, address FROM clients WHERE server_id=? AND id!=?", serverID, clientID)
        if err != nil {
                return false, "Failed to query existing clients", err
        }
        defer rows.Close()

        for rows.Next() {
                var id int
                var existingAddress string
                if err := rows.Scan(&id, &existingAddress); err != nil {
                        continue
                }

                existingIP, _, err := net.ParseCIDR(existingAddress)
                if err != nil {
                        continue
                }

                if clientIP.Equal(existingIP) {
                        return false, fmt.Sprintf("Client address %s conflicts with existing client address %s", address, existingAddress), nil
                }
        }

        return true, "", nil
}

func createClient(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        cl := new(Client)
        if err := c.Bind(cl); err != nil {
                writeLog(fmt.Sprintf("Failed to bind client data: %v", err))
                return err
        }

        // 检查客户端名称是否唯一
        isUnique, err := isClientNameUnique(db, cl.Name, cl.ServerID, -1)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to check client name uniqueness: %v", err))
                return err
        }
        if !isUnique {
                errorMsg := fmt.Sprintf("Client name '%s' already exists in this server", cl.Name)
                writeLog(errorMsg)
                return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
        }
        
        // 如果提供了客户端地址，则进行验证
        if cl.Address != "" {
                isValid, errorMsg, err := validateClientAddress(db, cl.Address, cl.ServerID, 0)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to validate client address: %v", err))
                        return err
                }
                if !isValid {
                        writeLog(errorMsg)
                        return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
                }
        }

        // 如果没有提供客户端地址，则自动分配一个
        if cl.Address == "" {
                // 获取服务器信息以确定地址范围
                var server Server
                err := db.QueryRow("SELECT id, name, address FROM servers WHERE id=?", cl.ServerID).Scan(&server.ID, &server.Name, &server.Address)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to get server info for client %s: %v", cl.Name, err))
                        return err
                }

                // 解析服务器地址，获取网段信息
                serverIP, ipNet, err := net.ParseCIDR(server.Address)
                if err != nil {
                        writeLog(fmt.Sprintf("Invalid server address format for server %s: %v", server.Name, err))
                        return err
                }

                // 获取同服务器下所有客户端的地址
                rows, err := db.Query("SELECT address FROM clients WHERE server_id=?", cl.ServerID)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to query existing client addresses: %v", err))
                        return err
                }
                defer rows.Close()

                // 收集已使用的地址
                usedAddresses := make(map[string]bool)
                for rows.Next() {
                        var addr string
                        if err := rows.Scan(&addr); err != nil {
                                writeLog(fmt.Sprintf("Failed to scan client address: %v", err))
                                continue
                        }
                        usedAddresses[addr] = true
                }

                // 找到下一个可用的地址
                var assignedAddress string
                // 从服务器IP的下一个地址开始查找
                for ip := nextIP(serverIP); ipNet.Contains(ip); ip = nextIP(ip) {
                        // 排除网络地址和广播地址
                        if isNetworkOrBroadcastAddress(ip, ipNet) {
                                continue
                        }

                        candidate := fmt.Sprintf("%s/32", ip.String())
                        if !usedAddresses[candidate] {
                                assignedAddress = candidate
                                break
                        }
                }

                if assignedAddress == "" {
                        writeLog(fmt.Sprintf("No available IP addresses in range for server %s", server.Name))
                        return fmt.Errorf("No available IP addresses in range")
                }

                cl.Address = assignedAddress
                writeLog(fmt.Sprintf("Auto-assigned address %s to client %s", cl.Address, cl.Name))
        }

        // 验证DNS格式（如果提供）
        if cl.DNS != "" {
                // 分割多个DNS地址
                dnsAddresses := strings.Split(cl.DNS, ",")
                for _, dnsAddr := range dnsAddresses {
                        dnsAddr = strings.TrimSpace(dnsAddr)
                        ip := net.ParseIP(dnsAddr)
                        if ip == nil {
                                writeLog(fmt.Sprintf("Invalid DNS address format: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid DNS address format: %s", dnsAddr)})
                        }
                }
        }

        // 验证MTU值（如果提供）
        if cl.MTU > 0 && cl.MTU >= 1600 {
                writeLog(fmt.Sprintf("MTU value must be less than 1600: %d", cl.MTU))
                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("MTU value must be less than 1600: %d", cl.MTU)})
        }

        // 如果没有提供密钥，则自动生成
        if cl.PrivateKey == "" || cl.PublicKey == "" {
                privateKey, publicKey, err := generateKeyPair()
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to generate key pair for client: %v", err))
                        return fmt.Errorf("failed to generate key pair: %v", err)
                }
                cl.PrivateKey = privateKey
                cl.PublicKey = publicKey
                writeLog(fmt.Sprintf("Generated key pair for client: %s", cl.Name))
        }

        // 如果没有提供预共享密钥且前端请求自动生成，则生成预共享密钥
        if cl.PresharedKey == "" && cl.AutoGeneratePresharedKey {
                presharedKey, err := generatePresharedKey()
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to generate preshared key for client: %v", err))
                        // 不要因为预共享密钥生成失败而终止整个操作，只记录日志
                        writeLog("Continuing without preshared key")
                } else {
                        cl.PresharedKey = presharedKey
                        writeLog(fmt.Sprintf("Generated preshared key for client: %s", cl.Name))
                }
        }

        // 处理ServerAllowedIPs
        serverAllowedIPsValue := ""
        if cl.ServerAllowedIPs != nil {
                serverAllowedIPsValue = *cl.ServerAllowedIPs
        }

        // 处理ClientAllowedIPs
        clientAllowedIPsValue := ""
        if cl.ClientAllowedIPs != nil {
                clientAllowedIPsValue = *cl.ClientAllowedIPs
        }

        writeLog(fmt.Sprintf("Before processing: AllowedIPs='%s', ServerAllowedIPs='%s', ClientAllowedIPs='%s', Address='%s'", cl.AllowedIPs, serverAllowedIPsValue, clientAllowedIPsValue, cl.Address))
        // 如果没有提供Allowed IPs，则自动设置为与Address相同的值
        if cl.AllowedIPs == "" {
                cl.AllowedIPs = cl.Address
                writeLog(fmt.Sprintf("Set AllowedIPs to Address: %s", cl.AllowedIPs))
        }

        // 如果没有提供Server Allowed IPs，则设置为与Address相同的值
        if cl.ServerAllowedIPs == nil || *cl.ServerAllowedIPs == "" {
                cl.ServerAllowedIPs = &cl.Address
                writeLog(fmt.Sprintf("Set ServerAllowedIPs to Address: %s", *cl.ServerAllowedIPs))
        }

        // 如果没有提供Client Allowed IPs，则设置为对应Server的Address
        if cl.ClientAllowedIPs == nil || *cl.ClientAllowedIPs == "" {
                // 获取服务器信息以获取服务器地址
                var server Server
                err = db.QueryRow("SELECT address FROM servers WHERE id=?", cl.ServerID).Scan(&server.Address)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to get server info for client %s: %v", cl.Name, err))
                        writeLog(fmt.Sprintf("Will use default server address for ClientAllowedIPs"))
                        defaultClientAllowedIPs := "0.0.0.0/0" // 默认值
                        cl.ClientAllowedIPs = &defaultClientAllowedIPs
                } else {
                        cl.ClientAllowedIPs = &server.Address
                        writeLog(fmt.Sprintf("Set ClientAllowedIPs to Server Address: %s", *cl.ClientAllowedIPs))
                }
        }
        writeLog(fmt.Sprintf("After processing: AllowedIPs='%s', ServerAllowedIPs='%s', ClientAllowedIPs='%s'", cl.AllowedIPs, *cl.ServerAllowedIPs, *cl.ClientAllowedIPs))

        // 获取下一个可用的 ID
        id, err := getNextClientID(db)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get next client ID: %v", err))
                return err
        }
        cl.ID = id

        stmt, err := db.Prepare("INSERT INTO clients (id, server_id, name, address, private_key, public_key, preshared_key, allowed_ips, server_allowed_ips, client_allowed_ips, status, enabled, persistent_keepalive, dns, mtu, online_time, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        if err != nil {
                writeLog(fmt.Sprintf("Failed to prepare client insert statement: %v", err))
                return err
        }
        defer stmt.Close()

        // 默认启用客户端
        cl.Enabled = 1
        // 如果没有提供PersistentKeepalive，则使用默认值25
        // 但允许设置为0来禁用
        if cl.PersistentKeepalive == 0 && c.Request().ContentLength > 0 {
                // 检查请求中是否明确包含了persistent_keepalive字段
                // 如果没有明确提供，则使用默认值25
                reqData := make(map[string]interface{})
                if err := c.Bind(&reqData); err == nil {
                        if _, exists := reqData["persistent_keepalive"]; !exists {
                                cl.PersistentKeepalive = 25
                        }
                } else {
                        cl.PersistentKeepalive = 25
                }
        } else if cl.PersistentKeepalive == 0 {
                // 对于空请求，使用默认值25
                cl.PersistentKeepalive = 25
        }

        // 初始化在线时间为0
        cl.OnlineTime = 0

        // 如果没有提供Allowed IPs，则自动设置为与Address相同的值
        if cl.AllowedIPs == "" {
                cl.AllowedIPs = cl.Address
        }
        var serverAllowedIPsValue2 string
        if cl.ServerAllowedIPs != nil {
                serverAllowedIPsValue2 = *cl.ServerAllowedIPs
        }

        var clientAllowedIPsValue2 string
        if cl.ClientAllowedIPs != nil {
                clientAllowedIPsValue2 = *cl.ClientAllowedIPs
        }

        _, err = stmt.Exec(cl.ID, cl.ServerID, cl.Name, cl.Address, cl.PrivateKey, cl.PublicKey, cl.PresharedKey, cl.AllowedIPs, serverAllowedIPsValue2, clientAllowedIPsValue2, cl.Status, cl.Enabled, cl.PersistentKeepalive, cl.DNS, cl.MTU, cl.OnlineTime, cl.Email)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to insert client: %v", err))
                return err
        }

        // 更新客户端表的auto_increment值，确保下次可以重用ID
        // 设置auto_increment为当前ID+1，这样下次可以重用之前的ID
        resetClientAutoIncrement(db, cl.ID)

        // 更新服务器配置文件
        updateServerConfig(db, cl.ServerID)

        // 获取服务器信息以生成客户端配置文件
        var server Server
        err = db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", cl.ServerID).Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get server info for client config generation: %v", err))
        } else {
                // 生成并保存客户端配置文件
                if err := saveClientConfigFile(*cl, server); err != nil {
                        writeLog(fmt.Sprintf("Failed to save client config file: %v", err))
                } else {
                        writeLog(fmt.Sprintf("Generated client config file for client: %s", cl.Name))
                }
        }

        writeLog(fmt.Sprintf("Created client: %s (ID: %d) for server ID: %d", cl.Name, cl.ID, cl.ServerID))
        return c.JSON(http.StatusCreated, cl)
      }
}

func updateClient(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")
        cl := new(Client)
        if err := c.Bind(cl); err != nil {
                return err
        }

        // 转换ID为整数
        clientID, err := strconv.Atoi(id)
        if err != nil {
                return err
        }

        // 检查客户端名称是否唯一（排除自己）
        writeLog(fmt.Sprintf("Debug: Checking name uniqueness for client ID %d, name '%s', server ID %d", clientID, cl.Name, cl.ServerID))
        isUnique, err := isClientNameUnique(db, cl.Name, cl.ServerID, clientID)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to check client name uniqueness: %v", err))
                return err
        }
        if !isUnique {
                errorMsg := fmt.Sprintf("Client name '%s' already exists in this server", cl.Name)
                writeLog(errorMsg)
                return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
        }
        writeLog(fmt.Sprintf("Debug: Client name '%s' is unique", cl.Name))

        // 如果提供了客户端地址，则进行验证
        if cl.Address != "" {
                isValid, errorMsg, err := validateClientAddress(db, cl.Address, cl.ServerID, clientID)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to validate client address: %v", err))
                        return err
                }
                if !isValid {
                        writeLog(errorMsg)
                        return c.JSON(http.StatusConflict, map[string]string{"error": errorMsg})
                }
        }

        // 验证DNS格式（如果提供）
        if cl.DNS != "" {
                // 分割多个DNS地址
                dnsAddresses := strings.Split(cl.DNS, ",")
                for _, dnsAddr := range dnsAddresses {
                        dnsAddr = strings.TrimSpace(dnsAddr)
                        ip := net.ParseIP(dnsAddr)
                        if ip == nil {
                                writeLog(fmt.Sprintf("Invalid DNS address format: %s", dnsAddr))
                                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid DNS address format: %s", dnsAddr)})
                        }
                }
        }

        // 验证MTU值（如果提供）
        if cl.MTU > 0 && cl.MTU >= 1600 {
                writeLog(fmt.Sprintf("MTU value must be less than 1600: %d", cl.MTU))
                return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("MTU value must be less than 1600: %d", cl.MTU)})
        }

        // 获取更新前的客户端信息
        var oldServerID int
        var oldClientName string
        row := db.QueryRow("SELECT server_id, name FROM clients WHERE id=?", id)
        err = row.Scan(&oldServerID, &oldClientName)
        if err != nil {
                return err
        }

        // 处理ServerAllowedIPs
        serverAllowedIPsValue := ""
        if cl.ServerAllowedIPs != nil {
                serverAllowedIPsValue = *cl.ServerAllowedIPs
        }

        // 处理ClientAllowedIPs
        clientAllowedIPsValue := ""
        if cl.ClientAllowedIPs != nil {
                clientAllowedIPsValue = *cl.ClientAllowedIPs
        }

        writeLog(fmt.Sprintf("Before processing: AllowedIPs='%s', ServerAllowedIPs='%s', ClientAllowedIPs='%s', Address='%s'", cl.AllowedIPs, serverAllowedIPsValue, clientAllowedIPsValue, cl.Address))
        // 如果没有提供Allowed IPs，则自动设置为与Address相同的值
        if cl.AllowedIPs == "" {
                cl.AllowedIPs = cl.Address
                writeLog(fmt.Sprintf("Set AllowedIPs to Address: %s", cl.AllowedIPs))
        }

        // 如果没有提供Server Allowed IPs，则设置为与Address相同的值
        if cl.ServerAllowedIPs == nil || *cl.ServerAllowedIPs == "" {
                cl.ServerAllowedIPs = &cl.Address
                writeLog(fmt.Sprintf("Set ServerAllowedIPs to Address: %s", *cl.ServerAllowedIPs))
        }

        // 如果没有提供Client Allowed IPs，则设置为对应Server的Address
        if cl.ClientAllowedIPs == nil || *cl.ClientAllowedIPs == "" {
                // 获取服务器信息以获取服务器地址
                var server Server
                err = db.QueryRow("SELECT address FROM servers WHERE id=?", cl.ServerID).Scan(&server.Address)
                if err != nil {
                        writeLog(fmt.Sprintf("Failed to get server info for client %s: %v", cl.Name, err))
                        writeLog(fmt.Sprintf("Will use default server address for ClientAllowedIPs"))
                        defaultClientAllowedIPs := "0.0.0.0/0" // 默认值
                        cl.ClientAllowedIPs = &defaultClientAllowedIPs
                } else {
                        cl.ClientAllowedIPs = &server.Address
                        writeLog(fmt.Sprintf("Set ClientAllowedIPs to Server Address: %s", *cl.ClientAllowedIPs))
                }
        }

        stmt, err := db.Prepare("UPDATE clients SET server_id=?, name=?, address=?, private_key=?, public_key=?, preshared_key=?, allowed_ips=?, server_allowed_ips=?, client_allowed_ips=?, status=?, persistent_keepalive=?, dns=?, mtu=?, email=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        if err != nil {
                return err
        }
        defer stmt.Close()

        // 如果没有提供PersistentKeepalive，则使用默认值25
        // 但允许设置为0来禁用
        if cl.PersistentKeepalive == 0 && c.Request().ContentLength > 0 {
                // 检查请求中是否明确包含了persistent_keepalive字段
                // 如果没有明确提供，则使用默认值25
                reqData := make(map[string]interface{})
                if err := c.Bind(&reqData); err == nil {
                        if _, exists := reqData["persistent_keepalive"]; !exists {
                                // 查询数据库获取当前值，而不是使用默认值
                                var currentKeepalive int
                                row := db.QueryRow("SELECT persistent_keepalive FROM clients WHERE id=?", id)
                                if err := row.Scan(&currentKeepalive); err == nil {
                                        cl.PersistentKeepalive = currentKeepalive
                                } else {
                                        cl.PersistentKeepalive = 25
                                }
                        }
                } else {
                        cl.PersistentKeepalive = 25
                }
        } else if cl.PersistentKeepalive == 0 {
                // 对于空请求，使用默认值25
                cl.PersistentKeepalive = 25
        }

        // 如果没有提供Allowed IPs，则自动设置为与Address相同的值
        if cl.AllowedIPs == "" {
                cl.AllowedIPs = cl.Address
        }

        var serverAllowedIPsValue2 string
        if cl.ServerAllowedIPs != nil {
                serverAllowedIPsValue2 = *cl.ServerAllowedIPs
        }

        var clientAllowedIPsValue2 string
        if cl.ClientAllowedIPs != nil {
                clientAllowedIPsValue2 = *cl.ClientAllowedIPs
        }

        _, err = stmt.Exec(cl.ServerID, cl.Name, cl.Address, cl.PrivateKey, cl.PublicKey, cl.PresharedKey, cl.AllowedIPs, serverAllowedIPsValue2, clientAllowedIPsValue2, cl.Status, cl.PersistentKeepalive, cl.DNS, cl.MTU, cl.Email, id)
        if err != nil {
                return err
        }

        // 更新相关服务器配置文件
        if oldServerID != cl.ServerID {
                updateServerConfig(db, oldServerID)
        }
        updateServerConfig(db, cl.ServerID)

        // 获取服务器信息以生成客户端配置文件
        var server Server
        err = db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", cl.ServerID).Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get server info for client config generation: %v", err))
        } else {
                // 更新客户端配置文件（如果客户端名称发生变化，需要先删除旧文件）
                if cl.Name != oldClientName {
                        // 删除旧的配置文件
                        oldClient := *cl
                        oldClient.Name = oldClientName
                        if err := deleteClientConfigFile(oldClient, server); err != nil {
                                writeLog(fmt.Sprintf("Failed to delete old client config file: %v", err))
                        }
                }

                // 生成并保存客户端配置文件
                if err := saveClientConfigFile(*cl, server); err != nil {
                        writeLog(fmt.Sprintf("Failed to save client config file: %v", err))
                } else {
                        writeLog(fmt.Sprintf("Generated client config file for client: %s", cl.Name))
                }
        }

        return c.JSON(http.StatusOK, cl)
      }
}

func deleteClient(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        id := c.Param("id")

        // 获取要删除的客户端信息
        var serverID int
        var client Client
        row := db.QueryRow("SELECT id, server_id, name, address, private_key, public_key, preshared_key, allowed_ips, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx, enabled, persistent_keepalive, dns, mtu, online_time, first_online FROM clients WHERE id=?", id)
        err := row.Scan(&client.ID, &client.ServerID, &client.Name, &client.Address, &client.PrivateKey, &client.PublicKey, &client.PresharedKey, &client.AllowedIPs, &client.ServerAllowedIPs, &client.ClientAllowedIPs, &client.Status, &client.LatestHandshake, &client.TransferRx, &client.TransferTx, &client.Enabled, &client.PersistentKeepalive, &client.DNS, &client.MTU, &client.OnlineTime, &client.FirstOnline)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get client info for client %s: %v", id, err))
                return err
        }
        serverID = client.ServerID

        // 获取服务器信息以删除客户端配置文件
        var server Server
        err = db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", serverID).Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get server info for client config deletion: %v", err))
        } else {
                // 删除客户端配置文件
                if err := deleteClientConfigFile(client, server); err != nil {
                        writeLog(fmt.Sprintf("Failed to delete client config file: %v", err))
                } else {
                        writeLog(fmt.Sprintf("Deleted client config file for client: %s", client.Name))
                }
        }

        stmt, err := db.Prepare("DELETE FROM clients WHERE id=?")
        if err != nil {
                writeLog(fmt.Sprintf("Failed to prepare client delete statement: %v", err))
                return err
        }
        defer stmt.Close()

        _, err = stmt.Exec(id)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to delete client ID %s: %v", id, err))
                return err
        }

        // 更新相关服务器配置文件
        updateServerConfig(db, serverID)

        // 重置客户端表的AUTO_INCREMENT值，确保ID可以被重用
        // 获取当前最大ID并设置AUTO_INCREMENT为该ID+1
        var maxID int
        err = db.QueryRow("SELECT COALESCE(MAX(id), -1) FROM clients").Scan(&maxID)
        if err != nil {
                writeLog(fmt.Sprintf("Failed to get max client ID: %v", err))
        } else {
                resetClientAutoIncrement(db, maxID)
        }

        writeLog(fmt.Sprintf("Deleted client ID: %s from server ID: %d", id, serverID))
        return c.NoContent(http.StatusNoContent)
      }
}

// PeerTraffic 表示一个peer的流量信息
type PeerTraffic struct {
      Interface     string
      PublicKey     string
      Endpoint      string
      AllowedIPs    string
      ReceivedBytes int64
      SentBytes     int64
}

// 解析wg show命令输出并更新客户端状态和流量统计
func updateClientStatuses(db *sql.DB) {
      // 执行wg show命令来获取握手时间信息
      cmd := exec.Command("wg", "show")
      output, err := cmd.CombinedOutput()

      // 用于存储接口和其客户端信息的映射
      interfacePeers := make(map[string][]map[string]string)

      if err != nil {
              writeLog(fmt.Sprintf("Failed to execute wg show: %v", err))
              // 当wg show命令执行失败时，将所有客户端标记为离线
              markAllClientsOffline(db)
              return
      }

      // 解析输出
      outputStr := string(output)
      lines := strings.Split(outputStr, "\n")

      // 如果输出为空，同样将所有客户端标记为离线
      if len(strings.TrimSpace(outputStr)) == 0 {
              writeLog("wg show returned empty output, marking all clients as offline")
              markAllClientsOffline(db)
              return
      }

      currentInterface := ""

      // 解析wg show输出
      for _, line := range lines {
              line = strings.TrimSpace(line)
              if strings.HasPrefix(line, "interface:") {
                      // 提取接口名称
                      parts := strings.Split(line, ":")
                      if len(parts) > 1 {
                              currentInterface = strings.TrimSpace(parts[1])
                              interfacePeers[currentInterface] = []map[string]string{}
                      }
              } else if strings.HasPrefix(line, "peer:") && currentInterface != "" {
                      // 提取peer公钥
                      parts := strings.Split(line, ":")
                      if len(parts) > 1 {
                              peer := make(map[string]string)
                              peer["public_key"] = strings.TrimSpace(parts[1])
                              interfacePeers[currentInterface] = append(interfacePeers[currentInterface], peer)
                      }
              } else if strings.HasPrefix(line, "latest handshake:") && currentInterface != "" && len(interfacePeers[currentInterface]) > 0 {
                      // 提取最新握手时间
                      parts := strings.Split(line, ":")
                      if len(parts) > 1 {
                              latestHandshake := strings.TrimSpace(parts[1])
                              // 更新最后一个peer的握手时间
                              lastIndex := len(interfacePeers[currentInterface]) - 1
                              interfacePeers[currentInterface][lastIndex]["latest_handshake"] = latestHandshake
                      }
              } else if strings.HasPrefix(line, "transfer:") && currentInterface != "" && len(interfacePeers[currentInterface]) > 0 {
                      // 提取传输数据
                      parts := strings.Split(line, ":")
                      if len(parts) > 1 {
                              transfer := strings.TrimSpace(parts[1])
                              // 更新最后一个peer的传输数据
                              lastIndex := len(interfacePeers[currentInterface]) - 1
                              interfacePeers[currentInterface][lastIndex]["transfer"] = transfer
                      }
              }
      }

      // 执行wg show all dump命令来获取流量数据
      writeLog("Debug: Executing wg show all dump command")
      cmd2 := exec.Command("wg", "show", "all", "dump")
      output2, err := cmd2.CombinedOutput()
      if err != nil {
              writeLog(fmt.Sprintf("Debug: Failed to execute wg show all dump: %v, output: %s", err, string(output2)))
      } else {
              writeLog(fmt.Sprintf("Debug: Successfully executed wg show all dump, output length: %d", len(output2)))
      }

      // 用于存储接口和其客户端流量信息的映射
      interfaceTrafficPeers := make(map[string]map[string]PeerTraffic)

      if err == nil {
              // 解析wg show all dump输出
              outputStr2 := string(output2)
              lines2 := strings.Split(outputStr2, "\n")

              for _, line := range lines2 {
                      line = strings.TrimSpace(line)
                      if line == "" {
                              continue
                      }

                      // 分割字段
                      fields := strings.Split(line, "\t")
                      if len(fields) < 8 {
                              // 这是接口行，不是peer行
                              continue
                      }

                      // 提取peer信息
                      interfaceName := fields[0]
                      publicKey := fields[1]
                      endpoint := fields[3]
                      allowedIPs := fields[4]
                      // 注意：wg show all dump的字段顺序是：
                      // interface public_key private_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
                      // 所以fields[6]是transfer_rx(接收流量)，fields[7]是transfer_tx(发送流量)
                      receivedBytes := parseInt64(fields[6])
                      sentBytes := parseInt64(fields[7])

                      // 初始化接口映射
                      if _, exists := interfaceTrafficPeers[interfaceName]; !exists {
                              interfaceTrafficPeers[interfaceName] = make(map[string]PeerTraffic)
                      }

                      // 添加调试日志
                      writeLog(fmt.Sprintf("Debug: Parsing peer traffic - Interface: %s, PublicKey: %s, ReceivedBytes: %d, SentBytes: %d", interfaceName, publicKey, receivedBytes, sentBytes))

                      // 存储peer流量信息
                      interfaceTrafficPeers[interfaceName][publicKey] = PeerTraffic{
                              Interface:     interfaceName,
                              PublicKey:     publicKey,
                              Endpoint:      endpoint,
                              AllowedIPs:    allowedIPs,
                              ReceivedBytes: receivedBytes,
                              SentBytes:     sentBytes,
                      }
              }
      }

      // 存储离线客户端信息，用于记录访问日志
      offlineClients := make(map[int]struct {
              OnlineTime     int
              OnlineReceived float64
              OnlineSent     float64
      })

      // 首先收集当前在线客户端的信息
      onlineClientRows, err := db.Query("SELECT id, online_time, online_received, online_sent FROM clients WHERE status = 'online'")
      if err != nil {
              writeLog(fmt.Sprintf("Failed to query online clients: %v", err))
      } else {
              for onlineClientRows.Next() {
                      var clientID int
                      var onlineTime int
                      var onlineReceived, onlineSent float64
                      err := onlineClientRows.Scan(&clientID, &onlineTime, &onlineReceived, &onlineSent)
                      if err != nil {
                              writeLog(fmt.Sprintf("Failed to scan online client row: %v", err))
                              continue
                      }
                      offlineClients[clientID] = struct {
                              OnlineTime     int
                              OnlineReceived float64
                              OnlineSent     float64
                      }{OnlineTime: onlineTime, OnlineReceived: onlineReceived, OnlineSent: onlineSent}
              }
              onlineClientRows.Close()
      }

      // 更新数据库中的客户端状态和流量统计
      for interfaceName, peers := range interfacePeers {
              // 从接口名称获取服务器ID
              serverID, err := getServerIDByInterfaceName(interfaceName, db)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to get server ID for interface %s: %v", interfaceName, err))
                      continue
              }

              // 获取该服务器的所有客户端
              clientRows, err := db.Query("SELECT id, public_key, status, online_time, first_online, received_30s, sent_30s, online_received, online_sent, client_total_received, client_total_sent, last_received_bytes, last_sent_bytes FROM clients WHERE server_id=?", serverID)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to query clients for server %d: %v", serverID, err))
                      continue
              }
              defer clientRows.Close()

              for clientRows.Next() {
                      var clientID int
                      var publicKey string
                      var currentStatus string
                      var onlineTime int
                      var firstOnline *string
                      var prevReceived30s, prevSent30s, prevOnlineReceived, prevOnlineSent, prevClientTotalReceived, prevClientTotalSent, lastReceivedBytes, lastSentBytes float64

                      err := clientRows.Scan(&clientID, &publicKey, &currentStatus, &onlineTime, &firstOnline, &prevReceived30s, &prevSent30s, &prevOnlineReceived, &prevOnlineSent, &prevClientTotalReceived, &prevClientTotalSent, &lastReceivedBytes, &lastSentBytes)
                      if err != nil {
                              writeLog(fmt.Sprintf("Failed to scan client row: %v", err))
                              continue
                      }

                      // 查找匹配的peer
                      newStatus := "offline"
                      var peerTraffic *PeerTraffic = nil
                      for _, peer := range peers {
                              if peer["public_key"] == publicKey {
                                      // 解析最新握手时间
                                      latestHandshake := peer["latest_handshake"]

                                      // 添加调试日志
                                      writeLog(fmt.Sprintf("Client %d (public key: %s) latest handshake: %s", clientID, publicKey, latestHandshake))

                                      // 检查是否存在latest handshake且值小于3分钟
                                      if latestHandshake != "(none)" && latestHandshake != "" {
                                              // 如果握手时间是 "Now"，则认为在线
                                              if latestHandshake == "Now" {
                                                      newStatus = "online"
                                              } else {
                                                      // 尝试解析握手时间
                                                      handshakeTime, err := parseHandshakeTime(latestHandshake)
                                                      if err == nil {
                                                              // 计算时间差（秒）
                                                              now := time.Now()
                                                              diff := now.Sub(handshakeTime).Seconds()
                                                              writeLog(fmt.Sprintf("Client %d time difference: %.0f seconds", clientID, diff))
                                                              // 如果最近3分钟内有握手，则认为在线
                                                              if diff <= 180 { // 3分钟 = 180秒
                                                                      newStatus = "online"
                                                              }
                                                      } else {
                                                              writeLog(fmt.Sprintf("Client %d failed to parse handshake time: %v", clientID, err))
                                                      }
                                              }
                                      }
                                      break
                              }
                      }

                      // 查找流量数据
                      if trafficPeers, exists := interfaceTrafficPeers[interfaceName]; exists {
                              if trafficPeer, exists := trafficPeers[publicKey]; exists {
                                      peerTraffic = &trafficPeer
                              }
                      }

                      // 添加调试日志
                      writeLog(fmt.Sprintf("Client %d new status: %s, current status: %s", clientID, newStatus, currentStatus))

                      // 更新客户端状态、在线时间和流量统计
                      updateClientStatusAndTime(db, clientID, newStatus, currentStatus, onlineTime, firstOnline)
                      updateClientTrafficStats(db, clientID, newStatus, peerTraffic, prevReceived30s, prevSent30s, prevOnlineReceived, prevOnlineSent, prevClientTotalReceived, prevClientTotalSent, lastReceivedBytes, lastSentBytes)
              }
      }

      // 更新服务器和全局流量统计
      updateServerAndGlobalTrafficStats(db)
}

// parseInt64 安全地将字符串转换为int64
func parseInt64(s string) int64 {
      var result int64
      fmt.Sscanf(s, "%d", &result)
      return result
}

// 解析握手时间字符串
func parseHandshakeTime(handshakeStr string) (time.Time, error) {
      // 首先检查是否是时间戳
      if timestamp, err := strconv.ParseInt(handshakeStr, 10, 64); err == nil {
              // 如果是时间戳，直接转换为时间
              return time.Unix(timestamp, 0), nil
      }

      // 移除末尾的"ago"
      handshakeStr = strings.TrimSuffix(handshakeStr, " ago")

      // 现在的时间
      now := time.Now()

      // 解析复合时间格式，例如"24 minutes, 7 seconds"
      totalSeconds := 0

      // 分割各个时间部分
      parts := strings.Split(handshakeStr, ",")
      for _, part := range parts {
              part = strings.TrimSpace(part)
              subParts := strings.Split(part, " ")
              if len(subParts) > 0 {
                      value, err := strconv.Atoi(subParts[0])
                      if err != nil {
                              continue
                      }

                      // 处理单数和复数形式的时间单位
                      if strings.Contains(part, "second") {
                              totalSeconds += value
                      } else if strings.Contains(part, "minute") {
                              totalSeconds += value * 60
                      } else if strings.Contains(part, "hour") {
                              totalSeconds += value * 3600
                      } else if strings.Contains(part, "day") {
                              totalSeconds += value * 86400
                      }
              }
      }

      // 如果没有解析到任何时间值，尝试直接解析单个时间值
      if totalSeconds == 0 {
              part := strings.TrimSpace(handshakeStr)
              subParts := strings.Split(part, " ")
              if len(subParts) > 0 {
                      value, err := strconv.Atoi(subParts[0])
                      if err == nil {
                              if strings.Contains(part, "second") {
                                      totalSeconds += value
                              } else if strings.Contains(part, "minute") {
                                      totalSeconds += value * 60
                              } else if strings.Contains(part, "hour") {
                                      totalSeconds += value * 3600
                              } else if strings.Contains(part, "day") {
                                      totalSeconds += value * 86400
                              }
                      }
              }
      }

      if totalSeconds > 0 {
              return now.Add(-time.Duration(totalSeconds) * time.Second), nil
      }

      return now, fmt.Errorf("unable to parse handshake time: %s", handshakeStr)
}

// 将所有客户端标记为离线
func markAllClientsOffline(db *sql.DB) {
	// 添加重试逻辑来处理数据库锁定问题
	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		// 如果不是第一次尝试，等待一段时间再重试
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}

		// 使用事务来确保操作的原子性
		tx, err := db.Begin()
		if err != nil {
			writeLog(fmt.Sprintf("Failed to begin transaction in markAllClientsOffline (attempt %d): %v", attempt+1, err))
			continue
		}

		// 将所有在线客户端标记为离线并重置在线时间
		result, err := tx.Exec("UPDATE clients SET status='offline', online_time=0, updated_at=CURRENT_TIMESTAMP WHERE status='online'")
		if err != nil {
			tx.Rollback()
			if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
				writeLog(fmt.Sprintf("Database locked in markAllClientsOffline, will retry (attempt %d): %v", attempt+1, err))
				continue
			}
			writeLog(fmt.Sprintf("Failed to update clients in markAllClientsOffline (attempt %d): %v", attempt+1, err))
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			writeLog(fmt.Sprintf("Failed to get rows affected in markAllClientsOffline (attempt %d): %v", attempt+1, err))
			continue
		}

		// 提交事务
		err = tx.Commit()
		if err != nil {
			if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
				writeLog(fmt.Sprintf("Database locked on commit in markAllClientsOffline, will retry (attempt %d): %v", attempt+1, err))
				continue
			}
			writeLog(fmt.Sprintf("Failed to commit transaction in markAllClientsOffline (attempt %d): %v", attempt+1, err))
			return
		}

		writeLog(fmt.Sprintf("Marked %d clients as offline due to wg show failure or empty output", rowsAffected))
		return
	}

	writeLog(fmt.Sprintf("Failed to mark clients as offline after %d attempts due to database lock", maxRetries))
}

// 更新客户端状态和在线时间
func updateClientStatusAndTime(db *sql.DB, clientID int, newStatus, currentStatus string, currentOnlineTime int, firstOnline *string) {
      // 添加重试逻辑来处理数据库锁定问题
      maxRetries := 5

      // 如果是从在线变为离线，需要在数据库更新之前获取online_time值和在线期间的流量数据
      var onlineTime int
      var onlineReceived, onlineSent float64
      if currentStatus == "online" && newStatus == "offline" {
              err := db.QueryRow("SELECT online_time, online_received, online_sent FROM clients WHERE id = ?", clientID).Scan(&onlineTime, &onlineReceived, &onlineSent)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to get client traffic data for access log: %v", err))
                      // 即使获取失败，我们仍然继续执行更新操作
                      onlineTime = 0
                      onlineReceived = 0
                      onlineSent = 0
              } else {
                      writeLog(fmt.Sprintf("Retrieved client traffic for offline log: clientID=%d, onlineTime=%d, onlineSent=%.2f, onlineReceived=%.2f", clientID, onlineTime, onlineSent, onlineReceived))
              }
      }

      for attempt := 0; attempt < maxRetries; attempt++ {
              // 如果不是第一次尝试，等待一段时间再重试
              if attempt > 0 {
                      time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
              }

              // 使用事务来确保操作的原子性
              tx, err := db.Begin()
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to begin transaction (attempt %d): %v", attempt+1, err))
                      
                      // 即使开始事务失败，在从online转为offline的情况下也要尝试记录访问日志
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Attempting to record offline log despite DB error, client %d, onlineTime=%d, onlineSent=%.2f, onlineReceived=%.2f", clientID, onlineTime, onlineSent, onlineReceived))
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
                      
                      continue
              }

              var result sql.Result
              var rowsAffected int64

              // 如果状态从未在线变为在线，记录首次在线时间
              if currentStatus != "online" && newStatus == "online" {
                      now := time.Now().Format("2006-01-02 15:04:05")
                      result, err = tx.Exec("UPDATE clients SET status=?, first_online=?, online_time=0, updated_at=CURRENT_TIMESTAMP WHERE id=?", newStatus, now, clientID)
              } else if currentStatus == "online" && newStatus == "online" {
                      // 如果继续保持在线，增加在线时间
                      newOnlineTime := currentOnlineTime + 30 // 每30秒增加30秒
                      result, err = tx.Exec("UPDATE clients SET status=?, online_time=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newStatus, newOnlineTime, clientID)
              } else if currentStatus == "online" && newStatus == "offline" {
                      // 如果从在线变为离线，重置在线时间为0
                      result, err = tx.Exec("UPDATE clients SET status=?, online_time=0, updated_at=CURRENT_TIMESTAMP WHERE id=?", newStatus, clientID)
              } else {
                      // 其他情况只更新状态
                      result, err = tx.Exec("UPDATE clients SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newStatus, clientID)
              }

              if err != nil {
                      tx.Rollback()
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      
                      writeLog(fmt.Sprintf("Failed to update client %d status (attempt %d): %v", clientID, attempt+1, err))
                      
                      // 即使更新失败，在从online转为offline的情况下也要记录访问日志
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Attempting to record offline log despite update error, client %d", clientID))
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
                      
                      return
              }

              rowsAffected, err = result.RowsAffected()
              if err != nil {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("Failed to get rows affected (attempt %d): %v", attempt+1, err))
                      
                      // 即使获取受影响行失败，在从online转为offline的情况下也要记录访问日志
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Attempting to record offline log despite rows affected error, client %d", clientID))
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
                      
                      continue
              }

              if rowsAffected == 0 {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("No rows updated for client %d (attempt %d)", clientID, attempt+1))
                      
                      // 即使没有行更新，在从online转为offline的情况下也要记录访问日志
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Attempting to record offline log after no rows updated, client %d, onlineTime=%d", clientID, onlineTime))
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
                      
                      continue
              }

              // 提交事务
              err = tx.Commit()
              if err != nil {
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked on commit, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      
                      writeLog(fmt.Sprintf("Failed to commit transaction (attempt %d): %v", attempt+1, err))
                      
                      // 即使提交失败，在从online转为offline的情况下也要记录访问日志
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Attempting to record offline log despite commit error, client %d", clientID))
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
                      
                      return
              }

              // 检查是否有行被更新，只有在更新成功时才记录状态变更日志
              if rowsAffected > 0 && currentStatus != newStatus {
                      writeLog(fmt.Sprintf("Client %d status changed from %s to %s", clientID, currentStatus, newStatus))
                      // 如果是从在线变为离线，记录在线时间重置
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Client %d online time reset to 0", clientID))
                      }

                      // 记录访问日志
                      if currentStatus == "offline" && newStatus == "online" {
                              // 客户端上线
                              go recordAccessLog(db, clientID, "online", 0, 0, 0)
                      } else if currentStatus == "online" && newStatus == "offline" {
                              // 客户端下线，使用在函数开始时获取的在线时长和流量数据
                              writeLog(fmt.Sprintf("Debug: Recording offline log for client %d with onlineTime=%d, onlineSent=%.2f, onlineReceived=%.2f", clientID, onlineTime, onlineSent, onlineReceived))
                              // 注意：onlineReceived是客户端在线期间接收的数据（下载），onlineSent是客户端在线期间发送的数据（上传）
                              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
                      }
              }
              return
      }

      writeLog(fmt.Sprintf("Failed to update client %d status after %d attempts due to database lock", clientID, maxRetries))
      
      // 如果所有重试都失败了，但之前获取了在线数据，也要记录离线日志
      if currentStatus == "online" && newStatus == "offline" {
              writeLog(fmt.Sprintf("All attempts failed, attempting one final offline log for client %d", clientID))
              go recordAccessLog(db, clientID, "offline", onlineTime, onlineSent, onlineReceived)
      }
}

// 记录访问日志
func recordAccessLog(db *sql.DB, clientID int, eventType string, onlineDuration int, uploadTraffic, downloadTraffic float64) {
      // 获取客户端和服务器信息
      var clientName, clientIP, serverName string
      var serverID int

      query := `
        SELECT c.name, c.address, s.name, c.server_id
        FROM clients c
        JOIN servers s ON c.server_id = s.id
        WHERE c.id = ?
      `

      err := db.QueryRow(query, clientID).Scan(&clientName, &clientIP, &serverName, &serverID)
      if err != nil {
              writeLog(fmt.Sprintf("Failed to get client info for access log: %v", err))
              return
      }

      // 插入访问日志
      insertQuery := `
        INSERT INTO access_logs (client_name, client_ip, server_name, event_type, online_duration, sent_traffic, received_traffic)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `

      _, err = db.Exec(insertQuery, clientName, clientIP, serverName, eventType, onlineDuration, uploadTraffic, downloadTraffic)
      if err != nil {
              writeLog(fmt.Sprintf("Failed to insert access log: %v", err))
              return
      }

      writeLog(fmt.Sprintf("Access log recorded: Client %s (%s) on server %s %s", clientName, clientIP, serverName, eventType))
}

// 更新客户端状态、在线时间和流量统计
func updateClientStatusAndTraffic(db *sql.DB, clientID int, newStatus, currentStatus string, currentOnlineTime int, firstOnline *string, peerTraffic *PeerTraffic, prevReceived30s, prevSent30s, prevOnlineReceived, prevOnlineSent, prevClientTotalReceived, prevClientTotalSent float64, serverID int) {
      // 添加重试逻辑来处理数据库锁定问题
      maxRetries := 5
      for attempt := 0; attempt < maxRetries; attempt++ {
              // 如果不是第一次尝试，等待一段时间再重试
              if attempt > 0 {
                      time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
              }

              // 使用事务来确保操作的原子性
              tx, err := db.Begin()
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to begin transaction (attempt %d): %v", attempt+1, err))
                      continue
              }

              var result sql.Result
              var rowsAffected int64

              // 初始化流量统计变量
              var received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent float64

              // 如果客户端在线且有流量数据
              if newStatus == "online" && peerTraffic != nil {
                      // 计算30秒内的流量差值（使用原始字节值进行计算）
                      rawReceivedDiff := float64(peerTraffic.ReceivedBytes) - prevOnlineReceived*1024.0 // 将KiB转换回字节
                      rawSentDiff := float64(peerTraffic.SentBytes) - prevOnlineSent*1024.0 // 将KiB转换回字节

                      // 转换为KiB单位
                      received30s = rawReceivedDiff / 1024.0
                      sent30s = rawSentDiff / 1024.0

                      // 如果是初次上线或之前是离线状态，只记录当前的流量差值，避免出现负数
                      if currentStatus != "online" {
                              // 如果是首次上线，使用当前流量值，不计算差值
                              rawReceivedDiff = float64(peerTraffic.ReceivedBytes)
                              rawSentDiff = float64(peerTraffic.SentBytes)
                              received30s = rawReceivedDiff / 1024.0
                              sent30s = rawSentDiff / 1024.0
                      }

                      // 确保流量差值为非负数
                      if received30s < 0 {
                              received30s = 0
                      }
                      if sent30s < 0 {
                              sent30s = 0
                      }

                      // 更新在线期间累计流量
                      onlineReceived = prevOnlineReceived + received30s
                      onlineSent = prevOnlineSent + sent30s

                      // 更新客户端总流量
                      clientTotalReceived = prevClientTotalReceived + received30s
                      clientTotalSent = prevClientTotalSent + sent30s
              } else {
                      // 如果客户端离线，30秒流量归零
                      received30s = 0
                      sent30s = 0
                      // 保留在线期间的累计流量，但将其归零
                      onlineReceived = 0
                      onlineSent = 0
                      // 客户端总流量保持不变
                      clientTotalReceived = prevClientTotalReceived
                      clientTotalSent = prevClientTotalSent
              }

              // 如果状态从未在线变为在线，记录首次在线时间
              if currentStatus != "online" && newStatus == "online" {
                      now := time.Now().Format("2006-01-02 15:04:05")
                      result, err = tx.Exec("UPDATE clients SET status=?, first_online=?, online_time=0, received_30s=?, sent_30s=?, online_received=?, online_sent=?, client_total_received=?, client_total_sent=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                              newStatus, now, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent, clientID)
              } else if currentStatus == "online" && newStatus == "online" {
                      // 如果继续保持在线，增加在线时间并更新流量统计
                      newOnlineTime := currentOnlineTime + 30 // 每30秒增加30秒
                      result, err = tx.Exec("UPDATE clients SET status=?, online_time=?, received_30s=?, sent_30s=?, online_received=?, online_sent=?, client_total_received=?, client_total_sent=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                              newStatus, newOnlineTime, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent, clientID)
              } else if currentStatus == "online" && newStatus == "offline" {
                      // 如果从在线变为离线，重置在线时间为0并更新流量统计
                      result, err = tx.Exec("UPDATE clients SET status=?, online_time=0, received_30s=?, sent_30s=?, online_received=?, online_sent=?, client_total_received=?, client_total_sent=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                              newStatus, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent, clientID)
              } else {
                      // 其他情况只更新状态和流量统计
                      result, err = tx.Exec("UPDATE clients SET status=?, received_30s=?, sent_30s=?, online_received=?, online_sent=?, client_total_received=?, client_total_sent=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                              newStatus, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent, clientID)
              }

              if err != nil {
                      tx.Rollback()
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      writeLog(fmt.Sprintf("Failed to update client %d status and traffic (attempt %d): %v", clientID, attempt+1, err))
                      return
              }

              rowsAffected, err = result.RowsAffected()
              if err != nil {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("Failed to get rows affected (attempt %d): %v", attempt+1, err))
                      continue
              }

              if rowsAffected == 0 {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("No rows updated for client %d (attempt %d)", clientID, attempt+1))
                      continue
              }

              // 提交事务
              err = tx.Commit()
              if err != nil {
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked on commit, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      writeLog(fmt.Sprintf("Failed to commit transaction (attempt %d): %v", attempt+1, err))
                      return
              }

              // 检查是否有行被更新，只有在更新成功时才记录状态变更日志
              if rowsAffected > 0 && currentStatus != newStatus {
                      writeLog(fmt.Sprintf("Client %d status changed from %s to %s", clientID, currentStatus, newStatus))
                      // 如果是从在线变为离线，记录在线时间重置
                      if currentStatus == "online" && newStatus == "offline" {
                              writeLog(fmt.Sprintf("Client %d online time reset to 0", clientID))
                      }
              }

              // 记录流量统计日志
              if peerTraffic != nil {
                      writeLog(fmt.Sprintf("Client %d traffic - Received: %.2f KiB/30s, Sent: %.2f KiB/30s, Online Received: %.2f KiB, Online Sent: %.2f KiB, Total Received: %.2f KiB, Total Sent: %.2f KiB",
                              clientID, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent))
              }

              return
      }

      writeLog(fmt.Sprintf("Failed to update client %d status and traffic after %d attempts due to database lock", clientID, maxRetries))
}

// 更新客户端流量统计
func updateClientTrafficStats(db *sql.DB, clientID int, currentStatus string, peerTraffic *PeerTraffic, prevReceived30s, prevSent30s, prevOnlineReceived, prevOnlineSent, prevClientTotalReceived, prevClientTotalSent, lastReceivedBytes, lastSentBytes float64) {
      // 添加调试日志
      writeLog(fmt.Sprintf("Debug: updateClientTrafficStats called for client %d, peerTraffic is nil: %t, currentStatus: %s", clientID, peerTraffic == nil, currentStatus))

      // 添加重试逻辑来处理数据库锁定问题
      maxRetries := 5
      for attempt := 0; attempt < maxRetries; attempt++ {
              // 如果不是第一次尝试，等待一段时间再重试
              if attempt > 0 {
                      time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
              }

              // 使用事务来确保操作的原子性
              tx, err := db.Begin()
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to begin transaction (attempt %d): %v", attempt+1, err))
                      continue
              }

              var result sql.Result
              var rowsAffected int64

              // 初始化流量统计变量
              var received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent float64

              // 如果客户端在线且有流量数据
              if currentStatus == "online" && peerTraffic != nil {
                      // 添加调试日志
                      writeLog(fmt.Sprintf("Debug: clientID=%d, currentReceived=%d, lastReceivedBytes=%.2f, currentSent=%d, lastSentBytes=%.2f",
                              clientID, peerTraffic.ReceivedBytes, lastReceivedBytes, peerTraffic.SentBytes, lastSentBytes))

                      // 检查是否是初次上线（lastReceivedBytes和lastSentBytes为0）
                      if lastReceivedBytes == 0 && lastSentBytes == 0 {
                              // 初次上线，只记录当前流量值，不计算差值
                              writeLog(fmt.Sprintf("Debug: First time online for client %d, setting last bytes to current values", clientID))
                              received30s = 0
                              sent30s = 0
                              // 更新在线期间累计流量
                              onlineReceived = prevOnlineReceived
                              onlineSent = prevOnlineSent
                              // 更新客户端总流量
                              clientTotalReceived = prevClientTotalReceived
                              clientTotalSent = prevClientTotalSent
                      } else {
                              // 计算30秒内的流量差值（使用原始字节值进行计算）
                              rawReceivedDiff := float64(peerTraffic.ReceivedBytes) - lastReceivedBytes
                              rawSentDiff := float64(peerTraffic.SentBytes) - lastSentBytes

                              // 添加调试日志
                              writeLog(fmt.Sprintf("Debug: rawReceivedDiff=%d-%.2f=%.2f, rawSentDiff=%d-%.2f=%.2f",
                                      peerTraffic.ReceivedBytes, lastReceivedBytes, rawReceivedDiff,
                                      peerTraffic.SentBytes, lastSentBytes, rawSentDiff))

                              // 转换为KiB单位
                              received30s = rawReceivedDiff / 1024.0
                              sent30s = rawSentDiff / 1024.0

                              // 添加调试日志
                              writeLog(fmt.Sprintf("Debug: rawReceivedDiff=%.2f, rawSentDiff=%.2f, received30s=%.2f KiB, sent30s=%.2f KiB",
                                      rawReceivedDiff, rawSentDiff, received30s, sent30s))

                              // 确保流量差值为非负数（避免计数器回绕）
                              if received30s < 0 {
                                      received30s = 0
                              }
                              if sent30s < 0 {
                                      sent30s = 0
                              }

                              // 更新在线期间累计流量
                              onlineReceived = prevOnlineReceived + received30s
                              onlineSent = prevOnlineSent + sent30s

                              // 更新客户端总流量
                              clientTotalReceived = prevClientTotalReceived + received30s
                              clientTotalSent = prevClientTotalSent + sent30s
                      }
              } else {
                      // 如果客户端离线，30秒流量归零
                      received30s = 0
                      sent30s = 0
                      // 在线期间流量归零
                      onlineReceived = 0
                      onlineSent = 0
                      // 客户端总流量保持不变
                      clientTotalReceived = prevClientTotalReceived
                      clientTotalSent = prevClientTotalSent
              }

              // 更新客户端流量统计
              // 注意：received_30s和sent_30s字段存储的是30秒流量差值（KiB）
              // last_received_bytes和last_sent_bytes字段存储的是上一次的原始字节值
              var newLastReceivedBytes, newLastSentBytes float64
              if peerTraffic != nil {
                      newLastReceivedBytes = float64(peerTraffic.ReceivedBytes)
                      newLastSentBytes = float64(peerTraffic.SentBytes)
              } else {
                      // 如果没有流量数据，保持原始值不变
                      newLastReceivedBytes = lastReceivedBytes
                      newLastSentBytes = lastSentBytes
              }

              writeLog(fmt.Sprintf("Debug: Updating client %d with received_30s=%.2f, sent_30s=%.2f, last_received_bytes=%.0f, last_sent_bytes=%.0f",
                      clientID, received30s, sent30s, newLastReceivedBytes, newLastSentBytes))

              result, err = tx.Exec("UPDATE clients SET received_30s=?, sent_30s=?, online_received=?, online_sent=?, client_total_received=?, client_total_sent=?, last_received_bytes=?, last_sent_bytes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                      received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent, newLastReceivedBytes, newLastSentBytes, clientID)

              if err != nil {
                      tx.Rollback()
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      writeLog(fmt.Sprintf("Failed to update client %d traffic stats (attempt %d): %v", clientID, attempt+1, err))
                      return
              }

              rowsAffected, err = result.RowsAffected()
              if err != nil {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("Failed to get rows affected (attempt %d): %v", attempt+1, err))
                      continue
              }

              if rowsAffected == 0 {
                      tx.Rollback()
                      writeLog(fmt.Sprintf("No rows updated for client %d (attempt %d)", clientID, attempt+1))
                      continue
              }

              // 提交事务
              err = tx.Commit()
              if err != nil {
                      if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
                              writeLog(fmt.Sprintf("Database locked on commit, will retry (attempt %d): %v", attempt+1, err))
                              continue
                      }
                      writeLog(fmt.Sprintf("Failed to commit transaction (attempt %d): %v", attempt+1, err))
                      return
              }

              // 记录流量统计日志
              if peerTraffic != nil {
                      writeLog(fmt.Sprintf("Client %d (%s) traffic - Received: %.2f KiB/30s, Sent: %.2f KiB/30s, Online Received: %.2f KiB, Online Sent: %.2f KiB, Total Received: %.2f KiB, Total Sent: %.2f KiB",
                              clientID, currentStatus, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent))
              } else {
                      writeLog(fmt.Sprintf("Client %d (%s) traffic - Received: %.2f KiB/30s, Sent: %.2f KiB/30s, Online Received: %.2f KiB, Online Sent: %.2f KiB, Total Received: %.2f KiB, Total Sent: %.2f KiB",
                              clientID, currentStatus, received30s, sent30s, onlineReceived, onlineSent, clientTotalReceived, clientTotalSent))
              }

              return
      }

      writeLog(fmt.Sprintf("Failed to update client %d traffic stats after %d attempts due to database lock", clientID, maxRetries))
}

// 更新服务器和全局流量统计
func updateServerAndGlobalTrafficStats(db *sql.DB) {
      // 获取所有服务器的流量统计
      serverRows, err := db.Query("SELECT id FROM servers")
      if err != nil {
              writeLog(fmt.Sprintf("Failed to query servers for traffic stats: %v", err))
              return
      }
      defer serverRows.Close()

      for serverRows.Next() {
              var serverID int
              err := serverRows.Scan(&serverID)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to scan server row: %v", err))
                      continue
              }

              // 计算该服务器下所有客户端的总流量
              var serverTotalReceived, serverTotalSent float64
              err = db.QueryRow("SELECT COALESCE(SUM(client_total_received), 0), COALESCE(SUM(client_total_sent), 0) FROM clients WHERE server_id=?", serverID).Scan(&serverTotalReceived, &serverTotalSent)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to calculate server %d total traffic: %v", serverID, err))
                      continue
              }

              // 更新服务器总流量
              _, err = db.Exec("UPDATE servers SET server_total_received=?, server_total_sent=? WHERE id=?", serverTotalReceived, serverTotalSent, serverID)
              if err != nil {
                      writeLog(fmt.Sprintf("Failed to update server %d traffic stats: %v", serverID, err))
                      continue
              }

              writeLog(fmt.Sprintf("Server %d total traffic - Received: %.2f KiB, Sent: %.2f KiB", serverID, serverTotalReceived, serverTotalSent))
      }

      // 计算全局总流量
      var totalReceived, totalSent float64
      err = db.QueryRow("SELECT COALESCE(SUM(server_total_received), 0), COALESCE(SUM(server_total_sent), 0) FROM servers").Scan(&totalReceived, &totalSent)
      if err != nil {
              writeLog(fmt.Sprintf("Failed to calculate global total traffic: %v", err))
              return
      }

      // 更新全局流量统计
      _, err = db.Exec("UPDATE vpn_stats SET total_received=?, total_sent=? WHERE id=1", totalReceived, totalSent)
      if err != nil {
              writeLog(fmt.Sprintf("Failed to update global traffic stats: %v", err))
              return
      }

      writeLog(fmt.Sprintf("Global total traffic - Received: %.2f KiB, Sent: %.2f KiB", totalReceived, totalSent))
}

// 清理三个月前的访问日志
func cleanupOldAccessLogs(db *sql.DB) {
      // 计算三个月前的时间
      threeMonthsAgo := time.Now().AddDate(0, -3, 0).Format("2006-01-02 15:04:05")

      // 删除三个月前的访问日志
      result, err := db.Exec("DELETE FROM access_logs WHERE event_time < ?", threeMonthsAgo)
      if err != nil {
              writeLog(fmt.Sprintf("Failed to cleanup old access logs: %v", err))
              return
      }

      rowsAffected, err := result.RowsAffected()
      if err != nil {
              writeLog(fmt.Sprintf("Failed to get rows affected for access log cleanup: %v", err))
              return
      }

      writeLog(fmt.Sprintf("Cleaned up %d old access logs (older than %s)", rowsAffected, threeMonthsAgo))
}

// WireGuard状态相关处理函数
func getWireGuardStatus(c echo.Context) error {
      cmd := exec.Command("wg", "show")
      output, err := cmd.CombinedOutput()
      if err != nil {
        return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %v\nOutput: %s", err, output))
      }

      return c.String(http.StatusOK, string(output))
}


// 流量单位转换函数
// bytesToHumanReadable 将字节数转换为人类可读的格式
func bytesToHumanReadable(bytes float64) string {
      const (
              KB = 1024
              MB = 1024 * KB
              GB = 1024 * MB
              TB = 1024 * GB
      )

      switch {
      case bytes >= TB:
              return fmt.Sprintf("%.2f TB", bytes/TB)
      case bytes >= GB:
              return fmt.Sprintf("%.2f GB", bytes/GB)
      case bytes >= MB:
              return fmt.Sprintf("%.2f MB", bytes/MB)
      case bytes >= KB:
              return fmt.Sprintf("%.2f KB", bytes/KB)
      default:
              return fmt.Sprintf("%.0f B", bytes)
      }
}

// humanReadableToBytes 将人类可读的格式转换为字节数
func humanReadableToBytes(value string) (float64, error) {
      value = strings.TrimSpace(value)
      re := regexp.MustCompile(`([0-9.]+)\s*([KMGT]?B)?`)
      matches := re.FindStringSubmatch(value)

      if len(matches) < 3 {
              return 0, fmt.Errorf("invalid format: %s", value)
      }

      num, err := strconv.ParseFloat(matches[1], 64)
      if err != nil {
              return 0, fmt.Errorf("invalid number: %s", matches[1])
      }

      unit := strings.ToUpper(matches[2])
      switch unit {
      case "KB":
              return num * 1024, nil
      case "MB":
              return num * 1024 * 1024, nil
      case "GB":
              return num * 1024 * 1024 * 1024, nil
      case "TB":
              return num * 1024 * 1024 * 1024 * 1024, nil
      default: // bytes or no unit
              return num, nil
      }
}

// 获取网络接口的IP地址和子网掩码
func getInterfaceIPAndMask(interfaceName string) (string, string, error) {
      cmd := exec.Command("ip", "addr", "show", interfaceName)
      output, err := cmd.Output()
      if err != nil {
          return "", "", err
      }

      // 使用正则表达式提取IPv4地址和子网掩码
      re := regexp.MustCompile(`inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)`)
      matches := re.FindStringSubmatch(string(output))
      if len(matches) < 3 {
          return "", "", fmt.Errorf("failed to extract IP and mask from interface %s", interfaceName)
      }

      return matches[1], matches[2], nil
}

// 检查IP地址是否在指定的CIDR范围内
func isIPInCIDR(ip, cidr string) bool {
      _, ipnet, err := net.ParseCIDR(cidr)
      if err != nil {
          return false
      }

      parsedIP := net.ParseIP(ip)
      if parsedIP == nil {
          return false
      }

      return ipnet.Contains(parsedIP)
}

// 检查UDP端口是否被占用
func isUDPPortInUse(port int) bool {
      cmd := exec.Command("ss", "-l", "-u", "-n")
      output, err := cmd.Output()
      if err != nil {
          return false
      }

      // 检查输出中是否包含指定端口
      portStr := fmt.Sprintf(":%d ", port)
      return strings.Contains(string(output), portStr)
}

// 检查IP网段是否重叠
func isCIDRConflict(cidr1, cidr2 string) bool {
      _, ipnet1, err1 := net.ParseCIDR(cidr1)
      _, ipnet2, err2 := net.ParseCIDR(cidr2)

      if err1 != nil || err2 != nil {
          return false
      }

      // 检查两个网段是否有重叠
      return ipnet1.Contains(ipnet2.IP) || ipnet2.Contains(ipnet1.IP)
}

// 检查网络配置冲突
func checkNetworkConflicts(server Server, db *sql.DB) (bool, string) {
      // 检查IP网段冲突
      _, _, err := net.ParseCIDR(server.Address)
      if err != nil {
          return false, "Invalid server address format"
      }

      // 获取所有网络接口信息
      interfaces, err := net.Interfaces()
      if err != nil {
          return false, "Failed to get network interfaces"
      }

      // 检查与系统网络接口的冲突
      serverIP, _, _ := net.ParseCIDR(server.Address)
      for _, iface := range interfaces {
          // 跳过环回接口
          if iface.Flags&net.FlagLoopback != 0 {
              continue
          }

          // 获取接口的IP地址
          addrs, err := iface.Addrs()
          if err != nil {
              continue
          }

          for _, addr := range addrs {
              if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
                  // 检查服务器IP是否与该接口的网段冲突
                  if ipnet.Contains(serverIP) {
                      // 如果服务器IP在该接口网段内，但不是该接口的IP，则冲突
                      if !ipnet.IP.Equal(serverIP) {
                          return false, fmt.Sprintf("IP address conflict: Server IP %s conflicts with interface %s network %s",
                              server.Address, iface.Name, ipnet.String())
                      }
                  }
              }
          }
      }

      // 检查与其他服务器的网段冲突
      rows, err := db.Query("SELECT id, name, address FROM servers WHERE id != ?", server.ID)
      if err != nil {
          return false, "Failed to query other servers"
      }
      defer rows.Close()

      for rows.Next() {
          var otherServer Server
          err := rows.Scan(&otherServer.ID, &otherServer.Name, &otherServer.Address)
          if err != nil {
              continue
          }

          if isCIDRConflict(server.Address, otherServer.Address) {
              return false, fmt.Sprintf("IP network conflict: Server network %s conflicts with server '%s' network %s",
                  server.Address, otherServer.Name, otherServer.Address)
          }
      }

      // 检查UDP端口冲突
      if isUDPPortInUse(server.ListenPort) {
          return false, fmt.Sprintf("UDP port conflict: Port %d is already in use", server.ListenPort)
      }

      return true, ""
}

func upWireGuardInterfaceHandler(c echo.Context, db *sql.DB) error {
      interfaceName := c.Param("interface")

      // 从接口名称中提取服务器ID
      serverID, err := getServerIDByInterfaceName(interfaceName, db)
      if err != nil {
          errorMsg := fmt.Sprintf("Failed to get server ID for interface %s: %v", interfaceName, err)
          writeLog(errorMsg)
          return c.String(http.StatusInternalServerError, errorMsg)
      }

      // 获取服务器配置
      row := db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface FROM servers WHERE id=?", serverID)
      server := Server{}
      err = row.Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface)
      if err != nil {
          errorMsg := fmt.Sprintf("Failed to get server config for ID %d: %v", serverID, err)
          writeLog(errorMsg)
          return c.String(http.StatusInternalServerError, errorMsg)
      }

      // 检查网络冲突
      noConflict, conflictMsg := checkNetworkConflicts(server, db)
      if !noConflict {
          errorMsg := fmt.Sprintf("Network conflict detected: %s", conflictMsg)
          writeLog(errorMsg)
          return c.String(http.StatusConflict, errorMsg)
      }

      // 启动WireGuard接口
      cmd := exec.Command("wg-quick", "up", interfaceName)
      output, err := cmd.CombinedOutput()
      if err != nil {
        errorMsg := fmt.Sprintf("Failed to start interface %s: %v\nOutput: %s", interfaceName, err, output)
        writeLog(errorMsg)
        return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %v\nOutput: %s", err, output))
      }

      writeLog(fmt.Sprintf("Started WireGuard interface: %s", interfaceName))
      return c.String(http.StatusOK, string(output))
}

func downWireGuardInterfaceHandler(c echo.Context, db *sql.DB) error {
      interfaceName := c.Param("interface")
      cmd := exec.Command("wg-quick", "down", interfaceName)
      output, err := cmd.CombinedOutput()
      if err != nil {
        errorMsg := fmt.Sprintf("Failed to stop interface %s: %v\nOutput: %s", interfaceName, err, output)
        writeLog(errorMsg)
        return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %v\nOutput: %s", err, output))
      }

      // 从接口名称获取服务器ID
      serverID, err := getServerIDByInterfaceName(interfaceName, db)
      if err != nil {
          writeLog(fmt.Sprintf("Failed to get server ID for interface %s: %v", interfaceName, err))
      } else {
          // 将该服务器的所有客户端标记为离线并重置在线时间
          stmt, err := db.Prepare("UPDATE clients SET status='offline', online_time=0, updated_at=CURRENT_TIMESTAMP WHERE server_id=? AND status='online'")
          if err != nil {
              writeLog(fmt.Sprintf("Failed to prepare update statement for server %d clients: %v", serverID, err))
          } else {
              defer stmt.Close()
              result, err := stmt.Exec(serverID)
              if err != nil {
                  writeLog(fmt.Sprintf("Failed to update clients for server %d: %v", serverID, err))
              } else {
                  rowsAffected, _ := result.RowsAffected()
                  writeLog(fmt.Sprintf("Marked %d clients as offline for server %d", rowsAffected, serverID))
              }
          }
      }

      writeLog(fmt.Sprintf("Stopped WireGuard interface: %s", interfaceName))
      return c.String(http.StatusOK, string(output))
}

// 重启WireGuard接口
func restartWireGuardInterfaceHandler(c echo.Context, db *sql.DB) error {
      interfaceName := c.Param("interface")

      // 先停止接口
      downCmd := exec.Command("wg-quick", "down", interfaceName)
      downOutput, err := downCmd.CombinedOutput()
      if err != nil {
        errorMsg := fmt.Sprintf("Failed to stop interface %s: %v\nOutput: %s", interfaceName, err, downOutput)
        writeLog(errorMsg)
        // 即使停止失败，我们也尝试启动接口
      }

      // 再启动接口
      upCmd := exec.Command("wg-quick", "up", interfaceName)
      upOutput, err := upCmd.CombinedOutput()
      if err != nil {
        errorMsg := fmt.Sprintf("Failed to start interface %s: %v\nOutput: %s", interfaceName, err, upOutput)
        writeLog(errorMsg)
        return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %v\nOutput: %s", err, upOutput))
      }

      // 从接口名称获取服务器ID
      serverID, err := getServerIDByInterfaceName(interfaceName, db)
      if err != nil {
          writeLog(fmt.Sprintf("Failed to get server ID for interface %s: %v", interfaceName, err))
      } else {
          // 将该服务器的所有客户端标记为离线并重置在线时间
          stmt, err := db.Prepare("UPDATE clients SET status='offline', online_time=0, updated_at=CURRENT_TIMESTAMP WHERE server_id=? AND status='online'")
          if err != nil {
              writeLog(fmt.Sprintf("Failed to prepare update statement for server %d clients: %v", serverID, err))
          } else {
              defer stmt.Close()
              result, err := stmt.Exec(serverID)
              if err != nil {
                  writeLog(fmt.Sprintf("Failed to update clients for server %d: %v", serverID, err))
              } else {
                  rowsAffected, _ := result.RowsAffected()
                  writeLog(fmt.Sprintf("Marked %d clients as offline for server %d", rowsAffected, serverID))
              }
          }
      }

      writeLog(fmt.Sprintf("Restarted WireGuard interface: %s", interfaceName))
      return c.String(http.StatusOK, string(upOutput))
}

// 检查接口是否处于活动状态
func isInterfaceUp(interfaceName string) bool {
      cmd := exec.Command("ip", "link", "show", interfaceName)
      output, err := cmd.CombinedOutput()
      if err != nil {
        return false
      }
      
      // 检查输出中是否包含"UP"标志
      outputStr := string(output)
      return strings.Contains(outputStr, "UP")
}

// 获取下一个IP地址
func nextIP(ip net.IP) net.IP {
      next := net.ParseIP(ip.String())
      for j := len(next) - 1; j >= 0; j-- {
              next[j]++
              if next[j] > 0 {
                      break
              }
      }
      return next
}

// 检查是否是网络地址或广播地址
func isNetworkOrBroadcastAddress(ip net.IP, ipNet *net.IPNet) bool {
      // 获取网络地址
      networkIP := ipNet.IP

      // 获取广播地址
      broadcastIP := net.ParseIP(networkIP.String())
      for i := range networkIP {
              broadcastIP[i] = networkIP[i] | ^ipNet.Mask[i]
      }

      // 检查是否是网络地址或广播地址
      return ip.Equal(networkIP) || ip.Equal(broadcastIP)
}

// 获取网络接口的IP地址
func getInterfaceIPAddress(interfaceName string) (string, error) {
      iface, err := net.InterfaceByName(interfaceName)
      if err != nil {
          return "", err
      }

      addrs, err := iface.Addrs()
      if err != nil {
          return "", err
      }

      for _, addr := range addrs {
          if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
              if ipnet.IP.To4() != nil {
                  return ipnet.IP.String(), nil
              }
          }
      }

      return "", fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}

// 获取网络接口列表
func getNetworkInterfaces(c echo.Context) error {
      interfaces, err := net.Interfaces()
      if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get network interfaces"})
      }

      // 过滤掉环回接口和不活动的接口
      var interfaceNames []string
      for _, iface := range interfaces {
        // 跳过环回接口
        if iface.Flags&net.FlagLoopback != 0 {
                continue
        }
        
        // 只包括活动的接口
        if iface.Flags&net.FlagUp != 0 {
                interfaceNames = append(interfaceNames, iface.Name)
        }
      }

      return c.JSON(http.StatusOK, interfaceNames)
}

// 获取在线客户端
func getOnlineClients(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        // 查询所有在线客户端，包含服务器信息
        query := `
        SELECT
          c.id,
          c.name,
          c.address,
          c.status,
          c.online_time,
          c.first_online,
          s.name as server_name
        FROM clients c
        JOIN servers s ON c.server_id = s.id
        WHERE c.status = 'online'
        `

        rows, err := db.Query(query)
        if err != nil {
                return err
        }
        defer rows.Close()

        type OnlineClient struct {
                ID         int     `json:"id"`
                Name       string  `json:"name"`
                Address    string  `json:"address"`
                Status     string  `json:"status"`
                OnlineTime int     `json:"online_time"`
                FirstOnline *string `json:"first_online"`
                ServerName string  `json:"server_name"`
        }

        clients := []OnlineClient{}
        for rows.Next() {
                var client OnlineClient
                err := rows.Scan(&client.ID, &client.Name, &client.Address, &client.Status, &client.OnlineTime, &client.FirstOnline, &client.ServerName)
                if err != nil {
                        return err
                }
                clients = append(clients, client)
        }

        return c.JSON(http.StatusOK, clients)
      }
}

// 流量统计相关处理函数
func getTrafficStats(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        rows, err := db.Query("SELECT id, name, transfer_rx, transfer_tx FROM clients")
        if err != nil {
                return err
        }
        defer rows.Close()

        type TrafficStat struct {
                ID         int    `json:"id"`
                Name       string `json:"name"`
                TransferRx int64  `json:"transfer_rx"`
                TransferTx int64  `json:"transfer_tx"`
        }

        stats := []TrafficStat{}
        var totalRx, totalTx int64

        for rows.Next() {
                var s TrafficStat
                err := rows.Scan(&s.ID, &s.Name, &s.TransferRx, &s.TransferTx)
                if err != nil {
                        return err
                }
                stats = append(stats, s)
                totalRx += s.TransferRx
                totalTx += s.TransferTx
        }

        result := map[string]interface{}{
                "clients":   stats,
                "total_rx":  totalRx,
                "total_tx":  totalTx,
                "total":     totalRx + totalTx,
        }

        return c.JSON(http.StatusOK, result)
      }
}


// 处理CIDR列表，去除空格并格式化

// 处理CIDR列表，去除空格并格式化
func processCIDRList(cidrList string) string {
	// 处理多个CIDR条目
	cidrs := strings.Split(cidrList, ",")
	processedCIDRs := make([]string, 0)
	for _, cidr := range cidrs {
		trimmed := strings.TrimSpace(cidr)
		if trimmed != "" {
			processedCIDRs = append(processedCIDRs, trimmed)
		}
	}
	if len(processedCIDRs) > 0 {
		return strings.Join(processedCIDRs, ",")
	}
	return cidrList
}

// 获取访问日志
func getAccessLogs(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        // 获取所有访问日志，按时间倒序排列
        rows, err := db.Query(`
          SELECT id, client_name, client_ip, server_name, event_type, event_time, online_duration, sent_traffic, received_traffic
          FROM access_logs
          ORDER BY event_time DESC
          LIMIT 1000
        `)
        if err != nil {
                return err
        }
        defer rows.Close()

        type AccessLog struct {
                ID             int     `json:"id"`
                ClientName     string  `json:"client_name"`
                ClientIP       string  `json:"client_ip"`
                ServerName     string  `json:"server_name"`
                EventType      string  `json:"event_type"`
                EventTime      string  `json:"event_time"`
                OnlineDuration int     `json:"online_duration"`
                SentTraffic  float64 `json:"sent_traffic"`
                ReceivedTraffic float64 `json:"received_traffic"`
        }

        logs := []AccessLog{}
        for rows.Next() {
                var log AccessLog
                err := rows.Scan(&log.ID, &log.ClientName, &log.ClientIP, &log.ServerName, &log.EventType, &log.EventTime, &log.OnlineDuration, &log.SentTraffic, &log.ReceivedTraffic)
                if err != nil {
                        return err
                }
                logs = append(logs, log)
        }

        return c.JSON(http.StatusOK, logs)
      }
}

// 搜索访问日志
func searchAccessLogs(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 获取查询参数
		query := c.QueryParam("q")
		clientName := c.QueryParam("client_name")
		clientIP := c.QueryParam("client_ip")
		serverName := c.QueryParam("server_name")
		startTime := c.QueryParam("start_time")
		endTime := c.QueryParam("end_time")

		// 添加调试日志
		writeLog(fmt.Sprintf("Search parameters - q: '%s', client_name: '%s', client_ip: '%s', server_name: '%s', start_time: '%s', end_time: '%s'",
			query, clientName, clientIP, serverName, startTime, endTime))

		// 构建SQL查询
		sqlQuery := `SELECT id, client_name, client_ip, server_name, event_type, event_time, online_duration, sent_traffic, received_traffic
		             FROM access_logs WHERE 1=1`

		var params []interface{}

		// 构建搜索条件
		var conditions []string
		var conditionParams []interface{}

		// 添加通用搜索条件
		if query != "" {
			conditions = append(conditions, "(client_name LIKE ? OR client_ip LIKE ? OR server_name LIKE ?)")
			conditionParams = append(conditionParams, "%"+query+"%", "%"+query+"%", "%"+query+"%")
		}

		// 添加特定字段搜索条件
		if clientName != "" {
			conditions = append(conditions, "client_name LIKE ?")
			conditionParams = append(conditionParams, "%"+clientName+"%")
		}
		if clientIP != "" {
			conditions = append(conditions, "client_ip LIKE ?")
			conditionParams = append(conditionParams, "%"+clientIP+"%")
		}
		if serverName != "" {
			conditions = append(conditions, "server_name LIKE ?")
			conditionParams = append(conditionParams, "%"+serverName+"%")
		}

		// 如果有任何搜索条件，使用 OR 连接它们以提供更宽松的搜索
		if len(conditions) > 0 {
			if query != "" && (clientName != "" || clientIP != "" || serverName != "") {
				// 如果同时提供了通用搜索和特定字段搜索，使用 OR 连接
				sqlQuery += " AND (" + conditions[0]
				for i := 1; i < len(conditions); i++ {
					sqlQuery += " OR " + conditions[i]
				}
				sqlQuery += ")"
			} else {
				// 否则使用 AND 连接（保持原有行为）
				for _, condition := range conditions {
					sqlQuery += " AND " + condition
				}
			}
			params = append(params, conditionParams...)
		}

		// 添加时间范围搜索条件
		// 处理ISO格式的时间字符串（前端datetime-local控件发送的格式，例如"2025-10-23T08:00:00"）
		if startTime != "" {
			// 尝试将ISO时间格式转换为SQLite时间格式
			isoTime := startTime
			if !strings.Contains(isoTime, " ") && strings.Contains(isoTime, "T") {
				// 将"T"替换为空格以匹配SQLite时间格式
				isoTime = strings.Replace(isoTime, "T", " ", 1)
			}
			sqlQuery += " AND event_time >= ?"
			params = append(params, isoTime)
		}
		if endTime != "" {
			// 尝试将ISO时间格式转换为SQLite时间格式
			isoTime := endTime
			if !strings.Contains(isoTime, " ") && strings.Contains(isoTime, "T") {
				// 将"T"替换为空格以匹配SQLite时间格式
				isoTime = strings.Replace(isoTime, "T", " ", 1)
			}
			sqlQuery += " AND event_time <= ?"
			params = append(params, isoTime)
		}

		// 按时间倒序排列并限制结果
		sqlQuery += " ORDER BY event_time DESC LIMIT 1000"

		writeLog(fmt.Sprintf("Executing search access logs query: %s with params: %v", sqlQuery, params))

		rows, err := db.Query(sqlQuery, params...)
		if err != nil {
			writeLog(fmt.Sprintf("Error executing search access logs query: %v", err))
			return err
		}
		defer rows.Close()

		type AccessLog struct {
			ID             int     `json:"id"`
			ClientName     string  `json:"client_name"`
			ClientIP       string  `json:"client_ip"`
			ServerName     string  `json:"server_name"`
			EventType      string  `json:"event_type"`
			EventTime      string  `json:"event_time"`
			OnlineDuration int     `json:"online_duration"`
			SentTraffic  float64 `json:"sent_traffic"`
			ReceivedTraffic float64 `json:"received_traffic"`
		}

		logs := []AccessLog{}
		for rows.Next() {
			var log AccessLog
			err := rows.Scan(&log.ID, &log.ClientName, &log.ClientIP, &log.ServerName, &log.EventType, &log.EventTime, &log.OnlineDuration, &log.SentTraffic, &log.ReceivedTraffic)
			if err != nil {
				writeLog(fmt.Sprintf("Error scanning access log row: %v", err))
				return err
			}
			logs = append(logs, log)
		}

		writeLog(fmt.Sprintf("Search returned %d access logs", len(logs)))
		return c.JSON(http.StatusOK, logs)
	}
}

// 获取服务器配置文件内容
func getServerConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")

		// 获取服务器信息
		row := db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", id)
		server := Server{}
		err := row.Scan(&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Server not found"})
		}

		// 构建配置文件路径
		interfaceName := "wg" + id
		configPath := filepath.Join("/etc/wireguard", interfaceName+".conf")

		// 读取配置文件内容
		content, err := os.ReadFile(configPath)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read config file"})
		}

		return c.JSON(http.StatusOK, map[string]string{"content": string(content)})
	}
}

// 搜索客户端
func searchClients(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		query := c.QueryParam("q")
		if query == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Query parameter 'q' is required"})
		}

		// 构建SQL查询，支持模糊匹配按名称、IP地址搜索
		// 使用模糊匹配方式：
		// 1. 模糊匹配客户端名称
		// 2. 模糊匹配IP地址
		// 3. 如果查询的是数字，也匹配客户端ID
		var sqlQuery string
		var rows *sql.Rows
		var err error

		// 尝试将查询解析为数字（客户端ID）
		clientID := 0
		_, parseErr := fmt.Sscanf(query, "%d", &clientID)
		if parseErr == nil {
			// 如果解析成功，也添加ID匹配条件
			sqlQuery = `
			SELECT id, server_id, name, address, private_key, public_key, preshared_key, allowed_ips, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx, enabled, persistent_keepalive, dns, mtu, online_time, first_online
			FROM clients
			WHERE name LIKE ? OR address LIKE ? OR id = ?
			`
			writeLog(fmt.Sprintf("Executing search query: %s with parameters: %%%s%%, %%%s%%, %d", sqlQuery, query, query, clientID))
			rows, err = db.Query(sqlQuery, "%"+query+"%", "%"+query+"%", clientID)
		} else {
			// 如果查询不是数字，使用模糊搜索名称和地址
			sqlQuery = `
			SELECT id, server_id, name, address, private_key, public_key, preshared_key, allowed_ips, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx, enabled, persistent_keepalive, dns, mtu, online_time, first_online
			FROM clients
			WHERE name LIKE ? OR address LIKE ?
			`
			writeLog(fmt.Sprintf("Executing search query: %s with parameters: %%%s%%, %%%s%%", sqlQuery, query, query))
			rows, err = db.Query(sqlQuery, "%"+query+"%", "%"+query+"%")
		}

		if err != nil {
			writeLog(fmt.Sprintf("Error executing search query: %v", err))
			return err
		}
		defer rows.Close()

		clients := []Client{}
		for rows.Next() {
			var cl Client
			err := rows.Scan(&cl.ID, &cl.ServerID, &cl.Name, &cl.Address, &cl.PrivateKey, &cl.PublicKey, &cl.PresharedKey, &cl.AllowedIPs, &cl.ServerAllowedIPs, &cl.ClientAllowedIPs, &cl.Status, &cl.LatestHandshake, &cl.TransferRx, &cl.TransferTx, &cl.Enabled, &cl.PersistentKeepalive, &cl.DNS, &cl.MTU, &cl.OnlineTime, &cl.FirstOnline)
			if err != nil {
				writeLog(fmt.Sprintf("Error scanning client row: %v", err))
				return err
			}
			clients = append(clients, cl)
		}

		writeLog(fmt.Sprintf("Search returned %d clients", len(clients)))
		return c.JSON(http.StatusOK, clients)
	}
}

// 获取客户端配置文件内容
func getClientConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")

		// 获取客户端信息
		row := db.QueryRow("SELECT id, server_id, name, address, private_key, public_key, preshared_key, server_allowed_ips, client_allowed_ips, status, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive, dns, mtu FROM clients WHERE id=?", id)
		var cl Client
		err := row.Scan(&cl.ID, &cl.ServerID, &cl.Name, &cl.Address, &cl.PrivateKey, &cl.PublicKey, &cl.PresharedKey, &cl.ServerAllowedIPs, &cl.ClientAllowedIPs, &cl.Status, &cl.LatestHandshake, &cl.TransferRx, &cl.TransferTx, &cl.PersistentKeepalive, &cl.DNS, &cl.MTU)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Client not found"})
		}

		// 构建配置文件路径
		interfaceName := "wg" + strconv.Itoa(cl.ServerID)
		clientDir := filepath.Join("/etc/wireguard", "Clients", interfaceName+"_clients")
		configPath := filepath.Join(clientDir, cl.Name+".conf")

		// 设置响应头以触发下载
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", cl.Name))
		c.Response().Header().Set("Content-Type", "application/octet-stream")

		// 直接返回文件内容
		return c.File(configPath)
	}
}

// User 结构体定义
type User struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	PasswordHash string `json:"password_hash"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// LoginRequest 登录请求结构体
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ChangePasswordRequest 密码更改请求结构体
type ChangePasswordRequest struct {
	Username     string `json:"username"`
	CurrentPassword string `json:"current_password"`
	NewPassword  string `json:"new_password"`
}

// Login 登录处理函数
func login(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		}

		var user User
		query := "SELECT id, username, password_hash FROM users WHERE username = ?"
		err := db.QueryRow(query, req.Username).Scan(&user.ID, &user.Username, &user.PasswordHash)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Server error"})
		}

		// 简单的密码验证（在实际应用中应该使用哈希比较）
		if req.Password != user.PasswordHash {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid username or password"})
		}

		// 登录成功，返回用户信息（不包括密码）
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Login successful",
			"user": map[string]interface{}{
				"id":       user.ID,
				"username": user.Username,
			},
		})
	}
}

// ChangePassword 密码更改处理函数
func changePassword(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req ChangePasswordRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		}

		var user User
		query := "SELECT id, username, password_hash FROM users WHERE username = ?"
		err := db.QueryRow(query, req.Username).Scan(&user.ID, &user.Username, &user.PasswordHash)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not found"})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Server error"})
		}

		// 验证当前密码
		if req.CurrentPassword != user.PasswordHash {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
		}

		// 更新密码
		updateQuery := "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?"
		_, err = db.Exec(updateQuery, req.NewPassword, req.Username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
	}
}

// CheckAuth 认证检查处理函数
func checkAuth(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "authenticated"})
}
// 获取详细的流量统计信息（包括新添加的流量字段）
// 获取详细的流量统计信息（包括新添加的流量字段）
func getDetailedTrafficStats(db *sql.DB) echo.HandlerFunc {
      return func(c echo.Context) error {
        // 获取所有客户端及其流量信息（包括在线和离线的）
        clientRows, err := db.Query(`
          SELECT id, name, server_id, status, received_30s, sent_30s, online_received, online_sent, client_total_received, client_total_sent
          FROM clients
          ORDER BY server_id, name
        `)
        if err != nil {
                return err
        }
        defer clientRows.Close()

        type ClientTraffic struct {
                ID                  int     `json:"id"`
                Name                string  `json:"name"`
                ServerID            int     `json:"server_id"`
                Status              string  `json:"status"`
                Received30s         float64 `json:"received_30s"`
                Sent30s             float64 `json:"sent_30s"`
                OnlineReceived      float64 `json:"online_received"`
                OnlineSent          float64 `json:"online_sent"`
                ClientTotalReceived float64 `json:"client_total_received"`
                ClientTotalSent     float64 `json:"client_total_sent"`
        }

        allClients := []ClientTraffic{}
        for clientRows.Next() {
                var client ClientTraffic
                err := clientRows.Scan(&client.ID, &client.Name, &client.ServerID, &client.Status, &client.Received30s, &client.Sent30s, &client.OnlineReceived, &client.OnlineSent, &client.ClientTotalReceived, &client.ClientTotalSent)
                if err != nil {
                        return err
                }
                // received_30s和sent_30s字段已经存储了30秒流量差值（KiB），无需转换
                allClients = append(allClients, client)
        }

        // 获取服务器及其流量信息
        serverRows, err := db.Query(`
          SELECT id, name, server_total_received, server_total_sent
          FROM servers
          ORDER BY id
        `)
        if err != nil {
                return err
        }
        defer serverRows.Close()

        type ServerTraffic struct {
                ID                  int     `json:"id"`
                Name                string  `json:"name"`
                ServerTotalReceived float64 `json:"server_total_received"`
                ServerTotalSent     float64 `json:"server_total_sent"`
                Clients             []ClientTraffic `json:"clients"`
        }

        servers := make(map[int]*ServerTraffic)

        for serverRows.Next() {
                var server ServerTraffic
                err := serverRows.Scan(&server.ID, &server.Name, &server.ServerTotalReceived, &server.ServerTotalSent)
                if err != nil {
                        return err
                }
                server.Clients = []ClientTraffic{}
                servers[server.ID] = &server
        }

        // 将客户端分配到对应的服务器
        for _, client := range allClients {
                if server, exists := servers[client.ServerID]; exists {
                        server.Clients = append(server.Clients, client)
                }
        }

        // 构建服务器列表
        serverList := make([]ServerTraffic, 0, len(servers))
        for _, server := range servers {
                serverList = append(serverList, *server)
        }

        // 获取全局流量统计
        var globalTotalReceived, globalTotalSent float64
        err = db.QueryRow("SELECT total_received, total_sent FROM vpn_stats WHERE id = 1").Scan(&globalTotalReceived, &globalTotalSent)
        if err != nil {
                // 如果没有找到记录，使用默认值
                globalTotalReceived = 0
                globalTotalSent = 0
        }

        result := map[string]interface{}{
                "servers": serverList,
                "global_total_received": globalTotalReceived,
                "global_total_sent": globalTotalSent,
        }

        return c.JSON(http.StatusOK, result)
      }
}

