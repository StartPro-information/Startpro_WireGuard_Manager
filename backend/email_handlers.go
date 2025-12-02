package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// 获取邮件配置
func getEmailConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var config EmailConfig
		err := db.QueryRow("SELECT id, smtp_host, smtp_port, username, password, from_email, from_name, enabled FROM email_config LIMIT 1").Scan(
			&config.ID, &config.SMTPHost, &config.SMTPPort, &config.Username, &config.Password, &config.FromEmail, &config.FromName, &config.Enabled)
		if err != nil {
			if err == sql.ErrNoRows {
				// 如果没有配置，返回默认值
				return c.JSON(200, EmailConfig{
					ID:        0,
					SMTPHost:  "",
					SMTPPort:  587,
					Username:  "",
					Password:  "",
					FromEmail: "",
					FromName:  "WireGuard Manager",
					Enabled:   0,
				})
			}
			return err
		}
		return c.JSON(200, config)
	}
}

// 更新邮件配置
func updateEmailConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var config EmailConfig
		if err := c.Bind(&config); err != nil {
			return c.JSON(400, map[string]string{"error": "Invalid request"})
		}

		// 检查是否已存在配置
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM email_config").Scan(&count)
		if err != nil {
			return err
		}

		if count == 0 {
			// 插入新配置
			_, err = db.Exec("INSERT INTO email_config (smtp_host, smtp_port, username, password, from_email, from_name, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
				config.SMTPHost, config.SMTPPort, config.Username, config.Password, config.FromEmail, config.FromName, config.Enabled)
		} else {
			// 更新现有配置
			_, err = db.Exec("UPDATE email_config SET smtp_host=?, smtp_port=?, username=?, password=?, from_email=?, from_name=?, enabled=?, updated_at=CURRENT_TIMESTAMP",
				config.SMTPHost, config.SMTPPort, config.Username, config.Password, config.FromEmail, config.FromName, config.Enabled)
		}

		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to save email configuration"})
		}

		return c.JSON(200, map[string]string{"message": "Email configuration saved successfully"})
	}
}

// 测试邮件配置
func testEmailConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var config EmailConfig
		if err := c.Bind(&config); err != nil {
			return c.JSON(400, map[string]string{"error": "Invalid request"})
		}

		// 如果没有提供测试配置，则从数据库获取
		if config.SMTPHost == "" {
			err := db.QueryRow("SELECT smtp_host, smtp_port, username, password, from_email, from_name FROM email_config WHERE enabled=1 LIMIT 1").Scan(
				&config.SMTPHost, &config.SMTPPort, &config.Username, &config.Password, &config.FromEmail, &config.FromName)
			if err != nil {
				if err == sql.ErrNoRows {
					return c.JSON(400, map[string]string{"error": "No email configuration found or email service is not enabled"})
				}
				return err
			}
		}

		// 发送测试邮件
		err := sendTestEmail(config)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to send test email: " + err.Error()})
		}

		return c.JSON(200, map[string]string{"message": "Test email sent successfully"})
	}
}

// 发送测试邮件
func sendTestEmail(config EmailConfig) error {
	// 创建邮件内容
	from := mail.Address{Name: config.FromName, Address: config.FromEmail}
	to := mail.Address{Name: "Test User", Address: config.FromEmail}
	subject := "WireGuard Manager Email Configuration Test"
	body := "This is a test email from WireGuard Manager to confirm that your email configuration is working correctly."

	// 创建SMTP认证
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	// 创建邮件消息
	message := fmt.Sprintf("From: %s\r\n", from.String())
	message += fmt.Sprintf("To: %s\r\n", to.String())
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/plain; charset=utf-8\r\n"
	message += "\r\n"
	message += body

	// 发送邮件
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	// 根据端口决定是否使用SSL
	if config.SMTPPort == 465 {
		// 使用SSL连接
		return sendEmailSSL(addr, auth, config.FromEmail, []string{to.Address}, []byte(message))
	} else {
		// 使用STARTTLS
		return smtp.SendMail(addr, auth, config.FromEmail, []string{to.Address}, []byte(message))
	}
}

// 使用SSL发送邮件
func sendEmailSSL(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	writeLog(fmt.Sprintf("Starting sendEmailSSL to %v via %s, message size: %d bytes", to, addr, len(msg)))
	
	// Create TLS config with more specific settings for QQ email
	tlsConfig := &tls.Config{
		ServerName: addr[:strings.Index(addr, ":")],
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		writeLog(fmt.Sprintf("tls dial failed: %v", err))
		return fmt.Errorf("tls dial failed: %v", err)
	}
	defer conn.Close()
	writeLog("TLS connection established successfully")

	client, err := smtp.NewClient(conn, addr[:strings.Index(addr, ":")])
	if err != nil {
		writeLog(fmt.Sprintf("smtp new client failed: %v", err))
		return fmt.Errorf("smtp new client failed: %v", err)
	}
	writeLog("SMTP client created successfully")
	// Don't defer client.Quit() as it might cause issues with QQ email

	if auth != nil {
		writeLog("Attempting SMTP authentication")
		if err = client.Auth(auth); err != nil {
			// Try to quit the client before returning
			client.Quit()
			writeLog(fmt.Sprintf("smtp auth failed: %v", err))
			return fmt.Errorf("smtp auth failed: %v", err)
		}
		writeLog("SMTP authentication successful")
	}

	writeLog("Sending MAIL command")
	if err = client.Mail(from); err != nil {
		// Try to quit the client before returning
		client.Quit()
		writeLog(fmt.Sprintf("smtp mail failed: %v", err))
		return fmt.Errorf("smtp mail failed: %v", err)
	}
	writeLog("MAIL command successful")

	for _, addr := range to {
		writeLog(fmt.Sprintf("Sending RCPT command for %s", addr))
		if err = client.Rcpt(addr); err != nil {
			// Try to quit the client before returning
			client.Quit()
			writeLog(fmt.Sprintf("smtp rcpt failed: %v", err))
			return fmt.Errorf("smtp rcpt failed: %v", err)
		}
		writeLog("RCPT command successful")
	}

	writeLog("Sending DATA command")
	writer, err := client.Data()
	if err != nil {
		// Try to quit the client before returning
		client.Quit()
		writeLog(fmt.Sprintf("smtp data failed: %v", err))
		return fmt.Errorf("smtp data failed: %v", err)
	}
	writeLog("DATA command successful")

	writeLog(fmt.Sprintf("Writing message data (%d bytes)", len(msg)))
	_, err = writer.Write(msg)
	if err != nil {
		// Try to close writer and quit client before returning
		writer.Close()
		client.Quit()
		writeLog(fmt.Sprintf("write message failed: %v", err))
		return fmt.Errorf("write message failed: %v", err)
	}
	writeLog("Message data written successfully")

	err = writer.Close()
	if err != nil {
		// Try to quit the client before returning
		client.Quit()
		writeLog(fmt.Sprintf("close writer failed: %v", err))
		return fmt.Errorf("close writer failed: %v", err)
	}
	writeLog("Writer closed successfully")

	// Try to quit the client, but don't return an error if it fails
	// as the email has already been sent successfully
	writeLog("Attempting to quit SMTP client")
	quitErr := client.Quit()
	if quitErr != nil {
		// Log the quit error but don't return it as the email was sent
		writeLog(fmt.Sprintf("DEBUG: SMTP quit error (but email was sent): %v", quitErr))
	} else {
		writeLog("SMTP client quit successfully")
	}

	writeLog("Email sent successfully via SSL")
	return nil
}

// 发送客户端配置文件
func sendClientConfig(db *sql.DB) echo.HandlerFunc {
	writeLog("sendClientConfig called")
	
	return func(c echo.Context) error {
		id := c.Param("id")
		writeLog(fmt.Sprintf("sendClientConfig processing request for client ID: %s", id))
		
		var req struct {
			Email string `json:"email"`
			Language string `json:"language"`
		}
		if err := c.Bind(&req); err != nil {
			writeLog(fmt.Sprintf("Failed to bind request: %v", err))
			return c.JSON(400, map[string]string{"error": "Invalid request"})
		}
		writeLog(fmt.Sprintf("Request bound successfully: email=%s, language=%s", req.Email, req.Language))

		// 验证邮箱地址
		if !isValidEmail(req.Email) {
			writeLog(fmt.Sprintf("Invalid email address: %s", req.Email))
			return c.JSON(400, map[string]string{"error": "Invalid email address"})
		}

		// 获取邮件配置
		writeLog("Fetching email configuration from database")
		var emailConfig EmailConfig
		err := db.QueryRow("SELECT smtp_host, smtp_port, username, password, from_email, from_name FROM email_config WHERE enabled=1 LIMIT 1").Scan(
			&emailConfig.SMTPHost, &emailConfig.SMTPPort, &emailConfig.Username, &emailConfig.Password, &emailConfig.FromEmail, &emailConfig.FromName)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to fetch email config: %v", err))
			if err == sql.ErrNoRows {
				writeLog("No email configuration found or service not enabled")
				return c.JSON(400, map[string]string{"error": "Email service is not configured or not enabled"})
			}
			return err
		}
		writeLog(fmt.Sprintf("Email config fetched successfully: host=%s, port=%d, from=%s", 
			emailConfig.SMTPHost, emailConfig.SMTPPort, emailConfig.FromEmail))

		// 获取客户端信息
		var client Client
		err = db.QueryRow("SELECT id, server_id, name, address, private_key, public_key, preshared_key, server_allowed_ips, client_allowed_ips, persistent_keepalive, dns, mtu FROM clients WHERE id=?", id).Scan(
			&client.ID, &client.ServerID, &client.Name, &client.Address, &client.PrivateKey, &client.PublicKey, &client.PresharedKey, &client.ServerAllowedIPs, &client.ClientAllowedIPs, &client.PersistentKeepalive, &client.DNS, &client.MTU)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(404, map[string]string{"error": "Client not found"})
			}
			return err
		}

		// 获取服务器信息
		var server Server
		err = db.QueryRow("SELECT id, name, address, listen_port, private_key, public_key, dns, mtu, interface, public_ip_port FROM servers WHERE id=?", client.ServerID).Scan(
			&server.ID, &server.Name, &server.Address, &server.ListenPort, &server.PrivateKey, &server.PublicKey, &server.DNS, &server.MTU, &server.Interface, &server.PublicIpPort)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(404, map[string]string{"error": "Server not found"})
			}
			return err
		}

		// 生成客户端配置内容
		configContent := generateClientConfig(client, server)

		// 创建带超时的上下文，用于处理可能的大附件
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // 30分钟超时足够处理大型附件
		defer cancel()
		
		// 在 goroutine 中发送邮件，以支持超时控制
		resultChan := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					resultChan <- fmt.Errorf("panic occurred during email sending: %v", r)
				}
			}()
			err := sendConfigEmail(emailConfig, req.Email, client.Name, configContent, db, req.Language)
			resultChan <- err
		}()
		
		// 等待邮件发送完成或超时
		select {
		case err := <-resultChan:
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to send email: " + err.Error()})
			}
		case <-ctx.Done():
			return c.JSON(500, map[string]string{"error": "Email sending timeout: operation took too long to complete"})
		}

		writeLog(fmt.Sprintf("Client configuration sent to %s for client %s", req.Email, client.Name))
		return c.JSON(200, map[string]string{"message": "Configuration sent successfully"})
	}
}

// 发送配置邮件
func sendConfigEmail(config EmailConfig, recipientEmail, clientName, configContent string, db *sql.DB, language string) error {
	writeLog(fmt.Sprintf("Starting sendConfigEmail for client %s to %s", clientName, recipientEmail))
	
	// 获取附加文件配置
	var fileConfig AdditionalFileConfig
	err := db.QueryRow("SELECT file_path, file_name, enabled FROM additional_file_config LIMIT 1").Scan(
		&fileConfig.FilePath, &fileConfig.FileName, &fileConfig.Enabled)
	if err != nil && err != sql.ErrNoRows {
		writeLog(fmt.Sprintf("Failed to get additional file config: %v", err))
		return fmt.Errorf("failed to get additional file config: %v", err)
	}
	writeLog(fmt.Sprintf("Additional file config: enabled=%d, file_path=%s, file_name=%s", 
		fileConfig.Enabled, fileConfig.FilePath, fileConfig.FileName))

	// 创建邮件内容 (根据语言选择不同的邮件内容)
	from := mail.Address{Name: config.FromName, Address: config.FromEmail}
	to := mail.Address{Name: "", Address: recipientEmail}

	var subject, body string
	if language == "zh" {
		subject = fmt.Sprintf("%s的WireGuard配置", clientName)
		body = fmt.Sprintf("您好，\n\n请查收客户端%s的WireGuard配置文件。\n\n此致\n%s", clientName, config.FromName)
	} else {
		// 默认使用英文
		subject = fmt.Sprintf("WireGuard Configuration for %s", clientName)
		body = fmt.Sprintf("Hello,\n\nPlease find attached the WireGuard configuration for client %s.\n\nBest regards,\n%s", clientName, config.FromName)
	}

	// 创建临时文件来构建邮件消息，避免内存使用过多
	tempFile, err := os.CreateTemp("", "email_message_*.txt")
	if err != nil {
		writeLog(fmt.Sprintf("Failed to create temporary file for email message: %v", err))
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // 删除临时文件
	defer tempFile.Close()

	// 创建SMTP认证
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	// 创建多部分邮件消息
	boundary := "wireguard-config-boundary"
	message := fmt.Sprintf("From: %s\r\n", from.String())
	message += fmt.Sprintf("To: %s\r\n", to.String())
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary)
	message += "\r\n"

	// 写入邮件头部到临时文件
	if _, err := tempFile.WriteString(message); err != nil {
		writeLog(fmt.Sprintf("Failed to write email header to temp file: %v", err))
		return fmt.Errorf("failed to write email header: %v", err)
	}

	// 添加文本部分
	message = fmt.Sprintf("--%s\r\n", boundary)
	message += "Content-Type: text/plain; charset=utf-8\r\n"
	message += "\r\n"
	message += body
	message += "\r\n"

	if _, err := tempFile.WriteString(message); err != nil {
		writeLog(fmt.Sprintf("Failed to write text part to temp file: %v", err))
		return fmt.Errorf("failed to write text part: %v", err)
	}

	// 添加配置文件附件
	message = fmt.Sprintf("--%s\r\n", boundary)
	message += "Content-Type: application/octet-stream\r\n"
	message += "Content-Disposition: attachment; filename=\"client.conf\"\r\n"
	message += "\r\n"
	message += configContent
	message += "\r\n"

	if _, err := tempFile.WriteString(message); err != nil {
		writeLog(fmt.Sprintf("Failed to write config attachment to temp file: %v", err))
		return fmt.Errorf("failed to write config attachment: %v", err)
	}

	// 如果启用了附加文件且文件存在，则添加附加文件附件
	if fileConfig.Enabled == 1 && fileConfig.FilePath != "" {
		// 检查文件大小
		fileInfo, err := os.Stat(fileConfig.FilePath)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to get file info for %s: %v", fileConfig.FilePath, err))
		} else {
			fileSize := fileInfo.Size()
			writeLog(fmt.Sprintf("Attachment file size: %d bytes (%.2f MB)", fileSize, float64(fileSize)/(1024*1024)))
			
			// 如果文件大于10MB，添加警告日志
			if fileSize > 10*1024*1024 {
				writeLog("Warning: Large attachment file detected, this may take some time to process")
			}
		}
		
		// 使用流式读取处理大文件，避免一次性加载到内存
		file, err := os.Open(fileConfig.FilePath)
		if err == nil {
			defer file.Close()
			
			// 添加附加文件附件
			message = fmt.Sprintf("--%s\r\n", boundary)
			message += "Content-Type: application/octet-stream\r\n"
			message += "Content-Transfer-Encoding: base64\r\n"
			message += fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", fileConfig.FileName)
			message += "\r\n"

			if _, err := tempFile.WriteString(message); err != nil {
				writeLog(fmt.Sprintf("Failed to write attachment header to temp file: %v", err))
				return fmt.Errorf("failed to write attachment header: %v", err)
			}
			
			// 使用base64编码器和缓冲来处理大文件
			encoder := base64.NewEncoder(base64.StdEncoding, tempFile)
			buffer := make([]byte, 3*1024) // 3KB缓冲区，确保base64编码后是4的倍数
			
			// 按块读取文件并进行base64编码
			totalBytes := int64(0)
			for {
				n, err := file.Read(buffer)
				if n > 0 {
					// 编码并写入临时文件
					encoded := make([]byte, base64.StdEncoding.EncodedLen(n))
					base64.StdEncoding.Encode(encoded, buffer[:n])
					// 每76个字符添加换行符（符合RFC标准）
					for i := 0; i < len(encoded); i += 76 {
						end := i + 76
						if end > len(encoded) {
							end = len(encoded)
						}
						if _, writeErr := tempFile.Write(encoded[i:end]); writeErr != nil {
							encoder.Close()
							writeLog(fmt.Sprintf("Failed to write encoded data to temp file: %v", writeErr))
							return fmt.Errorf("failed to write encoded data: %v", writeErr)
						}
						if end < len(encoded) { // 如果还有更多数据，添加换行符
							if _, writeErr := tempFile.WriteString("\r\n"); writeErr != nil {
								encoder.Close()
								writeLog(fmt.Sprintf("Failed to write newline to temp file: %v", writeErr))
								return fmt.Errorf("failed to write newline: %v", writeErr)
							}
						}
					}
					totalBytes += int64(n)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					encoder.Close()
					writeLog(fmt.Sprintf("Failed to read file %s: %v", fileConfig.FilePath, err))
					return fmt.Errorf("failed to read file: %v", err)
				}
			}
			encoder.Close() // 完成编码
			
			// 添加结束行
			if _, err := tempFile.WriteString("\r\n"); err != nil {
				writeLog(fmt.Sprintf("Failed to write attachment end to temp file: %v", err))
				return fmt.Errorf("failed to write attachment end: %v", err)
			}
			
			writeLog(fmt.Sprintf("Base64 encoded attachment added, total bytes processed: %d", totalBytes))
		} else {
			// 添加错误日志
			writeLog(fmt.Sprintf("Failed to open additional file %s: %v", fileConfig.FilePath, err))
		}
	}

	// 结束边界
	message = fmt.Sprintf("--%s--\r\n", boundary)
	if _, err := tempFile.WriteString(message); err != nil {
		writeLog(fmt.Sprintf("Failed to write end boundary to temp file: %v", err))
		return fmt.Errorf("failed to write end boundary: %v", err)
	}

	// 关闭临时文件以确保所有数据都写入
	if err := tempFile.Close(); err != nil {
		writeLog(fmt.Sprintf("Failed to close temp file: %v", err))
		return fmt.Errorf("failed to close temp file: %v", err)
	}

	// 重新打开临时文件以读取完整内容
	tempFile, err = os.Open(tempFile.Name())
	if err != nil {
		writeLog(fmt.Sprintf("Failed to reopen temp file for reading: %v", err))
		return fmt.Errorf("failed to reopen temp file: %v", err)
	}
	defer tempFile.Close()

	// 获取文件大小
	fileInfo, err := tempFile.Stat()
	if err != nil {
		writeLog(fmt.Sprintf("Failed to get temp file info: %v", err))
		return fmt.Errorf("failed to get temp file info: %v", err)
	}
	messageSize := fileInfo.Size()
	writeLog(fmt.Sprintf("Total email message size: %d bytes (%.2f MB)", messageSize, float64(messageSize)/(1024*1024)))

	// 发送邮件
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	writeLog(fmt.Sprintf("Attempting to send email to %s via %s", to.Address, addr))

	// 根据端口决定是否使用SSL
	if config.SMTPPort == 465 {
		// 使用SSL连接
		writeLog("Using SSL connection for email")
		// 对于SSL连接，我们需要将整个消息读入内存
		messageBytes, err := io.ReadAll(tempFile)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to read temp file for SSL email: %v", err))
			return fmt.Errorf("failed to read temp file: %v", err)
		}
		err = sendEmailSSL(addr, auth, config.FromEmail, []string{to.Address}, messageBytes)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to send email via SSL: %v", err))
			return fmt.Errorf("failed to send email via SSL: %v", err)
		}
		writeLog("Email sent successfully via SSL")
		return nil
	} else {
		// 使用STARTTLS发送邮件（流式发送）
		writeLog("Using STARTTLS for email with streaming")
		
		// 为STARTTLS创建一个新的连接
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to connect to SMTP server: %v", err))
			return fmt.Errorf("failed to connect to SMTP server: %v", err)
		}
		defer conn.Close()
		
		// 创建SMTP客户端
		client, err := smtp.NewClient(conn, config.SMTPHost)
		if err != nil {
			writeLog(fmt.Sprintf("Failed to create SMTP client: %v", err))
			return fmt.Errorf("failed to create SMTP client: %v", err)
		}
		defer client.Quit()
		
		// STARTTLS
		if err = client.StartTLS(nil); err != nil {
			writeLog(fmt.Sprintf("Failed to start TLS: %v", err))
			return fmt.Errorf("failed to start TLS: %v", err)
		}
		
		// 认证
		if err = client.Auth(auth); err != nil {
			writeLog(fmt.Sprintf("Failed to authenticate: %v", err))
			return fmt.Errorf("failed to authenticate: %v", err)
		}
		
		// 设置发件人和收件人
		if err = client.Mail(config.FromEmail); err != nil {
			writeLog(fmt.Sprintf("Failed to set sender: %v", err))
			return fmt.Errorf("failed to set sender: %v", err)
		}
		
		if err = client.Rcpt(to.Address); err != nil {
			writeLog(fmt.Sprintf("Failed to set recipient: %v", err))
			return fmt.Errorf("failed to set recipient: %v", err)
		}
		
		// 发送数据
		writer, err := client.Data()
		if err != nil {
			writeLog(fmt.Sprintf("Failed to create data writer: %v", err))
			return fmt.Errorf("failed to create data writer: %v", err)
		}
		
		// 将临时文件内容复制到SMTP数据写入器
		_, err = io.Copy(writer, tempFile)
		if err != nil {
			writer.Close()
			writeLog(fmt.Sprintf("Failed to send email data: %v", err))
			return fmt.Errorf("failed to send email data: %v", err)
		}
		
		err = writer.Close()
		if err != nil {
			writeLog(fmt.Sprintf("Failed to close data writer: %v", err))
			return fmt.Errorf("failed to close data writer: %v", err)
		}
		
		writeLog("Email sent successfully via STARTTLS")
		return nil
	}
}

// 验证邮箱地址格式
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// 获取附加文件配置
func getAdditionalFileConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var config AdditionalFileConfig
		err := db.QueryRow("SELECT id, file_path, file_name, enabled FROM additional_file_config LIMIT 1").Scan(
			&config.ID, &config.FilePath, &config.FileName, &config.Enabled)
		if err != nil {
			if err == sql.ErrNoRows {
				// 如果没有配置，返回默认值
				return c.JSON(200, AdditionalFileConfig{
					ID:       0,
					FilePath: "",
					FileName: "",
					Enabled:  0,
				})
			}
			return err
		}
		return c.JSON(200, config)
	}
}

// 更新附加文件配置（启用/禁用）
func updateAdditionalFileConfig(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req struct {
			Enabled int `json:"enabled"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(400, map[string]string{"error": "Invalid request"})
		}

		// 更新配置
		_, err := db.Exec("UPDATE additional_file_config SET enabled=?, updated_at=CURRENT_TIMESTAMP", req.Enabled)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to update additional file configuration"})
		}

		return c.JSON(200, map[string]string{"message": "Additional file configuration updated successfully"})
	}
}

// 上传附加文件
func uploadAdditionalFile(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 检查是否有文件上传
		file, err := c.FormFile("file")
		if err != nil {
			return c.JSON(400, map[string]string{"error": "No file uploaded"})
		}

		// 检查文件大小（限制为20MB）
		if file.Size > 20*1024*1024 {
			return c.JSON(400, map[string]string{"error": "File size exceeds 20MB limit"})
		}

		// 获取文件信息
		src, err := file.Open()
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to open uploaded file"})
		}
		defer src.Close()

		// 创建上传目录
		uploadDir := "/etc/wireguard/wireguard-manager/uploads"
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to create upload directory"})
		}

		// 生成文件路径
		filePath := filepath.Join(uploadDir, file.Filename)

		// 检查是否已存在同名文件
		if _, err := os.Stat(filePath); err == nil {
			// 文件已存在，删除旧文件
			if err := os.Remove(filePath); err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to remove existing file"})
			}
		}

		// 创建目标文件
		dst, err := os.Create(filePath)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to create file"})
		}
		defer dst.Close()

		// 复制文件内容
		if _, err := io.Copy(dst, src); err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to save file"})
		}

		// 更新数据库配置
		_, err = db.Exec("UPDATE additional_file_config SET file_path=?, file_name=?, updated_at=CURRENT_TIMESTAMP", filePath, file.Filename)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to update file configuration"})
		}

		return c.JSON(200, map[string]string{"message": "File uploaded successfully", "file_path": filePath, "file_name": file.Filename})
	}
}

// 删除附加文件
func deleteAdditionalFile(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 获取当前文件信息
		var filePath string
		err := db.QueryRow("SELECT file_path FROM additional_file_config LIMIT 1").Scan(&filePath)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to get file information"})
		}

		// 删除文件（如果存在）
		if filePath != "" {
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				return c.JSON(500, map[string]string{"error": "Failed to delete file"})
			}
		}

		// 更新数据库配置
		_, err = db.Exec("UPDATE additional_file_config SET file_path='', file_name='', updated_at=CURRENT_TIMESTAMP")
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to update file configuration"})
		}

		return c.JSON(200, map[string]string{"message": "File deleted successfully"})
	}
}