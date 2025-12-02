package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

// 数据库配置结构
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

// 获取数据库配置
func getDBConfig() DBConfig {
	return DBConfig{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnvInt("DB_PORT", 3306),
		User:     getEnv("DB_USER", "wireguard"),
		Password: getEnv("DB_PASSWORD", "wireguard123"),
		Database: getEnv("DB_NAME", "wireguard_manager"),
	}
}

// 从环境变量获取值，如果不存在则使用默认值
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// 从环境变量获取整数值
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}

// 初始化MySQL数据库连接
func initDBConnection() (*sql.DB, error) {
	config := getDBConfig()

	// 构建MySQL连接字符串
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.User, config.Password, config.Host, config.Port, config.Database)

	// 打开数据库连接
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return nil, fmt.Errorf("无法连接到MySQL数据库: %v", err)
	}

	// 测试连接
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("无法ping通MySQL数据库: %v", err)
	}

	// 设置连接池参数
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(0)

	log.Println("成功连接到MySQL数据库")
	return db, nil
}