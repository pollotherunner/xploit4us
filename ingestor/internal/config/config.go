package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the ingestor
type Config struct {
	Database DatabaseConfig
	NIST     NISTConfig
	Logging  LoggingConfig
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type NISTConfig struct {
	MaxRetries     int
	RetryDelay     time.Duration
	RequestDelay   time.Duration
}

type LoggingConfig struct {
	Level  string
	Format string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	dbPort, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	maxRetries, err := strconv.Atoi(getEnv("NIST_MAX_RETRIES", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid NIST_MAX_RETRIES: %w", err)
	}

	retryDelaySec, err := strconv.Atoi(getEnv("NIST_RETRY_DELAY_SEC", "10"))
	if err != nil {
		return nil, fmt.Errorf("invalid NIST_RETRY_DELAY_SEC: %w", err)
	}

	requestDelayMs, err := strconv.Atoi(getEnv("NIST_REQUEST_DELAY_MS", "600"))
	if err != nil {
		return nil, fmt.Errorf("invalid NIST_REQUEST_DELAY_MS: %w", err)
	}

	return &Config{
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     dbPort,
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", "postgres"),
			DBName:   getEnv("DB_NAME", "db"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		NIST: NISTConfig{
			MaxRetries:   maxRetries,
			RetryDelay:   time.Duration(retryDelaySec) * time.Second,
			RequestDelay: time.Duration(requestDelayMs) * time.Millisecond,
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
		},
	}, nil
}

// DSN returns the database connection string
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
