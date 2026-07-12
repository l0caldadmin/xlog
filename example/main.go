package main

import (
	"fmt"
	"time"

	"github.com/l0caldadmin/xlog"
)

func main() {
	fmt.Println("=== xlog Example ===")
	fmt.Println()
	fmt.Println("This example demonstrates various logging features.")
	fmt.Println("You can control the output using environment variables:")
	fmt.Println("  LOG_LEVEL=debug|info|warn|error")
	fmt.Println("  LOG_FORMAT=default|text|json")
	fmt.Println()

	// Demonstrate all log levels
	fmt.Println("--- Log Levels ---")
	xlog.Debug("This is a debug message", "component", "example", "trace_id", "abc123")
	xlog.Info("Application started", "version", "1.0.0", "port", 8080)
	xlog.Warn("This is a warning", "threshold", 85, "current", 90)
	xlog.Error("An error occurred", "error", "connection timeout", "retries", 3)

	fmt.Println()
	fmt.Println("--- Key-Value Pairs ---")
	xlog.Info("User action",
		"user_id", 12345,
		"action", "login",
		"ip", "192.168.1.100",
		"timestamp", time.Now(),
		"success", true,
	)

	fmt.Println()
	fmt.Println("--- Complex Data ---")
	xlog.Info("Processing request",
		"request_id", "req-789",
		"method", "POST",
		"path", "/api/users",
		"duration_ms", 45.67,
		"status_code", 200,
		"headers", map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer token123",
		},
	)

	fmt.Println()
	fmt.Println("--- Nested Attributes ---")
	xlog.Info("Database query",
		"query", "SELECT * FROM users",
		"database", map[string]interface{}{
			"name":     "mydb",
			"host":     "localhost",
			"port":     5432,
			"ssl_mode": true,
		},
		"execution_time", 12*time.Millisecond,
	)

	fmt.Println()
	fmt.Println("--- Error Scenarios ---")
	xlog.Error("Failed to connect",
		"service", "database",
		"host", "db.example.com",
		"port", 5432,
		"error", "connection refused",
		"attempt", 1,
		"max_attempts", 3,
	)

	fmt.Println()
	fmt.Println("--- Performance Metrics ---")
	xlog.Info("Request completed",
		"endpoint", "/api/data",
		"method", "GET",
		"duration", 125*time.Millisecond,
		"bytes_sent", 2048,
		"bytes_received", 512,
		"cache_hit", false,
	)

	fmt.Println()
	fmt.Println("--- Different Data Types ---")
	xlog.Debug("Various data types",
		"string", "hello",
		"integer", 42,
		"float", 3.14159,
		"boolean", true,
		"duration", 5*time.Second,
		"timestamp", time.Now(),
	)

	fmt.Println()
	fmt.Println("--- Contextual Information ---")
	xlog.Info("Order processed",
		"order_id", "ORD-12345",
		"customer_id", 67890,
		"items", []string{"item1", "item2", "item3"},
		"total", 99.99,
		"currency", "USD",
		"payment_method", "credit_card",
	)

	fmt.Println()
	fmt.Println("--- Warning Example ---")
	xlog.Warn("High memory usage detected",
		"current_mb", 512,
		"max_mb", 1024,
		"percentage", 50.0,
		"threshold", 80.0,
	)

	// Demonstrate fatal (commented out to avoid exiting)
	fmt.Println()
	fmt.Println("--- Fatal Example (commented out to avoid exit) ---")
	fmt.Println("// xlog.Fatal(\"Critical error\", \"error\", \"cannot recover\")")
	fmt.Println("// This would call os.Exit(1)")

	fmt.Println()
	fmt.Println("=== Example Complete ===")
	fmt.Println()
	fmt.Println("Try running with different environment variables:")
	fmt.Println("  LOG_LEVEL=debug LOG_FORMAT=default go run example/main.go")
	fmt.Println("  LOG_LEVEL=info LOG_FORMAT=json go run example/main.go")
	fmt.Println("  LOG_LEVEL=warn LOG_FORMAT=text go run example/main.go")
}
