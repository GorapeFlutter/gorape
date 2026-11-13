package share

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/global"
	"github.com/gin-gonic/gin"
)

// ServerLoggerConfig represents server logger configuration
type ServerLoggerConfig struct {
	Component    string `json:"component" yaml:"component"`
	Service      string `json:"service" yaml:"service"`
	Level        string `json:"level" yaml:"level"`
	Structured   bool   `json:"structured" yaml:"structured"`
	EnableCaller bool   `json:"enable_caller" yaml:"enable_caller"`
	Output       string `json:"output" yaml:"output"`
}

// ServerLoggerInterface defines the server logging interface
type ServerLoggerInterface interface {
	DEBUG(requestID string, mcode global.MCode, optionalMessage string, fields ...map[string]interface{})
	INFO(requestID string, mcode global.MCode, optionalMessage string)
	WARN(requestID string, mcode global.MCode, optionalMessage string)
	ERROR(requestID string, mcode global.MCode, optionalMessage string)
	FATAL(requestID string, mcode global.MCode, optionalMessage string)
}

// ServerLogLevel represents the log level
type ServerLogLevel int

const (
	SERVER_DEBUG ServerLogLevel = iota
	SERVER_INFO
	SERVER_WARN
	SERVER_ERROR
	SERVER_FATAL
)

// String returns string representation of log level
func (rcvr ServerLogLevel) String() string {
	switch rcvr {
	case SERVER_DEBUG:
		return "DEBUG  "
	case SERVER_INFO:
		return "INFO   "
	case SERVER_WARN:
		return "WARN   "
	case SERVER_ERROR:
		return "ERROR  "
	case SERVER_FATAL:
		return "FATAL  "
	default:
		return "UNKNOWN"
	}
}

// ServerLogEntry represents a structured log entry
type ServerLogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Code      string                 `json:"code"`
	Component string                 `json:"component"`
	Service   string                 `json:"service"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	File      string                 `json:"file,omitempty"`
	Function  string                 `json:"function,omitempty"`
	Line      int                    `json:"line,omitempty"`
	TraceID   string                 `json:"trace_id,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// ServerLogger represents the server application logger
type ServerLogger struct {
	config     *ServerLoggerConfig
	level      ServerLogLevel
	output     io.Writer
	baseConfig interface{}
}

// Global server logger instance
var globalServerLogger *ServerLogger

// GetServerLogger returns the global server logger instance
func GetServerLogger() *ServerLogger {
	return globalServerLogger
}

// SetServerLogger sets the global server logger instance
func SetServerLogger(logger *ServerLogger) {
	globalServerLogger = logger
}

// Backward compatibility aliases
type MCode = global.MCode
type LoggerConfig = ServerLoggerConfig
type LoggerInterface = ServerLoggerInterface
type LogLevel = ServerLogLevel
type LogEntry = ServerLogEntry
type Logger = ServerLogger

const (
	DEBUG = SERVER_DEBUG
	INFO  = SERVER_INFO
	WARN  = SERVER_WARN
	ERROR = SERVER_ERROR
	FATAL = SERVER_FATAL
)

// NewServerLogger creates a new server logger instance
func NewServerLogger(loggerConfig ServerLoggerConfig, baseConfig interface{}) ServerLoggerInterface {
	logger := &ServerLogger{
		config:     &loggerConfig,
		baseConfig: baseConfig,
		output:     os.Stdout,
	}

	// Set log level
	switch strings.ToUpper(loggerConfig.Level) {
	case "DEBUG":
		logger.level = SERVER_DEBUG
	case "INFO":
		logger.level = SERVER_INFO
	case "WARN":
		logger.level = SERVER_WARN
	case "ERROR":
		logger.level = SERVER_ERROR
	case "FATAL":
		logger.level = SERVER_FATAL
	default:
		logger.level = SERVER_INFO
	}

	// Set output
	switch loggerConfig.Output {
	case "stderr":
		logger.output = os.Stderr
	case "stdout", "":
		logger.output = os.Stdout
	default:
		// File output
		if file, err := os.OpenFile(loggerConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666); err == nil {
			logger.output = file
		} else {
			logger.output = os.Stdout
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", loggerConfig.Output, err)
		}
	}

	return logger
}

// NewLogger creates a new logger instance (backward compatibility)
func NewLogger(loggerConfig LoggerConfig, baseConfig interface{}) LoggerInterface {
	return NewServerLogger(loggerConfig, baseConfig)
}

// formatServerWithOptional formats the message with optional additional message
func formatServerWithOptional(mcode global.MCode, optionalMessage string) string {
	if optionalMessage == "" {
		return mcode.Message
	}
	return fmt.Sprintf("%s: %s", mcode.Message, optionalMessage)
}

// log writes a log entry using global.MCode
func (rcvr *ServerLogger) log(level ServerLogLevel, requestID string, mcode global.MCode, optionalMessage string, fields map[string]interface{}) {
	if level < rcvr.level {
		return
	}

	finalMessage := formatServerWithOptional(mcode, optionalMessage)

	// Get current time in UTC and format with " UTC" string (with space before UTC)
	now := time.Now().UTC()
	// Format: 2025-11-08T05:01:15.791560000 UTC
	timestamp := now.Format("2006-01-02T15:04:05.000000000") + " UTC"

	entry := ServerLogEntry{
		Timestamp: timestamp,
		Level:     level.String(),
		Code:      mcode.PaddedCode(),
		Component: rcvr.config.Component,
		Service:   rcvr.config.Service,
		Message:   finalMessage,
		Fields:    fields,
		RequestID: requestID,
	}

	rcvr.writeLogEntry(entry)
}

// writeLogEntry writes the actual log entry to output
func (rcvr *ServerLogger) writeLogEntry(entry ServerLogEntry) {
	// Add caller information if enabled or DEBUG level
	if rcvr.config.EnableCaller || rcvr.level == SERVER_DEBUG {
		if pc, file, line, ok := runtime.Caller(4); ok {
			entry.File = file
			entry.Line = line
			if fn := runtime.FuncForPC(pc); fn != nil {
				entry.Function = fn.Name()
			}
		}
	}

	// Extract common fields from fields map
	if entry.Fields != nil {
		if traceID, ok := entry.Fields["trace_id"].(string); ok {
			entry.TraceID = traceID
			delete(entry.Fields, "trace_id")
		}
		if requestID, ok := entry.Fields["request_id"].(string); ok {
			entry.RequestID = requestID
			delete(entry.Fields, "request_id")
		}
		if userID, ok := entry.Fields["user_id"].(string); ok {
			entry.UserID = userID
			delete(entry.Fields, "user_id")
		}
		if err, ok := entry.Fields["error"].(string); ok {
			entry.Error = err
			delete(entry.Fields, "error")
		}
		if err, ok := entry.Fields["error"].(error); ok {
			entry.Error = err.Error()
			delete(entry.Fields, "error")
		}
	}

	if rcvr.config.Structured {
		// JSON format
		if jsonBytes, err := json.Marshal(entry); err == nil {
			fmt.Fprintln(rcvr.output, string(jsonBytes))
		} else {
			// Fallback to simple format
			fmt.Fprintf(rcvr.output, "[%s] [%s] [%s] %s\n",
				entry.Timestamp, entry.Level, entry.Code, entry.Message)
		}
	} else {
		// Human-readable format
		// Format: [timestamp] [level] [code] [request_id] message
		requestIDStr := entry.RequestID
		if requestIDStr == "" {
			requestIDStr = "xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
		}
		fmt.Fprintf(rcvr.output, "[%s] [%s] [%s] [%s] %s",
			entry.Timestamp, entry.Level, entry.Code, requestIDStr, entry.Message)
		// Only output fields for DEBUG level
		if len(entry.Fields) > 0 && entry.Level == "DEBUG  " {
			if fieldsJSON, err := json.Marshal(entry.Fields); err == nil {
				fmt.Fprintf(rcvr.output, " %s", string(fieldsJSON))
			}
		}
		fmt.Fprintln(rcvr.output)
	}
}

// DEBUG logs a debug message using global.MCode
func (rcvr *ServerLogger) DEBUG(requestID string, mcode global.MCode, optionalMessage string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	rcvr.log(SERVER_DEBUG, requestID, mcode, optionalMessage, f)
}

// INFO logs an info message using global.MCode
func (rcvr *ServerLogger) INFO(requestID string, mcode global.MCode, optionalMessage string) {
	rcvr.log(SERVER_INFO, requestID, mcode, optionalMessage, nil)
}

// WARN logs a warning message using global.MCode
func (rcvr *ServerLogger) WARN(requestID string, mcode global.MCode, optionalMessage string) {
	rcvr.log(SERVER_WARN, requestID, mcode, optionalMessage, nil)
}

// ERROR logs an error message using global.MCode
func (rcvr *ServerLogger) ERROR(requestID string, mcode global.MCode, optionalMessage string) {
	rcvr.log(SERVER_ERROR, requestID, mcode, optionalMessage, nil)
}

// FATAL logs a fatal message using global.MCode and exits
func (rcvr *ServerLogger) FATAL(requestID string, mcode global.MCode, optionalMessage string) {
	rcvr.log(SERVER_FATAL, requestID, mcode, optionalMessage, nil)
	os.Exit(1)
}

// GinLoggerWriter wraps our custom server logger to implement io.Writer for Gin
type GinLoggerWriter struct {
	logger ServerLoggerInterface
}

// Write implements io.Writer interface for Gin logging
func (rcvr *GinLoggerWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Remove trailing newline if present
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}

	// Skip empty messages
	if msg == "" {
		return len(p), nil
	}

	// Parse Gin HTTP request logs (format: "[GIN] 2025/11/08 - 14:04:27 | 400 |    2.531667ms |       127.0.0.1 | POST     "/v1/public/user"")
	// These are from gin.Default() logger, which we skip because LoggerWithConfig middleware handles request logging
	if strings.HasPrefix(msg, "[GIN] ") && strings.Contains(msg, " | ") {
		// Skip Gin's default HTTP request logs (they contain " | " separator)
		return len(p), nil
	}

	// Parse Gin debug/warning/error messages - use empty message to avoid redundancy
	mcode := global.MCode{Code: "GINLOG", Message: ""}

	// Clean up the message - remove [GIN-debug], [GIN-warning], etc prefixes and redundant [WARNING], [ERROR] text
	cleanMsg := msg
	cleanMsg = strings.TrimPrefix(cleanMsg, "[GIN-debug] ")
	cleanMsg = strings.TrimPrefix(cleanMsg, "[GIN-warning] ")
	cleanMsg = strings.TrimPrefix(cleanMsg, "[GIN-error] ")
	cleanMsg = strings.TrimPrefix(cleanMsg, "[GIN] ")

	// Remove redundant [WARNING], [ERROR] brackets from the message
	cleanMsg = strings.ReplaceAll(cleanMsg, "[WARNING] ", "")
	cleanMsg = strings.ReplaceAll(cleanMsg, "[ERROR] ", "")
	cleanMsg = strings.ReplaceAll(cleanMsg, "[DEBUG] ", "")

	// Compact route registration logs: ": DELETE /v1/..." -> "DELETE /v1/..."
	cleanMsg = strings.TrimPrefix(cleanMsg, ": ")

	// Determine log level based on message content
	if strings.Contains(msg, "[WARNING]") || strings.Contains(msg, "[GIN-warning]") || strings.Contains(msg, "WARNING") {
		rcvr.logger.WARN("", mcode, cleanMsg)
	} else if strings.Contains(msg, "[ERROR]") || strings.Contains(msg, "[GIN-error]") || strings.Contains(msg, "ERROR") {
		rcvr.logger.ERROR("", mcode, cleanMsg)
	} else if strings.Contains(msg, "[GIN-debug]") || strings.Contains(msg, "[debug]") {
		rcvr.logger.DEBUG("", mcode, cleanMsg, nil)
	} else {
		rcvr.logger.INFO("", mcode, cleanMsg)
	}

	return len(p), nil
}

// NewGinLoggerWriter creates a new GinLoggerWriter
func NewGinLoggerWriter(logger ServerLoggerInterface) *GinLoggerWriter {
	return &GinLoggerWriter{logger: logger}
}

// LoggerWithConfig returns a Gin middleware for HTTP request logging
func LoggerWithConfig(logger ServerLoggerInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		end := time.Now()
		latency := end.Sub(start)

		if raw != "" {
			path = path + "?" + raw
		}

		requestID := GetRequestID(c)
		fields := map[string]interface{}{
			"request_id": requestID,
			"method":     c.Request.Method,
			"path":       path,
			"client_ip":  c.ClientIP(),
			"status":     c.Writer.Status(),
			"latency_ms": latency.Milliseconds(),
		}

		// Add error if exists
		if len(c.Errors) > 0 {
			fields["error"] = c.Errors.Last().Error()
		}

		// Log based on status code
		status := c.Writer.Status()
		// Format: "METHOD /path STATUS" (e.g., "POST /v1/public/user 200")
		requestInfo := fmt.Sprintf("%s %s %d", c.Request.Method, path, status)

		if status >= 500 {
			logger.ERROR(requestID, global.SMLWC5, requestInfo)
		} else if status >= 400 {
			logger.WARN(requestID, global.SMLWC4, requestInfo)
		} else {
			logger.INFO(requestID, global.SMLWC3, requestInfo)
		}
	}
}
