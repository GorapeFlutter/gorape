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
)

// ClientLoggerConfig represents client logger configuration
type ClientLoggerConfig struct {
	Component    string `json:"component" yaml:"component"`
	Service      string `json:"service" yaml:"service"`
	Level        string `json:"level" yaml:"level"`
	Structured   bool   `json:"structured" yaml:"structured"`
	EnableCaller bool   `json:"enable_caller" yaml:"enable_caller"`
	Output       string `json:"output" yaml:"output"`
}

// ClientLoggerInterface defines the client logging interface
type ClientLoggerInterface interface {
	DEBUG(mcode global.MCode, optionalMessage string, fields ...map[string]interface{})
	INFO(mcode global.MCode, optionalMessage string)
	WARN(mcode global.MCode, optionalMessage string)
	ERROR(mcode global.MCode, optionalMessage string)
	FATAL(mcode global.MCode, optionalMessage string)
}

// ClientLogLevel represents the log level
type ClientLogLevel int

const (
	CLIENT_DEBUG ClientLogLevel = iota
	CLIENT_INFO
	CLIENT_WARN
	CLIENT_ERROR
	CLIENT_FATAL
)

// String returns string representation of log level
func (rcvr ClientLogLevel) String() string {
	switch rcvr {
	case CLIENT_DEBUG:
		return "DEBUG  "
	case CLIENT_INFO:
		return "INFO   "
	case CLIENT_WARN:
		return "WARN   "
	case CLIENT_ERROR:
		return "ERROR  "
	case CLIENT_FATAL:
		return "FATAL  "
	default:
		return "UNKNOWN"
	}
}

// ClientLogEntry represents a structured log entry
type ClientLogEntry struct {
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
	Error     string                 `json:"error,omitempty"`
}

// ClientLogger represents the client application logger
type ClientLogger struct {
	config *ClientLoggerConfig
	level  ClientLogLevel
	output io.Writer
}

// NewClientLogger creates a new client logger instance
func NewClientLogger(config ClientLoggerConfig) ClientLoggerInterface {
	logger := &ClientLogger{
		config: &config,
		output: os.Stdout,
	}

	// Set log level
	switch strings.ToUpper(config.Level) {
	case "DEBUG":
		logger.level = CLIENT_DEBUG
	case "INFO":
		logger.level = CLIENT_INFO
	case "WARN":
		logger.level = CLIENT_WARN
	case "ERROR":
		logger.level = CLIENT_ERROR
	case "FATAL":
		logger.level = CLIENT_FATAL
	default:
		logger.level = CLIENT_INFO
	}

	// Set output
	switch config.Output {
	case "stderr":
		logger.output = os.Stderr
	case "stdout", "":
		logger.output = os.Stdout
	default:
		// File output
		if file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666); err == nil {
			logger.output = file
		} else {
			logger.output = os.Stdout
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", config.Output, err)
		}
	}

	return logger
}

// formatClientWithOptional formats the message with optional additional message
func formatClientWithOptional(mcode global.MCode, optionalMessage string) string {
	if optionalMessage == "" {
		return mcode.Message
	}
	return fmt.Sprintf("%s: %s", mcode.Message, optionalMessage)
}

// log writes a log entry
func (rcvr *ClientLogger) log(level ClientLogLevel, mcode global.MCode, optionalMessage string, fields map[string]interface{}) {
	if level < rcvr.level {
		return
	}

	finalMessage := formatClientWithOptional(mcode, optionalMessage)

	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02T15:04:05.000000000") + " UTC"

	entry := ClientLogEntry{
		Timestamp: timestamp,
		Level:     level.String(),
		Code:      mcode.Code,
		Component: rcvr.config.Component,
		Service:   rcvr.config.Service,
		Message:   finalMessage,
		Fields:    fields,
	}

	rcvr.writeLogEntry(entry)
}

// writeLogEntry writes the actual log entry to output
func (rcvr *ClientLogger) writeLogEntry(entry ClientLogEntry) {
	// Add caller information if enabled or DEBUG level
	if rcvr.config.EnableCaller || rcvr.level == CLIENT_DEBUG {
		if pc, file, line, ok := runtime.Caller(4); ok {
			entry.File = file
			entry.Line = line
			if fn := runtime.FuncForPC(pc); fn != nil {
				entry.Function = fn.Name()
			}
		}
	}

	// Extract error field
	if entry.Fields != nil {
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
			// Fallback
			fmt.Fprintf(rcvr.output, "[%s] [%s] [%s] %s\n",
				entry.Timestamp, entry.Level, entry.Code, entry.Message)
		}
	} else {
		// Human-readable format for CLI
		fmt.Fprintf(rcvr.output, "[%s] [%s] [%s] %s",
			entry.Timestamp, entry.Level, entry.Code, entry.Message)
		if len(entry.Fields) > 0 && entry.Level == "DEBUG  " {
			if fieldsJSON, err := json.Marshal(entry.Fields); err == nil {
				fmt.Fprintf(rcvr.output, " %s", string(fieldsJSON))
			}
		}
		fmt.Fprintln(rcvr.output)
	}
}

// DEBUG logs a debug message
func (rcvr *ClientLogger) DEBUG(mcode global.MCode, optionalMessage string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	rcvr.log(CLIENT_DEBUG, mcode, optionalMessage, f)
}

// INFO logs an info message
func (rcvr *ClientLogger) INFO(mcode global.MCode, optionalMessage string) {
	rcvr.log(CLIENT_INFO, mcode, optionalMessage, nil)
}

// WARN logs a warning message
func (rcvr *ClientLogger) WARN(mcode global.MCode, optionalMessage string) {
	rcvr.log(CLIENT_WARN, mcode, optionalMessage, nil)
}

// ERROR logs an error message
func (rcvr *ClientLogger) ERROR(mcode global.MCode, optionalMessage string) {
	rcvr.log(CLIENT_ERROR, mcode, optionalMessage, nil)
}

// FATAL logs a fatal message and exits
func (rcvr *ClientLogger) FATAL(mcode global.MCode, optionalMessage string) {
	rcvr.log(CLIENT_FATAL, mcode, optionalMessage, nil)
	os.Exit(1)
}
