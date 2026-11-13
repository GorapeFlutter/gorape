package share

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDKey = "requestID"

// RequestID middleware generates a unique request ID for each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID already exists in header
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate new UUID
			requestID = uuid.New().String()
		}

		// Store in context
		c.Set(RequestIDKey, requestID)

		// Set response header
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(RequestIDKey); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}
