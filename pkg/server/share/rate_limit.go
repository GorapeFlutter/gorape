package share

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateEntry struct {
	start time.Time
	count int
}

func RateLimit(perMinute int) gin.HandlerFunc {
	var mu sync.Mutex
	items := map[string]rateEntry{}
	return func(c *gin.Context) {
		now := time.Now()
		key := c.ClientIP()
		mu.Lock()
		v := items[key]
		if v.start.IsZero() || now.Sub(v.start) >= time.Minute {
			v = rateEntry{start: now}
		}
		v.count++
		items[key] = v
		allowed := v.count <= perMinute
		mu.Unlock()
		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"code": "rate_limited", "message": "too many requests"})
			return
		}
		c.Next()
	}
}
