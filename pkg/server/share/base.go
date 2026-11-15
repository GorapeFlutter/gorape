package share

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/usecase"
	"github.com/gin-gonic/gin"
)

const authContextKey = "gorape_auth"

// GF-10003 — Validates an access token and attaches project auth context.
func Authenticate(s *usecase.Service, byIssuer bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			abortAuth(c, errors.New("bearer token required"))
			return
		}
		var a model.AuthContext
		var e error
		if byIssuer {
			a, e = s.AuthenticateIssuer(c.Request.Context(), strings.TrimSpace(raw))
		} else {
			a, e = s.Authenticate(c.Request.Context(), c.Param("projectId"), strings.TrimSpace(raw))
		}
		if e != nil {
			abortAuth(c, e)
			return
		}
		c.Set(authContextKey, a)
		c.Next()
	}
}

// AuthenticatePlatform validates a platform administrator token. It does not
// require a Gorape project, which is what allows bootstrapping the first
// project through the server.
// GF-10004 — Validates platform-issuer tokens for provisioning routes.
func AuthenticatePlatform(s *usecase.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			abortAuth(c, errors.New("bearer token required"))
			return
		}
		a, e := s.AuthenticatePlatform(c.Request.Context(), strings.TrimSpace(raw))
		if e != nil {
			abortAuth(c, e)
			return
		}
		c.Set(authContextKey, a)
		c.Next()
	}
}
func Auth(c *gin.Context) (model.AuthContext, bool) {
	v, ok := c.Get(authContextKey)
	if !ok {
		return model.AuthContext{}, false
	}
	a, ok := v.(model.AuthContext)
	return a, ok
}
func abortAuth(c *gin.Context, _ error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "authentication_failed", "message": "valid Keycloak access token required"})
}
func ForPublic() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
