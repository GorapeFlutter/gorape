package share

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSAllowsOnlyExactConfiguredOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS([]string{"https://app.example.test"}))
	router.POST("/v1/devices", func(c *gin.Context) { c.Status(http.StatusCreated) })

	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest(http.MethodOptions, "/v1/devices", nil)
	allowedRequest.Header.Set("Origin", "https://app.example.test")
	allowedRequest.Header.Set("Access-Control-Request-Method", "POST")
	router.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusNoContent || allowed.Header().Get("Access-Control-Allow-Origin") != "https://app.example.test" {
		t.Fatalf("allowed preflight = %d, ACAO=%q", allowed.Code, allowed.Header().Get("Access-Control-Allow-Origin"))
	}
	if got := allowed.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("allowed headers = %q, want Authorization", got)
	}

	denied := httptest.NewRecorder()
	deniedRequest := httptest.NewRequest(http.MethodOptions, "/v1/devices", nil)
	deniedRequest.Header.Set("Origin", "https://attacker.example.test")
	router.ServeHTTP(denied, deniedRequest)
	if denied.Code != http.StatusForbidden || denied.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unconfigured origin was not denied: %d, ACAO=%q", denied.Code, denied.Header().Get("Access-Control-Allow-Origin"))
	}
}
