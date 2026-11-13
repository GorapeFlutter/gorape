//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHealth(t *testing.T) {
	endpoint := os.Getenv("GORAPE_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("GORAPE_E2E_ENDPOINT is not set")
	}
	r, err := http.Get(endpoint + "/health")
	require.NoError(t, err)
	defer r.Body.Close()
	require.Equal(t, http.StatusOK, r.StatusCode)
}
