package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	clientshare "github.com/Gorapeflutter/gorape/pkg/client/share"
)

type APIInterface interface {
	Do(method, path string, body any) (json.RawMessage, error)
}

type API struct {
	base   string
	client *http.Client
}

func NewAPI(m *clientshare.Manager) *API { return &API{base: m.ServerBase(), client: m.HTTPClient()} }

func (rcvr *API) Do(method, path string, body any) (json.RawMessage, error) {
	var r io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		r = bytes.NewReader(b)
	}
	req, e := http.NewRequest(method, rcvr.base+path, r)
	if e != nil {
		return nil, e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := rcvr.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return b, nil
}
