package response

// Capabilities はattestation検証機能のレスポンス
type Capabilities struct {
	Verifiers map[string]string `json:"verifiers"`
}
