package request

// DeviceChallenge はデバイス登録チャレンジリクエスト
type DeviceChallenge struct {
	Platform string `json:"platform" binding:"required"`
}

// RegistrationVerify はデバイス登録検証リクエスト
type RegistrationVerify struct {
	ChallengeID   string         `json:"challenge_id" binding:"required"`
	Platform      string         `json:"platform" binding:"required"`
	DisplayName   string         `json:"display_name" binding:"required"`
	PublicKeyPEM  string         `json:"public_key_pem" binding:"required"`
	KeyIdentifier string         `json:"key_identifier" binding:"required"`
	Algorithm     string         `json:"algorithm" binding:"required"`
	Evidence      map[string]any `json:"evidence" binding:"required"`
}

// ProofVerify はデバイス所有証明検証リクエスト
type ProofVerify struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Signature   string `json:"signature" binding:"required"`
}

// DeviceGroupCreate はデバイスをグループに追加するリクエスト
type DeviceGroupCreate struct {
	DeviceID string `json:"device_id" binding:"required"`
}
