package response

// Challenge はデバイスチャレンジのレスポンス
type Challenge struct {
	ID        string `json:"challenge_id"`
	Value     string `json:"challenge"`
	ExpiresIn int64  `json:"expires_in"`
}
