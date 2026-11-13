package response

import "time"

// Challenge はデバイスチャレンジのレスポンス
type Challenge struct {
	ID        string    `json:"challenge_id"`
	Value     string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}
