package request

import "github.com/Gorapeflutter/gorape/pkg/entity/model"

// RoleCreate はロール付与リクエスト
type RoleCreate struct {
	OIDCSubject string     `json:"oidc_subject" binding:"required"`
	Role        model.Role `json:"role" binding:"required"`
}
