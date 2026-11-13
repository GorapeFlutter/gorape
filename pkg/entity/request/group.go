package request

// GroupCreate はグループ作成リクエスト
type GroupCreate struct {
	Slug string `json:"slug" binding:"required"`
	Name string `json:"name" binding:"required"`
}

// GroupUpdate はグループ更新リクエスト
type GroupUpdate struct {
	Name   string `json:"name" binding:"required"`
	Status string `json:"status"`
}
