package usecase

import (
	"encoding/json"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
)

type Group interface {
	ListGroups(project string) (json.RawMessage, error)
	CreateGroup(project, slug, name string) (json.RawMessage, error)
}

type groupUsecase struct {
	repo repository.APIInterface
}

func NewGroup(repo repository.APIInterface) Group {
	return &groupUsecase{repo: repo}
}

func (rcvr *groupUsecase) ListGroups(project string) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodGet, "/v1/projects/"+project+"/groups", nil)
}

func (rcvr *groupUsecase) CreateGroup(project, slug, name string) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodPost, "/v1/projects/"+project+"/groups", map[string]string{"slug": slug, "name": name})
}
