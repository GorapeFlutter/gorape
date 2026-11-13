package usecase

import (
	"encoding/json"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
)

type Project interface {
	ListProjects() (json.RawMessage, error)
}

type projectUsecase struct {
	repo repository.APIInterface
}

func NewProject(repo repository.APIInterface) Project {
	return &projectUsecase{repo: repo}
}

func (rcvr *projectUsecase) ListProjects() (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodGet, "/v1/projects", nil)
}
