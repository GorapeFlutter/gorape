package usecase

import (
	"encoding/json"
	"net/http"

	"github.com/Gorapeflutter/gorape/pkg/client/repository"
)

type Device interface {
	ListDevices(project string) (json.RawMessage, error)
	RevokeDevice(project, device string) (json.RawMessage, error)
}

type deviceUsecase struct {
	repo repository.APIInterface
}

func NewDevice(repo repository.APIInterface) Device {
	return &deviceUsecase{repo: repo}
}

func (rcvr *deviceUsecase) ListDevices(project string) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodGet, "/v1/projects/"+project+"/devices", nil)
}

func (rcvr *deviceUsecase) RevokeDevice(project, device string) (json.RawMessage, error) {
	return rcvr.repo.Do(http.MethodDelete, "/v1/projects/"+project+"/devices/"+device, nil)
}
