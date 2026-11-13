package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/spf13/cobra"
)

type Device interface {
	AddCommands(root *cobra.Command)
}

type deviceController struct {
	api *usecase.API
}

func NewDevice(api *usecase.API) Device {
	return &deviceController{api: api}
}

func (rcvr *deviceController) AddCommands(root *cobra.Command) {
	var rp, rd string
	revoke := &cobra.Command{Use: "revoke-device", RunE: func(*cobra.Command, []string) error { b, e := rcvr.api.RevokeDevice(rp, rd); return printJSON(b, e) }}
	revoke.Flags().StringVar(&rp, "project", "", "project UUID")
	revoke.Flags().StringVar(&rd, "device", "", "device UUID")
	_ = revoke.MarkFlagRequired("project")
	_ = revoke.MarkFlagRequired("device")
	root.AddCommand(revoke)
}
