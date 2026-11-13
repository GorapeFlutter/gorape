package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/spf13/cobra"
)

type Project interface {
	AddCommands(root *cobra.Command)
}

type projectController struct {
	api *usecase.API
}

func NewProject(api *usecase.API) Project {
	return &projectController{api: api}
}

func (rcvr *projectController) AddCommands(root *cobra.Command) {
	list := &cobra.Command{Use: "list"}
	list.AddCommand(&cobra.Command{Use: "projects", RunE: printCall(rcvr.api.ListProjects)})

	var p string
	g := &cobra.Command{Use: "groups", RunE: func(*cobra.Command, []string) error { b, e := rcvr.api.ListGroups(p); return printJSON(b, e) }}
	g.Flags().StringVar(&p, "project", "", "project UUID")
	_ = g.MarkFlagRequired("project")
	list.AddCommand(g)

	var dp string
	d := &cobra.Command{Use: "devices", RunE: func(*cobra.Command, []string) error { b, e := rcvr.api.ListDevices(dp); return printJSON(b, e) }}
	d.Flags().StringVar(&dp, "project", "", "project UUID")
	_ = d.MarkFlagRequired("project")
	list.AddCommand(d)

	root.AddCommand(list)
}
