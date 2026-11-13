package controller

import (
	"github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/spf13/cobra"
)

type Group interface {
	AddCommands(root *cobra.Command)
}

type groupController struct {
	api *usecase.API
}

func NewGroup(api *usecase.API) Group {
	return &groupController{api: api}
}

func (rcvr *groupController) AddCommands(root *cobra.Command) {
	var cp, slug, name string
	create := &cobra.Command{Use: "create-group", RunE: func(*cobra.Command, []string) error {
		b, e := rcvr.api.CreateGroup(cp, slug, name)
		return printJSON(b, e)
	}}
	create.Flags().StringVar(&cp, "project", "", "project UUID")
	create.Flags().StringVar(&slug, "slug", "", "group slug")
	create.Flags().StringVar(&name, "name", "", "group name")
	for _, f := range []string{"project", "slug", "name"} {
		_ = create.MarkFlagRequired(f)
	}
	root.AddCommand(create)
}
