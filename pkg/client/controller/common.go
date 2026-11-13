package controller

import (
	"encoding/json"
	"fmt"

	clientshare "github.com/Gorapeflutter/gorape/pkg/client/share"
	"github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/spf13/cobra"
)

type Controller interface {
	AddAPICommands(root *cobra.Command, m *clientshare.Manager, api *usecase.API)
}

type commonController struct{}

func NewController() Controller {
	return &commonController{}
}

func (rcvr *commonController) AddAPICommands(root *cobra.Command, m *clientshare.Manager, api *usecase.API) {
	AddAPICommands(root, m, api)
}

func AddAPICommands(root *cobra.Command, m *clientshare.Manager, api *usecase.API) {
	root.AddCommand(&cobra.Command{Use: "login", Short: "authenticate with Keycloak using Authorization Code + PKCE", RunE: func(*cobra.Command, []string) error { return m.ForceLogin("keycloak") }})
	root.AddCommand(&cobra.Command{Use: "logout", Run: func(*cobra.Command, []string) { m.ClearTokens() }})

	proj := NewProject(api)
	proj.AddCommands(root)

	grp := NewGroup(api)
	grp.AddCommands(root)

	dev := NewDevice(api)
	dev.AddCommands(root)
}

func printCall(fn func() (json.RawMessage, error)) func(*cobra.Command, []string) error {
	return func(*cobra.Command, []string) error { b, e := fn(); return printJSON(b, e) }
}

func printJSON(b json.RawMessage, e error) error {
	if e != nil {
		return e
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		pretty, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(pretty))
	}
	return nil
}
