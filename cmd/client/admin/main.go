package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	clientctrl "github.com/Gorapeflutter/gorape/pkg/client/controller"
	clientrepo "github.com/Gorapeflutter/gorape/pkg/client/repository"
	clientshare "github.com/Gorapeflutter/gorape/pkg/client/share"
	clientuc "github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/Gorapeflutter/gorape/pkg/config"
	"github.com/spf13/cobra"
)

func main() {
	var file string
	root := &cobra.Command{Use: "gorape-admin", Short: "Gorape operations client"}
	root.PersistentFlags().StringVarP(&file, "config", "c", "etc/admin.yaml", "configuration file")
	_ = root.ParseFlags(os.Args[1:])
	_ = os.Setenv("CONFIG_FILE", file)
	conf := config.NewBaseConfig()
	manager := clientshare.NewManager(*conf, strings.TrimSuffix(filepath.Base(file), ".yaml"))
	api := clientuc.NewAPI(clientrepo.NewAPI(manager))
	clientctrl.AddAPICommands(root, manager, api)
	root.AddCommand(bootstrapCommand(api))
	if root.Execute() != nil {
		os.Exit(1)
	}
}

// bootstrapCommand creates a project and its first administrator through the
// Gorape server. The caller must hold a platform administrator token so the
// server, not the CLI, remains the only component that writes PostgreSQL and
// Keycloak.
func bootstrapCommand(api *clientuc.API) *cobra.Command {
	var slug, name, issuer, realm, subject string
	c := &cobra.Command{Use: "bootstrap-project", Short: "create a project and its first admin through the server", RunE: func(*cobra.Command, []string) error {
		b, e := api.BootstrapProject(slug, name, issuer, realm, subject)
		if e != nil {
			return e
		}
		fmt.Println(string(b))
		return nil
	}}
	c.Flags().StringVar(&slug, "slug", "", "project slug")
	c.Flags().StringVar(&name, "name", "", "project name")
	c.Flags().StringVar(&issuer, "issuer", "", "Keycloak realm issuer (HTTPS)")
	c.Flags().StringVar(&realm, "realm", "", "Keycloak realm name")
	c.Flags().StringVar(&subject, "admin-subject", "", "OIDC subject for the initial admin")
	for _, f := range []string{"slug", "name", "issuer", "admin-subject"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}
