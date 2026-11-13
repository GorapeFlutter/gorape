package main

import (
	clientctrl "github.com/Gorapeflutter/gorape/pkg/client/controller"
	clientrepo "github.com/Gorapeflutter/gorape/pkg/client/repository"
	clientshare "github.com/Gorapeflutter/gorape/pkg/client/share"
	clientuc "github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/Gorapeflutter/gorape/pkg/config"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var file string
	root := &cobra.Command{Use: "gorape-client", Short: "Gorape API client"}
	root.PersistentFlags().StringVarP(&file, "config", "c", "etc/app.yaml", "configuration file")
	root.PersistentPreRun = func(*cobra.Command, []string) { _ = os.Setenv("CONFIG_FILE", file) }
	_ = root.ParseFlags(os.Args[1:])
	_ = os.Setenv("CONFIG_FILE", file)
	conf := config.NewClientConfig()
	manager := clientshare.NewManager(*conf, strings.TrimSuffix(filepath.Base(file), ".yaml"))
	clientctrl.AddAPICommands(root, manager, clientuc.NewAPI(clientrepo.NewAPI(manager)))
	if root.Execute() != nil {
		os.Exit(1)
	}
}
