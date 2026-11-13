package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientctrl "github.com/Gorapeflutter/gorape/pkg/client/controller"
	clientrepo "github.com/Gorapeflutter/gorape/pkg/client/repository"
	clientshare "github.com/Gorapeflutter/gorape/pkg/client/share"
	clientuc "github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/Gorapeflutter/gorape/pkg/config"
	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func main() {
	var file string
	root := &cobra.Command{Use: "gorape-admin", Short: "Gorape operations client"}
	root.PersistentFlags().StringVarP(&file, "config", "c", "etc/admin.yaml", "configuration file")
	_ = root.ParseFlags(os.Args[1:])
	_ = os.Setenv("CONFIG_FILE", file)
	conf := config.NewBaseConfig()
	manager := clientshare.NewManager(*conf, strings.TrimSuffix(filepath.Base(file), ".yaml"))
	clientctrl.AddAPICommands(root, manager, clientuc.NewAPI(clientrepo.NewAPI(manager)))
	root.AddCommand(bootstrapCommand(conf))
	if root.Execute() != nil {
		os.Exit(1)
	}
}
func bootstrapCommand(conf *config.BaseConfig) *cobra.Command {
	var slug, name, issuer, realm, subject string
	c := &cobra.Command{Use: "bootstrap-project", Short: "create a project and its first admin directly in PostgreSQL", RunE: func(*cobra.Command, []string) error {
		if e := conf.ConnectDB(); e != nil {
			return e
		}
		now := time.Now().UTC()
		p := model.ProjectDomain{ID: uuid.New(), Slug: slug, Name: name, OIDCIssuer: strings.TrimRight(issuer, "/"), KeycloakRealm: realm, Status: "active", CreatedAt: now, UpdatedAt: now}
		principal := model.IdentityPrincipal{ID: uuid.New(), ProjectID: p.ID, OIDCIssuer: p.OIDCIssuer, OIDCSubject: subject, CreatedAt: now}
		role := model.ProjectRoleBinding{ID: uuid.New(), ProjectID: p.ID, PrincipalID: principal.ID, Role: model.RoleAdmin, CreatedAt: now}
		if e := conf.DBConnection.Transaction(func(tx *gorm.DB) error {
			if e := tx.Create(&p).Error; e != nil {
				return e
			}
			if e := tx.Create(&principal).Error; e != nil {
				return e
			}
			return tx.Create(&role).Error
		}); e != nil {
			return e
		}
		fmt.Println(p.ID)
		return nil
	}}
	c.Flags().StringVar(&slug, "slug", "", "project slug")
	c.Flags().StringVar(&name, "name", "", "project name")
	c.Flags().StringVar(&issuer, "issuer", "", "Keycloak realm issuer (HTTPS)")
	c.Flags().StringVar(&realm, "realm", "", "Keycloak realm name")
	c.Flags().StringVar(&subject, "admin-subject", "", "OIDC subject for the initial admin")
	for _, f := range []string{"slug", "name", "issuer", "realm", "admin-subject"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}
