package controller

import (
	"os"

	"github.com/Gorapeflutter/gorape/pkg/client/usecase"
	"github.com/Gorapeflutter/gorape/pkg/entity/provisioning"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Provisioning interface {
	AddCommands(root *cobra.Command)
}

type provisioningController struct {
	api *usecase.API
}

func NewProvisioning(api *usecase.API) Provisioning {
	return &provisioningController{api: api}
}

func (rcvr *provisioningController) AddCommands(root *cobra.Command) {
	cmd := &cobra.Command{Use: "provision", Short: "plan and apply declarative Keycloak + Gorape manifests"}

	var planFile string
	plan := &cobra.Command{Use: "plan", Short: "show the changes a manifest would make", RunE: func(*cobra.Command, []string) error {
		m, e := loadManifest(planFile)
		if e != nil {
			return e
		}
		b, e := rcvr.api.PlanProvisioning(m)
		return printJSON(b, e)
	}}
	plan.Flags().StringVarP(&planFile, "file", "f", "", "manifest file (YAML or JSON)")
	_ = plan.MarkFlagRequired("file")

	var applyFile string
	apply := &cobra.Command{Use: "apply", Short: "apply a manifest through the Gorape server", RunE: func(*cobra.Command, []string) error {
		m, e := loadManifest(applyFile)
		if e != nil {
			return e
		}
		b, e := rcvr.api.ApplyProvisioning(m)
		return printJSON(b, e)
	}}
	apply.Flags().StringVarP(&applyFile, "file", "f", "", "manifest file (YAML or JSON)")
	_ = apply.MarkFlagRequired("file")

	cmd.AddCommand(plan, apply)
	root.AddCommand(cmd)
}

func loadManifest(path string) (provisioning.Manifest, error) {
	var m provisioning.Manifest
	raw, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	if e = yaml.Unmarshal(raw, &m); e != nil {
		return m, e
	}
	if e = m.Validate(); e != nil {
		return m, e
	}
	return m, nil
}
