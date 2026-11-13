package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"net/http"
	"os"
)

func main() {
	var endpoint string
	root := &cobra.Command{Use: "gorape-health", RunE: func(*cobra.Command, []string) error {
		r, e := http.Get(endpoint + "/health")
		if e != nil {
			return e
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("health HTTP %d", r.StatusCode)
		}
		fmt.Println("ok")
		return nil
	}}
	root.Flags().StringVar(&endpoint, "endpoint", "http://localhost:8000", "Gorape endpoint")
	if root.Execute() != nil {
		os.Exit(1)
	}
}
