package server

import (
	"fmt"
	"log"

	"github.com/Gorapeflutter/gorape/pkg/config"
)

func Main(conf config.BaseConfig) {
	address := fmt.Sprintf(":%d", conf.YamlConfig.Application.Server.Port)
	log.Printf("gorape listening on %s", address)
	if err := InitRouter(conf).Run(address); err != nil {
		log.Fatal(err)
	}
}
