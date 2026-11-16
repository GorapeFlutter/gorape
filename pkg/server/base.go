package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Gorapeflutter/gorape/pkg/config"
)

// GF-10001 — Starts the API's HTTP and optional TLS listeners.
func Main(conf config.BaseConfig) {
	serverConfig := conf.YamlConfig.Application.Server
	if (serverConfig.TLSCertFile == "") != (serverConfig.TLSKeyFile == "") {
		log.Fatal("TLS requires both tls_cert_file and tls_key_file (or both GORAPE_TLS_CERT_FILE and GORAPE_TLS_KEY_FILE)")
	}
	if serverConfig.TLSCertFile != "" && serverConfig.TLSPort == serverConfig.Port {
		log.Fatal("tls_port must differ from port")
	}

	handler := InitRouter(conf)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if serverConfig.TLSCertFile == "" {
		log.Printf("gorape listening on http://%s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
		return
	}

	tlsServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.TLSPort),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Printf("gorape listening on http://%s and https://%s", httpServer.Addr, tlsServer.Addr)
	errors := make(chan error, 2)
	go func() { errors <- httpServer.ListenAndServe() }()
	go func() { errors <- tlsServer.ListenAndServeTLS(serverConfig.TLSCertFile, serverConfig.TLSKeyFile) }()
	if err := <-errors; err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
