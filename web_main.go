//go:build web

package main

import (
	"context"
	"embed"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"cpa-control-center/internal/backend"
	"cpa-control-center/internal/web"
)

//go:embed all:frontend/dist
var webAssets embed.FS

func main() {
	dataDir, err := resolveWebDataDir()
	if err != nil {
		log.Fatalf("resolve data dir: %v", err)
	}

	listenAddr := strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_LISTEN"))
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	username := strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_WEB_USERNAME"))
	password := strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_WEB_PASSWORD"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("cpa-control-center web listening on %s", listenAddr)
	if password != "" {
		if username == "" {
			username = "admin"
		}
		log.Printf("basic auth enabled for user %s", username)
	}

	err = web.Run(
		ctx,
		dataDir,
		webAssets,
		listenAddr,
		web.Options{
			AuthUsername: username,
			AuthPassword: password,
		},
	)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func resolveWebDataDir() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_DATA_DIR")); configured != "" {
		return configured, nil
	}
	return backend.DefaultDataDir()
}
