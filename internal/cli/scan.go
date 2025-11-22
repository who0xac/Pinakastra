package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/executor"
	"github.com/who0xac/pinakastra/internal/logger"
	"github.com/who0xac/pinakastra/internal/notifier"
	"github.com/who0xac/pinakastra/internal/storage"
	"github.com/who0xac/pinakastra/internal/tools"
	"github.com/who0xac/pinakastra/internal/websocket"
)

func runScan(cmd *cobra.Command, args []string) {
	log := logger.New()
	cfg := config.Load()

	if enableNotify {
		cfg.Notifications.Telegram = true
		cfg.Notifications.Desktop = true
	} else {
		cfg.Notifications.Telegram = false
		cfg.Notifications.Desktop = false
	}

	hub := websocket.NewHub()
	go hub.Run()

	notify := notifier.New(cfg, hub)
	store := storage.New(cfg.Storage.BasePath)
	registry := tools.NewRegistry(cfg)
	exec := executor.New(hub, notify, log)

	scanDomain(domain, cfg, exec, registry, store, notify, hub, log)
}

func scanDomain(targetDomain string, cfg *config.Config, exec *executor.Executor, registry *tools.Registry, store *storage.Storage, notify *notifier.Notifier, hub *websocket.Hub, log *logger.Logger) {
	startTime := time.Now()

	outDir := outputDir
	if outDir == "" {
		outDir = filepath.Join(cfg.Storage.BasePath, targetDomain)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Error("Failed to create output directory: %v", err)
		return
	}

	notify.Send(notifier.Event{
		Type:    notifier.ScanStart,
		Domain:  targetDomain,
		Message: fmt.Sprintf("Starting reconnaissance on %s", targetDomain),
	})

	log.Info("Starting scan for: %s", color.CyanString(targetDomain))
	log.Info("Output directory: %s", color.YellowString(outDir))

	toolsToRun := registry.GetEnabledTools()

	ctx := &executor.ScanContext{
		Domain:    targetDomain,
		OutputDir: outDir,
		Config:    cfg,
		Hub:       hub,
		StartTime: startTime,
	}

	results := exec.RunTools(ctx, toolsToRun)

	if err := store.SaveResults(targetDomain, results); err != nil {
		log.Error("Failed to save results: %v", err)
	}

	duration := time.Since(startTime)

	notify.Send(notifier.Event{
		Type:    notifier.ScanComplete,
		Domain:  targetDomain,
		Message: fmt.Sprintf("Scan completed for %s in %s", targetDomain, duration.Round(time.Second)),
		Data:    results,
	})

	log.Success("Scan completed in %s", duration.Round(time.Second))
}
