package cli

import (
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/executor"
	"github.com/who0xac/pinakastra/internal/logger"
	"github.com/who0xac/pinakastra/internal/notifier"
	"github.com/who0xac/pinakastra/internal/tools"
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

	notify := notifier.New(cfg)
	registry := tools.NewRegistry(cfg)
	exec := executor.New(notify, log)

	scanDomain(domain, cfg, exec, registry, notify, log)
}

func scanDomain(targetDomain string, cfg *config.Config, exec *executor.Executor, registry *tools.Registry, notify *notifier.Notifier, log *logger.Logger) {
	startTime := time.Now()

	outDir := outputDir
	if outDir == "" {
		outDir = filepath.Join(cfg.Storage.BasePath, targetDomain)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Error("Failed to create output directory: %v", err)
		return
	}

	notify.SendStart(targetDomain)

	log.Info("Starting scan for: %s", color.CyanString(targetDomain))
	log.Info("Output directory: %s", color.YellowString(outDir))

	toolsToRun := registry.GetEnabledTools()

	ctx := &executor.ScanContext{
		Domain:    targetDomain,
		OutputDir: outDir,
		Config:    cfg,
		StartTime: startTime,
	}

	exec.RunTools(ctx, toolsToRun)

	duration := time.Since(startTime)

	notify.SendComplete(targetDomain, duration)

	log.Success("Scan completed in %s", duration.Round(time.Second))
}
