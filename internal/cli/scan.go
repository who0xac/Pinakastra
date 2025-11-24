package cli

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/logger"
	"github.com/who0xac/pinakastra/internal/notifier"
	"github.com/who0xac/pinakastra/internal/recon"
)

func runScan(cmd *cobra.Command, args []string) {
	// Setup signal handler for graceful cancellation
	ctx := SetupSignalHandler()

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

	scanDomain(ctx, domain, cfg, notify, log)
}

func scanDomain(ctx context.Context, targetDomain string, cfg *config.Config, notify *notifier.Notifier, log *logger.Logger) {
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

	// Step 1: Subdomain Enumeration
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	subdomainEnum := recon.NewSubdomainEnum(targetDomain, outDir, cfg)
	subdomainEnum.Run()
	subdomainEnum.MergeAndClean()
	ResetInterruptCount()

	// Step 2: Live Host Probing
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	liveHost := recon.NewLiveHostProbe(outDir)
	liveHost.Run()
	ResetInterruptCount()

	// Step 3: DNS Resolution
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	resolver := recon.NewIPResolver(outDir)
	resolver.Run()
	ResetInterruptCount()

	// Step 4: URL Gathering
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	urlGathering := recon.NewURLGathering(targetDomain, outDir)
	urlGathering.Run()
	ResetInterruptCount()

	// Step 5: GF Pattern Matching
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	gfPatterns := recon.NewGFPatterns(targetDomain, outDir)
	gfPatterns.Run()
	ResetInterruptCount()

	// Step 6: API Endpoint Discovery
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	apiEndpoints := recon.NewAPIEndpointFinder(targetDomain, outDir)
	apiEndpoints.Run()
	ResetInterruptCount()

	// Step 7: Nuclei Vulnerability Scanning
	if ctx.Err() != nil {
		log.Warning("Scan cancelled")
		return
	}
	nuclei := recon.NewNucleiScanner(targetDomain, outDir)
	nuclei.Run()
	ResetInterruptCount()

	duration := time.Since(startTime)

	notify.SendComplete(targetDomain, duration)

	log.Success("Scan completed in %s", duration.Round(time.Second))
}
