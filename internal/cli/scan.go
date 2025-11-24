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
	log.Info("Step 1/7: Subdomain Enumeration")
	subdomainEnum := recon.NewSubdomainEnum(targetDomain, outDir, cfg)
	subdomainEnum.Run()
	subdomainEnum.MergeAndClean()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 2: Live Host Probing
	log.Info("Step 2/7: Live Host Probing")
	liveHost := recon.NewLiveHostProbe(outDir)
	liveHost.Run()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 3: DNS Resolution
	log.Info("Step 3/7: DNS Resolution")
	resolver := recon.NewIPResolver(outDir)
	resolver.Run()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 4: URL Gathering
	log.Info("Step 4/7: URL Gathering")
	urlGathering := recon.NewURLGathering(targetDomain, outDir)
	urlGathering.Run()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 5: GF Pattern Matching
	log.Info("Step 5/7: GF Pattern Matching")
	gfPatterns := recon.NewGFPatterns(targetDomain, outDir)
	gfPatterns.Run()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 6: API Endpoint Discovery
	log.Info("Step 6/7: API Endpoint Discovery")
	apiEndpoints := recon.NewAPIEndpointFinder(targetDomain, outDir)
	apiEndpoints.Run()
	if ctx.Err() != nil {
		log.Warning("Interrupted - moving to next step")
		ResetInterruptCount()
	}

	// Step 7: Nuclei Vulnerability Scanning
	log.Info("Step 7/7: Nuclei Vulnerability Scanning")
	nuclei := recon.NewNucleiScanner(targetDomain, outDir)
	nuclei.Run()
	if ctx.Err() != nil {
		log.Warning("Scan interrupted")
	}

	duration := time.Since(startTime)

	notify.SendComplete(targetDomain, duration)

	log.Success("Scan completed in %s", duration.Round(time.Second))
}
