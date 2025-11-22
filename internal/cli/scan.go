package cli

import (
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

	scanDomain(domain, cfg, notify, log)
}

func scanDomain(targetDomain string, cfg *config.Config, notify *notifier.Notifier, log *logger.Logger) {
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
	subdomainEnum := recon.NewSubdomainEnum(targetDomain, outDir, cfg)
	subdomainEnum.Run()
	subdomainEnum.MergeAndClean()

	// Step 2: Live Host Probing
	liveHost := recon.NewLiveHostProbe(outDir)
	liveHost.Run()

	// Step 3: DNS Resolution
	resolver := recon.NewIPResolver(outDir)
	resolver.Run()

	// Step 4: URL Gathering
	urlGathering := recon.NewURLGathering(targetDomain, outDir)
	urlGathering.Run()

	// Step 5: GF Pattern Matching
	gfPatterns := recon.NewGFPatterns(targetDomain, outDir)
	gfPatterns.Run()

	// Step 6: API Endpoint Discovery
	apiEndpoints := recon.NewAPIEndpointFinder(targetDomain, outDir)
	apiEndpoints.Run()

	// Step 7: Nuclei Vulnerability Scanning
	nuclei := recon.NewNucleiScanner(targetDomain, outDir)
	nuclei.Run()

	duration := time.Since(startTime)

	notify.SendComplete(targetDomain, duration)

	log.Success("Scan completed in %s", duration.Round(time.Second))
}
