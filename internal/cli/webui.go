package cli

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/logger"
	"github.com/who0xac/pinakastra/internal/webui"
	"github.com/who0xac/pinakastra/internal/websocket"
)

var (
	port     int
	autoOpen bool
)

var webuiCmd = &cobra.Command{
	Use:   "webui",
	Short: "Start web UI",
	Run:   runWebUI,
}

func init() {
	webuiCmd.Flags().IntVarP(&port, "port", "p", 9000, "Port")
	webuiCmd.Flags().BoolVar(&autoOpen, "open", true, "Auto open browser")
}

func runWebUI(cmd *cobra.Command, args []string) {
	log := logger.New()
	cfg := config.Load()

	if port == 9000 && cfg.WebUI.Port != 0 {
		port = cfg.WebUI.Port
	}

	hub := websocket.NewHub()
	go hub.Run()

	server := webui.NewServer(port, hub, cfg)

	url := fmt.Sprintf("http://localhost:%d", port)
	log.Info("Starting web interface at %s", color.CyanString(url))

	if autoOpen || cfg.WebUI.AutoOpen {
		go openBrowser(url)
	}

	log.Info("Press Ctrl+C to stop the server")

	if err := server.Start(); err != nil {
		log.Error("Server error: %v", err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	_ = cmd.Start()
}
