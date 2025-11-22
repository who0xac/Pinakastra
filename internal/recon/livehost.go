package recon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

type LiveHostProbe struct {
	OutputDir  string
	InputFile  string
	StartTime  time.Time
	EndTime    time.Time
	LiveCount  int
	TotalCount int
}

func NewLiveHostProbe(outputDir string) *LiveHostProbe {
	return &LiveHostProbe{
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "all_subdomains.txt"),
	}
}

func (h *LiveHostProbe) Run() error {
	h.StartTime = time.Now()

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                          LIVE HOST PROBING\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check input file
	if !fileExists(h.InputFile) {
		fmt.Println("\033[31m[✗]\033[0m all_subdomains.txt not found!")
		return fmt.Errorf("input file not found")
	}

	// Count total subdomains
	h.TotalCount = countLines(h.InputFile)

	// Output files
	httpxResults := filepath.Join(h.OutputDir, "httpx_results.txt")
	liveURLs := filepath.Join(h.OutputDir, "live_urls.txt")

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mhttpx\033[0m...\n\n")

	// Run httpx
	// Rate limit: 150 threads, 50 req/s
	cmd := exec.Command("httpx",
		"-l", h.InputFile,
		"-sc",
		"-mc", "200,301,302,403,500",
		"-fr",
		"-td",
		"-location",
		"-o", httpxResults,
		"-threads", "150",
		"-rate-limit", "50",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	h.EndTime = time.Now()
	duration := h.EndTime.Sub(h.StartTime)

	// Extract live URLs (first column)
	h.extractLiveURLs(httpxResults, liveURLs)
	h.LiveCount = countLines(liveURLs)

	fmt.Println()
	if err != nil {
		fmt.Printf("    \033[31m├─ Live hosts found : 0\033[0m\n")
		fmt.Printf("    \033[31m├─ Time elapsed     : %s\033[0m\n", duration.Round(time.Second))
		fmt.Printf("    \033[31m└─ Status           : ✗ Failed\033[0m\n")
		return err
	} else {
		fmt.Printf("    \033[32m├─ Live hosts found : %d\033[0m\n", h.LiveCount)
		fmt.Printf("    \033[32m├─ Time elapsed     : %s\033[0m\n", duration.Round(time.Second))
		fmt.Printf("    \033[32m└─ Status           : ✓ Complete\033[0m\n")
	}

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Live Host Probing Complete\n")
	fmt.Printf("    \033[34m•\033[0m Live Hosts    : %d\n", h.LiveCount)
	fmt.Printf("    \033[34m•\033[0m Output File   : live_urls.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", duration.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (h *LiveHostProbe) extractLiveURLs(input, output string) {
	file, err := os.Open(input)
	if err != nil {
		return
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// First field is the URL
		parts := strings.Fields(line)
		if len(parts) > 0 {
			urls = append(urls, parts[0])
		}
	}

	os.WriteFile(output, []byte(strings.Join(urls, "\n")), 0644)
}
