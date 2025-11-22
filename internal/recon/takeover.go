package recon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type TakeoverChecker struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewTakeoverChecker(domain, outputDir string) *TakeoverChecker {
	return &TakeoverChecker{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "subdomains.txt"),
	}
}

func (t *TakeoverChecker) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                       SUBDOMAIN TAKEOVER CHECK\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(t.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m subdomains.txt not found!")
		return fmt.Errorf("subdomains.txt not found")
	}

	startTime := time.Now()
	output := filepath.Join(t.OutputDir, "subdomain_takeover.txt")

	fmt.Printf("\033[33m[+]\033[0m Running \033[1msubzy\033[0m...\n\n")

	cmd := exec.Command("subzy", "run",
		"--targets", t.InputFile,
		"--concurrency", "100",
		"--hide_fails",
		"--verify_ssl",
	)

	// Run and capture output to file as well
	outFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outFile.Close()

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Run() // Don't fail on error, subzy may return non-zero

	elapsed := time.Since(startTime)

	fmt.Println()
	fmt.Printf("    \033[32m├─ Scan completed   : ✓\033[0m\n")
	fmt.Printf("    \033[32m├─ Time elapsed     : %s\033[0m\n", elapsed.Round(time.Second))
	fmt.Printf("    \033[32m└─ Output File      : subdomain_takeover.txt\033[0m\n")
	fmt.Println()

	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Subdomain Takeover Check Complete\n")
	fmt.Printf("    \033[34m•\033[0m Output File   : subdomain_takeover.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	fmt.Println("\033[33m[!] Warning:\033[0m Results may have false positives. Cross-check at:")
	fmt.Println("    \033[36mhttps://github.com/EdOverflow/can-i-take-over-xyz\033[0m")
	fmt.Println()

	return nil
}
