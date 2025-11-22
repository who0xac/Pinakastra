package recon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type NucleiScanner struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewNucleiScanner(domain, outputDir string) *NucleiScanner {
	return &NucleiScanner{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "all_discovered_urls.txt"),
	}
}

func (n *NucleiScanner) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                      NUCLEI VULNERABILITY SCAN\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(n.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m all_discovered_urls.txt not found!")
		return fmt.Errorf("all_discovered_urls.txt not found")
	}

	// Create nuclei output directory
	nucleiDir := filepath.Join(n.OutputDir, "nuclei_scans")
	if err := os.MkdirAll(nucleiDir, 0755); err != nil {
		return err
	}

	txtOutput := filepath.Join(nucleiDir, "all_findings.txt")
	jsonOutput := filepath.Join(nucleiDir, "all_findings.json")

	startTime := time.Now()

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mnuclei\033[0m...\n\n")

	// Run nuclei
	cmd := exec.Command("nuclei",
		"-l", n.InputFile,
		"-severity", "critical,high,medium,low,info",
		"-o", txtOutput,
		"-je", jsonOutput,
		"-rate-limit", "250",
		"-c", "150",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	elapsed := time.Since(startTime)

	// Count findings
	critical, high, medium, low, info, total := n.countFindings(txtOutput)

	fmt.Println()
	if err != nil {
		fmt.Printf("    \033[31m├─ Status : ✗ Error\033[0m\n")
	} else {
		fmt.Printf("    \033[32m├─ Vulnerabilities : %d\033[0m\n", total)
		fmt.Printf("    \033[32m├─ Time elapsed    : %s\033[0m\n", elapsed.Round(time.Second))
		fmt.Printf("    \033[32m└─ Status          : ✓ Complete\033[0m\n")
	}

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Nuclei Vulnerability Scan Complete\n")
	fmt.Printf("    \033[34m•\033[0m Findings Summary:\n")
	if critical > 0 {
		fmt.Printf("      \033[31m●\033[0m Critical : %d\n", critical)
	}
	if high > 0 {
		fmt.Printf("      \033[91m●\033[0m High     : %d\n", high)
	}
	if medium > 0 {
		fmt.Printf("      \033[33m●\033[0m Medium   : %d\n", medium)
	}
	if low > 0 {
		fmt.Printf("      \033[32m●\033[0m Low      : %d\n", low)
	}
	if info > 0 {
		fmt.Printf("      \033[36m●\033[0m Info     : %d\n", info)
	}
	fmt.Printf("    \033[34m•\033[0m Total Findings : %d\n", total)
	fmt.Printf("    \033[34m•\033[0m Output Dir     : nuclei_scans/\n")
	fmt.Printf("    \033[34m•\033[0m Duration       : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (n *NucleiScanner) countFindings(txtFile string) (int, int, int, int, int, int) {
	file, err := os.Open(txtFile)
	if err != nil {
		return 0, 0, 0, 0, 0, 0
	}
	defer file.Close()

	critical := 0
	high := 0
	medium := 0
	low := 0
	info := 0
	total := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		total++
		if strings.Contains(line, "[critical]") {
			critical++
		} else if strings.Contains(line, "[high]") {
			high++
		} else if strings.Contains(line, "[medium]") {
			medium++
		} else if strings.Contains(line, "[low]") {
			low++
		} else if strings.Contains(line, "[info]") {
			info++
		}
	}

	return critical, high, medium, low, info, total
}

func (n *NucleiScanner) printFindingsSummary(txtFile string) {
	critical, high, medium, low, info, total := n.countFindings(txtFile)

	fmt.Println()
	fmt.Println("\033[34m[+]\033[0m Findings Summary:")
	if critical > 0 {
		fmt.Printf("    \033[31m●\033[0m Critical: %d\n", critical)
	}
	if high > 0 {
		fmt.Printf("    \033[91m●\033[0m High: %d\n", high)
	}
	if medium > 0 {
		fmt.Printf("    \033[33m●\033[0m Medium: %d\n", medium)
	}
	if low > 0 {
		fmt.Printf("    \033[32m●\033[0m Low: %d\n", low)
	}
	if info > 0 {
		fmt.Printf("    \033[36m●\033[0m Info: %d\n", info)
	}
	fmt.Printf("\n\033[32m[+]\033[0m Total vulnerabilities: \033[1m%d\033[0m\n", total)
}
