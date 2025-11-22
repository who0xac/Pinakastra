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

type PortScanner struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewPortScanner(domain, outputDir string) *PortScanner {
	return &PortScanner{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "resolved_ips.txt"),
	}
}

func (p *PortScanner) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                       NMAP PORT & VULN SCAN\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(p.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m resolved_ips.txt not found!")
		return fmt.Errorf("resolved_ips.txt not found")
	}

	// Create nmap output directory
	nmapDir := filepath.Join(p.OutputDir, "nmap_scans")
	if err := os.MkdirAll(nmapDir, 0755); err != nil {
		return err
	}

	// Read all IPs
	ips, err := p.readIPs()
	if err != nil {
		return err
	}

	totalIPs := len(ips)
	fmt.Println("\033[33m[!] Warning:\033[0m Full port scan with vuln scripts may take long time per IP")
	fmt.Println()

	startTime := time.Now()

	for i, ip := range ips {
		fmt.Printf("\033[33m[+]\033[0m [\033[1m%d/%d\033[0m] Running \033[1mnmap\033[0m on: \033[33m%s\033[0m\n\n", i+1, totalIPs, ip)

		// Create output filename from IP
		outputFile := filepath.Join(nmapDir, strings.ReplaceAll(ip, ".", "_"))

		// Run nmap with full options
		cmd := exec.Command("nmap",
			"-p-",
			"-sC",
			"-sV",
			"-T4",
			"-A",
			"--script=vuln",
			"-oA", outputFile,
			ip,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()

		fmt.Println()
		if err != nil {
			fmt.Printf("    \033[31m└─ Status : ✗ Error\033[0m\n")
		} else {
			fmt.Printf("    \033[32m└─ Status : ✓ Complete\033[0m\n")
		}
		fmt.Println()
	}

	elapsed := time.Since(startTime)
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Nmap Port & Vuln Scan Complete\n")
	fmt.Printf("    \033[34m•\033[0m IPs Scanned   : %d\n", totalIPs)
	fmt.Printf("    \033[34m•\033[0m Output Dir    : nmap_scans/\n")
	fmt.Printf("    \033[34m•\033[0m Output Formats: .nmap, .xml, .gnmap\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (p *PortScanner) readIPs() ([]string, error) {
	file, err := os.Open(p.InputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, scanner.Err()
}
