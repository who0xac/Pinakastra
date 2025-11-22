package recon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type IPResolver struct {
	OutputDir     string
	InputFile     string
	StartTime     time.Time
	EndTime       time.Time
	ResolvedCount int
}

func NewIPResolver(outputDir string) *IPResolver {
	return &IPResolver{
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "live_urls.txt"),
	}
}

func (r *IPResolver) Run() error {
	r.StartTime = time.Now()

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                            DNS RESOLUTION\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check input file
	if !fileExists(r.InputFile) {
		fmt.Println("\033[31m[✗]\033[0m live_urls.txt not found!")
		return fmt.Errorf("input file not found")
	}

	// Extract hostnames from URLs
	hostnamesFile := filepath.Join(r.OutputDir, "live_hostnames.txt")
	r.extractHostnames(r.InputFile, hostnamesFile)

	// Output file
	resolvedFile := filepath.Join(r.OutputDir, "resolved_ips.txt")
	dnsxOutput := filepath.Join(r.OutputDir, "dnsx_output.txt")

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mdnsx\033[0m...\n\n")

	// Run dnsx with live output
	cmd := exec.Command("dnsx",
		"-l", hostnamesFile,
		"-a",
		"-resp",
		"-o", dnsxOutput,
		"-t", "100",
	)

	// Show output in terminal
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	r.EndTime = time.Now()
	duration := r.EndTime.Sub(r.StartTime)

	// Extract only IPs from dnsx output for file
	r.extractIPs(dnsxOutput, resolvedFile)
	r.ResolvedCount = countLines(resolvedFile)

	fmt.Println()
	if err != nil {
		fmt.Printf("    \033[31m├─ Resolved IPs   : 0\033[0m\n")
		fmt.Printf("    \033[31m├─ Time elapsed   : %s\033[0m\n", duration.Round(time.Second))
		fmt.Printf("    \033[31m└─ Status         : ✗ Failed\033[0m\n")
		return err
	} else {
		fmt.Printf("    \033[32m├─ Resolved IPs   : %d\033[0m\n", r.ResolvedCount)
		fmt.Printf("    \033[32m├─ Time elapsed   : %s\033[0m\n", duration.Round(time.Second))
		fmt.Printf("    \033[32m└─ Status         : ✓ Complete\033[0m\n")
	}

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m DNS Resolution Complete\n")
	fmt.Printf("    \033[34m•\033[0m Resolved IPs  : %d\n", r.ResolvedCount)
	fmt.Printf("    \033[34m•\033[0m Output File   : resolved_ips.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", duration.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (r *IPResolver) extractHostnames(input, output string) {
	file, err := os.Open(input)
	if err != nil {
		return
	}
	defer file.Close()

	unique := make(map[string]bool)
	// Regex to extract hostname from URL
	urlRegex := regexp.MustCompile(`^https?://([^/]+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := urlRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			hostname := matches[1]
			// Remove port if present
			if idx := strings.Index(hostname, ":"); idx != -1 {
				hostname = hostname[:idx]
			}
			unique[hostname] = true
		}
	}

	var hostnames []string
	for h := range unique {
		hostnames = append(hostnames, h)
	}

	os.WriteFile(output, []byte(strings.Join(hostnames, "\n")), 0644)
}

func (r *IPResolver) extractIPs(input, output string) {
	file, err := os.Open(input)
	if err != nil {
		return
	}
	defer file.Close()

	unique := make(map[string]bool)
	// Regex to extract IP addresses
	ipRegex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := ipRegex.FindAllString(line, -1)
		for _, ip := range matches {
			unique[ip] = true
		}
	}

	var ips []string
	for ip := range unique {
		ips = append(ips, ip)
	}

	os.WriteFile(output, []byte(strings.Join(ips, "\n")), 0644)
}
