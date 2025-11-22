package recon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type APIEndpointFinder struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewAPIEndpointFinder(domain, outputDir string) *APIEndpointFinder {
	return &APIEndpointFinder{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "live_hosts.txt"),
	}
}

func (a *APIEndpointFinder) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                        API ENDPOINT FINDER\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(a.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m live_hosts.txt not found!")
		return fmt.Errorf("live_hosts.txt not found")
	}

	startTime := time.Now()

	// Create API directory
	apiDir := filepath.Join(a.OutputDir, "api")
	if err := os.MkdirAll(apiDir, 0755); err != nil {
		return err
	}

	fmt.Printf("\033[33m[+]\033[0m Searching for API endpoints...\n\n")

	// API pattern regex
	apiPattern := regexp.MustCompile(`(?i)(api|v[0-9]+|graphql|rest|swagger|openapi)`)

	// Read input file and find API endpoints
	inFile, err := os.Open(a.InputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outputFile := filepath.Join(apiDir, "api_urls.txt")
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	apiCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if apiPattern.MatchString(line) {
			fmt.Printf("  \033[32m→\033[0m %s\n", line)
			outFile.WriteString(line + "\n")
			apiCount++
		}
	}

	elapsed := time.Since(startTime)

	fmt.Println()
	fmt.Printf("    \033[32m├─ API endpoints found : %d\033[0m\n", apiCount)
	fmt.Printf("    \033[32m├─ Time elapsed        : %s\033[0m\n", elapsed.Round(time.Second))
	fmt.Printf("    \033[32m└─ Status              : ✓ Complete\033[0m\n")

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m API Endpoint Search Complete\n")
	fmt.Printf("    \033[34m•\033[0m API Endpoints : %d\n", apiCount)
	fmt.Printf("    \033[34m•\033[0m Output File   : api/api_urls.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}
