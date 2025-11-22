package recon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pinakastra/internal/config"
)

type JSSecretFinder struct {
	Domain    string
	OutputDir string
	InputFile string
	JSAPath   string
}

func NewJSSecretFinder(domain, outputDir string) *JSSecretFinder {
	cfg := config.Load()
	return &JSSecretFinder{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "all_discovered_urls.txt"),
		JSAPath:   cfg.Paths.JSAPath,
	}
}

func (j *JSSecretFinder) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                         JS SECRET FINDER\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(j.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m all_discovered_urls.txt not found!")
		return fmt.Errorf("all_discovered_urls.txt not found")
	}

	// Create js_secretfinder output directory
	jsSecretDir := filepath.Join(j.OutputDir, "js_secretfinder")
	if err := os.MkdirAll(jsSecretDir, 0755); err != nil {
		return err
	}

	// Make automation.sh executable
	automationScript := filepath.Join(j.JSAPath, "automation.sh")
	exec.Command("chmod", "+x", automationScript).Run()

	// Read all URLs
	urls, err := j.readURLs()
	if err != nil {
		return err
	}

	totalURLs := len(urls)
	startTime := time.Now()

	for i, url := range urls {
		fmt.Printf("\033[33m[+]\033[0m [\033[1m%d/%d\033[0m] Running \033[1mJSA\033[0m on: \033[33m%s\033[0m\n\n", i+1, totalURLs, url)

		// Create output filename from URL
		outputFile := j.getOutputFilename(jsSecretDir, url)

		// Run JSA automation.sh
		cmd := exec.Command("bash", automationScript)
		cmd.Dir = j.JSAPath
		cmd.Stdin = strings.NewReader(url + "\n")

		// Capture output to file and stdout
		outFile, err := os.Create(outputFile)
		if err != nil {
			fmt.Printf("\033[31m[✗]\033[0m Failed to create output file: %v\n", err)
			continue
		}

		cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
		cmd.Stderr = os.Stderr

		cmd.Run()
		outFile.Close()

		fmt.Println()
		fmt.Printf("    \033[32m└─ Status : ✓ Complete\033[0m\n")
		fmt.Println()
	}

	elapsed := time.Since(startTime)
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m JS Secret Finder Complete\n")
	fmt.Printf("    \033[34m•\033[0m URLs Scanned  : %d\n", totalURLs)
	fmt.Printf("    \033[34m•\033[0m Output Dir    : js_secretfinder/\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (j *JSSecretFinder) readURLs() ([]string, error) {
	file, err := os.Open(j.InputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls, scanner.Err()
}

func (j *JSSecretFinder) getOutputFilename(dir, url string) string {
	name := strings.ReplaceAll(url, "https://", "")
	name = strings.ReplaceAll(name, "http://", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "&", "_")
	return filepath.Join(dir, name+".txt")
}
