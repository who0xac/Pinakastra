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

type FFuf struct {
	Domain    string
	OutputDir string
	InputFile string
	Wordlist  string
}

func NewFFuf(domain, outputDir string) *FFuf {
	cfg := config.Load()
	return &FFuf{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "live_hosts.txt"),
		Wordlist:  cfg.Paths.DirectoriesWordlist,
	}
}

func (f *FFuf) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                        FFUF DIRECTORY FUZZING\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(f.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m live_hosts.txt not found!")
		return fmt.Errorf("live_hosts.txt not found")
	}

	// Create ffuf output directory
	ffufDir := filepath.Join(f.OutputDir, "ffuf_output")
	if err := os.MkdirAll(ffufDir, 0755); err != nil {
		return err
	}

	// Read all URLs
	urls, err := f.readURLs()
	if err != nil {
		return err
	}

	totalURLs := len(urls)
	startTime := time.Now()
	allFoundURLs := []string{}

	for i, url := range urls {
		fmt.Printf("\033[33m[+]\033[0m [\033[1m%d/%d\033[0m] Running \033[1mffuf\033[0m on: \033[33m%s\033[0m\n\n", i+1, totalURLs, url)

		// Create output filename from URL
		outputFile := f.getOutputFilename(ffufDir, url)

		// Run ffuf
		fuzzURL := strings.TrimSuffix(url, "/") + "/FUZZ"
		cmd := exec.Command("ffuf",
			"-u", fuzzURL,
			"-w", f.Wordlist,
			"-mc", "200,301,302,403",
			"-fc", "404",
			"-rate", "100",
		)
		// Capture output to file and stdout
		outFile, _ := os.Create(outputFile)
		defer outFile.Close()

		cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
		cmd.Stderr = os.Stderr

		cmd.Run() // Continue even if error

		// Collect found URLs from this scan
		foundURLs := f.extractFoundURLs(outputFile, url)
		allFoundURLs = append(allFoundURLs, foundURLs...)

		fmt.Println()
		fmt.Printf("    \033[32m└─ Status : ✓ Complete (%d paths found)\033[0m\n", len(foundURLs))
		fmt.Println()
	}

	// Merge live URLs with ffuf discovered URLs
	mergedFile := filepath.Join(f.OutputDir, "all_discovered_urls.txt")
	err = f.mergeURLs(mergedFile, urls, allFoundURLs)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m Error merging URLs: %v\n", err)
	}

	elapsed := time.Since(startTime)
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m FFUF Directory Fuzzing Complete\n")
	fmt.Printf("    \033[34m•\033[0m URLs Scanned    : %d\n", totalURLs)
	fmt.Printf("    \033[34m•\033[0m Paths Found     : %d\n", len(allFoundURLs))
	fmt.Printf("    \033[34m•\033[0m Output Dir      : ffuf_output/\n")
	fmt.Printf("    \033[34m•\033[0m Merged File     : all_discovered_urls.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration        : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (f *FFuf) readURLs() ([]string, error) {
	file, err := os.Open(f.InputFile)
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

func (f *FFuf) getOutputFilename(dir, url string) string {
	name := strings.ReplaceAll(url, "https://", "")
	name = strings.ReplaceAll(name, "http://", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	return filepath.Join(dir, name+".txt")
}

func (f *FFuf) extractFoundURLs(csvFile, baseURL string) []string {
	var urls []string

	file, err := os.Open(csvFile)
	if err != nil {
		return urls
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Skip header line
	if scanner.Scan() {
		// Header skipped
	}

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			fullURL := baseURL + "/" + parts[0]
			urls = append(urls, fullURL)
		}
	}
	return urls
}

func (f *FFuf) mergeURLs(outputFile string, liveURLs, ffufURLs []string) error {
	// Use map to deduplicate
	urlMap := make(map[string]bool)

	for _, url := range liveURLs {
		urlMap[url] = true
	}
	for _, url := range ffufURLs {
		urlMap[url] = true
	}

	// Write to file
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for url := range urlMap {
		file.WriteString(url + "\n")
	}

	fmt.Printf("\033[32m[+]\033[0m Merged URLs: %d (live) + %d (ffuf) = %d unique\n",
		len(liveURLs), len(ffufURLs), len(urlMap))

	return nil
}
