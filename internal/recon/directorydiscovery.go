package recon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type DirectoryDiscovery struct {
	OutputDir string
	Config    *config.Config
}

func NewDirectoryDiscovery(outputDir string, cfg *config.Config) *DirectoryDiscovery {
	return &DirectoryDiscovery{
		OutputDir: outputDir,
		Config:    cfg,
	}
}

func (d *DirectoryDiscovery) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                       DIRECTORY DISCOVERY\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	startTime := time.Now()

	// Run dirsearch
	dirsearchCount, err := d.runDirsearch()
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m Dirsearch failed: %v\n", err)
	}

	// Run ffuf
	ffufCount, err := d.runFFUF()
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m FFUF failed: %v\n", err)
	}

	// Merge all discovered URLs
	totalURLs := d.mergeDiscoveredURLs()

	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Directory Discovery Complete\n")
	fmt.Printf("    \033[34m•\033[0m Dirsearch URLs : %d\n", dirsearchCount)
	fmt.Printf("    \033[34m•\033[0m FFUF URLs      : %d\n", ffufCount)
	fmt.Printf("    \033[34m•\033[0m Total Unique   : %d\n", totalURLs)
	fmt.Printf("    \033[34m•\033[0m Duration       : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (d *DirectoryDiscovery) runDirsearch() (int, error) {
	liveURLs := filepath.Join(d.OutputDir, "live_urls.txt")
	dirsearchDir := filepath.Join(d.OutputDir, "dirsearch")

	if _, err := os.Stat(liveURLs); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗] live_urls.txt not found for dirsearch!\033[0m")
		return 0, err
	}

	// Create dirsearch output directory
	os.MkdirAll(dirsearchDir, 0755)

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mdirsearch\033[0m on each URL...\n\n")

	// Read URLs
	file, err := os.Open(liveURLs)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	urlCount := 0
	totalFound := 0

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}
		urlCount++

		// Create output file for this URL
		outputFile := filepath.Join(dirsearchDir, fmt.Sprintf("url_%d.txt", urlCount))

		fmt.Printf("  [%d] %s\n", urlCount, url)

		// Run dirsearch without wordlist (simple discovery)
		cmd := exec.Command("dirsearch",
			"-u", url,
			"-x", "500,502,429,404,400",
			"-R", "5",
			"--random-agent",
			"-t", "100",
			"-F",
			"-o", outputFile,
			"--delay", "0",
		)
		cmd.Run() // Ignore errors, continue with other URLs

		// Count results
		if fileExists(outputFile) {
			count := countLines(outputFile)
			totalFound += count
		}
	}

	fmt.Println()
	fmt.Printf("\033[32m✓\033[0m \033[1mdirsearch\033[0m completed - %d URLs found\n", totalFound)
	fmt.Printf("\033[34m[+]\033[0m Saved to: dirsearch/\n")
	fmt.Println()

	return totalFound, nil
}

func (d *DirectoryDiscovery) runFFUF() (int, error) {
	liveURLs := filepath.Join(d.OutputDir, "live_urls.txt")
	output := filepath.Join(d.OutputDir, "ffuf_results.txt")
	wordlist := expandPath(d.Config.Paths.Directories)

	if _, err := os.Stat(liveURLs); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗] live_urls.txt not found for FFUF!\033[0m")
		return 0, err
	}

	if wordlist == "" || !fileExists(wordlist) {
		fmt.Printf("\033[31m[✗] Directory wordlist not found at %s\033[0m\n", wordlist)
		return 0, fmt.Errorf("no wordlist")
	}

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mffuf\033[0m with wordlist...\n\n")

	// Read URLs and run ffuf on each
	file, err := os.Open(liveURLs)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	outFile, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(file)
	totalFound := 0

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}

		// Add FUZZ placeholder
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		url += "FUZZ"

		fmt.Printf("  Fuzzing: %s\n", url)

		cmd := exec.Command("ffuf",
			"-u", url,
			"-w", wordlist,
			"-mc", "200,301,302,403",
			"-t", "100",
			"-o", output+".tmp",
			"-of", "csv",
			"-s",
		)
		cmd.Run()

		// Append results
		if fileExists(output + ".tmp") {
			tmpData, _ := os.ReadFile(output + ".tmp")
			outFile.Write(tmpData)
			os.Remove(output + ".tmp")
		}
	}

	totalFound = countLines(output)

	fmt.Println()
	fmt.Printf("\033[32m✓\033[0m \033[1mffuf\033[0m completed - %d URLs found\n", totalFound)
	fmt.Printf("\033[34m[+]\033[0m Saved to: ffuf_results.txt\n")
	fmt.Println()

	return totalFound, nil
}

func (d *DirectoryDiscovery) mergeDiscoveredURLs() int {
	fmt.Println("\033[36m►\033[0m Merging discovered URLs...")

	mergedFile := filepath.Join(d.OutputDir, "all_discovered_urls.txt")
	urlMap := make(map[string]bool)

	// Add live_urls.txt
	liveURLs := filepath.Join(d.OutputDir, "live_urls.txt")
	readFileToMap(liveURLs, urlMap)

	// Add dirsearch results
	dirsearchDir := filepath.Join(d.OutputDir, "dirsearch")
	if dirEntries, err := os.ReadDir(dirsearchDir); err == nil {
		for _, entry := range dirEntries {
			if !entry.IsDir() {
				readFileToMap(filepath.Join(dirsearchDir, entry.Name()), urlMap)
			}
		}
	}

	// Add ffuf results
	ffufResults := filepath.Join(d.OutputDir, "ffuf_results.txt")
	readFileToMap(ffufResults, urlMap)

	// Write merged file
	outFile, _ := os.Create(mergedFile)
	defer outFile.Close()

	for url := range urlMap {
		outFile.WriteString(url + "\n")
	}

	fmt.Printf("\033[32m✓\033[0m Merged URLs: %d unique\n", len(urlMap))
	fmt.Printf("\033[34m[+]\033[0m Saved to: all_discovered_urls.txt\n")

	return len(urlMap)
}
