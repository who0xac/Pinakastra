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

type DirSearch struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewDirSearch(domain, outputDir string) *DirSearch {
	return &DirSearch{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "live_hosts.txt"),
	}
}

func (d *DirSearch) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                        DIRECTORY BRUTEFORCE\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(d.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m live_hosts.txt not found!")
		return fmt.Errorf("live_hosts.txt not found")
	}

	// Create dirsearch output directory
	dirsearchDir := filepath.Join(d.OutputDir, "dirsearch_output")
	if err := os.MkdirAll(dirsearchDir, 0755); err != nil {
		return err
	}

	// Read all URLs
	urls, err := d.readURLs()
	if err != nil {
		return err
	}

	totalURLs := len(urls)
	startTime := time.Now()

	for i, url := range urls {
		fmt.Printf("\033[33m[+]\033[0m [\033[1m%d/%d\033[0m] Running \033[1mdirsearch\033[0m on: \033[33m%s\033[0m\n\n", i+1, totalURLs, url)

		// Create output filename from URL
		outputFile := d.getOutputFilename(dirsearchDir, url)

		// Run dirsearch
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
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		cmd.Run() // Continue even if error

		fmt.Println()
		fmt.Printf("    \033[32m└─ Status : ✓ Complete\033[0m\n")
		fmt.Println()
	}

	elapsed := time.Since(startTime)
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Directory Bruteforce Complete\n")
	fmt.Printf("    \033[34m•\033[0m URLs Scanned  : %d\n", totalURLs)
	fmt.Printf("    \033[34m•\033[0m Output Dir    : dirsearch_output/\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (d *DirSearch) readURLs() ([]string, error) {
	file, err := os.Open(d.InputFile)
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

func (d *DirSearch) getOutputFilename(dir, url string) string {
	// Remove protocol and replace special chars
	name := strings.ReplaceAll(url, "https://", "")
	name = strings.ReplaceAll(name, "http://", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "&", "_")

	return filepath.Join(dir, name+".txt")
}
