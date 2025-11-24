package recon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type SubdomainResult struct {
	Tool      string
	Count     int
	Duration  time.Duration
	Error     error
	OutputFile string
}

type SubdomainEnum struct {
	Domain    string
	OutputDir string
	Config    *config.Config
	Results   []SubdomainResult
	StartTime time.Time
	EndTime   time.Time
	Errors    int
}

func NewSubdomainEnum(domain, outputDir string, cfg *config.Config) *SubdomainEnum {
	return &SubdomainEnum{
		Domain:    domain,
		OutputDir: outputDir,
		Config:    cfg,
		Results:   []SubdomainResult{},
	}
}

func (s *SubdomainEnum) Run() {
	s.StartTime = time.Now()

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                          SUBDOMAIN ENUMERATION\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Create output dir
	os.MkdirAll(s.OutputDir, 0755)

	tools := []struct {
		name string
		run  func() (string, error)
	}{
		{"amass", s.runAmass},
		{"subfinder", s.runSubfinder},
		{"findomain", s.runFindomain},
		{"assetfinder", s.runAssetfinder},
		{"sublist3r", s.runSublist3r},
		{"chaos", s.runChaos},
		{"crtsh", s.runCrtsh},
		{"shodan", s.runShodan},
		{"puredns", s.runPuredns},
	}

	for _, tool := range tools {
		fmt.Printf("\033[33m[+]\033[0m Running \033[1m%s\033[0m...\n\n", tool.name)

		toolStart := time.Now()
		outputFile, err := tool.run()
		duration := time.Since(toolStart)

		count := 0
		if err == nil && outputFile != "" {
			count = countLines(outputFile)
		}

		result := SubdomainResult{
			Tool:       tool.name,
			Count:      count,
			Duration:   duration,
			Error:      err,
			OutputFile: outputFile,
		}
		s.Results = append(s.Results, result)

		fmt.Println()
		if err != nil {
			fmt.Printf("    \033[31m├─ Subdomains found : 0\033[0m\n")
			fmt.Printf("    \033[31m├─ Time elapsed     : %s\033[0m\n", duration.Round(time.Second))
			fmt.Printf("    \033[31m└─ Status           : ✗ Failed\033[0m\n")
			s.Errors++
		} else {
			fmt.Printf("    \033[32m├─ Subdomains found : %d\033[0m\n", count)
			fmt.Printf("    \033[32m├─ Time elapsed     : %s\033[0m\n", duration.Round(time.Second))
			fmt.Printf("    \033[32m└─ Status           : ✓ Complete\033[0m\n")
		}
		fmt.Println()
	}

	s.EndTime = time.Now()
	s.printSummary()
}

func (s *SubdomainEnum) runAmass() (string, error) {
	output := filepath.Join(s.OutputDir, "amass.txt")
	args := []string{"enum", "-active", "-d", s.Domain, "-o", output}

	if s.Config.Paths.AmassConfig != "" && fileExists(s.Config.Paths.AmassConfig) {
		args = append(args, "-config", s.Config.Paths.AmassConfig)
	}
	if s.Config.Paths.Resolvers != "" && fileExists(s.Config.Paths.Resolvers) {
		args = append(args, "-rf", s.Config.Paths.Resolvers)
	}

	cmd := exec.Command("amass", args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runSubfinder() (string, error) {
	output := filepath.Join(s.OutputDir, "subfinder.txt")
	cmd := exec.Command("subfinder", "-d", s.Domain, "-o", output, "-rate-limit", "30")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runFindomain() (string, error) {
	output := filepath.Join(s.OutputDir, "findomain.txt")
	cmd := exec.Command("findomain", "-t", s.Domain, "-u", output)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runAssetfinder() (string, error) {
	output := filepath.Join(s.OutputDir, "assetfinder.txt")
	outFile, _ := os.Create(output)
	defer outFile.Close()

	cmd := exec.Command("assetfinder", "-subs-only", s.Domain)
	cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runSublist3r() (string, error) {
	output := filepath.Join(s.OutputDir, "sublist3r.txt")
	cmd := exec.Command("sublist3r", "-d", s.Domain,
		"-e", "baidu,yahoo,google,bing,ask,netcraft,threatcrowd,ssl,passivedns",
		"-o", output)
	cmd.Stdout = os.Stdout
	// Suppress Python SyntaxWarnings using PYTHONWARNINGS environment variable
	cmd.Env = append(os.Environ(), "PYTHONWARNINGS=ignore")
	cmd.Stderr = nil
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runChaos() (string, error) {
	if s.Config.APIKeys.Chaos == "" {
		return "", fmt.Errorf("no API key")
	}
	output := filepath.Join(s.OutputDir, "chaos.txt")
	cmd := exec.Command("chaos", "-key", s.Config.APIKeys.Chaos, "-d", s.Domain, "-o", output)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runCrtsh() (string, error) {
	output := filepath.Join(s.OutputDir, "crtsh.txt")
	outFile, _ := os.Create(output)
	defer outFile.Close()

	cmd := exec.Command("crtsh", "-d", s.Domain, "-r")
	cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runShodan() (string, error) {
	if s.Config.APIKeys.Shodan == "" {
		return "", fmt.Errorf("no API key")
	}

	// Initialize Shodan API key (suppress output)
	initCmd := exec.Command("shodan", "init", s.Config.APIKeys.Shodan)
	initCmd.Stdout = nil
	initCmd.Stderr = nil
	initCmd.Run() // Ignore errors, init might already be done

	output := filepath.Join(s.OutputDir, "shodan.txt")

	// Use bash to pipe through tr for proper formatting
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("shodan search --fields hostnames 'ssl:%s' --limit 0 2>/dev/null | tr ';' '\\n' | tee %s",
			s.Domain, output))
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) runPuredns() (string, error) {
	output := filepath.Join(s.OutputDir, "puredns.txt")
	wordlist := expandPath(s.Config.Paths.Subdomains)
	resolvers := expandPath(s.Config.Paths.Resolvers)

	if wordlist == "" || !fileExists(wordlist) {
		return "", fmt.Errorf("no wordlist at %s", wordlist)
	}

	if resolvers == "" || !fileExists(resolvers) {
		return "", fmt.Errorf("no resolvers at %s", resolvers)
	}

	args := []string{"bruteforce", wordlist, s.Domain, "-w", output, "-r", resolvers, "-t", "500"}

	cmd := exec.Command("puredns", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return output, err
}

func (s *SubdomainEnum) printSummary() {
	totalDuration := s.EndTime.Sub(s.StartTime)
	totalCount := 0
	for _, r := range s.Results {
		totalCount += r.Count
	}

	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Subdomain Enumeration Complete\n")
	fmt.Printf("    \033[34m•\033[0m Total Unique  : %d\n", totalCount)
	fmt.Printf("    \033[34m•\033[0m Output File   : all_subdomains.txt\n")
	fmt.Printf("    \033[34m•\033[0m Duration      : %s\n", totalDuration.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()
}

func (s *SubdomainEnum) MergeAndClean() (string, int) {
	fmt.Printf("\033[33m[+]\033[0m Merging and cleaning subdomains...\n")

	// Clean amass output first
	amassFile := filepath.Join(s.OutputDir, "amass.txt")
	amassCleanedFile := filepath.Join(s.OutputDir, "amass_cleaned.txt")
	if fileExists(amassFile) {
		s.cleanAmassOutput(amassFile, amassCleanedFile)
	} else {
		os.WriteFile(amassCleanedFile, []byte{}, 0644)
	}

	// Collect all subdomains
	unique := make(map[string]bool)
	domainPattern := regexp.MustCompile(`(?i)^([a-zA-Z0-9_-]+\.)+` + regexp.QuoteMeta(s.Domain) + `$`)

	files := []string{
		amassCleanedFile,
		filepath.Join(s.OutputDir, "subfinder.txt"),
		filepath.Join(s.OutputDir, "findomain.txt"),
		filepath.Join(s.OutputDir, "assetfinder.txt"),
		filepath.Join(s.OutputDir, "sublist3r.txt"),
		filepath.Join(s.OutputDir, "chaos.txt"),
		filepath.Join(s.OutputDir, "crtsh.txt"),
		filepath.Join(s.OutputDir, "shodan.txt"),
		filepath.Join(s.OutputDir, "puredns.txt"),
	}

	for _, f := range files {
		if !fileExists(f) {
			continue
		}
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Remove ANSI codes
			line = stripAnsi(line)
			// Convert to lowercase
			line = strings.ToLower(line)
			// Remove trailing dot
			line = strings.TrimSuffix(line, ".")
			// Validate domain pattern
			if line != "" && domainPattern.MatchString(line) {
				unique[line] = true
			}
		}
		file.Close()
	}

	// Sort and write
	var subs []string
	for sub := range unique {
		subs = append(subs, sub)
	}
	sort.Strings(subs)

	merged := filepath.Join(s.OutputDir, "all_subdomains.txt")
	os.WriteFile(merged, []byte(strings.Join(subs, "\n")), 0644)

	fmt.Printf("\033[32m✓\033[0m Total unique subdomains: \033[35m%d\033[0m\n", len(subs))
	fmt.Println()

	return merged, len(subs)
}

func (s *SubdomainEnum) cleanAmassOutput(input, output string) {
	domainPattern := regexp.MustCompile(`([a-zA-Z0-9_-]+\.)+` + regexp.QuoteMeta(s.Domain))

	file, err := os.Open(input)
	if err != nil {
		return
	}
	defer file.Close()

	unique := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Remove ANSI codes
		line = stripAnsi(line)
		// Find domain matches
		matches := domainPattern.FindAllString(line, -1)
		for _, match := range matches {
			match = strings.ToLower(match)
			match = strings.TrimSuffix(match, ".")
			unique[match] = true
		}
	}

	var cleaned []string
	for sub := range unique {
		cleaned = append(cleaned, sub)
	}

	os.WriteFile(output, []byte(strings.Join(cleaned, "\n")), 0644)
}
