package recon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type GFPatterns struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewGFPatterns(domain, outputDir string) *GFPatterns {
	return &GFPatterns{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "alive_gathered_urls.txt"),
	}
}

func (g *GFPatterns) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                        GF PATTERN MATCHING\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	if _, err := os.Stat(g.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m alive_gathered_urls.txt not found!")
		return fmt.Errorf("alive_gathered_urls.txt not found")
	}

	// Create gf_patterns directory
	gfDir := filepath.Join(g.OutputDir, "gf_patterns")
	os.MkdirAll(gfDir, 0755)

	patterns := []string{
		"debug_logic",
		"idor",
		"img-traversal",
		"interestingEXT",
		"interestingparams",
		"interestingsubs",
		"jsvar",
		"lfi",
		"rce",
		"redirect",
		"sqli",
		"ssrf",
		"ssti",
		"xss",
	}

	fmt.Printf("\033[33m[+]\033[0m Running GF pattern matching with %d patterns...\n\n", len(patterns))
	fmt.Println()

	startTime := time.Now()

	for _, pattern := range patterns {
		outputFile := filepath.Join(gfDir, pattern+".txt")

		// cat alive_gathered_urls.txt | gf pattern > output
		catCmd := exec.Command("cat", g.InputFile)
		gfCmd := exec.Command("gf", pattern)

		// Pipe cat output to gf
		pipe, _ := catCmd.StdoutPipe()
		gfCmd.Stdin = pipe

		outFile, err := os.Create(outputFile)
		if err != nil {
			continue
		}

		gfCmd.Stdout = outFile
		gfCmd.Stderr = os.Stderr

		catCmd.Start()
		gfCmd.Run()
		catCmd.Wait()
		outFile.Close()

		count := countLines(outputFile)
		if count > 0 {
			fmt.Printf("  \033[32m✓\033[0m %s: %d matches\n", pattern, count)
		} else {
			fmt.Printf("  \033[90m○\033[0m %s: 0 matches\n", pattern)
		}
	}

	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m GF Pattern Matching Complete\n")
	fmt.Printf("    \033[34m•\033[0m Patterns Scanned : %d\n", len(patterns))
	fmt.Printf("    \033[34m•\033[0m Output Dir       : gf_patterns/\n")
	fmt.Printf("    \033[34m•\033[0m Duration         : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}
