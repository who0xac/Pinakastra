package recon

import (
	"bufio"
	"os"
	"regexp"
)

// countLines counts the number of lines in a file
func countLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// stripAnsi removes ANSI color codes from a string
func stripAnsi(str string) string {
	ansiRegex := regexp.MustCompile(`\x1B\[[0-9;]*[mK]`)
	return ansiRegex.ReplaceAllString(str, "")
}
