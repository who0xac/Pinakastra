package recon

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if runtime.GOOS == "windows" {
			return filepath.Join(home, strings.ReplaceAll(path[2:], "/", "\\"))
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
