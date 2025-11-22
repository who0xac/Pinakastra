package recon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type Screenshot struct {
	Domain    string
	OutputDir string
	InputFile string
}

func NewScreenshot(domain, outputDir string) *Screenshot {
	return &Screenshot{
		Domain:    domain,
		OutputDir: outputDir,
		InputFile: filepath.Join(outputDir, "live_hosts.txt"),
	}
}

func (s *Screenshot) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                        SCREENSHOT CAPTURE\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Check if input file exists
	if _, err := os.Stat(s.InputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗]\033[0m live_hosts.txt not found!")
		return fmt.Errorf("live_hosts.txt not found")
	}

	// Create screenshots output directory
	screenshotDir := filepath.Join(s.OutputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return err
	}

	startTime := time.Now()

	// Run gowitness
	fmt.Printf("\033[33m[+]\033[0m Running \033[1mgowitness\033[0m...\n\n")

	cmd := exec.Command("gowitness",
		"file",
		"-f", s.InputFile,
		"--screenshot-path", screenshotDir,
		"--threads", "10",
		"--timeout", "30",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	// Count screenshots
	screenshotCount := s.countScreenshots(screenshotDir)

	elapsed := time.Since(startTime)
	fmt.Println()
	if err != nil {
		fmt.Printf("    \033[31m├─ Screenshots : %d\033[0m\n", screenshotCount)
		fmt.Printf("    \033[31m├─ Time elapsed : %s\033[0m\n", elapsed.Round(time.Second))
		fmt.Printf("    \033[31m└─ Status       : ✗ Error\033[0m\n")
	} else {
		fmt.Printf("    \033[32m├─ Screenshots : %d\033[0m\n", screenshotCount)
		fmt.Printf("    \033[32m├─ Time elapsed : %s\033[0m\n", elapsed.Round(time.Second))
		fmt.Printf("    \033[32m└─ Status       : ✓ Complete\033[0m\n")
	}

	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m Screenshot Capture Complete\n")
	fmt.Printf("    \033[34m•\033[0m Screenshots : %d\n", screenshotCount)
	fmt.Printf("    \033[34m•\033[0m Output Dir  : screenshots/\n")
	fmt.Printf("    \033[34m•\033[0m Duration    : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	// Open Eyeballer for analysis
	s.openEyeballer()

	return nil
}

func (s *Screenshot) countScreenshots(dir string) int {
	count := 0
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (filepath.Ext(path) == ".png" || filepath.Ext(path) == ".jpg" || filepath.Ext(path) == ".jpeg") {
			count++
		}
		return nil
	})
	return count
}

func (s *Screenshot) openEyeballer() {
	fmt.Println()
	fmt.Println("\033[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
	fmt.Println("\033[36m[+] Opening Eyeballer for screenshot analysis...\033[0m")
	fmt.Println("\033[33m[!] Upload your screenshots from:\033[0m")
	fmt.Printf("    \033[1m%s\033[0m\n", filepath.Join(s.OutputDir, "screenshots"))
	fmt.Println()

	eyeballerURL := "https://bishopfox.github.io/eyeballer/"

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", eyeballerURL)
	case "darwin":
		cmd = exec.Command("open", eyeballerURL)
	default: // linux
		cmd = exec.Command("xdg-open", eyeballerURL)
	}

	err := cmd.Start()
	if err != nil {
		fmt.Printf("\033[33m[!] Could not open browser automatically.\033[0m\n")
		fmt.Printf("\033[33m[!] Please manually visit: %s\033[0m\n", eyeballerURL)
	} else {
		fmt.Printf("\033[32m✓\033[0m Eyeballer opened in browser\n")
		fmt.Println("\033[36m    URL: https://bishopfox.github.io/eyeballer/\033[0m")
	}

	fmt.Println()
	fmt.Println("\033[33m[!] Note:\033[0m Eyeballer uses AI to analyze screenshots for:")
	fmt.Println("    • Login pages")
	fmt.Println("    • Custom 404 pages")
	fmt.Println("    • Old-looking websites")
	fmt.Println("    • Potentially vulnerable pages")
}
