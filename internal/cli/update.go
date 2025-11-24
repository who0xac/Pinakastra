package cli

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/fatih/color"
)

func runUpdate() {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Println()
	cyan.Print("Updating Pinakastra to latest version")

	// Start spinner in background
	done := make(chan bool)
	go func() {
		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\r%s Updating Pinakastra to latest version %s", cyan.Sprint(""), spinner[i])
				i = (i + 1) % len(spinner)
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()

	cmd := exec.Command("go", "install", "github.com/who0xac/pinakastra@latest")
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Run()
	done <- true
	time.Sleep(100 * time.Millisecond) // Let spinner finish

	fmt.Print("\r") // Clear spinner line

	if err != nil {
		color.Red("✗ Update failed: %v", err)
		fmt.Println()
		yellow.Println("Try manually:")
		fmt.Println("  go install github.com/who0xac/pinakastra@latest")
		fmt.Println()
		return
	}

	green.Println("✓ Update complete! Pinakastra has been updated to the latest version")
	fmt.Println()
}
