package cli

import (
	"fmt"
	"os/exec"

	"github.com/fatih/color"
)

func runUpdate() {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Println()
	yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	yellow.Println("           🔄 UPDATING PINAKASTRA")
	yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	cyan.Println("  Updating to latest version...")
	fmt.Println()

	cmd := exec.Command("go", "install", "github.com/who0xac/pinakastra@latest")
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		color.Red("  ✗ Update failed: %v", err)
		fmt.Println()
		yellow.Println("  Try manually:")
		fmt.Println("    go install github.com/who0xac/pinakastra@latest")
		fmt.Println()
		return
	}

	fmt.Println()
	green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	green.Println("            ✅ UPDATE COMPLETE!")
	green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	cyan.Println("  Pinakastra has been updated to the latest version")
	fmt.Println()
}
