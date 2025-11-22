package cli

import (
	"fmt"

	"github.com/fatih/color"
)

const banner = `
 ____  _             _            _
|  _ \(_)_ __   __ _| | ____ _ __| |_ _ __ __ _
| |_) | | '_ \ / _' | |/ / _' / __| __| '__/ _' |
|  __/| | | | | (_| |   < (_| \__ \ |_| | | (_| |
|_|   |_|_| |_|\__,_|_|\_\__,_|___/\__|_|  \__,_|
`

const version = "v1.0.0"

func printBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)

	cyan.Println(banner)
	fmt.Print("              ")
	yellow.Printf("%s", version)
	fmt.Print(" | ")
	cyan.Println("@who0xac")
	fmt.Println()
}
