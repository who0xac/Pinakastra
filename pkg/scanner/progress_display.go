package scanner

import (
	"fmt"
	"strings"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// ProgressDisplayer handles real-time progress display for Active Exploitation
type ProgressDisplayer struct {
	testStates map[string]*TestState
	testOrder  []string // Track order of tests
}

// TestState tracks the state of a single test
type TestState struct {
	Name        string
	Status      string // "queued", "running", "complete", "error"
	Payload     string
	CurrentTest int
	TotalTests  int
	LineNumber  int // Track which line this test is on
	FoundCount  int // Number of vulnerabilities found
}

// NewProgressDisplayer creates a new progress displayer
func NewProgressDisplayer() *ProgressDisplayer {
	return &ProgressDisplayer{
		testStates: make(map[string]*TestState),
		testOrder:  []string{},
	}
}

// InitializeTests sets up the initial test states
func (pd *ProgressDisplayer) InitializeTests() {
	tests := []string{
		"XSS",
		"SQLi",
		"IDOR",
		"Path Traversal",
		"SSRF",
		"Open Redirect",
		"JWT",
		"JavaScript Analysis",
	}

	fmt.Println() // Add spacing

	for i, test := range tests {
		pd.testStates[test] = &TestState{
			Name:        test,
			Status:      "queued",
			Payload:     "",
			CurrentTest: 0,
			TotalTests:  10, // 7 hardcoded advanced + 3 AI bypass variants
			LineNumber:  i,
		}
		pd.testOrder = append(pd.testOrder, test)

		// Print initial queued state
		fmt.Printf("   %s %-20s %s\n",
			terminal.Gray("[~]"),
			test,
			terminal.Gray("Queued"),
		)
	}

	// Move cursor back up to start of test list
	fmt.Printf("\033[%dA", len(tests))
}

// UpdateProgress updates and displays progress based on message
func (pd *ProgressDisplayer) UpdateProgress(msg string) {
	parts := strings.Split(msg, ":")
	if len(parts) < 3 {
		return
	}

	msgType := parts[0]
	testName := parts[1]

	state, exists := pd.testStates[testName]
	if !exists {
		return
	}

	switch msgType {
	case "start":
		// Test is starting
		state.Status = "running"
		state.CurrentTest = 0
		pd.redrawTest(state, fmt.Sprintf("%s Starting...", terminal.Cyan("[>]")))

	case "generating":
		// AI is generating payload
		if len(parts) >= 3 {
			state.Status = "running"
			state.Payload = parts[2]
			pd.redrawTest(state, fmt.Sprintf("%s %s", terminal.Cyan("[>]"), terminal.Gray(parts[2])))
		}

	case "payload":
		// Testing a specific payload
		if len(parts) >= 5 {
			state.Status = "running"
			state.Payload = parts[2]
			fmt.Sscanf(parts[3], "%d", &state.CurrentTest)
			fmt.Sscanf(parts[4], "%d", &state.TotalTests)

			// Truncate payload if too long
			displayPayload := state.Payload
			if len(displayPayload) > 30 {
				displayPayload = displayPayload[:27] + "..."
			}

			msg := fmt.Sprintf("%s %s Testing: %s",
				terminal.Cyan(fmt.Sprintf("[%d/%d]", state.CurrentTest, state.TotalTests)),
				terminal.Cyan("[>]"),
				terminal.White(displayPayload),
			)

			// Show found count if any vulnerabilities found
			if state.FoundCount > 0 {
				msg += fmt.Sprintf(" | %s", terminal.Green(fmt.Sprintf("Found: %d", state.FoundCount)))
			}

			pd.redrawTest(state, msg)
		}

	case "found":
		// Vulnerability found - increment counter
		if len(parts) >= 2 {
			state.FoundCount++

			// Redraw with updated count
			displayPayload := state.Payload
			if len(displayPayload) > 30 {
				displayPayload = displayPayload[:27] + "..."
			}

			msg := fmt.Sprintf("%s %s Testing: %s | %s",
				terminal.Cyan(fmt.Sprintf("[%d/%d]", state.CurrentTest, state.TotalTests)),
				terminal.Cyan("[>]"),
				terminal.White(displayPayload),
				terminal.Green(fmt.Sprintf("Found: %d", state.FoundCount)),
			)
			pd.redrawTest(state, msg)
		}

	case "complete":
		// Test completed
		state.Status = "complete"
		state.Payload = ""

		// Show different message based on whether vulns were found
		var msg string
		if state.FoundCount > 0 {
			msg = fmt.Sprintf("%s Complete (%d payloads tested) | %s",
				terminal.Green("[+]"),
				state.TotalTests,
				terminal.Green(fmt.Sprintf("Found: %d ✓", state.FoundCount)),
			)
		} else {
			msg = fmt.Sprintf("%s Complete (%d payloads tested)",
				terminal.Green("[+]"),
				state.TotalTests,
			)
		}
		pd.redrawTest(state, msg)

	case "error":
		// Test encountered an error
		state.Status = "error"
		if len(parts) >= 3 {
			state.Payload = parts[2]
		}
		msg := fmt.Sprintf("%s Error", terminal.Red("[!]"))
		pd.redrawTest(state, msg)
	}
}

// redrawTest redraws a single test line in-place
func (pd *ProgressDisplayer) redrawTest(state *TestState, message string) {
	// Calculate how many lines down from current cursor position
	currentLine := 0
	for i, name := range pd.testOrder {
		if name == state.Name {
			currentLine = i
			break
		}
	}

	// Move cursor to the correct line
	if currentLine > 0 {
		fmt.Printf("\033[%dB", currentLine) // Move down
	}

	// Clear the line and rewrite
	fmt.Print("\r\033[K") // Clear line
	fmt.Printf("   %-20s %s", state.Name, message)

	// Move cursor back to top
	if currentLine > 0 {
		fmt.Printf("\033[%dA", currentLine) // Move back up
	}
}

// Finalize moves cursor past all test lines
func (pd *ProgressDisplayer) Finalize() {
	// Move cursor past all tests
	fmt.Printf("\033[%dB", len(pd.testOrder))
	fmt.Println()
}

// RunProgressDisplay starts the progress display goroutine
func RunProgressDisplay(progressChan <-chan string) {
	displayer := NewProgressDisplayer()
	displayer.InitializeTests()

	for msg := range progressChan {
		displayer.UpdateProgress(msg)
	}

	displayer.Finalize()
}
