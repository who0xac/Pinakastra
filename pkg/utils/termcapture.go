package utils

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// TerminalCapture captures terminal output
type TerminalCapture struct {
	lines      []string
	mu         sync.Mutex
	origStdout *os.File
	origStderr *os.File
	pipeRead   *os.File
	pipeWrite  *os.File
}

// NewTerminalCapture creates a new terminal capture instance
func NewTerminalCapture() *TerminalCapture {
	return &TerminalCapture{
		lines: make([]string, 0),
	}
}

// AddLine adds a line to the terminal output capture
func (t *TerminalCapture) AddLine(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
}

// AddLinef adds a formatted line to the terminal output capture
func (t *TerminalCapture) AddLinef(format string, args ...interface{}) {
	t.AddLine(fmt.Sprintf(format, args...))
}

// GetLines returns all captured lines
func (t *TerminalCapture) GetLines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.lines...)
}

// Clear clears all captured lines
func (t *TerminalCapture) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = make([]string, 0)
}

// CaptureWriter returns a writer that captures output
type CaptureWriter struct {
	capture *TerminalCapture
	writer  io.Writer
}

// Write implements io.Writer interface
func (cw *CaptureWriter) Write(p []byte) (n int, err error) {
	// Write to original output
	n, err = cw.writer.Write(p)

	// Capture the line
	if n > 0 {
		cw.capture.AddLine(string(p[:n]))
	}

	return n, err
}

// NewCaptureWriter creates a writer that captures and writes
func NewCaptureWriter(capture *TerminalCapture, writer io.Writer) *CaptureWriter {
	return &CaptureWriter{
		capture: capture,
		writer:  writer,
	}
}
