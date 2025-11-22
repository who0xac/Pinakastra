package logger

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Logger struct {
	showTimestamp bool
}

func New() *Logger {
	return &Logger{
		showTimestamp: true,
	}
}

func (l *Logger) timestamp() string {
	if l.showTimestamp {
		return color.HiBlackString("[%s] ", time.Now().Format("15:04:05"))
	}
	return ""
}

func (l *Logger) Info(format string, args ...interface{}) {
	prefix := color.CyanString("[*]")
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Success(format string, args ...interface{}) {
	prefix := color.GreenString("[+]")
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Warning(format string, args ...interface{}) {
	prefix := color.YellowString("[!]")
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Error(format string, args ...interface{}) {
	prefix := color.RedString("[-]")
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(format string, args ...interface{}) {
	prefix := color.MagentaString("[D]")
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Tool(toolName, format string, args ...interface{}) {
	prefix := color.HiBlueString("[%s]", toolName)
	fmt.Printf("%s%s %s\n", l.timestamp(), prefix, fmt.Sprintf(format, args...))
}

func (l *Logger) Progress(current, total int, message string) {
	percent := float64(current) / float64(total) * 100
	bar := l.progressBar(percent)
	fmt.Printf("\r%s %s %.1f%% %s", color.CyanString("[*]"), bar, percent, message)
	if current == total {
		fmt.Println()
	}
}

func (l *Logger) progressBar(percent float64) string {
	width := 30
	filled := int(percent / 100 * float64(width))
	empty := width - filled

	bar := color.GreenString(repeat("█", filled)) + color.HiBlackString(repeat("░", empty))
	return fmt.Sprintf("[%s]", bar)
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func (l *Logger) SetTimestamp(show bool) {
	l.showTimestamp = show
}
