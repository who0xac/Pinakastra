package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/fatih/color"
)

var (
	interruptCount int32
	cancelFunc     context.CancelFunc
)

// SetupSignalHandler sets up graceful cancellation on Ctrl+C
func SetupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancelFunc = cancel

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for range signalChan {
			count := atomic.AddInt32(&interruptCount, 1)

			yellow := color.New(color.FgYellow, color.Bold)
			red := color.New(color.FgRed, color.Bold)

			fmt.Println()
			if count == 1 {
				yellow.Println("⚠ Interrupt received! Stopping current tool...")
				yellow.Println("  Press Ctrl+C again to force exit")
				cancel()
			} else if count == 2 {
				yellow.Println("⚠ Second interrupt! Preparing to exit...")
				yellow.Println("  Press Ctrl+C once more to force immediate exit")
			} else {
				red.Println("✗ Force exit!")
				os.Exit(1)
			}
			fmt.Println()
		}
	}()

	return ctx
}

// ResetInterruptCount resets the interrupt counter (call after each tool completes)
func ResetInterruptCount() {
	atomic.StoreInt32(&interruptCount, 0)
}
