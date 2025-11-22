package executor

import (
	"sync"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/logger"
	"github.com/who0xac/pinakastra/internal/notifier"
	"github.com/who0xac/pinakastra/internal/tools"
)

type ScanContext struct {
	Domain    string
	OutputDir string
	Config    *config.Config
	StartTime time.Time
}

type ToolResult struct {
	Tool       string        `json:"tool"`
	Success    bool          `json:"success"`
	Output     string        `json:"output"`
	Error      string        `json:"error,omitempty"`
	Duration   time.Duration `json:"duration"`
	Findings   int           `json:"findings"`
	OutputFile string        `json:"output_file,omitempty"`
}

type Executor struct {
	notifier *notifier.Notifier
	log      *logger.Logger
}

func New(notifier *notifier.Notifier, log *logger.Logger) *Executor {
	return &Executor{
		notifier: notifier,
		log:      log,
	}
}

func (e *Executor) RunTools(ctx *ScanContext, toolList []tools.Tool) map[string]*ToolResult {
	results := make(map[string]*ToolResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Group tools by phase for proper execution order
	phases := groupByPhase(toolList)

	for _, phase := range phases {
		e.log.Info("Starting phase: %s", phase.Name)

		// Run tools in parallel within each phase
		for _, tool := range phase.Tools {
			wg.Add(1)
			go func(t tools.Tool) {
				defer wg.Done()

				result := e.runTool(ctx, t)

				mu.Lock()
				results[t.Name()] = result
				mu.Unlock()
			}(tool)
		}

		wg.Wait()
	}

	return results
}

func (e *Executor) runTool(ctx *ScanContext, tool tools.Tool) *ToolResult {
	e.log.Tool(tool.Name(), "Starting...")

	startTime := time.Now()

	// Run with retry
	output, err := e.runWithRetry(ctx, tool, 3)

	duration := time.Since(startTime)
	result := &ToolResult{
		Tool:     tool.Name(),
		Duration: duration,
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		e.log.Error("%s failed: %v", tool.Name(), err)

		// Notify error
		e.notifier.SendError(ctx.Domain, tool.Name()+" failed: "+err.Error())
	} else {
		result.Success = true
		result.Output = output
		result.Findings = tool.CountFindings(output)
		result.OutputFile = tool.OutputFile(ctx.OutputDir)
		e.log.Success("%s completed (%d findings in %s)", tool.Name(), result.Findings, duration.Round(time.Millisecond))
	}

	return result
}

func (e *Executor) runWithRetry(ctx *ScanContext, tool tools.Tool, maxRetries int) (string, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		output, err := tool.Run(ctx.Domain, ctx.OutputDir, ctx.Config)
		if err == nil {
			return output, nil
		}

		lastErr = err
		if attempt < maxRetries {
			e.log.Warning("%s attempt %d failed, retrying...", tool.Name(), attempt)
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
	}

	return "", lastErr
}

type Phase struct {
	Name  string
	Tools []tools.Tool
}

func groupByPhase(toolList []tools.Tool) []Phase {
	phaseMap := make(map[int][]tools.Tool)

	for _, t := range toolList {
		phase := t.Phase()
		phaseMap[phase] = append(phaseMap[phase], t)
	}

	// Create ordered phases
	phaseNames := map[int]string{
		1: "Subdomain Enumeration",
		2: "DNS Resolution",
		3: "Port Scanning",
		4: "HTTP Probing",
		5: "Content Discovery",
		6: "Vulnerability Scanning",
	}

	var phases []Phase
	for i := 1; i <= 6; i++ {
		if tools, ok := phaseMap[i]; ok {
			phases = append(phases, Phase{
				Name:  phaseNames[i],
				Tools: tools,
			})
		}
	}

	return phases
}
