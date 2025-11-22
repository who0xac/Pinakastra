package tools

import (
	"github.com/who0xac/pinakastra/internal/config"
)

type Registry struct {
	tools  map[string]Tool
	config *config.Config
}

func NewRegistry(cfg *config.Config) *Registry {
	r := &Registry{
		tools:  make(map[string]Tool),
		config: cfg,
	}

	// Register all available tools here
	// Tools will be added as you provide them
	r.registerDefaultTools()

	return r
}

func (r *Registry) registerDefaultTools() {
	// Phase 1: Subdomain Enumeration
	r.Register(NewSubfinder(r.config))
	r.Register(NewAmass(r.config))

	// Phase 4: HTTP Probing
	r.Register(NewHttpx(r.config))
}

func (r *Registry) Register(tool Tool) {
	r.tools[tool.Name()] = tool
}

func (r *Registry) Get(name string) (Tool, bool) {
	tool, ok := r.tools[name]
	return tool, ok
}

func (r *Registry) GetAll() []Tool {
	var tools []Tool
	for _, tool := range r.tools {
		tools = append(tools, tool)
	}
	return tools
}

func (r *Registry) GetEnabledTools() []Tool {
	// Return all registered tools as enabled
	// Tool-specific configuration can be added later if needed
	return r.GetAll()
}

func (r *Registry) FilterTools(names []string) []Tool {
	nameMap := make(map[string]bool)
	for _, n := range names {
		nameMap[n] = true
	}

	var filtered []Tool
	for name, tool := range r.tools {
		if nameMap[name] {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

func (r *Registry) ExcludeTools(tools []Tool, exclude []string) []Tool {
	excludeMap := make(map[string]bool)
	for _, n := range exclude {
		excludeMap[n] = true
	}

	var filtered []Tool
	for _, tool := range tools {
		if !excludeMap[tool.Name()] {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

func (r *Registry) GetByPhase(phase int) []Tool {
	var tools []Tool
	for _, tool := range r.tools {
		if tool.Phase() == phase {
			tools = append(tools, tool)
		}
	}
	return tools
}
