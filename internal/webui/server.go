package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/gorilla/websocket"
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/storage"
	ws "github.com/who0xac/pinakastra/internal/websocket"
)

//go:embed all:../../web/templates/* all:../../web/static/*
var embeddedFiles embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Server struct {
	port    int
	hub     *ws.Hub
	config  *config.Config
	storage *storage.Storage
}

func NewServer(port int, hub *ws.Hub, cfg *config.Config) *Server {
	return &Server{
		port:    port,
		hub:     hub,
		config:  cfg,
		storage: storage.New(cfg.Storage.BasePath),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/scan/", s.handleScanDetails)
	mux.HandleFunc("/api/tools", s.handleTools)

	// WebSocket
	mux.HandleFunc("/ws", s.handleWebSocket)

	// Static files
	mux.HandleFunc("/static/", s.handleStatic)

	// Main page
	mux.HandleFunc("/", s.handleIndex)

	addr := fmt.Sprintf(":%d", s.port)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Try embedded first, then local
	tmplContent, err := embeddedFiles.ReadFile("web/templates/index.html")
	if err != nil {
		// Try local file
		http.ServeFile(w, r, "web/templates/index.html")
		return
	}

	tmpl, err := template.New("index").Parse(string(tmplContent))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "Pinakastra Dashboard",
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Try embedded first
	filePath := "web" + r.URL.Path[len("/"):]
	content, err := embeddedFiles.ReadFile(filePath)
	if err != nil {
		// Try local file
		http.ServeFile(w, r, filepath.Join("web", r.URL.Path[len("/static"):]))
		return
	}

	// Set content type
	ext := filepath.Ext(r.URL.Path)
	switch ext {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	}

	w.Write(content)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := ws.NewClient(s.hub, conn)
	s.hub.Register(client)

	go client.WritePump()
	go client.ReadPump()
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	domains, err := s.storage.ListScans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var scans []map[string]interface{}
	for _, domain := range domains {
		result, err := s.storage.LoadResults(domain)
		if err != nil {
			continue
		}

		scans = append(scans, map[string]interface{}{
			"domain":    domain,
			"timestamp": result.Timestamp,
			"tools":     len(result.Results),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func (s *Server) handleScanDetails(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Path[len("/api/scan/"):]
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	result, err := s.storage.LoadResults(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	// Return list of available tools
	tools := []map[string]interface{}{
		{"name": "subfinder", "phase": 1, "description": "Subdomain enumeration"},
		{"name": "amass", "phase": 1, "description": "Subdomain enumeration"},
		{"name": "httpx", "phase": 4, "description": "HTTP probing"},
		{"name": "nuclei", "phase": 6, "description": "Vulnerability scanning"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tools)
}

func getEmbeddedFS() fs.FS {
	sub, _ := fs.Sub(embeddedFiles, "web")
	return sub
}
