package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for local development
	},
}

// Server represents the web UI server
type Server struct {
	port       int
	domain     string
	server     *http.Server
	clients    map[*websocket.Conn]bool
	clientsMux sync.RWMutex
	broadcast  chan ScanUpdate
	webFS      fs.FS
}

// ScanUpdate represents real-time scan updates
type ScanUpdate struct {
	Type      string      `json:"type"`      // "subdomain", "vulnerability", "status", "port", etc.
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// SubdomainUpdate for new subdomain discoveries
type SubdomainUpdate struct {
	Subdomain string `json:"subdomain"`
	IPAddress string `json:"ip_address,omitempty"`
	Status    string `json:"status"` // "active", "inactive"
}

// VulnerabilityUpdate for new vulnerability findings
type VulnerabilityUpdate struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // "sqli", "xss", "cors", etc.
	Severity    string    `json:"severity"`    // "critical", "high", "medium", "low", "info"
	URL         string    `json:"url"`
	Endpoint    string    `json:"endpoint"`
	Description string    `json:"description"`
	CVE         string    `json:"cve,omitempty"`
	Payload     string    `json:"payload,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// StatusUpdate for scan progress
type StatusUpdate struct {
	Phase       string  `json:"phase"`        // Current phase name
	PhaseNumber int     `json:"phase_number"` // 1-7
	Progress    float64 `json:"progress"`     // 0-100
	Message     string  `json:"message"`
	ElapsedTime string  `json:"elapsed_time"`
}

// StatsUpdate for dashboard statistics
type StatsUpdate struct {
	TotalSubdomains     int            `json:"total_subdomains"`
	LiveHosts           int            `json:"live_hosts"`
	TotalURLs           int            `json:"total_urls"`
	TotalVulnerabilities int           `json:"total_vulnerabilities"`
	VulnsBySeverity     map[string]int `json:"vulns_by_severity"` // critical, high, medium, low, info
	HTTPStatusCodes     map[string]int `json:"http_status_codes"` // "200": 123, "403": 45, etc.
	OpenPorts           int            `json:"open_ports"`
}

// NewServer creates a new web UI server
func NewServer(port int, domain string, webFS fs.FS) *Server {
	return &Server{
		port:      port,
		domain:    domain,
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan ScanUpdate, 100),
		webFS:     webFS,
	}
}

// Start starts the web server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Serve static files from embedded FS
	staticFS, err := fs.Sub(s.webFS, "web/static")
	if err != nil {
		return fmt.Errorf("failed to load embedded static files: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Serve main dashboard
	mux.HandleFunc("/", s.handleIndex)

	// WebSocket endpoint for real-time updates
	mux.HandleFunc("/ws", s.handleWebSocket)

	// API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/subdomains", s.handleSubdomains)
	mux.HandleFunc("/api/vulnerabilities", s.handleVulnerabilities)
	mux.HandleFunc("/api/export", s.handleExport)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	// Start broadcasting goroutine
	go s.handleBroadcasts()

	fmt.Printf("\n🌐 Web UI started: http://localhost:%d\n", s.port)

	return s.server.ListenAndServe()
}

// Stop stops the web server
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// SendUpdate broadcasts an update to all connected clients
func (s *Server) SendUpdate(updateType string, data interface{}) {
	update := ScanUpdate{
		Type:      updateType,
		Timestamp: time.Now(),
		Data:      data,
	}
	s.broadcast <- update
}

// handleIndex serves the main dashboard page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.webFS, "web/templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}

	// Replace placeholder with actual domain
	html := string(data)
	html = strings.Replace(html, "{{DOMAIN}}", s.domain, 1)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMux.Lock()
	s.clients[conn] = true
	s.clientsMux.Unlock()

	defer func() {
		s.clientsMux.Lock()
		delete(s.clients, conn)
		s.clientsMux.Unlock()
		conn.Close()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// handleBroadcasts sends updates to all connected WebSocket clients
func (s *Server) handleBroadcasts() {
	for update := range s.broadcast {
		s.clientsMux.RLock()
		for client := range s.clients {
			err := client.WriteJSON(update)
			if err != nil {
				log.Printf("WebSocket write error: %v", err)
				client.Close()
				s.clientsMux.Lock()
				delete(s.clients, client)
				s.clientsMux.Unlock()
			}
		}
		s.clientsMux.RUnlock()
	}
}

// handleStats returns current scan statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement stats retrieval from scanner
	stats := StatsUpdate{
		TotalSubdomains:      0,
		LiveHosts:            0,
		TotalURLs:            0,
		TotalVulnerabilities: 0,
		VulnsBySeverity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
		HTTPStatusCodes: map[string]int{},
		OpenPorts:       0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleSubdomains returns list of discovered subdomains
func (s *Server) handleSubdomains(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement subdomain list retrieval
	subdomains := []SubdomainUpdate{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subdomains)
}

// handleVulnerabilities returns list of vulnerabilities with optional filters
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement vulnerability list retrieval with filters
	// Query params: ?severity=critical&type=sqli
	vulns := []VulnerabilityUpdate{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}

// handleExport exports scan results in requested format
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement export functionality
	// Query param: ?format=json|csv|pdf
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "not_implemented",
		"format": format,
	})
}
