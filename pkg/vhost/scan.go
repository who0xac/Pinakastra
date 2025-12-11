package vhost

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Scanner performs virtual host discovery
type Scanner struct {
	InputFile   string
	SubdomainFile string
	OutputDir   string
	Timeout     time.Duration
}

// VHostResult contains vhost discovery results
type VHostResult struct {
	IP        string
	VHosts    []string
	TotalFound int
}

// NewScanner creates a new VHost scanner
func NewScanner(inputFile, subdomainFile, outputDir string) *Scanner {
	return &Scanner{
		InputFile:     inputFile,
		SubdomainFile: subdomainFile,
		OutputDir:     outputDir,
		Timeout:       5 * time.Second,
	}
}

// Run executes virtual host discovery
func (s *Scanner) Run(ctx context.Context) ([]*VHostResult, error) {
	// Read IPs
	ips, err := readLines(s.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPs: %v", err)
	}

	// Read subdomains
	subdomains, err := readLines(s.SubdomainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read subdomains: %v", err)
	}

	if len(ips) == 0 || len(subdomains) == 0 {
		return nil, fmt.Errorf("no IPs or subdomains to scan")
	}

	// Perform VHost scanning
	results := s.scanVHosts(ctx, ips, subdomains)

	return results, nil
}

// scanVHosts scans for virtual hosts
func (s *Scanner) scanVHosts(ctx context.Context, ips, subdomains []string) []*VHostResult {
	var results []*VHostResult
	var mu sync.Mutex

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit to 5 concurrent IPs

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vhosts := s.findVHostsForIP(ctx, ipAddr, subdomains)
			if len(vhosts) > 0 {
				mu.Lock()
				results = append(results, &VHostResult{
					IP:         ipAddr,
					VHosts:     vhosts,
					TotalFound: len(vhosts),
				})
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	return results
}

// findVHostsForIP finds virtual hosts for a specific IP
func (s *Scanner) findVHostsForIP(ctx context.Context, ip string, subdomains []string) []string {
	var vhosts []string
	var mu sync.Mutex

	client := &http.Client{
		Timeout: s.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get baseline response (no Host header)
	baselineStatus, baselineSize := s.makeRequest(ctx, client, ip, "")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 10 concurrent requests per IP

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Make request with Host header
			status, size := s.makeRequest(ctx, client, ip, host)

			// Check if response differs from baseline
			if status != baselineStatus || size != baselineSize {
				mu.Lock()
				vhosts = append(vhosts, host)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()

	return vhosts
}

// makeRequest makes HTTP request with custom Host header
func (s *Scanner) makeRequest(ctx context.Context, client *http.Client, ip, host string) (int, int) {
	url := fmt.Sprintf("http://%s/", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0
	}

	if host != "" {
		req.Host = host
		req.Header.Set("Host", host)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	// Read body to get size
	buf := make([]byte, 4096)
	totalSize := 0
	for {
		n, err := resp.Body.Read(buf)
		totalSize += n
		if err != nil {
			break
		}
	}

	return resp.StatusCode, totalSize
}

// readLines reads lines from file
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}
