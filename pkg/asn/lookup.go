package asn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ASNInfo contains ASN information for an IP
type ASNInfo struct {
	IP          string
	ASN         string
	Description string
	Country     string
	Registry    string
}

// ASNStats contains aggregated ASN statistics
type ASNStats struct {
	ASN         string
	Description string
	Count       int
	IPs         []string
}

// Lookup performs ASN lookups for IPs
type Lookup struct {
	cache map[string]*ASNInfo
	mu    sync.RWMutex
}

// NewLookup creates a new ASN lookup instance
func NewLookup() *Lookup {
	return &Lookup{
		cache: make(map[string]*ASNInfo),
	}
}

// LookupIP performs ASN lookup for a single IP using Team Cymru DNS
func (l *Lookup) LookupIP(ctx context.Context, ip string) (*ASNInfo, error) {
	// Check cache first
	l.mu.RLock()
	if cached, ok := l.cache[ip]; ok {
		l.mu.RUnlock()
		return cached, nil
	}
	l.mu.RUnlock()

	// Parse IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	// Reverse IP for DNS query
	reversedIP := reverseIP(ip)
	if reversedIP == "" {
		return nil, fmt.Errorf("failed to reverse IP: %s", ip)
	}

	// Query Team Cymru DNS: origin.asn.cymru.com
	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversedIP)

	// Perform TXT record lookup
	resolver := &net.Resolver{}
	txtRecords, err := resolver.LookupTXT(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ASN lookup failed: %v", err)
	}

	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no ASN data found")
	}

	// Parse TXT record: "ASN | IP | BGP Prefix | CC | Registry | Allocated"
	// Example: "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01"
	info := parseASNRecord(ip, txtRecords[0])
	if info == nil {
		return nil, fmt.Errorf("failed to parse ASN record")
	}

	// Get ASN description
	if info.ASN != "" {
		desc, err := l.lookupASNDescription(ctx, info.ASN)
		if err == nil {
			info.Description = desc
		}
	}

	// Cache result
	l.mu.Lock()
	l.cache[ip] = info
	l.mu.Unlock()

	return info, nil
}

// LookupBatch performs ASN lookups for multiple IPs concurrently
func (l *Lookup) LookupBatch(ctx context.Context, ips []string) ([]*ASNInfo, error) {
	results := make([]*ASNInfo, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrency to 10

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			// Add timeout per IP
			ipCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			info, err := l.LookupIP(ipCtx, ipAddr)
			if err == nil {
				results[index] = info
			}
		}(i, ip)
	}

	wg.Wait()

	// Filter out nil results
	var validResults []*ASNInfo
	for _, result := range results {
		if result != nil {
			validResults = append(validResults, result)
		}
	}

	return validResults, nil
}

// lookupASNDescription queries AS name using Team Cymru DNS
func (l *Lookup) lookupASNDescription(ctx context.Context, asn string) (string, error) {
	// Query: AS[number].asn.cymru.com
	query := fmt.Sprintf("AS%s.asn.cymru.com", asn)

	resolver := &net.Resolver{}
	txtRecords, err := resolver.LookupTXT(ctx, query)
	if err != nil {
		return "", err
	}

	if len(txtRecords) == 0 {
		return "", fmt.Errorf("no description found")
	}

	// Parse TXT record: "ASN | CC | Registry | Allocated | AS Name"
	// Example: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
	parts := strings.Split(txtRecords[0], "|")
	if len(parts) >= 5 {
		return strings.TrimSpace(parts[4]), nil
	}

	return "", fmt.Errorf("invalid description format")
}

// GetStatistics aggregates ASN statistics from results
func GetStatistics(results []*ASNInfo) []*ASNStats {
	asnMap := make(map[string]*ASNStats)

	for _, info := range results {
		if info.ASN == "" {
			continue
		}

		key := info.ASN
		if _, exists := asnMap[key]; !exists {
			asnMap[key] = &ASNStats{
				ASN:         info.ASN,
				Description: info.Description,
				Count:       0,
				IPs:         []string{},
			}
		}

		asnMap[key].Count++
		asnMap[key].IPs = append(asnMap[key].IPs, info.IP)
	}

	// Convert map to slice
	var stats []*ASNStats
	for _, stat := range asnMap {
		stats = append(stats, stat)
	}

	// Sort by count (descending)
	for i := 0; i < len(stats)-1; i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Count > stats[i].Count {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	return stats
}

// reverseIP reverses IP address for DNS PTR-style lookup
func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}

	// Reverse octets
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// parseASNRecord parses Team Cymru TXT record
func parseASNRecord(ip, record string) *ASNInfo {
	// Format: "ASN | IP | BGP Prefix | CC | Registry | Allocated"
	parts := strings.Split(record, "|")
	if len(parts) < 5 {
		return nil
	}

	return &ASNInfo{
		IP:       ip,
		ASN:      strings.TrimSpace(parts[0]),
		Country:  strings.TrimSpace(parts[3]),
		Registry: strings.TrimSpace(parts[4]),
	}
}
