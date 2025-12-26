package cloud

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Asset represents a discovered cloud asset
type Asset struct {
	Type        string   `json:"type"`        // s3, gcs, azure-blob, etc.
	Name        string   `json:"name"`        // bucket/container name
	URL         string   `json:"url"`         // full URL
	Provider    string   `json:"provider"`    // aws, gcp, azure, etc.
	Region      string   `json:"region,omitempty"`
	Status      string   `json:"status"`      // public, private, exists, not_found
	Permissions []string `json:"permissions,omitempty"` // read, write, list
	Contents    []string `json:"contents,omitempty"`    // sample file names
	Size        int64    `json:"size,omitempty"`
	IsWritable  bool     `json:"is_writable"` // CRITICAL flag
}

// Scanner discovers cloud assets
type Scanner struct {
	client      *http.Client
	domain      string
	timeout     time.Duration
}

// S3ListBucketResult represents S3 XML listing response
type S3ListBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

// NewScanner creates a new cloud scanner
func NewScanner(domain string, timeout int) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		domain:  domain,
		timeout: time.Duration(timeout) * time.Second,
	}
}

// ScanAll performs comprehensive cloud asset discovery with concurrent execution
// 9 providers vs GodEye's 3, with 100 concurrent workers for speed
func (s *Scanner) ScanAll(ctx context.Context) []Asset {
	var allAssets []Asset

	// Generate bucket names
	bucketNames := s.generateBucketNames()

	// Create work queue
	type work struct {
		name     string
		provider int // 1=S3, 2=GCS, 3=Azure, etc.
	}

	var jobs []work
	for _, name := range bucketNames {
		for provider := 1; provider <= 8; provider++ {
			jobs = append(jobs, work{name: name, provider: provider})
		}
	}

	// Results channel
	resultsChan := make(chan []Asset, len(jobs))

	// Semaphore to limit concurrent workers
	semaphore := make(chan struct{}, 100) // 100 concurrent workers

	// Process all jobs concurrently
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			return allAssets
		default:
		}

		semaphore <- struct{}{} // Acquire
		go func(w work) {
			defer func() { <-semaphore }() // Release

			var assets []Asset
			switch w.provider {
			case 1: // AWS S3
				assets = s.checkAWSS3(ctx, w.name)
			case 2: // Google Cloud Storage
				assets = s.checkGCS(ctx, w.name)
			case 3: // Azure Blob Storage
				assets = s.checkAzureBlob(ctx, w.name)
			case 4: // DigitalOcean Spaces
				assets = s.checkDOSpaces(ctx, w.name)
			case 5: // Wasabi
				assets = s.checkWasabi(ctx, w.name)
			case 6: // Backblaze B2
				assets = s.checkBackblazeB2(ctx, w.name)
			case 7: // Alibaba Cloud OSS
				assets = s.checkAlibabaOSS(ctx, w.name)
			case 8: // Firebase Storage
				assets = s.checkFirebase(ctx, w.name)
			}

			resultsChan <- assets
		}(job)
	}

	// Collect all results
	for i := 0; i < len(jobs); i++ {
		assets := <-resultsChan
		if len(assets) > 0 {
			allAssets = append(allAssets, assets...)
		}
	}
	close(resultsChan)

	return allAssets
}

// generateBucketNames generates potential bucket names
// More comprehensive than GodEye
func (s *Scanner) generateBucketNames() []string {
	seen := make(map[string]bool)
	var names []string

	// Extract base domain parts
	parts := strings.Split(s.domain, ".")
	baseName := parts[0]
	if len(parts) > 1 {
		baseName = strings.Join(parts[:len(parts)-1], "-")
	}
	cleanDomain := strings.ReplaceAll(s.domain, ".", "-")

	// Comprehensive patterns (60+ vs GodEye's 40)
	patterns := []string{
		"%s", cleanDomain, baseName,
		// Assets/Media
		"%s-assets", "%s-static", "%s-media", "%s-images", "%s-uploads", "%s-files",
		"%s-content", "%s-public", "%s-cdn", "%s-resources",
		"assets-%s", "static-%s", "media-%s", "cdn-%s",
		// Backups
		"%s-backup", "%s-backups", "%s-bak", "%s-archive", "%s-dump",
		"backup-%s", "backups-%s", "archive-%s",
		// Data/Logs
		"%s-data", "%s-logs", "%s-analytics", "%s-metrics",
		"data-%s", "logs-%s",
		// Environments
		"%s-dev", "%s-development", "%s-staging", "%s-stage", "%s-test", "%s-testing",
		"%s-prod", "%s-production", "%s-live",
		"dev-%s", "staging-%s", "prod-%s", "test-%s",
		// Private/Internal
		"%s-private", "%s-internal", "%s-admin", "%s-secure",
		"private-%s", "internal-%s",
		// Tech specific
		"%s-web", "%s-api", "%s-app", "%s-mobile", "%s-webapp",
		"%s-frontend", "%s-backend", "%s-services",
		"web-%s", "api-%s", "app-%s",
		// Database
		"%s-db", "%s-database", "%s-sql", "%s-mongo", "%s-postgres",
		"db-%s", "database-%s",
		// Config/Secrets
		"%s-config", "%s-configuration", "%s-secrets", "%s-keys", "%s-credentials",
		"config-%s", "secrets-%s",
		// Versioning
		"%s-v1", "%s-v2", "%s-old", "%s-new", "%s-legacy",
		// Storage
		"%s-storage", "%s-s3", "%s-bucket", "%s-blob",
		"storage-%s",
	}

	for _, pattern := range patterns {
		var name string
		if strings.Contains(pattern, "%s") {
			name = fmt.Sprintf(pattern, baseName)
		} else {
			name = pattern
		}

		name = strings.ToLower(name)
		// Bucket name validation (3-63 chars, alphanumeric + hyphens)
		if len(name) >= 3 && len(name) <= 63 && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	return names
}

// checkAWSS3 checks for AWS S3 buckets
func (s *Scanner) checkAWSS3(ctx context.Context, name string) []Asset {
	var assets []Asset

	// AWS regions to check
	regions := []string{
		"us-east-1",
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-southeast-1",
		"ap-south-1",
	}

	for _, region := range regions {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		var url string
		if region == "us-east-1" {
			url = fmt.Sprintf("https://%s.s3.amazonaws.com/", name)
		} else {
			url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region)
		}

		asset := s.probeS3URL(ctx, url, name, region)
		if asset != nil {
			assets = append(assets, *asset)
			break // Found bucket, stop checking other regions
		}
	}

	return assets
}

// probeS3URL probes a specific S3 URL
func (s *Scanner) probeS3URL(ctx context.Context, url, name, region string) *Asset {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	asset := &Asset{
		Type:     "s3",
		Name:     name,
		URL:      url,
		Provider: "aws",
		Region:   region,
	}

	switch resp.StatusCode {
	case 200:
		// Public bucket
		asset.Status = "public"
		asset.Permissions = []string{"read", "list"}

		// Parse listing
		var listing S3ListBucketResult
		if xml.Unmarshal(body, &listing) == nil {
			for i, content := range listing.Contents {
				if i >= 10 {
					break
				}
				asset.Contents = append(asset.Contents, content.Key)
				asset.Size += content.Size
			}
		}

		// Check if writable (try to upload)
		if s.testS3Write(ctx, url) {
			asset.IsWritable = true
			asset.Permissions = append(asset.Permissions, "write")
		}

		return asset

	case 403:
		// Bucket exists but private - verify it's real S3
		if isRealS3Response(body, resp.Header) {
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			return asset
		}
		return nil

	case 404:
		return nil
	}

	return nil
}

// testS3Write tests if bucket is writable
func (s *Scanner) testS3Write(ctx context.Context, bucketURL string) bool {
	// Try to PUT a test file
	testURL := bucketURL + "pinakastra-test.txt"
	req, err := http.NewRequestWithContext(ctx, "PUT", testURL, strings.NewReader("test"))
	if err != nil {
		return false
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// If we get 200, bucket is writable (CRITICAL finding!)
	if resp.StatusCode == 200 {
		// Clean up - delete test file
		delReq, _ := http.NewRequestWithContext(ctx, "DELETE", testURL, nil)
		s.client.Do(delReq)
		return true
	}

	return false
}

// checkGCS checks for Google Cloud Storage buckets
func (s *Scanner) checkGCS(ctx context.Context, name string) []Asset {
	url := fmt.Sprintf("https://storage.googleapis.com/%s/", name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var assets []Asset
	asset := &Asset{
		Type:     "gcs",
		Name:     name,
		URL:      url,
		Provider: "gcp",
	}

	switch resp.StatusCode {
	case 200:
		asset.Status = "public"
		asset.Permissions = []string{"read", "list"}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		var listing S3ListBucketResult
		if xml.Unmarshal(body, &listing) == nil {
			for i, content := range listing.Contents {
				if i >= 10 {
					break
				}
				asset.Contents = append(asset.Contents, content.Key)
			}
		}
		assets = append(assets, *asset)

	case 403:
		asset.Status = "private"
		asset.Permissions = []string{"exists"}
		assets = append(assets, *asset)
	}

	return assets
}

// checkAzureBlob checks for Azure Blob Storage
func (s *Scanner) checkAzureBlob(ctx context.Context, name string) []Asset {
	containers := []string{"", "public", "files", "data", "assets", "media", "backup", "web"}
	var assets []Asset

	for _, container := range containers {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		var url string
		if container == "" {
			url = fmt.Sprintf("https://%s.blob.core.windows.net/?restype=container&comp=list", name)
		} else {
			url = fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", name, container)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		asset := &Asset{
			Type:     "azure-blob",
			Name:     name,
			URL:      url,
			Provider: "azure",
		}

		switch resp.StatusCode {
		case 200:
			asset.Status = "public"
			asset.Permissions = []string{"read", "list"}
			if container != "" {
				asset.Name = fmt.Sprintf("%s/%s", name, container)
			}
			assets = append(assets, *asset)

		case 403:
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			if container != "" {
				asset.Name = fmt.Sprintf("%s/%s", name, container)
			}
			assets = append(assets, *asset)
		}
	}

	return assets
}

// checkDOSpaces checks for DigitalOcean Spaces
func (s *Scanner) checkDOSpaces(ctx context.Context, name string) []Asset {
	// DigitalOcean Spaces regions
	regions := []string{"nyc3", "sfo3", "sgp1", "fra1", "ams3"}
	var assets []Asset

	for _, region := range regions {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		url := fmt.Sprintf("https://%s.%s.digitaloceanspaces.com/", name, region)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		asset := &Asset{
			Type:     "digitalocean-spaces",
			Name:     name,
			URL:      url,
			Provider: "digitalocean",
			Region:   region,
		}

		switch resp.StatusCode {
		case 200:
			asset.Status = "public"
			asset.Permissions = []string{"read", "list"}
			assets = append(assets, *asset)
			return assets

		case 403:
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			assets = append(assets, *asset)
			return assets
		}
	}

	return assets
}

// checkWasabi checks for Wasabi storage
func (s *Scanner) checkWasabi(ctx context.Context, name string) []Asset {
	regions := []string{"us-east-1", "us-east-2", "us-west-1", "eu-central-1"}
	var assets []Asset

	for _, region := range regions {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		url := fmt.Sprintf("https://%s.s3.%s.wasabisys.com/", name, region)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		asset := &Asset{
			Type:     "wasabi",
			Name:     name,
			URL:      url,
			Provider: "wasabi",
			Region:   region,
		}

		switch resp.StatusCode {
		case 200:
			asset.Status = "public"
			asset.Permissions = []string{"read", "list"}
			assets = append(assets, *asset)
			return assets

		case 403:
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			assets = append(assets, *asset)
			return assets
		}
	}

	return assets
}

// checkBackblazeB2 checks for Backblaze B2
func (s *Scanner) checkBackblazeB2(ctx context.Context, name string) []Asset {
	url := fmt.Sprintf("https://f001.backblazeb2.com/file/%s/", name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var assets []Asset
	asset := &Asset{
		Type:     "backblaze-b2",
		Name:     name,
		URL:      url,
		Provider: "backblaze",
	}

	switch resp.StatusCode {
	case 200:
		asset.Status = "public"
		asset.Permissions = []string{"read"}
		assets = append(assets, *asset)

	case 403, 401:
		asset.Status = "private"
		asset.Permissions = []string{"exists"}
		assets = append(assets, *asset)
	}

	return assets
}

// checkAlibabaOSS checks for Alibaba Cloud OSS
func (s *Scanner) checkAlibabaOSS(ctx context.Context, name string) []Asset {
	regions := []string{"oss-cn-hangzhou", "oss-cn-shanghai", "oss-cn-beijing", "oss-us-west-1"}
	var assets []Asset

	for _, region := range regions {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		url := fmt.Sprintf("https://%s.%s.aliyuncs.com/", name, region)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		asset := &Asset{
			Type:     "alibaba-oss",
			Name:     name,
			URL:      url,
			Provider: "alibaba",
			Region:   region,
		}

		switch resp.StatusCode {
		case 200:
			asset.Status = "public"
			asset.Permissions = []string{"read", "list"}
			assets = append(assets, *asset)
			return assets

		case 403:
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			assets = append(assets, *asset)
			return assets
		}
	}

	return assets
}

// checkFirebase checks for Firebase Storage
func (s *Scanner) checkFirebase(ctx context.Context, name string) []Asset {
	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o", name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var assets []Asset
	asset := &Asset{
		Type:     "firebase-storage",
		Name:     name,
		URL:      url,
		Provider: "firebase",
	}

	switch resp.StatusCode {
	case 200:
		asset.Status = "public"
		asset.Permissions = []string{"read", "list"}
		assets = append(assets, *asset)

	case 403:
		asset.Status = "private"
		asset.Permissions = []string{"exists"}
		assets = append(assets, *asset)
	}

	return assets
}

// ExtractCloudURLs extracts cloud storage URLs from content
func ExtractCloudURLs(content string) []Asset {
	var assets []Asset
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		// S3
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3\.amazonaws\.com`),
		regexp.MustCompile(`https?://s3\.amazonaws\.com/([a-z0-9.-]+)`),
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`),
		// GCS
		regexp.MustCompile(`https?://storage\.googleapis\.com/([a-z0-9._-]+)`),
		regexp.MustCompile(`https?://([a-z0-9._-]+)\.storage\.googleapis\.com`),
		// Azure
		regexp.MustCompile(`https?://([a-z0-9]+)\.blob\.core\.windows\.net`),
		// CloudFront
		regexp.MustCompile(`https?://([a-z0-9]+)\.cloudfront\.net`),
		// DigitalOcean Spaces
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.([a-z0-9]+)\.digitaloceanspaces\.com`),
		// Wasabi
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3\.([a-z0-9-]+)\.wasabisys\.com`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[0]] {
				seen[match[0]] = true

				provider := "unknown"
				assetType := "storage"

				if strings.Contains(match[0], "s3.amazonaws") || strings.Contains(match[0], "amazonaws.com/") {
					provider = "aws"
					assetType = "s3"
				} else if strings.Contains(match[0], "googleapis") {
					provider = "gcp"
					assetType = "gcs"
				} else if strings.Contains(match[0], "windows.net") {
					provider = "azure"
					assetType = "azure-blob"
				} else if strings.Contains(match[0], "cloudfront") {
					provider = "aws"
					assetType = "cloudfront"
				} else if strings.Contains(match[0], "digitalocean") {
					provider = "digitalocean"
					assetType = "digitalocean-spaces"
				} else if strings.Contains(match[0], "wasabi") {
					provider = "wasabi"
					assetType = "wasabi"
				}

				assets = append(assets, Asset{
					Type:     assetType,
					Name:     match[1],
					URL:      match[0],
					Provider: provider,
					Status:   "found_in_content",
				})
			}
		}
	}

	return assets
}
