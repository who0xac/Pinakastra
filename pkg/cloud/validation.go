package cloud

import (
	"net/http"
	"strings"
)

// isRealS3Response validates that a 403 response is from real S3, not WAF/CDN
// This prevents FALSE POSITIVES (GodEye's major weakness)
func isRealS3Response(body []byte, headers http.Header) bool {
	bodyStr := string(body)

	// 1. Check for S3-specific headers
	server := headers.Get("Server")
	if server != "" {
		if strings.Contains(strings.ToLower(server), "amazons3") {
			return true
		}
	}

	// 2. Check for x-amz headers (S3 specific)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-amz-") {
			return true
		}
	}

	// 3. Check for S3-specific error codes in XML
	s3ErrorCodes := []string{
		"AccessDenied",
		"AllAccessDisabled",
		"AccountProblem",
		"InvalidAccessKeyId",
		"SignatureDoesNotMatch",
		"NoSuchBucket",
		"<Code>",
		"<Message>",
	}

	for _, code := range s3ErrorCodes {
		if strings.Contains(bodyStr, code) {
			return true
		}
	}

	// 4. Check for S3 XML error structure
	if strings.Contains(bodyStr, "<Error>") && strings.Contains(bodyStr, "<?xml") {
		return true
	}

	// 5. If response is HTML or generic error page, likely WAF/CDN
	if strings.Contains(bodyStr, "<html") || strings.Contains(bodyStr, "<!DOCTYPE") {
		return false
	}

	// 6. Check for common WAF signatures
	wafSignatures := []string{
		"cloudflare",
		"Access Denied",
		"Request ID:",
		"Ray ID:",
		"Attention Required",
		"cf-ray",
	}

	for _, sig := range wafSignatures {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(sig)) {
			return false
		}
	}

	// 7. Short XML-like responses are more likely real S3
	if len(body) < 1000 && strings.Contains(bodyStr, "<?xml") {
		return true
	}

	// Default: if uncertain, assume it's NOT real S3 (avoid false positives)
	return false
}

// isRealGCSResponse validates GCS response
func isRealGCSResponse(body []byte, headers http.Header) bool {
	bodyStr := string(body)

	// Check for GCS-specific headers
	server := headers.Get("Server")
	if strings.Contains(strings.ToLower(server), "uploadserver") ||
	   strings.Contains(strings.ToLower(server), "gws") {
		return true
	}

	// Check for x-goog headers
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-goog-") {
			return true
		}
	}

	// Check for GCS error structure
	if strings.Contains(bodyStr, "<?xml") && strings.Contains(bodyStr, "<Error>") {
		return true
	}

	return false
}

// isRealAzureResponse validates Azure response
func isRealAzureResponse(body []byte, headers http.Header) bool {
	bodyStr := string(body)

	// Check for Azure-specific headers
	server := headers.Get("Server")
	if strings.Contains(strings.ToLower(server), "windows-azure-blob") {
		return true
	}

	// Check for x-ms headers
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-ms-") {
			return true
		}
	}

	// Check for Azure error codes
	azureErrors := []string{
		"BlobNotFound",
		"ContainerNotFound",
		"AuthenticationFailed",
		"ResourceNotFound",
	}

	for _, code := range azureErrors {
		if strings.Contains(bodyStr, code) {
			return true
		}
	}

	return false
}

// GetCriticalAssets returns only critical findings (public + writable)
func GetCriticalAssets(assets []Asset) []Asset {
	var critical []Asset
	for _, asset := range assets {
		if asset.Status == "public" || asset.IsWritable {
			critical = append(critical, asset)
		}
	}
	return critical
}

// GetPublicAssets returns public assets
func GetPublicAssets(assets []Asset) []Asset {
	var public []Asset
	for _, asset := range assets {
		if asset.Status == "public" {
			public = append(public, asset)
		}
	}
	return public
}

// GetPrivateAssets returns private (exists but not accessible) assets
func GetPrivateAssets(assets []Asset) []Asset {
	var private []Asset
	for _, asset := range assets {
		if asset.Status == "private" {
			private = append(private, asset)
		}
	}
	return private
}

// GroupByProvider groups assets by cloud provider
func GroupByProvider(assets []Asset) map[string][]Asset {
	grouped := make(map[string][]Asset)
	for _, asset := range assets {
		grouped[asset.Provider] = append(grouped[asset.Provider], asset)
	}
	return grouped
}
