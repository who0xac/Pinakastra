package secrets

import "regexp"

// SecretPattern represents a secret detection pattern
type SecretPattern struct {
	Name        string
	Pattern     string
	Regex       *regexp.Regexp
	Entropy     float64 // Minimum entropy threshold (0 = disabled)
	Description string
	Severity    string // critical, high, medium, low
	FalsePositivePatterns []string // Patterns that indicate false positive
}

// SecretPatterns contains all secret detection patterns
// More comprehensive than GodEye with better false positive filtering
var SecretPatterns = []SecretPattern{
	// ===== AWS CREDENTIALS =====
	{
		Name:        "AWS Access Key ID",
		Pattern:     `(?i)(aws_access_key_id|aws_access_key|aws_key_id|AKIA[0-9A-Z]{16})`,
		Description: "AWS Access Key ID",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "AWS Secret Access Key",
		Pattern:     `(?i)(aws_secret_access_key|aws_secret_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`,
		Description: "AWS Secret Access Key",
		Severity:    "critical",
		Entropy:     4.5,
	},
	{
		Name:        "AWS Session Token",
		Pattern:     `(?i)(aws_session_token|aws_security_token)[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?`,
		Description: "AWS Session Token",
		Severity:    "high",
		Entropy:     4.0,
	},
	{
		Name:        "AWS S3 Bucket URL",
		Pattern:     `https?://[a-z0-9.-]+\.s3[.-]([a-z0-9-]+)?\.amazonaws\.com`,
		Description: "AWS S3 Bucket URL",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== GOOGLE CLOUD =====
	{
		Name:        "Google Cloud API Key",
		Pattern:     `(?i)(AIza[0-9A-Za-z\\-_]{35})`,
		Description: "Google Cloud API Key",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Google OAuth Access Token",
		Pattern:     `(?i)(ya29\.[0-9A-Za-z\-_]+)`,
		Description: "Google OAuth Access Token",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Google Service Account",
		Pattern:     `(?i)"type":\s*"service_account"`,
		Description: "Google Service Account JSON",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== AZURE =====
	{
		Name:        "Azure Storage Account Key",
		Pattern:     `(?i)(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88})`,
		Description: "Azure Storage Account Connection String",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Azure Client Secret",
		Pattern:     `(?i)(client_secret|ClientSecret)[\s]*[=:]\s*['\"]?([A-Za-z0-9~._-]{34,40})['\"]?`,
		Description: "Azure Client Secret",
		Severity:    "critical",
		Entropy:     4.0,
	},

	// ===== GITHUB =====
	{
		Name:        "GitHub Personal Access Token",
		Pattern:     `(?i)(ghp_[A-Za-z0-9]{36})`,
		Description: "GitHub Personal Access Token",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "GitHub OAuth Token",
		Pattern:     `(?i)(gho_[A-Za-z0-9]{36})`,
		Description: "GitHub OAuth Access Token",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "GitHub App Token",
		Pattern:     `(?i)(ghu_|ghs_|ghr_)([A-Za-z0-9]{36})`,
		Description: "GitHub App/Refresh/Server Token",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "GitHub Fine-grained Token",
		Pattern:     `(?i)(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})`,
		Description: "GitHub Fine-grained Personal Access Token",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== GITLAB =====
	{
		Name:        "GitLab Personal Access Token",
		Pattern:     `(?i)(glpat-[A-Za-z0-9\-_]{20})`,
		Description: "GitLab Personal Access Token",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== SLACK =====
	{
		Name:        "Slack Token",
		Pattern:     `(?i)(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32})`,
		Description: "Slack API Token",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "Slack Webhook",
		Pattern:     `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}`,
		Description: "Slack Webhook URL",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== STRIPE =====
	{
		Name:        "Stripe Secret Key",
		Pattern:     `(?i)(sk_live_[0-9a-zA-Z]{24,})`,
		Description: "Stripe Live Secret Key",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Stripe Restricted Key",
		Pattern:     `(?i)(rk_live_[0-9a-zA-Z]{24,})`,
		Description: "Stripe Live Restricted Key",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "Stripe Publishable Key",
		Pattern:     `(?i)(pk_live_[0-9a-zA-Z]{24,})`,
		Description: "Stripe Live Publishable Key",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== TWILIO =====
	{
		Name:        "Twilio API Key",
		Pattern:     `(?i)(SK[0-9a-fA-F]{32})`,
		Description: "Twilio API Key",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "Twilio Account SID",
		Pattern:     `(?i)(AC[0-9a-fA-F]{32})`,
		Description: "Twilio Account SID",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== MAILGUN =====
	{
		Name:        "Mailgun API Key",
		Pattern:     `(?i)(key-[0-9a-zA-Z]{32})`,
		Description: "Mailgun API Key",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== SENDGRID =====
	{
		Name:        "SendGrid API Key",
		Pattern:     `(?i)(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})`,
		Description: "SendGrid API Key",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== HEROKU =====
	{
		Name:        "Heroku API Key",
		Pattern:     `(?i)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
		Description: "Heroku API Key (UUID format)",
		Severity:    "high",
		Entropy:     0,
		FalsePositivePatterns: []string{
			`(?i)example`,
			`(?i)test`,
			`(?i)sample`,
			`00000000-0000-0000-0000-000000000000`,
			`D27CDB6E-AE6D-11CF-96B8-444553540000`, // Adobe Flash Player CLSID
			`(?i)D27CDB6E-AE6D-11CF-96B8-`, // Flash CLSID prefix (case insensitive)
			`(?i)CLSID`,
			`(?i)classid`,
		},
	},

	// ===== DIGITAL OCEAN =====
	{
		Name:        "DigitalOcean Token",
		Pattern:     `(?i)(dop_v1_[a-f0-9]{64})`,
		Description: "DigitalOcean Personal Access Token",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== NPM =====
	{
		Name:        "NPM Token",
		Pattern:     `(?i)(npm_[A-Za-z0-9]{36})`,
		Description: "NPM Access Token",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== GENERIC API KEYS =====
	{
		Name:        "Generic API Key",
		Pattern:     `(?i)(api_key|apikey|api-key)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{32,})['\"]?`,
		Description: "Generic API Key",
		Severity:    "medium",
		Entropy:     4.0,
		FalsePositivePatterns: []string{
			`(?i)your_api_key`,
			`(?i)example`,
			`(?i)test`,
			`(?i)sample`,
			`(?i)placeholder`,
			`(?i)xxxxxxxx`,
		},
	},
	{
		Name:        "Generic Secret",
		Pattern:     `(?i)(secret|secret_key|app_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`,
		Description: "Generic Secret",
		Severity:    "medium",
		Entropy:     4.5,
		FalsePositivePatterns: []string{
			`(?i)your_secret`,
			`(?i)example`,
			`(?i)test`,
			`(?i)sample`,
		},
	},

	// ===== PRIVATE KEYS =====
	{
		Name:        "RSA Private Key",
		Pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
		Description: "RSA Private Key",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "SSH Private Key",
		Pattern:     `-----BEGIN OPENSSH PRIVATE KEY-----`,
		Description: "OpenSSH Private Key",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "EC Private Key",
		Pattern:     `-----BEGIN EC PRIVATE KEY-----`,
		Description: "EC Private Key",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "PGP Private Key",
		Pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		Description: "PGP Private Key",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== DATABASE CREDENTIALS =====
	{
		Name:        "Database Connection String",
		Pattern:     `(?i)(mongodb|mysql|postgres|postgresql)://[^\s'"]+:[^\s'"]+@[^\s'"]+`,
		Description: "Database Connection String with Credentials",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "JDBC Connection String",
		Pattern:     `(?i)jdbc:[^\s'"]+password=[^\s'";]+`,
		Description: "JDBC Connection String with Password",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== JWT TOKENS =====
	{
		Name:        "JWT Token",
		Pattern:     `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
		Description: "JSON Web Token (JWT)",
		Severity:    "high",
		Entropy:     0,
		FalsePositivePatterns: []string{
			`(?i)example`,
			`(?i)test`,
		},
	},

	// ===== OAUTH / BEARER TOKENS =====
	{
		Name:        "Bearer Token",
		Pattern:     `(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})`,
		Description: "Bearer Token",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== PASSWORDS IN CODE =====
	{
		Name:        "Password in Code",
		Pattern:     `(?i)(password|passwd|pwd)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]`,
		Description: "Hardcoded Password",
		Severity:    "high",
		Entropy:     3.5,
		FalsePositivePatterns: []string{
			`(?i)password`,
			`(?i)your_password`,
			`(?i)example`,
			`(?i)test`,
			`(?i)\*\*\*\*`,
		},
	},

	// ===== ENCRYPTION KEYS =====
	{
		Name:        "Encryption Key",
		Pattern:     `(?i)(encryption_key|encrypt_key|cipher_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{32,})['\"]?`,
		Description: "Encryption Key",
		Severity:    "critical",
		Entropy:     4.5,
	},

	// ===== WEBHOOKS =====
	{
		Name:        "Discord Webhook",
		Pattern:     `https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`,
		Description: "Discord Webhook URL",
		Severity:    "medium",
		Entropy:     0,
	},
	{
		Name:        "Telegram Bot Token",
		Pattern:     `(?i)\d{8,10}:[A-Za-z0-9_-]{35}`,
		Description: "Telegram Bot Token",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== CLOUD STORAGE =====
	{
		Name:        "Google Cloud Storage URL",
		Pattern:     `https://storage\.googleapis\.com/[a-z0-9._-]+`,
		Description: "Google Cloud Storage URL",
		Severity:    "low",
		Entropy:     0,
	},
	{
		Name:        "Azure Blob Storage URL",
		Pattern:     `https://[a-z0-9]+\.blob\.core\.windows\.net`,
		Description: "Azure Blob Storage URL",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== INTERNAL IPs / DOMAINS =====
	{
		Name:        "Internal IP Address",
		Pattern:     `(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`,
		Description: "Internal/Private IP Address",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== HIGH ENTROPY STRINGS =====
	{
		Name:        "High Entropy String",
		Pattern:     `(?i)(token|key|secret|password|passwd|auth)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{32,})['\"]?`,
		Description: "High Entropy String (Potential Secret)",
		Severity:    "medium",
		Entropy:     5.0, // High entropy threshold
		FalsePositivePatterns: []string{
			`(?i)example`,
			`(?i)test`,
			`(?i)sample`,
			`(?i)placeholder`,
		},
	},

	// ===== CONFIGURATION FILES (.env, config, etc.) =====
	{
		Name:        ".env File Exposed",
		Pattern:     `\.env`,
		Description: "Environment configuration file (.env) detected",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Config File with Credentials",
		Pattern:     `(?i)(config\.(json|yml|yaml|xml|ini|conf|properties))`,
		Description: "Configuration file that may contain credentials",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "Environment Variable in Code",
		Pattern:     `(?i)(process\.env\.|env\[|ENV\[)['"]([A-Z_]+)['"]`,
		Description: "Environment variable reference (may expose variable names)",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== REDIS / MEMCACHED =====
	{
		Name:        "Redis Connection String",
		Pattern:     `redis://[^\s'"]+:[^\s'"]+@[^\s'"]+`,
		Description: "Redis connection string with password",
		Severity:    "critical",
		Entropy:     0,
	},
	{
		Name:        "Redis Password",
		Pattern:     `(?i)(redis_password|redispass)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "Redis password",
		Severity:    "high",
		Entropy:     3.5,
	},

	// ===== SMTP / EMAIL =====
	{
		Name:        "SMTP Credentials",
		Pattern:     `(?i)smtp://[^\s'"]+:[^\s'"]+@[^\s'"]+`,
		Description: "SMTP connection string with credentials",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "Email Password",
		Pattern:     `(?i)(email_password|mail_password|smtp_password)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "Email/SMTP password",
		Severity:    "high",
		Entropy:     3.5,
	},

	// ===== FTP CREDENTIALS =====
	{
		Name:        "FTP Connection String",
		Pattern:     `ftp://[^\s'"]+:[^\s'"]+@[^\s'"]+`,
		Description: "FTP connection string with credentials",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== OAUTH / SESSION =====
	{
		Name:        "OAuth Client Secret",
		Pattern:     `(?i)(oauth_client_secret|client_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`,
		Description: "OAuth client secret",
		Severity:    "critical",
		Entropy:     4.0,
	},
	{
		Name:        "Session Secret/Key",
		Pattern:     `(?i)(session_secret|session_key|cookie_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?`,
		Description: "Session secret key",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== TOKENS =====
	{
		Name:        "Access Token",
		Pattern:     `(?i)(access_token)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?`,
		Description: "Generic access token",
		Severity:    "high",
		Entropy:     4.0,
		FalsePositivePatterns: []string{
			`(?i)your_token`,
			`(?i)access_token_here`,
		},
	},
	{
		Name:        "Refresh Token",
		Pattern:     `(?i)(refresh_token)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?`,
		Description: "Refresh token",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== CERTIFICATE PASSWORDS =====
	{
		Name:        "Certificate Password",
		Pattern:     `(?i)(cert_password|certificate_password|keystore_password)[\s]*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?`,
		Description: "Certificate/Keystore password",
		Severity:    "high",
		Entropy:     3.0,
	},

	// ===== CRYPTO WALLETS =====
	{
		Name:        "Bitcoin Private Key",
		Pattern:     `(?i)(bitcoin_private_key|btc_private)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{51,52})['\"]?`,
		Description: "Bitcoin private key",
		Severity:    "critical",
		Entropy:     4.5,
	},
	{
		Name:        "Ethereum Private Key",
		Pattern:     `(?i)(ethereum_private_key|eth_private)[\s]*[=:]\s*['\"]?(0x[a-fA-F0-9]{64})['\"]?`,
		Description: "Ethereum private key",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== AUTHORIZATION HEADERS =====
	{
		Name:        "Authorization Header",
		Pattern:     `(?i)authorization[\s]*:[\s]*['"]?([A-Za-z0-9+/=_\-]{20,})['"]?`,
		Description: "Authorization header value",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== DATADOG / NEW RELIC =====
	{
		Name:        "Datadog API Key",
		Pattern:     `(?i)(datadog_api_key|dd_api_key)[\s]*[=:]\s*['\"]?([a-f0-9]{32})['\"]?`,
		Description: "Datadog API key",
		Severity:    "high",
		Entropy:     0,
	},
	{
		Name:        "New Relic License Key",
		Pattern:     `(?i)(new_relic_license_key|newrelic_license)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?`,
		Description: "New Relic license key",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== PAYPAL / RAZORPAY =====
	{
		Name:        "PayPal Credentials",
		Pattern:     `(?i)(paypal_client_id|paypal_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`,
		Description: "PayPal API credentials",
		Severity:    "critical",
		Entropy:     4.0,
	},
	{
		Name:        "Razorpay Key",
		Pattern:     `(?i)(razorpay_key_id|razorpay_key_secret|rzp_test_|rzp_live_)[\s]*[=:]*\s*['\"]?([A-Za-z0-9]{20,})['\"]?`,
		Description: "Razorpay API key",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== SOCIAL MEDIA API KEYS =====
	{
		Name:        "Facebook Access Token",
		Pattern:     `(?i)(facebook_access_token|fb_access_token|facebook_app_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{32,})['\"]?`,
		Description: "Facebook API access token or app secret",
		Severity:    "high",
		Entropy:     4.0,
	},
	{
		Name:        "Twitter API Secret",
		Pattern:     `(?i)(twitter_api_secret|twitter_consumer_secret|twitter_access_token)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{35,})['\"]?`,
		Description: "Twitter API secret or access token",
		Severity:    "high",
		Entropy:     4.0,
	},
	{
		Name:        "LinkedIn Secret",
		Pattern:     `(?i)(linkedin_client_secret|linkedin_api_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{16,})['\"]?`,
		Description: "LinkedIn API secret",
		Severity:    "high",
		Entropy:     4.0,
	},
	{
		Name:        "Instagram Access Token",
		Pattern:     `(?i)(instagram_access_token|instagram_client_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{32,})['\"]?`,
		Description: "Instagram API access token or secret",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== PLAID =====
	{
		Name:        "Plaid Secret",
		Pattern:     `(?i)(plaid_secret|plaid_client_id)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{24,})['\"]?`,
		Description: "Plaid API secret",
		Severity:    "critical",
		Entropy:     4.0,
	},

	// ===== FIREBASE =====
	{
		Name:        "Firebase API Key",
		Pattern:     `(?i)(firebase_api_key|firebase)[\s]*[=:]\s*['\"]?(AIza[0-9A-Za-z\-_]{35})['\"]?`,
		Description: "Firebase API Key",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== MONGODB =====
	{
		Name:        "MongoDB Credentials",
		Pattern:     `(?i)(mongo_pass|mongo_password|mongodb_password)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "MongoDB password",
		Severity:    "critical",
		Entropy:     3.5,
	},

	// ===== CLOUDFLARE =====
	{
		Name:        "Cloudflare API Key",
		Pattern:     `(?i)(cloudflare_api_key|cf_api_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{37,})['\"]?`,
		Description: "Cloudflare API key",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== CLOUDFRONT / BIGQUERY =====
	{
		Name:        "AWS CloudFront Key",
		Pattern:     `(?i)(cloudfront_key|cloudfront_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{40,})['\"]?`,
		Description: "AWS CloudFront signing key",
		Severity:    "high",
		Entropy:     4.0,
	},
	{
		Name:        "BigQuery Credentials",
		Pattern:     `(?i)(bigquery|gcp_bigquery)`,
		Description: "BigQuery credentials reference",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== STORAGE BUCKETS =====
	{
		Name:        "S3 Bucket Reference",
		Pattern:     `(?i)(s3_bucket|s3\.bucket|bucket_name)[\s]*[=:]\s*['\"]?([a-z0-9.-]{3,63})['\"]?`,
		Description: "AWS S3 bucket reference",
		Severity:    "low",
		Entropy:     0,
	},
	{
		Name:        "GCP Storage Bucket",
		Pattern:     `(?i)(gs://[a-z0-9._-]+)`,
		Description: "Google Cloud Storage bucket",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== ROLE ARN / SERVICE ACCOUNT =====
	{
		Name:        "AWS Role ARN",
		Pattern:     `(?i)(arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_\-+=,.@]+)`,
		Description: "AWS IAM Role ARN",
		Severity:    "medium",
		Entropy:     0,
	},
	{
		Name:        "GCP Service Account Email",
		Pattern:     `(?i)([a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com)`,
		Description: "GCP Service Account Email",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== BILLING / PAYMENT =====
	{
		Name:        "Payment Token Reference",
		Pattern:     `(?i)(billing|payment|billing_key|payment_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?`,
		Description: "Payment/Billing token",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== CONSUMER KEYS =====
	{
		Name:        "Consumer Key/Secret",
		Pattern:     `(?i)(consumer_key|consumer_secret)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`,
		Description: "OAuth consumer key or secret",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== IMAP / MAIL =====
	{
		Name:        "IMAP Credentials",
		Pattern:     `(?i)(imap_password|imap_user|mail_password)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "IMAP/Mail credentials",
		Severity:    "high",
		Entropy:     3.5,
	},

	// ===== APP IDs =====
	{
		Name:        "Application ID",
		Pattern:     `(?i)(app_id|appid|application_id)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{16,})['\"]?`,
		Description: "Application ID",
		Severity:    "low",
		Entropy:     0,
		FalsePositivePatterns: []string{
			`(?i)your_app_id`,
			`(?i)example`,
		},
	},

	// ===== SESSION ID =====
	{
		Name:        "Session ID",
		Pattern:     `(?i)(session_id|sid|sessionid)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{32,})['\"]?`,
		Description: "Session identifier",
		Severity:    "medium",
		Entropy:     4.0,
	},

	// ===== PROXY CREDENTIALS =====
	{
		Name:        "Proxy Password",
		Pattern:     `(?i)(proxy_pass|proxy_password|http_proxy_password)[\s]*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?`,
		Description: "Proxy password",
		Severity:    "high",
		Entropy:     3.0,
	},

	// ===== HOSTNAME / USERNAME =====
	{
		Name:        "Admin Username",
		Pattern:     `(?i)(admin|administrator|root|superuser)[\s]*[=:]\s*['\"]?(admin|administrator|root|sa)['\"]?`,
		Description: "Administrative username",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== CIPHER / DECODE / HASH =====
	{
		Name:        "Cipher Key",
		Pattern:     `(?i)(cipher|cipher_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{24,})['\"]?`,
		Description: "Cipher key",
		Severity:    "high",
		Entropy:     4.5,
	},
	{
		Name:        "Salt Value",
		Pattern:     `(?i)(salt|password_salt|hash_salt)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?`,
		Description: "Cryptographic salt",
		Severity:    "medium",
		Entropy:     4.0,
	},

	// ===== CSRF TOKENS =====
	{
		Name:        "CSRF Token",
		Pattern:     `(?i)(csrf_token|csrf|x_csrf_token|xsrf_token)[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`,
		Description: "CSRF protection token",
		Severity:    "low",
		Entropy:     0,
	},

	// ===== MASTER KEY =====
	{
		Name:        "Master Key",
		Pattern:     `(?i)(master_key|masterkey)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{24,})['\"]?`,
		Description: "Master encryption key",
		Severity:    "critical",
		Entropy:     4.5,
	},

	// ===== BACKUP / RECOVERY =====
	{
		Name:        "Backup Credentials",
		Pattern:     `(?i)(backup_password|recovery_key|restore_key)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "Backup or recovery credentials",
		Severity:    "high",
		Entropy:     3.5,
	},

	// ===== KEYSTORE =====
	{
		Name:        "Java Keystore",
		Pattern:     `(?i)(keystore|jks_password|keystore_pass)[\s]*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?`,
		Description: "Java KeyStore password",
		Severity:    "high",
		Entropy:     3.0,
	},

	// ===== ID TOKEN =====
	{
		Name:        "ID Token",
		Pattern:     `(?i)(id_token)[\s]*[=:]\s*['\"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['\"]?`,
		Description: "OpenID Connect ID token",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== WEBHOOK URLs =====
	{
		Name:        "Generic Webhook URL",
		Pattern:     `(?i)(webhook|webhook_url|hook_url)[\s]*[=:]\s*['\"]?(https?://[^\s'\"]+)['\"]?`,
		Description: "Webhook URL",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== SIGNIN/SIGNUP =====
	{
		Name:        "Login Credentials",
		Pattern:     `(?i)(login|signin|signup)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "Login/Signin credentials",
		Severity:    "medium",
		Entropy:     3.5,
		FalsePositivePatterns: []string{
			`(?i)/login`,
			`(?i)/signin`,
			`(?i)login_url`,
		},
	},

	// ===== DECODE =====
	{
		Name:        "Decode Key",
		Pattern:     `(?i)(decode_key|decode)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{20,})['\"]?`,
		Description: "Decoding key",
		Severity:    "high",
		Entropy:     4.0,
	},

	// ===== SIGNATURE =====
	{
		Name:        "Signature Secret",
		Pattern:     `(?i)(signature|signature_secret|signing_key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{24,})['\"]?`,
		Description: "Digital signature secret",
		Severity:    "high",
		Entropy:     4.5,
	},

	// ===== ACCOUNT =====
	{
		Name:        "Account Credentials",
		Pattern:     `(?i)(account_key|account_secret|account_password)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?`,
		Description: "Account credentials",
		Severity:    "high",
		Entropy:     3.5,
	},

	// ===== KEY_ID =====
	{
		Name:        "Key ID",
		Pattern:     `(?i)(key_id|keyid)[\s]*[=:]\s*['\"]?([A-Za-z0-9]{16,})['\"]?`,
		Description: "Cryptographic key identifier",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== SENSITIVE FILES =====
	{
		Name:        "Sensitive File Extensions",
		Pattern:     `(?i)\.(log|cache|secret|db|backup|bak|swp|old|tar|tgz|7z|passwd|htpasswd|pgp|ovpn|bash_history|zsh_history|mysql_history|psql_history|sqlite3|dmp|rdp|sftp|sql|plist|dockerfile|bashrc|zshrc|npmrc|gitconfig|pgpass|id_rsa|ppk|openvpn|gpg|csr|cer|apk|mobileprovision|keystore|token|cloud|envrc|bash_aliases|my\.cnf|netrc|enc)$`,
		Description: "Sensitive file with potentially leaked credentials",
		Severity:    "high",
		Entropy:     0,
	},

	// ===== SSL/TLS CERTIFICATES =====
	{
		Name:        "Certificate File",
		Pattern:     `(?i)\.(crt|pem|key|p12|pfx|p7b|cert)$`,
		Description: "SSL/TLS certificate or key file",
		Severity:    "critical",
		Entropy:     0,
	},

	// ===== ARCHIVE/COMPRESSED FILES =====
	{
		Name:        "Archive with Potential Secrets",
		Pattern:     `(?i)\.(gz|rar|zip|tgz|tar\.gz|7z)$`,
		Description: "Compressed archive that may contain sensitive files",
		Severity:    "medium",
		Entropy:     0,
	},

	// ===== SCRIPT FILES =====
	{
		Name:        "Shell Script",
		Pattern:     `(?i)\.(sh|ps1|rc|profile)$`,
		Description: "Shell script that may contain credentials",
		Severity:    "medium",
		Entropy:     0,
	},
}

// CompilePatterns pre-compiles all regex patterns
func CompilePatterns() {
	for i := range SecretPatterns {
		if SecretPatterns[i].Regex == nil {
			SecretPatterns[i].Regex = regexp.MustCompile(SecretPatterns[i].Pattern)
		}
	}
}

// IsFalsePositive checks if a match is a false positive
func (sp *SecretPattern) IsFalsePositive(match string) bool {
	for _, fpPattern := range sp.FalsePositivePatterns {
		if matched, _ := regexp.MatchString(fpPattern, match); matched {
			return true
		}
	}
	return false
}

// GetPatternsBySeverity returns patterns filtered by severity
func GetPatternsBySeverity(severity string) []SecretPattern {
	var filtered []SecretPattern
	for _, p := range SecretPatterns {
		if p.Severity == severity {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
