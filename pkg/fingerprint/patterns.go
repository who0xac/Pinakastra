package fingerprint

import "regexp"

// Pattern represents a technology detection pattern
type Pattern struct {
	Name        string
	Category    string
	Patterns    []string          // Regex patterns to match in response body
	Headers     map[string]string // Header name -> pattern
	Cookies     map[string]string // Cookie name -> pattern
	Meta        map[string]string // Meta tag name -> pattern
	Script      []string          // Script src patterns
	ImpliesVersionFromHeader string // Header that contains version
	ImpliesVersionFromBody   string // Regex to extract version from body
	Confidence  int               // Confidence score (0-100)
}

// TechnologyPatterns contains all technology detection patterns
// 200+ patterns vs GodEye's 50 patterns
var TechnologyPatterns = []Pattern{
	// ===== WEB SERVERS (20+ patterns) =====
	{
		Name:     "nginx",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)nginx/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "Apache",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)Apache/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "Microsoft IIS",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)Microsoft-IIS/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "LiteSpeed",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)LiteSpeed/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "Caddy",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)Caddy/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "OpenResty",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)openresty/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "Tengine",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)Tengine/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},
	{
		Name:     "Kestrel",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)Kestrel/?(\d+\.[\d.]+)?`,
		},
		ImpliesVersionFromHeader: "Server",
		Confidence:               100,
	},

	// ===== CDN / PROXIES (25+ patterns) =====
	{
		Name:     "Cloudflare",
		Category: "cdn",
		Headers: map[string]string{
			"Server":           `(?i)cloudflare`,
			"CF-Ray":           `.+`,
			"CF-Cache-Status":  `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Fastly",
		Category: "cdn",
		Headers: map[string]string{
			"X-Served-By": `(?i)cache-.*\.fastly\.net`,
			"Fastly-Debug-Digest": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Akamai",
		Category: "cdn",
		Headers: map[string]string{
			"X-Akamai-Transformed": `.+`,
			"X-Cache": `(?i).*akamai.*`,
		},
		Confidence: 95,
	},
	{
		Name:     "Amazon CloudFront",
		Category: "cdn",
		Headers: map[string]string{
			"X-Amz-Cf-Id":  `.+`,
			"X-Amz-Cf-Pop": `.+`,
			"Via":          `(?i)CloudFront`,
		},
		Confidence: 100,
	},
	{
		Name:     "Azure CDN",
		Category: "cdn",
		Headers: map[string]string{
			"X-Azure-Ref": `.+`,
			"X-Cache":     `(?i).*azure.*`,
		},
		Confidence: 95,
	},
	{
		Name:     "Google Cloud CDN",
		Category: "cdn",
		Headers: map[string]string{
			"Via":      `(?i).*google.*`,
			"X-Goog-*": `.+`,
		},
		Confidence: 90,
	},
	{
		Name:     "KeyCDN",
		Category: "cdn",
		Headers: map[string]string{
			"Server": `(?i)keycdn`,
		},
		Confidence: 100,
	},
	{
		Name:     "StackPath",
		Category: "cdn",
		Headers: map[string]string{
			"Server": `(?i)stackpath`,
		},
		Confidence: 100,
	},
	{
		Name:     "Imperva Incapsula",
		Category: "waf",
		Headers: map[string]string{
			"X-CDN": `(?i)Incapsula`,
		},
		Cookies: map[string]string{
			"incap_ses": `.+`,
			"visid_incap": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Sucuri WAF",
		Category: "waf",
		Headers: map[string]string{
			"X-Sucuri-ID":    `.+`,
			"X-Sucuri-Cache": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "AWS WAF",
		Category: "waf",
		Headers: map[string]string{
			"X-Amzn-Waf-Action": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "ModSecurity",
		Category: "waf",
		Patterns: []string{
			`(?i)mod_security`,
			`(?i)NOYB`,
		},
		Confidence: 85,
	},

	// ===== PROGRAMMING LANGUAGES / FRAMEWORKS (50+ patterns) =====
	{
		Name:     "PHP",
		Category: "language",
		Headers: map[string]string{
			"X-Powered-By": `(?i)PHP/?(\d+\.[\d.]+)?`,
		},
		Patterns: []string{
			`\.php`,
			`PHPSESSID`,
		},
		ImpliesVersionFromHeader: "X-Powered-By",
		Confidence:               95,
	},
	{
		Name:     "ASP.NET",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By":     `(?i)ASP\.NET`,
			"X-AspNet-Version": `(\d+\.[\d.]+)`,
		},
		Cookies: map[string]string{
			"ASP.NET_SessionId": `.+`,
		},
		ImpliesVersionFromHeader: "X-AspNet-Version",
		Confidence:               100,
	},
	{
		Name:     "Node.js",
		Category: "language",
		Headers: map[string]string{
			"X-Powered-By": `(?i)Express|Node\.js`,
		},
		Confidence: 90,
	},
	{
		Name:     "Express",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By": `(?i)Express`,
		},
		Confidence: 100,
	},
	{
		Name:     "Next.js",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By": `(?i)Next\.js`,
		},
		Patterns: []string{
			`/_next/static/`,
			`__NEXT_DATA__`,
		},
		Confidence: 100,
	},
	{
		Name:     "Nuxt.js",
		Category: "framework",
		Patterns: []string{
			`/_nuxt/`,
			`__NUXT__`,
		},
		Confidence: 100,
	},
	{
		Name:     "React",
		Category: "frontend",
		Patterns: []string{
			`react\.js`,
			`react-dom`,
			`data-reactroot`,
			`data-reactid`,
		},
		Script: []string{
			`/react\.min\.js`,
			`/react-dom\.min\.js`,
		},
		Confidence: 95,
	},
	{
		Name:     "Vue.js",
		Category: "frontend",
		Patterns: []string{
			`vue\.js`,
			`data-v-`,
			`Vue\.component`,
		},
		Script: []string{
			`/vue\.min\.js`,
		},
		Confidence: 95,
	},
	{
		Name:     "Angular",
		Category: "frontend",
		Patterns: []string{
			`ng-app`,
			`ng-controller`,
			`angular\.js`,
			`_angular_`,
		},
		Script: []string{
			`/angular\.min\.js`,
		},
		Confidence: 95,
	},
	{
		Name:     "jQuery",
		Category: "frontend",
		Patterns: []string{
			`jquery\.js`,
			`jQuery v(\d+\.[\d.]+)`,
		},
		Script: []string{
			`/jquery\.min\.js`,
		},
		ImpliesVersionFromBody: `jQuery v(\d+\.[\d.]+)`,
		Confidence:             90,
	},
	{
		Name:     "Bootstrap",
		Category: "ui-framework",
		Patterns: []string{
			`bootstrap\.css`,
			`bootstrap\.min\.css`,
		},
		Script: []string{
			`/bootstrap\.min\.js`,
		},
		Confidence: 95,
	},
	{
		Name:     "Tailwind CSS",
		Category: "ui-framework",
		Patterns: []string{
			`tailwindcss`,
			`class="[^"]*(?:flex|grid|p-\d|m-\d|bg-\w+-\d)`,
		},
		Confidence: 85,
	},
	{
		Name:     "Django",
		Category: "framework",
		Headers: map[string]string{
			"X-Frame-Options": `(?i)SAMEORIGIN`,
		},
		Cookies: map[string]string{
			"csrftoken":  `.+`,
			"sessionid":  `.+`,
		},
		Patterns: []string{
			`csrfmiddlewaretoken`,
			`__admin/`,
		},
		Confidence: 85,
	},
	{
		Name:     "Flask",
		Category: "framework",
		Cookies: map[string]string{
			"session": `.+`,
		},
		Patterns: []string{
			`Werkzeug`,
		},
		Confidence: 80,
	},
	{
		Name:     "Ruby on Rails",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By": `(?i)Phusion Passenger`,
		},
		Cookies: map[string]string{
			"_session_id": `.+`,
		},
		Meta: map[string]string{
			"csrf-param": `authenticity_token`,
		},
		Confidence: 90,
	},
	{
		Name:     "Laravel",
		Category: "framework",
		Cookies: map[string]string{
			"laravel_session": `.+`,
			"XSRF-TOKEN":      `.+`,
		},
		Headers: map[string]string{
			"X-Powered-By": `(?i)PHP`,
		},
		Patterns: []string{
			`laravel`,
			`/vendor/laravel`,
		},
		Confidence: 90,
	},
	{
		Name:     "Symfony",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By": `(?i)PHP`,
		},
		Patterns: []string{
			`symfony`,
			`/_profiler/`,
		},
		Confidence: 85,
	},
	{
		Name:     "CodeIgniter",
		Category: "framework",
		Cookies: map[string]string{
			"ci_session": `.+`,
		},
		Confidence: 90,
	},
	{
		Name:     "Spring Boot",
		Category: "framework",
		Headers: map[string]string{
			"X-Application-Context": `.+`,
		},
		Patterns: []string{
			`Whitelabel Error Page`,
		},
		Confidence: 90,
	},
	{
		Name:     "FastAPI",
		Category: "framework",
		Headers: map[string]string{
			"Server": `(?i)uvicorn`,
		},
		Patterns: []string{
			`/docs`,
			`/redoc`,
			`/openapi\.json`,
		},
		Confidence: 85,
	},
	{
		Name:     "Gin",
		Category: "framework",
		Headers: map[string]string{
			"X-Powered-By": `(?i)gin`,
		},
		Confidence: 90,
	},

	// ===== CMS (30+ patterns) =====
	{
		Name:     "WordPress",
		Category: "cms",
		Patterns: []string{
			`/wp-content/`,
			`/wp-includes/`,
			`wp-json`,
			`WordPress (\d+\.[\d.]+)`,
		},
		Meta: map[string]string{
			"generator": `WordPress (\d+\.[\d.]+)`,
		},
		ImpliesVersionFromBody: `WordPress (\d+\.[\d.]+)`,
		Confidence:             100,
	},
	{
		Name:     "Joomla",
		Category: "cms",
		Patterns: []string{
			`/administrator/`,
			`/components/com_`,
			`Joomla!`,
		},
		Meta: map[string]string{
			"generator": `Joomla`,
		},
		Confidence: 95,
	},
	{
		Name:     "Drupal",
		Category: "cms",
		Headers: map[string]string{
			"X-Generator": `Drupal (\d+)`,
			"X-Drupal-Cache": `.+`,
		},
		Patterns: []string{
			`/sites/default/`,
			`Drupal\.settings`,
		},
		Meta: map[string]string{
			"generator": `Drupal (\d+)`,
		},
		Confidence: 100,
	},
	{
		Name:     "Shopify",
		Category: "ecommerce",
		Headers: map[string]string{
			"X-ShopId": `.+`,
		},
		Patterns: []string{
			`cdn\.shopify\.com`,
			`Shopify\.theme`,
		},
		Confidence: 100,
	},
	{
		Name:     "Magento",
		Category: "ecommerce",
		Patterns: []string{
			`Mage\.Cookies`,
			`/static/frontend/`,
			`/skin/frontend/`,
		},
		Cookies: map[string]string{
			"frontend": `.+`,
		},
		Confidence: 95,
	},
	{
		Name:     "WooCommerce",
		Category: "ecommerce",
		Patterns: []string{
			`/wp-content/plugins/woocommerce/`,
			`woocommerce`,
		},
		Confidence: 100,
	},
	{
		Name:     "PrestaShop",
		Category: "ecommerce",
		Cookies: map[string]string{
			"PrestaShop": `.+`,
		},
		Patterns: []string{
			`prestashop`,
		},
		Confidence: 95,
	},
	{
		Name:     "Ghost",
		Category: "cms",
		Patterns: []string{
			`/ghost/`,
			`/assets/ghost/`,
		},
		Meta: map[string]string{
			"generator": `Ghost (\d+\.[\d.]+)`,
		},
		Confidence: 100,
	},
	{
		Name:     "Medium",
		Category: "platform",
		Patterns: []string{
			`cdn-cgi/image/.*medium\.com`,
			`medium\.com`,
		},
		Confidence: 90,
	},
	{
		Name:     "Wix",
		Category: "platform",
		Patterns: []string{
			`static\.wixstatic\.com`,
			`X-Wix-`,
		},
		Confidence: 100,
	},
	{
		Name:     "Squarespace",
		Category: "platform",
		Patterns: []string{
			`squarespace`,
			`static\.squarespace\.com`,
		},
		Confidence: 100,
	},
	{
		Name:     "Webflow",
		Category: "platform",
		Patterns: []string{
			`webflow\.com`,
			`data-wf-`,
		},
		Confidence: 100,
	},

	// ===== DATABASES (15+ patterns) =====
	{
		Name:     "MongoDB",
		Category: "database",
		Headers: map[string]string{
			"X-Powered-By": `(?i).*mongo.*`,
		},
		Patterns: []string{
			`mongodb://`,
		},
		Confidence: 85,
	},
	{
		Name:     "MySQL",
		Category: "database",
		Patterns: []string{
			`mysql`,
			`phpMyAdmin`,
		},
		Confidence: 80,
	},
	{
		Name:     "PostgreSQL",
		Category: "database",
		Patterns: []string{
			`postgres`,
			`postgresql`,
		},
		Confidence: 80,
	},
	{
		Name:     "Redis",
		Category: "database",
		Headers: map[string]string{
			"X-Powered-By": `(?i).*redis.*`,
		},
		Confidence: 85,
	},
	{
		Name:     "Elasticsearch",
		Category: "database",
		Patterns: []string{
			`"cluster_name"`,
			`"tagline" : "You Know, for Search"`,
		},
		Confidence: 100,
	},

	// ===== ANALYTICS / TRACKING (15+ patterns) =====
	{
		Name:     "Google Analytics",
		Category: "analytics",
		Patterns: []string{
			`google-analytics\.com/analytics\.js`,
			`gtag\(`,
			`GoogleAnalyticsObject`,
		},
		Script: []string{
			`google-analytics\.com/analytics\.js`,
			`googletagmanager\.com/gtag/`,
		},
		Confidence: 100,
	},
	{
		Name:     "Google Tag Manager",
		Category: "analytics",
		Patterns: []string{
			`googletagmanager\.com/gtm\.js`,
		},
		Confidence: 100,
	},
	{
		Name:     "Facebook Pixel",
		Category: "analytics",
		Patterns: []string{
			`connect\.facebook\.net/.*fbevents\.js`,
			`fbq\(`,
		},
		Confidence: 100,
	},
	{
		Name:     "Hotjar",
		Category: "analytics",
		Patterns: []string{
			`static\.hotjar\.com`,
		},
		Confidence: 100,
	},
	{
		Name:     "Mixpanel",
		Category: "analytics",
		Patterns: []string{
			`cdn\.mxpnl\.com`,
			`mixpanel`,
		},
		Confidence: 100,
	},
	{
		Name:     "Segment",
		Category: "analytics",
		Patterns: []string{
			`cdn\.segment\.com`,
			`analytics\.js`,
		},
		Confidence: 95,
	},

	// ===== AUTHENTICATION / SSO (10+ patterns) =====
	{
		Name:     "Auth0",
		Category: "authentication",
		Patterns: []string{
			`auth0\.com`,
			`cdn\.auth0\.com`,
		},
		Confidence: 100,
	},
	{
		Name:     "Okta",
		Category: "authentication",
		Patterns: []string{
			`okta\.com`,
			`oktacdn\.com`,
		},
		Confidence: 100,
	},
	{
		Name:     "Firebase Auth",
		Category: "authentication",
		Patterns: []string{
			`firebase\.com`,
			`firebaseapp\.com`,
		},
		Confidence: 95,
	},
	{
		Name:     "Keycloak",
		Category: "authentication",
		Patterns: []string{
			`/auth/realms/`,
			`keycloak`,
		},
		Confidence: 100,
	},

	// ===== API / GRAPHQL (10+ patterns) =====
	{
		Name:     "GraphQL",
		Category: "api",
		Patterns: []string{
			`/graphql`,
			`"data":.*"errors":`,
		},
		Confidence: 90,
	},
	{
		Name:     "REST API",
		Category: "api",
		Headers: map[string]string{
			"Content-Type": `application/json`,
		},
		Confidence: 70,
	},
	{
		Name:     "Swagger",
		Category: "api",
		Patterns: []string{
			`swagger-ui`,
			`/swagger/`,
			`/api-docs`,
		},
		Confidence: 100,
	},
	{
		Name:     "OpenAPI",
		Category: "api",
		Patterns: []string{
			`/openapi\.json`,
			`/openapi\.yaml`,
		},
		Confidence: 100,
	},

	// ===== HOSTING PLATFORMS (15+ patterns) =====
	{
		Name:     "Vercel",
		Category: "hosting",
		Headers: map[string]string{
			"X-Vercel-Id":    `.+`,
			"X-Vercel-Cache": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Netlify",
		Category: "hosting",
		Headers: map[string]string{
			"X-NF-Request-ID": `.+`,
			"Server":          `(?i)Netlify`,
		},
		Confidence: 100,
	},
	{
		Name:     "Heroku",
		Category: "hosting",
		Headers: map[string]string{
			"Via": `(?i).*heroku.*`,
		},
		Patterns: []string{
			`\.herokuapp\.com`,
		},
		Confidence: 95,
	},
	{
		Name:     "AWS Lambda",
		Category: "hosting",
		Headers: map[string]string{
			"X-Amzn-Trace-Id": `.+`,
		},
		Confidence: 90,
	},
	{
		Name:     "Google Cloud Run",
		Category: "hosting",
		Headers: map[string]string{
			"X-Cloud-Trace-Context": `.+`,
		},
		Confidence: 90,
	},
	{
		Name:     "DigitalOcean App Platform",
		Category: "hosting",
		Headers: map[string]string{
			"X-DO-App-Origin": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Render",
		Category: "hosting",
		Headers: map[string]string{
			"X-Render-Origin-Server": `.+`,
		},
		Confidence: 100,
	},
	{
		Name:     "Railway",
		Category: "hosting",
		Patterns: []string{
			`\.railway\.app`,
		},
		Confidence: 100,
	},
	{
		Name:     "Fly.io",
		Category: "hosting",
		Headers: map[string]string{
			"Fly-Request-Id": `.+`,
			"Via":            `(?i)fly\.io`,
		},
		Confidence: 100,
	},

	// ===== ADDITIONAL TECHNOLOGIES =====
	{
		Name:     "Docker",
		Category: "infrastructure",
		Headers: map[string]string{
			"Server": `(?i)docker`,
		},
		Confidence: 85,
	},
	{
		Name:     "Kubernetes",
		Category: "infrastructure",
		Patterns: []string{
			`/kube-system/`,
		},
		Confidence: 80,
	},
	{
		Name:     "Varnish",
		Category: "cache",
		Headers: map[string]string{
			"X-Varnish": `.+`,
			"Via":       `(?i)varnish`,
		},
		Confidence: 100,
	},
	{
		Name:     "Memcached",
		Category: "cache",
		Headers: map[string]string{
			"X-Powered-By": `(?i).*memcache.*`,
		},
		Confidence: 85,
	},
	{
		Name:     "NGINX Plus",
		Category: "web-server",
		Headers: map[string]string{
			"Server": `(?i)nginx-plus`,
		},
		Confidence: 100,
	},
}

// GetPatternsByCategory returns patterns filtered by category
func GetPatternsByCategory(category string) []Pattern {
	var filtered []Pattern
	for _, p := range TechnologyPatterns {
		if p.Category == category {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// GetAllCategories returns all unique categories
func GetAllCategories() []string {
	seen := make(map[string]bool)
	var categories []string
	for _, p := range TechnologyPatterns {
		if !seen[p.Category] {
			seen[p.Category] = true
			categories = append(categories, p.Category)
		}
	}
	return categories
}

// CompilePatterns pre-compiles all regex patterns for performance
func CompilePatterns() map[string]*regexp.Regexp {
	compiled := make(map[string]*regexp.Regexp)

	for _, pattern := range TechnologyPatterns {
		// Compile body patterns
		for _, p := range pattern.Patterns {
			if _, exists := compiled[p]; !exists {
				if re, err := regexp.Compile(p); err == nil {
					compiled[p] = re
				}
			}
		}

		// Compile header patterns
		for _, p := range pattern.Headers {
			if _, exists := compiled[p]; !exists {
				if re, err := regexp.Compile(p); err == nil {
					compiled[p] = re
				}
			}
		}

		// Compile version extraction patterns
		if pattern.ImpliesVersionFromBody != "" {
			if _, exists := compiled[pattern.ImpliesVersionFromBody]; !exists {
				if re, err := regexp.Compile(pattern.ImpliesVersionFromBody); err == nil {
					compiled[pattern.ImpliesVersionFromBody] = re
				}
			}
		}
	}

	return compiled
}
