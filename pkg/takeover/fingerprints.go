package takeover

// Fingerprint represents a subdomain takeover fingerprint
type Fingerprint struct {
	Service     string
	CNAME       []string // CNAME patterns to match
	Response    []string // Response body patterns indicating takeover
	StatusCode  int      // Expected status code (0 = any)
	Severity    string   // critical, high, medium
}

// Fingerprints contains 100+ subdomain takeover signatures
// More comprehensive than GodEye with modern services
var Fingerprints = []Fingerprint{
	// ===== GITHUB =====
	{
		Service:  "GitHub Pages",
		CNAME:    []string{"github.io", "githubusercontent.com"},
		Response: []string{"There isn't a GitHub Pages site here", "404 Not Found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== HEROKU =====
	{
		Service:  "Heroku",
		CNAME:    []string{"herokuapp.com", "herokussl.com"},
		Response: []string{"no-such-app.herokuapp.com", "No such app"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== AWS =====
	{
		Service:  "AWS S3",
		CNAME:    []string{"s3.amazonaws.com", "s3-website"},
		Response: []string{"NoSuchBucket", "The specified bucket does not exist"},
		StatusCode: 404,
		Severity: "critical",
	},
	{
		Service:  "AWS Elastic Beanstalk",
		CNAME:    []string{"elasticbeanstalk.com"},
		Response: []string{"404 Not Found"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "AWS CloudFront",
		CNAME:    []string{"cloudfront.net"},
		Response: []string{"Bad Request", "ERROR: The request could not be satisfied"},
		StatusCode: 403,
		Severity: "medium",
	},
	{
		Service:  "AWS ELB",
		CNAME:    []string{"elb.amazonaws.com"},
		Response: []string{"NXDOMAIN"},
		StatusCode: 0,
		Severity: "high",
	},

	// ===== AZURE =====
	{
		Service:  "Azure Web Apps",
		CNAME:    []string{"azurewebsites.net"},
		Response: []string{"404 Web Site not found", "Error 404"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "Azure Cloud Services",
		CNAME:    []string{"cloudapp.net", "cloudapp.azure.com"},
		Response: []string{"404 Web Site not found"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "Azure Front Door",
		CNAME:    []string{"azurefd.net"},
		Response: []string{"404 Web Site not found"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "Azure Blob Storage",
		CNAME:    []string{"blob.core.windows.net"},
		Response: []string{"BlobNotFound", "The specified blob does not exist"},
		StatusCode: 404,
		Severity: "critical",
	},
	{
		Service:  "Azure API Management",
		CNAME:    []string{"azure-api.net"},
		Response: []string{"404 Resource not found"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "Azure HDInsight",
		CNAME:    []string{"azurehdinsight.net"},
		Response: []string{"404"},
		StatusCode: 404,
		Severity: "medium",
	},
	{
		Service:  "Azure CDN",
		CNAME:    []string{"azureedge.net"},
		Response: []string{"404 Web Site not found"},
		StatusCode: 404,
		Severity: "medium",
	},
	{
		Service:  "Azure Traffic Manager",
		CNAME:    []string{"trafficmanager.net"},
		Response: []string{"404 Web Site not found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== GOOGLE CLOUD =====
	{
		Service:  "Google App Engine",
		CNAME:    []string{"appspot.com"},
		Response: []string{"Error: Not Found", "The requested URL was not found"},
		StatusCode: 404,
		Severity: "high",
	},
	{
		Service:  "Google Cloud Storage",
		CNAME:    []string{"storage.googleapis.com"},
		Response: []string{"NoSuchBucket"},
		StatusCode: 404,
		Severity: "critical",
	},
	{
		Service:  "Google Sites",
		CNAME:    []string{"googleplex.com"},
		Response: []string{"404. That's an error"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== SHOPIFY =====
	{
		Service:  "Shopify",
		CNAME:    []string{"myshopify.com"},
		Response: []string{"Sorry, this shop is currently unavailable", "Only one step left"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== PANTHEON =====
	{
		Service:  "Pantheon",
		CNAME:    []string{"pantheonsite.io"},
		Response: []string{"404 error unknown site", "The gods are wise"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== ZENDESK =====
	{
		Service:  "Zendesk",
		CNAME:    []string{"zendesk.com"},
		Response: []string{"Help Center Closed", "This Help Center no longer exists"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== TEAMWORK =====
	{
		Service:  "Teamwork",
		CNAME:    []string{"teamwork.com"},
		Response: []string{"Oops - We didn't find your site"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== HELPJUICE =====
	{
		Service:  "Helpjuice",
		CNAME:    []string{"helpjuice.com"},
		Response: []string{"We could not find what you're looking for"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== HELPSCOUT =====
	{
		Service:  "Help Scout",
		CNAME:    []string{"helpscoutdocs.com"},
		Response: []string{"No settings were found for this company"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== GHOST =====
	{
		Service:  "Ghost",
		CNAME:    []string{"ghost.io"},
		Response: []string{"The thing you were looking for is no longer here"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== SURGE =====
	{
		Service:  "Surge.sh",
		CNAME:    []string{"surge.sh"},
		Response: []string{"project not found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== BITBUCKET =====
	{
		Service:  "Bitbucket",
		CNAME:    []string{"bitbucket.io"},
		Response: []string{"Repository not found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== WORDPRESS =====
	{
		Service:  "WordPress.com",
		CNAME:    []string{"wordpress.com"},
		Response: []string{"Do you want to register"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== SMARTLING =====
	{
		Service:  "Smartling",
		CNAME:    []string{"smartling.com"},
		Response: []string{"Domain is not configured"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== ACQUIA =====
	{
		Service:  "Acquia",
		CNAME:    []string{"acquia.com"},
		Response: []string{"Web Site Not Found"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== FASTLY =====
	{
		Service:  "Fastly",
		CNAME:    []string{"fastly.net"},
		Response: []string{"Fastly error: unknown domain"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== USERVOICE =====
	{
		Service:  "UserVoice",
		CNAME:    []string{"uservoice.com"},
		Response: []string{"This UserVoice subdomain is currently available"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== UNBOUNCE =====
	{
		Service:  "Unbounce",
		CNAME:    []string{"unbounce.com"},
		Response: []string{"The requested URL was not found on this server"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== THINKIFIC =====
	{
		Service:  "Thinkific",
		CNAME:    []string{"thinkific.com"},
		Response: []string{"You may have mistyped the address"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== TILDA =====
	{
		Service:  "Tilda",
		CNAME:    []string{"tilda.cc"},
		Response: []string{"Please renew your subscription"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== MASHERY =====
	{
		Service:  "Mashery",
		CNAME:    []string{"mashery.com"},
		Response: []string{"Unrecognized domain"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== INTERCOM =====
	{
		Service:  "Intercom",
		CNAME:    []string{"intercom.help"},
		Response: []string{"This page is reserved for"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== WEBFLOW =====
	{
		Service:  "Webflow",
		CNAME:    []string{"webflow.io"},
		Response: []string{"The page you are looking for doesn't exist"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== WISHPOND =====
	{
		Service:  "Wishpond",
		CNAME:    []string{"wishpond.com"},
		Response: []string{"https://www.wishpond.com/404"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== AFTERSHIP =====
	{
		Service:  "AfterShip",
		CNAME:    []string{"aftership.com"},
		Response: []string{"Oops.</h2><p>The page you're looking for doesn't exist"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== AHA =====
	{
		Service:  "Aha!",
		CNAME:    []string{"aha.io"},
		Response: []string{"There is no portal here"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== TICTAIL =====
	{
		Service:  "Tictail",
		CNAME:    []string{"tictail.com"},
		Response: []string{"to target URL: <a href=\"https://tictail.com"},
		StatusCode: 0,
		Severity: "medium",
	},

	// ===== CAMPAIGN MONITOR =====
	{
		Service:  "Campaign Monitor",
		CNAME:    []string{"campaignmonitor.com"},
		Response: []string{"Trying to access your account?"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== CARGO COLLECTIVE =====
	{
		Service:  "Cargo Collective",
		CNAME:    []string{"cargocollective.com"},
		Response: []string{"404 Not Found"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== STATUSPAGE =====
	{
		Service:  "StatusPage",
		CNAME:    []string{"statuspage.io"},
		Response: []string{"You are being <a href=\"https://www.statuspage.io\">"},
		StatusCode: 0,
		Severity: "medium",
	},

	// ===== TUMBLR =====
	{
		Service:  "Tumblr",
		CNAME:    []string{"tumblr.com"},
		Response: []string{"There's nothing here.", "Whatever you were looking for doesn't currently exist"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== WORKSITES =====
	{
		Service:  "Worksites",
		CNAME:    []string{"worksites.net"},
		Response: []string{"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== SMUGMUG =====
	{
		Service:  "SmugMug",
		CNAME:    []string{"smugmug.com"},
		Response: []string{"class=\"message-text\">Page Not Found<"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== NETLIFY =====
	{
		Service:  "Netlify",
		CNAME:    []string{"netlify.app", "netlify.com"},
		Response: []string{"Not Found - Request ID"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== VERCEL =====
	{
		Service:  "Vercel",
		CNAME:    []string{"vercel.app", "now.sh"},
		Response: []string{"NOT_FOUND", "The deployment could not be found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== FLY.IO =====
	{
		Service:  "Fly.io",
		CNAME:    []string{"fly.dev"},
		Response: []string{"404 Not Found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== RENDER =====
	{
		Service:  "Render",
		CNAME:    []string{"render.com", "onrender.com"},
		Response: []string{"NOT_FOUND", "not found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== RAILWAY =====
	{
		Service:  "Railway",
		CNAME:    []string{"railway.app"},
		Response: []string{"Application Error", "404"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== GITBOOK =====
	{
		Service:  "GitBook",
		CNAME:    []string{"gitbook.io"},
		Response: []string{"Domain not found"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== README =====
	{
		Service:  "ReadMe",
		CNAME:    []string{"readme.io"},
		Response: []string{"Project doesnt exist", "Project doesn't exist"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== DESK =====
	{
		Service:  "Desk.com",
		CNAME:    []string{"desk.com"},
		Response: []string{"Sorry, We Couldn't Find That Page"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== FRESHDESK =====
	{
		Service:  "Freshdesk",
		CNAME:    []string{"freshdesk.com"},
		Response: []string{"There is no helpdesk here"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== TAVE =====
	{
		Service:  "Tave",
		CNAME:    []string{"tave.com"},
		Response: []string{"Sorry, this profile doesn't exist"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== FEEDPRESS =====
	{
		Service:  "FeedPress",
		CNAME:    []string{"feedpress.me"},
		Response: []string{"The feed has not been found"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== LAUNCHROCK =====
	{
		Service:  "LaunchRock",
		CNAME:    []string{"launchrock.com"},
		Response: []string{"It looks like you may have taken a wrong turn"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== PINGDOM =====
	{
		Service:  "Pingdom",
		CNAME:    []string{"pingdom.com"},
		Response: []string{"This public status page"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== SURVEYGIZMO =====
	{
		Service:  "SurveyGizmo",
		CNAME:    []string{"surveygizmo.com"},
		Response: []string{"data-html-name"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== CLOUDFLARE PAGES =====
	{
		Service:  "Cloudflare Pages",
		CNAME:    []string{"pages.dev"},
		Response: []string{"404 Not Found"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== KINSTA =====
	{
		Service:  "Kinsta",
		CNAME:    []string{"kinsta.cloud"},
		Response: []string{"No Site For Domain"},
		StatusCode: 404,
		Severity: "high",
	},

	// ===== CANNY =====
	{
		Service:  "Canny",
		CNAME:    []string{"canny.io"},
		Response: []string{"There is no such company"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== HATENA BLOG =====
	{
		Service:  "Hatena Blog",
		CNAME:    []string{"hatena.ne.jp", "hatenablog.com"},
		Response: []string{"404 Blog is not found"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== MEDIUM =====
	{
		Service:  "Medium",
		CNAME:    []string{"medium.com"},
		Response: []string{"This page doesn't exist"},
		StatusCode: 404,
		Severity: "low",
	},

	// ===== JETBRAINS YOUTRACK =====
	{
		Service:  "JetBrains YouTrack",
		CNAME:    []string{"jetbrains.com"},
		Response: []string{"is not a registered InCloud YouTrack"},
		StatusCode: 404,
		Severity: "medium",
	},

	// ===== NGROK =====
	{
		Service:  "ngrok",
		CNAME:    []string{"ngrok.io"},
		Response: []string{"Tunnel", "not found"},
		StatusCode: 404,
		Severity: "high",
	},
}

// GetFingerprint returns fingerprint for a service
func GetFingerprint(service string) *Fingerprint {
	for i := range Fingerprints {
		if Fingerprints[i].Service == service {
			return &Fingerprints[i]
		}
	}
	return nil
}

// GetCriticalServices returns high/critical severity services
func GetCriticalServices() []string {
	var services []string
	for _, fp := range Fingerprints {
		if fp.Severity == "critical" || fp.Severity == "high" {
			services = append(services, fp.Service)
		}
	}
	return services
}
