package recon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type URLGathering struct {
	Domain    string
	OutputDir string
}

func NewURLGathering(domain, outputDir string) *URLGathering {
	return &URLGathering{
		Domain:    domain,
		OutputDir: outputDir,
	}
}

func (u *URLGathering) Run() error {
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println("\033[36m                            URL GATHERING\033[0m")
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	startTime := time.Now()

	// Run Katana
	katanaOutput, err := u.runKatana()
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m Katana failed: %v\n", err)
	}

	// Run GAU
	gauOutput, err := u.runGau()
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m GAU failed: %v\n", err)
	}

	// Merge and deduplicate
	_, totalURLs := u.mergeURLs(katanaOutput, gauOutput)

	// Find sensitive files
	sensitiveCount := u.findSensitiveFiles(filepath.Join(u.OutputDir, "all_gathered_urls.txt"))

	// Probe gathered URLs for alive ones
	aliveCount := u.probeAliveURLs()

	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Printf("\033[32m[✓]\033[0m URL Gathering Complete\n")
	fmt.Printf("    \033[34m•\033[0m Total URLs      : %d\n", totalURLs)
	fmt.Printf("    \033[34m•\033[0m Alive URLs      : %d\n", aliveCount)
	fmt.Printf("    \033[34m•\033[0m Sensitive Files : %d\n", sensitiveCount)
	fmt.Printf("    \033[34m•\033[0m Duration        : %s\n", elapsed.Round(time.Second))
	fmt.Println("\033[36m→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→\033[0m")
	fmt.Println()

	return nil
}

func (u *URLGathering) runKatana() (string, error) {
	liveURLs := filepath.Join(u.OutputDir, "live_urls.txt")
	output := filepath.Join(u.OutputDir, "katana_urls.txt")

	if _, err := os.Stat(liveURLs); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗] live_urls.txt not found for Katana!\033[0m")
		return "", err
	}

	fmt.Printf("\033[33m[+]\033[0m Running \033[1mkatana\033[0m...\n\n")

	cmd := exec.Command("katana",
		"-list", liveURLs,
		"-d", "5",
		"-kf",
		"-jc",
		"-fx",
		"-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg",
		"-o", output,
		"-rl", "150",
		"-c", "10",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Run()

	count := countLines(output)
	fmt.Println()
	fmt.Printf("\033[32m✓\033[0m \033[1mkatana\033[0m completed - %d URLs found\n", count)
	fmt.Printf("\033[34m[+]\033[0m Saved to: katana_urls.txt\n")
	fmt.Println()

	return output, nil
}

func (u *URLGathering) runGau() (string, error) {
	subdomains := filepath.Join(u.OutputDir, "all_subdomains.txt")
	output := filepath.Join(u.OutputDir, "gau_urls.txt")

	if _, err := os.Stat(subdomains); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗] all_subdomains.txt not found for GAU!\033[0m")
		return "", err
	}

	fmt.Println("\033[36m►\033[0m \033[1mgau\033[0m started...")
	fmt.Println()

	// Read subdomains and pipe to gau
	inFile, err := os.Open(subdomains)
	if err != nil {
		return "", err
	}
	defer inFile.Close()

	outFile, err := os.Create(output)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	cmd := exec.Command("gau")
	cmd.Stdin = inFile
	cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
	cmd.Stderr = os.Stderr

	cmd.Run()

	count := countLines(output)
	fmt.Println()
	fmt.Printf("\033[32m✓\033[0m \033[1mgau\033[0m completed - %d URLs found\n", count)
	fmt.Printf("\033[34m[+]\033[0m Saved to: gau_urls.txt\n")
	fmt.Println()

	return output, nil
}

func (u *URLGathering) mergeURLs(files ...string) (string, int) {
	fmt.Println("\033[36m►\033[0m Merging and deduplicating URLs...")

	mergedFile := filepath.Join(u.OutputDir, "all_gathered_urls.txt")
	urlMap := make(map[string]bool)

	// Read all tool outputs
	for _, file := range files {
		if file != "" {
			readFileToMap(file, urlMap)
		}
	}

	// Also include all_discovered_urls.txt if exists
	discoveredURLs := filepath.Join(u.OutputDir, "all_discovered_urls.txt")
	if _, err := os.Stat(discoveredURLs); err == nil {
		readFileToMap(discoveredURLs, urlMap)
	}

	// Write merged file
	outFile, _ := os.Create(mergedFile)
	defer outFile.Close()

	for url := range urlMap {
		outFile.WriteString(url + "\n")
	}

	fmt.Printf("\033[32m✓\033[0m Merged URLs: %d unique\n", len(urlMap))
	fmt.Printf("\033[34m[+]\033[0m Saved to: all_gathered_urls.txt\n")

	return mergedFile, len(urlMap)
}

func (u *URLGathering) probeAliveURLs() int {
	fmt.Println()
	fmt.Println("\033[36m►\033[0m Probing gathered URLs for alive ones...")

	inputFile := filepath.Join(u.OutputDir, "all_gathered_urls.txt")
	outputFile := filepath.Join(u.OutputDir, "alive_gathered_urls.txt")

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Println("\033[31m[✗] all_gathered_urls.txt not found!\033[0m")
		return 0
	}

	cmd := exec.Command("httpx",
		"-l", inputFile,
		"-mc", "200,301,302,403,500",
		"-o", outputFile,
		"-threads", "150",
		"-rate-limit", "50",
		"-http-proxy", "socks5://127.0.0.1:9050",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Run()

	count := countLines(outputFile)
	fmt.Printf("\033[32m✓\033[0m Alive URLs found: %d\n", count)
	fmt.Printf("\033[34m[+]\033[0m Saved to: alive_gathered_urls.txt\n")

	return count
}

func (u *URLGathering) findSensitiveFiles(mergedFile string) int {
	fmt.Println()
	fmt.Println("\033[36m►\033[0m Hunting for sensitive files and parameters...")

	sensitiveFile := filepath.Join(u.OutputDir, "sensitive_findings.txt")

	// Comprehensive sensitive patterns
	sensitivePatterns := []string{
		// File extensions
		`\.txt`, `\.log`, `\.cache`, `\.secret`, `\.db`, `\.backup`, `\.yml`, `\.yaml`, `\.json`,
		`\.gz`, `\.rar`, `\.zip`, `\.config`, `\.env`, `\.crt`, `\.ini`, `\.pem`, `\.bak`, `\.swp`,
		`\.key`, `\.p12`, `\.pfx`, `\.ps1`, `\.xml`, `\.csv`, `\.dat`, `\.old`, `\.tar`, `\.tgz`,
		`\.7z`, `\.asc`, `\.passwd`, `\.htpasswd`, `\.pgp`, `\.ovpn`, `\.rc`, `\.conf`, `\.cert`,
		`\.p7b`, `\.bash_history`, `\.zsh_history`, `\.mysql_history`, `\.psql_history`, `\.sqlite3`,
		`\.dmp`, `\.rdp`, `\.sftp`, `\.sql`, `\.plist`, `\.dockerfile`, `\.sh`, `\.bashrc`, `\.zshrc`,
		`\.profile`, `\.npmrc`, `\.gitconfig`, `\.gitignore`, `\.aws`, `\.pgpass`, `\.id_rsa`, `\.ppk`,
		`\.openvpn`, `\.gpg`, `\.csr`, `\.cer`, `\.apk`, `\.mobileprovision`, `\.keystore`, `\.token`,
		`\.cloud`, `\.envrc`, `\.bash_aliases`, `\.my\.cnf`, `\.netrc`, `\.enc`, `\.ssl`, `\.wsdl`,
		`\.wadl`, `\.properties`, `\.toml`, `\.lock`, `\.gradle`, `\.sbt`, `\.htaccess`, `\.DS_Store`,
		`\.idea`, `\.vscode`, `\.sublime`, `\.editorconfig`, `\.travis\.yml`, `\.circleci`, `\.gitlab-ci`,
		`\.jenkins`, `\.terraform`, `\.tfstate`, `\.tfvars`, `\.kubeconfig`, `\.kube`, `\.helm`,
		// Sensitive keywords
		`api_key`, `apikey`, `api-key`, `secret`, `token`, `auth`, `password`, `passwd`, `pwd`,
		`private`, `credentials`, `credential`, `session`, `sensitive`, `access_key`, `accesskey`,
		`auth_token`, `client_secret`, `client_id`, `admin`, `root`, `user`, `key_id`, `account`,
		`config`, `configuration`, `authorization`, `jwt`, `bearer`, `oauth`, `oauth2`, `ssh`, `ftp`,
		`sftp`, `aws`, `gcp`, `azure`, `database`, `db_pass`, `db_user`, `db_password`, `db_host`,
		`encrypt`, `decrypt`, `decode`, `hash`, `salt`, `signature`, `cipher`, `encryption`,
		`login`, `signin`, `signup`, `logout`, `register`, `csrf`, `x_csrf`, `xsrf`, `access_token`,
		`refresh_token`, `master_key`, `masterkey`, `security`, `backup`, `recovery`, `keystore`,
		`sid`, `sessionid`, `appid`, `app_id`, `consumer_key`, `consumer_secret`, `smtp`, `imap`,
		`mail`, `email`, `id_token`, `auth_key`, `service_account`, `firestore`, `bigquery`,
		`storage`, `cloudfront`, `billing`, `payment`, `stripe`, `paypal`, `braintree`, `username`,
		`hostname`, `proxy`, `proxy_pass`, `bucket`, `s3`, `role_arn`, `session_token`, `azure_key`,
		`azure_secret`, `firebase`, `mongodb`, `mongo_pass`, `mongo_uri`, `redis`, `redis_pass`,
		`cloudflare`, `twilio`, `plaid`, `github_token`, `gitlab_token`, `slack_token`, `webhook`,
		`hook_url`, `razorpay`, `linkedin_secret`, `twitter_secret`, `facebook_secret`, `instagram_secret`,
		`twilio_sid`, `twilio_token`, `twilio_auth`, `sendgrid`, `mailgun`, `mailchimp`, `heroku`,
		`digitalocean`, `linode`, `vultr`, `openai`, `anthropic`, `cohere`, `huggingface`, `replicate`,
		`sentry`, `datadog`, `newrelic`, `splunk`, `elasticsearch`, `kibana`, `grafana`, `prometheus`,
		`vault`, `consul`, `nomad`, `kubernetes`, `docker`, `compose`, `swarm`, `portainer`,
		`jenkins`, `travis`, `circleci`, `gitlab`, `bitbucket`, `codecov`, `sonarqube`, `snyk`,
		`npm_token`, `pypi_token`, `rubygems`, `nuget`, `maven`, `gradle`, `artifactory`, `nexus`,
		`debug`, `staging`, `development`, `production`, `internal`, `private_key`, `public_key`,
		`rsa`, `dsa`, `ecdsa`, `ed25519`, `x509`, `certificate`, `ca_cert`, `tls`, `ssl_cert`,
	}

	// Build regex pattern
	pattern := regexp.MustCompile(`(?i)(` + strings.Join(sensitivePatterns, "|") + `)`)

	inFile, err := os.Open(mergedFile)
	if err != nil {
		return 0
	}
	defer inFile.Close()

	outFile, _ := os.Create(sensitiveFile)
	defer outFile.Close()

	sensitiveMap := make(map[string]bool)
	scanner := bufio.NewScanner(inFile)

	for scanner.Scan() {
		line := scanner.Text()
		if pattern.MatchString(line) {
			sensitiveMap[line] = true
		}
	}

	for finding := range sensitiveMap {
		outFile.WriteString(finding + "\n")
	}

	fmt.Printf("\033[32m✓\033[0m Sensitive findings: %d\n", len(sensitiveMap))
	fmt.Printf("\033[34m[+]\033[0m Saved to: sensitive_findings.txt\n")

	return len(sensitiveMap)
}

func readFileToMap(filename string, urlMap map[string]bool) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urlMap[line] = true
		}
	}
}
