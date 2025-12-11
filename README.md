# 🔱 Pinakastra

**Advanced Automated Reconnaissance & Vulnerability Assessment Tool**

Pinakastra is a comprehensive reconnaissance tool that automates subdomain enumeration, vulnerability scanning, and security testing. Built for penetration testers and bug bounty hunters.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org)

---

## ✨ Features

### 🔍 Reconnaissance
- **Subdomain Enumeration**: 10+ tools (subfinder, amass, findomain, chaos, shodan, etc.)
- **HTTP Probing**: Fast live host detection with httpx
- **IP Resolution**: DNS resolution with ASN lookups
- **URL Discovery**: Katana & GAU for comprehensive URL gathering
- **Port Scanning**: Nmap integration with service detection

### 🛡️ Security Analysis
- **Vulnerability Scanning**: Nuclei integration with custom templates
- **Subdomain Takeover**: Detection for 50+ services
- **Cloud Asset Discovery**: AWS S3, Azure, GCP bucket enumeration
- **CORS Misconfiguration**: Advanced CORS testing
- **Security Headers**: Comprehensive header analysis
- **TLS/SSL Analysis**: Certificate validation and vulnerabilities
- **Secret Detection**: JavaScript file scanning for API keys/tokens

### 🤖 AI-Powered Analysis
- **Exploit Generation**: Automatic exploit generation for findings
- **False Positive Reduction**: AI-powered validation
- **Technical Reports**: Auto-generated security reports

### 🌐 Web Interface
- **Real-time Dashboard**: Live scan progress with WebSocket updates
- **Interactive UI**: Dark theme with modern design
- **Export Options**: JSON, CSV, TXT, HTML, PDF formats
- **Visual Charts**: Vulnerability distribution and statistics

---

## 🚀 Quick Start

### Direct Installation (Recommended)

**One-line install:**
```bash
go install github.com/who0xac/pinakastra/cmd/pinakastra@latest
```

This will:
- Download and compile Pinakastra
- Install to `$GOPATH/bin/pinakastra`
- Make it available globally

**Or use install script:**
```bash
curl -sSL https://raw.githubusercontent.com/who0xac/Pinakastra/main/install.sh | bash
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/who0xac/Pinakastra.git
cd Pinakastra

# Run installation script (Linux only)
chmod +x install.sh
./install.sh
```

### Requirements

**System:**
- Linux (Ubuntu, Debian, Arch, Fedora, etc.)
- Go 1.21 or higher

**External Tools (automatically checked):**
- subfinder, httpx, katana (required)
- amass, puredns, nuclei, nmap (optional)
- shodan CLI (optional, for Shodan API)

---

## 📖 Usage

### Basic Scan

```bash
pinakastra -d target.com
```

### With Web UI

```bash
pinakastra -d target.com --web-ui
# Open http://localhost:8888 in browser
```

### Advanced Options

```bash
# Skip port scanning
pinakastra -d target.com --no-portscan

# Skip DNS brute-forcing
pinakastra -d target.com --no-bruteforce

# Use TOR proxy
pinakastra -d target.com --use-tor

# Custom web UI port
pinakastra -d target.com --web-port 9000

# AI-powered exploitation
pinakastra -d target.com --ai-deep
```

---

## ⚙️ Configuration

Configuration is stored in `~/.config/pinakastra/config.yaml`:

```yaml
api_keys:
  chaos: "your-chaos-api-key"
  shodan: "your-shodan-api-key"

paths:
  resolvers: ""
  wordlist: ""

scan:
  default_threads: 1000
  default_rate_limit: 100
  default_timeout: 5
```

### Getting API Keys

- **Chaos API**: https://chaos.projectdiscovery.io/ (free tier)
- **Shodan API**: https://account.shodan.io/register (paid)

---

## 🛠️ Tool Checks

Verify installed tools:

```bash
pinakastra check
# or
pinakastra c
```

Output:
```
✅ subfinder    - installed
✅ httpx        - installed
✅ katana       - installed
⚠️  nuclei      - not installed (optional)
⚠️  nmap        - not installed (optional)
```

---

## 📁 Project Structure

```
pinakastra/
├── cmd/pinakastra/      # CLI entry point
├── pkg/                 # Core packages
│   ├── subdomain/       # Subdomain enumeration
│   ├── httpprobe/       # HTTP probing
│   ├── scanner/         # Main scanner
│   ├── exploit/         # Exploitation modules
│   ├── webui/           # Web UI server
│   ├── config/          # Configuration
│   └── ...
├── web/                 # Web UI frontend
│   ├── templates/       # HTML templates
│   ├── static/          # CSS/JS assets
│   └── src/             # React components
├── wordlists/           # Wordlists for fuzzing
│   └── directories_fuzz.txt  # 100k directory entries
├── install.sh           # Installation script
├── go.mod               # Go dependencies
└── README.md            # This file
```

---

## 🔧 Installation Details

### Prerequisites

**Install Go:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install golang-go

# Arch Linux
sudo pacman -S go

# Fedora/RHEL
sudo dnf install golang
```

### Required Tools

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### Optional Tools

```bash
# GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Puredns (DNS brute-forcing)
go install github.com/d3mondev/puredns/v2@latest

# Nuclei (vulnerability scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Shodan CLI
pip install shodan

# Nmap
sudo apt install nmap  # Ubuntu/Debian
sudo pacman -S nmap     # Arch
```

### Manual Installation

```bash
# Build binary
go build -o pinakastra ./cmd/pinakastra

# Install globally
go install ./cmd/pinakastra

# Add to PATH
export PATH="$PATH:$(go env GOPATH)/bin"
```

---

## 📊 Scan Phases

Pinakastra executes scans in 7 phases:

1. **Phase 1: Subdomain Enumeration**
   - Passive: subfinder, amass, chaos, shodan, crt.sh
   - Active: puredns DNS brute-forcing (optional)

2. **Phase 2: HTTP Probing**
   - Live host detection with httpx
   - Technology fingerprinting

3. **Phase 3: IP Resolution**
   - DNS resolution with dnsx
   - ASN lookup
   - Virtual host discovery

4. **Phase 4: URL Discovery**
   - Katana web crawling
   - GAU historical URLs
   - Parameter extraction

5. **Phase 5: Port Scanning** (optional)
   - Nmap service detection
   - CVE lookup for services

6. **Phase 6: Deep Security Analysis**
   - Subdomain takeover detection
   - Cloud asset discovery
   - CORS testing
   - TLS/SSL analysis
   - Secret scanning

7. **Phase 7: Output Generation**
   - JSON, CSV, TXT reports
   - HTML/PDF reports
   - Exploit generation

---

## 📤 Output Formats

Generated reports are saved in `outputs/<domain>_<timestamp>/`:

```
outputs/target.com_2024-01-15_143022/
├── all_subdomains.txt       # All discovered subdomains
├── live_urls.txt            # Live HTTP/HTTPS hosts
├── all_urls.txt             # All discovered URLs
├── api_endpoints.txt        # Extracted API endpoints
├── ips_only.txt             # Resolved IP addresses
├── asn_data.txt             # ASN information
├── vhosts.txt               # Virtual hosts
├── secrets_found.txt        # Found secrets/API keys
├── takeover_vulns.txt       # Subdomain takeover vulns
├── cloud_assets.txt         # Cloud storage buckets
├── scan_results.json        # Full results (JSON)
├── scan_results.txt         # Summary report (TXT)
└── subdomains.csv           # Subdomain data (CSV)
```

---

## 🌐 Web UI

Start scan with Web UI:

```bash
pinakastra -d target.com --web-ui
```

Access at: http://localhost:8888

**Features:**
- Real-time scan progress
- Live subdomain updates
- Vulnerability dashboard
- Export functionality
- Dark mode interface

---

## 🔐 DNS Resolvers

Pinakastra uses 24 fast public DNS resolvers for puredns:

- Cloudflare (1.1.1.1, 1.0.0.1)
- Google (8.8.8.8, 8.8.4.4)
- Quad9 (9.9.9.9, 149.112.112.112)
- OpenDNS (208.67.222.222, 208.67.220.220)
- AdGuard (94.140.14.14, 94.140.15.15)
- Control D (76.76.2.0, 76.76.10.0)
- CleanBrowsing (185.228.168.9, 185.228.169.9)
- Verisign (64.6.64.6, 64.6.65.6)
- Yandex (77.88.8.8, 77.88.8.1)
- DNS.Watch (84.200.69.80, 84.200.70.40)
- Neustar (156.154.70.1, 156.154.71.1)
- Dyn (216.146.35.35, 216.146.36.36)

Configure custom resolvers in `~/.config/pinakastra/configs/resolvers.txt`

---

## 📝 Wordlists

**Subdomain wordlist**: `~/.config/pinakastra/wordlists/subdomains.txt` (10k entries)

**Directory wordlist**: `wordlists/directories_fuzz.txt` (100k entries)

---

## 🐛 Troubleshooting

### Command not found

```bash
# Check if Go bin is in PATH
echo $PATH | grep $(go env GOPATH)/bin

# Add to PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Make permanent
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Tools not found

```bash
# Check what's missing
pinakastra check

# Install missing tools (see Installation section)
```

### Permission denied

```bash
chmod +x pinakastra
chmod +x install.sh
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## 📜 License

This project is licensed under the MIT License.

---

## ⚠️ Disclaimer

This tool is for educational and ethical testing purposes only. Always ensure you have proper authorization before testing any systems. The developers are not responsible for misuse or damage caused by this tool.

---

## 🔗 Links

- GitHub: https://github.com/who0xac/Pinakastra
- Issues: https://github.com/who0xac/Pinakastra/issues

---

## 📞 Support

For questions or support:
- Open an issue on GitHub
- Run `pinakastra --help` for command help
- Run `pinakastra check` to verify tool installation

---

**Built with ❤️ for the security community**

🔱 **Pinakastra** - *Advanced Reconnaissance Redefined*
