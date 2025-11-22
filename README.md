# 🎯 Pinakastra

A powerful Go-based reconnaissance automation framework for bug bounty hunters and penetration testers.

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)

## ✨ Features

- **Beautiful Terminal Output** - Colored output with progress indicators
- **12+ Recon Phases** - Complete reconnaissance workflow
- **Parallel Execution** - Fast scanning using Go goroutines
- **Modular Architecture** - Easy to add new tools
- **File-based Storage** - Results saved in organized directories
- **Telegram Notifications** - Real-time alerts for scan events
- **Tool Checker** - Verify all required tools are installed

## 🚀 Quick Installation

### Using Go Install (Recommended)

```bash
go install github.com/who0xac/pinakastra@latest
```

After installation, the `pinakastra` command will be globally available!

### Using Installation Scripts

**Linux / macOS:**
```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
chmod +x install.sh
sudo ./install.sh
```

**Windows (PowerShell as Admin):**
```powershell
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
.\install.ps1
```

### Using Makefile

```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
make install
```

### Verify Installation

```bash
pinakastra -h
```

## 📖 Usage

### Check Required Tools

```bash
pinakastra -c
```

### Run a Scan

```bash
# Basic scan
pinakastra -d example.com

# Custom output directory
pinakastra -d example.com -o /path/to/output

# Enable Telegram notifications
pinakastra -d example.com --nt
```

## 🛠️ Supported Tools

### Subdomain Enumeration
- **amass** - OWASP Amass
- **subfinder** - Fast subdomain discovery
- **findomain** - Subdomains finder
- **assetfinder** - Find domains and subdomains
- **sublist3r** - Fast subdomains enumeration
- **chaos** - ProjectDiscovery Chaos
- **crtsh** - Certificate transparency logs
- **puredns** - DNS bruteforcing

### DNS Resolution
- **dnsx** - Fast DNS toolkit
- **massdns** - High-performance DNS resolver

### HTTP Probing
- **httpx** - Fast HTTP toolkit

### Subdomain Takeover
- **subzy** - Subdomain takeover tool

### Content Discovery
- **ffuf** - Fast web fuzzer
- **dirsearch** - Web path scanner

### URL Gathering
- **gau** - Get All URLs
- **katana** - Crawling and spidering framework
- **hakrawler** - Web crawler
- **subjs** - Fetches javascript files

### Parameter Discovery
- **arjun** - HTTP parameter discovery

### Pattern Matching
- **gf** - Wrapper around grep

### Secret Finding
- **secretfinder** - Discover sensitive data

### Screenshots
- **gowitness** - Web screenshot utility

### Port Scanning
- **nmap** - Network mapper

### Vulnerability Scanning
- **nuclei** - Fast vulnerability scanner

## 📁 Output Structure

```
~/recon-results/
└── example.com/
    ├── amass.txt
    ├── subfinder.txt
    ├── all_subdomains.txt
    ├── live_urls.txt
    ├── httpx_results.txt
    ├── resolved_ips.txt
    ├── ffuf_results.txt
    ├── nuclei_results.txt
    └── ...
```

## ⚙️ Configuration

Config file location: `~/.config/pinakastra/config.yaml`

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  chaos: "YOUR_CHAOS_KEY"
  virustotal: "YOUR_VT_KEY"
  securitytrails: "YOUR_ST_KEY"

paths:
  resolvers: "/path/to/resolvers.txt"
  subdomains: "/path/to/subdomain-wordlist.txt"
  amass_config: "/path/to/amass/config.yaml"

storage:
  base_path: "~/recon-results"

notifications:
  telegram:
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

## 🔔 Telegram Setup

1. Create a bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID via [@userinfobot](https://t.me/userinfobot)
3. Add to config file

## 🔄 Reconnaissance Workflow

```
1. Subdomain Enumeration (9 tools)
   ↓
2. DNS Resolution
   ↓
3. Live Host Probing
   ↓
4. Subdomain Takeover Check
   ↓
5. Content Discovery
   ↓
6. URL Gathering
   ↓
7. GF Pattern Matching
   ↓
8. JS Secret Finding
   ↓
9. Screenshots
   ↓
10. Port Scanning
    ↓
11. Vulnerability Scanning
```

## 🧰 Installing Recon Tools

### Using Go

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Other Go tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest
```

### Using Package Managers

**Kali Linux:**
```bash
sudo apt update
sudo apt install amass subfinder httpx nuclei dnsx nmap
```

**macOS:**
```bash
brew install amass subfinder httpx nuclei dnsx nmap
```

## 📜 License

MIT License - see [LICENSE](LICENSE)

## 👤 Author

**who0xac**
- GitHub: [@who0xac](https://github.com/who0xac)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

1. Fork it
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Create a Pull Request

## ⭐ Show Your Support

Give a ⭐ if this project helped you!

---

**Happy Hunting! 🎯**
