# 🎯 Pinakastra

A powerful Go-based reconnaissance automation framework with beautiful CLI, real-time Web UI, and Telegram notifications.

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)

## ✨ Features

- **Beautiful CLI** - Colored output, progress bars, and live status updates
- **Real-time Web UI** - Modern dashboard with WebSocket for live scan updates
- **Telegram Notifications** - Real-time alerts for scan events and critical findings
- **Desktop Notifications** - Native OS notifications
- **Parallel Execution** - Fast scanning using Go goroutines
- **Modular Architecture** - Easy to add new tools
- **File-based Storage** - Results saved in `~/recon-results/{domain}/`
- **Multiple Export Formats** - JSON, HTML, CSV reports
- **Tool Checker** - Verify all required tools are installed

## 🚀 Installation

### Using Go Install (Recommended)

```bash
go install github.com/who0xac/pinakastra@latest
```

### From Source

```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
go build -o pinakastra .
sudo mv pinakastra /usr/local/bin/
```

### Verify Installation

```bash
pinakastra --help
```

## ⚙️ Configuration

Create config file at `~/.pinakastra/config.yaml`:

```bash
mkdir -p ~/.pinakastra
cp configs/config.example.yaml ~/.pinakastra/config.yaml
```

Edit the config with your API keys:

```yaml
# API Keys
api_keys:
  telegram_bot_token: "your-bot-token"
  telegram_chat_id: "your-chat-id"
  shodan: "your-shodan-key"
  # ... more keys

# Wordlists
wordlists:
  subdomains: "/path/to/subdomains.txt"
  dns: "/path/to/dns-wordlist.txt"
  directories: "/path/to/directory-wordlist.txt"

# Storage
storage:
  base_path: "~/recon-results"

# Web UI
webui:
  port: 8080
  auto_open: true

# Notifications
notifications:
  telegram: true
  desktop: true
  on_start: true
  on_complete: true
  on_critical: true
  on_error: true
  send_files: true
```

## 📖 Usage

### Check Required Tools

```bash
pinakastra check-tools
```

### Run a Scan

```bash
# Single domain
pinakastra scan -d example.com

# Multiple domains from file
pinakastra scan -l domains.txt

# Custom output directory
pinakastra scan -d example.com -o /path/to/output

# Skip specific tools
pinakastra scan -d example.com --skip subfinder,amass

# Run only specific tools
pinakastra scan -d example.com --only httpx,nuclei
```

### Start Web UI

```bash
# Default port 8080
pinakastra webui

# Custom port
pinakastra webui -p 9000

# Disable auto-open browser
pinakastra webui --open=false
```

## 🛠️ Supported Tools

### Subdomain Enumeration (Phase 1)
- subfinder
- amass
- assetfinder
- findomain

### DNS Tools (Phase 2)
- dnsx
- massdns
- puredns

### Port Scanning (Phase 3)
- naabu
- nmap
- masscan

### HTTP Probing (Phase 4)
- httpx
- httprobe

### Content Discovery (Phase 5)
- ffuf
- feroxbuster
- gobuster
- dirsearch

### Vulnerability Scanning (Phase 6)
- nuclei
- nikto

### URL & JS Discovery
- katana
- waybackurls
- gau
- hakrawler

### Other Tools
- arjun (parameter discovery)
- paramspider
- gowitness (screenshots)
- gf (pattern matching)
- anew
- qsreplace

## 📁 Output Structure

```
~/recon-results/
└── example.com/
    ├── scan_results.json    # All results in JSON
    ├── report.html          # HTML report
    ├── report.csv           # CSV export
    ├── subfinder.txt        # Tool-specific outputs
    ├── httpx.txt
    ├── nuclei.txt
    └── ...
```

## 🔔 Telegram Setup

1. Create a bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID via [@userinfobot](https://t.me/userinfobot)
3. Add to config:
   ```yaml
   api_keys:
     telegram_bot_token: "123456:ABC-DEF..."
     telegram_chat_id: "123456789"
   ```

## 🌐 Web UI

Access the dashboard at `http://localhost:8080` (default)

Features:
- Real-time scan progress
- Live activity feed
- Scan history
- Tool status
- Export reports

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
