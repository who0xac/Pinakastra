# Pinakastra Installation Guide

## 🚀 Quick Install with Go

The easiest way to install Pinakastra globally:

```bash
go install github.com/who0xac/pinakastra@latest
```

After this command completes, `pinakastra` will be available globally from any directory!

### Verify Installation

```bash
pinakastra -h
```

### Requirements

- Go 1.21 or higher
- `$GOPATH/bin` in your system PATH

### Adding Go Bin to PATH

If the command is not found after installation:

**Linux/macOS (.bashrc or .zshrc):**
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

**Windows (PowerShell):**
```powershell
$env:Path += ";$(go env GOPATH)\bin"
```

---

## 📦 Alternative Installation Methods

### 1. Using Installation Scripts

**Linux / macOS:**
```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
chmod +x install.sh
sudo ./install.sh
```

**Windows (PowerShell as Administrator):**
```powershell
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
.\install.ps1
```

### 2. Using Makefile (Linux/macOS)

```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
make install
```

### 3. Manual Build and Install

**Linux/macOS:**
```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
go build -ldflags="-s -w" -o pinakastra .
sudo mv pinakastra /usr/local/bin/
sudo chmod +x /usr/local/bin/pinakastra
```

**Windows:**
```powershell
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
go build -ldflags="-s -w" -o pinakastra.exe .
# Move to a directory in your PATH
move pinakastra.exe "$env:ProgramFiles\Pinakastra\"
# Add to PATH manually via System Properties
```

---

## 📍 Installation Paths

### Linux / macOS

| Item | Path |
|------|------|
| Binary (go install) | `$GOPATH/bin/pinakastra` |
| Binary (script/make) | `/usr/local/bin/pinakastra` |
| Config | `~/.config/pinakastra/config.yaml` |
| Results | `~/recon-results/` |

### Windows

| Item | Path |
|------|------|
| Binary (go install) | `%GOPATH%\bin\pinakastra.exe` |
| Binary (script) | `C:\Program Files\Pinakastra\pinakastra.exe` |
| Config | `%USERPROFILE%\.config\pinakastra\config.yaml` |
| Results | `%USERPROFILE%\recon-results\` |

---

## ⚙️ Post-Installation Setup

### 1. Create Config Directory

```bash
mkdir -p ~/.config/pinakastra
```

### 2. Create Config File (Optional)

Create `~/.config/pinakastra/config.yaml`:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  chaos: "YOUR_CHAOS_KEY"

paths:
  resolvers: "/path/to/resolvers.txt"
  subdomains: "/path/to/subdomain-wordlist.txt"

storage:
  base_path: "~/recon-results"

notifications:
  telegram:
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

### 3. Install Recon Tools

Install the tools you want to use:

```bash
# Essential tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Check what's installed
pinakastra -c
```

---

## 🔄 Updating Pinakastra

### Using Go Install

```bash
go install github.com/who0xac/pinakastra@latest
```

### From Source

```bash
cd pinakastra
git pull origin main
make install
# or
./install.sh
```

---

## 🗑️ Uninstallation

### If Installed via Go Install

```bash
rm $(go env GOPATH)/bin/pinakastra
```

### If Installed via Scripts/Makefile

**Linux/macOS:**
```bash
make uninstall
# or
sudo rm /usr/local/bin/pinakastra
```

**Windows:**
```powershell
Remove-Item "$env:ProgramFiles\Pinakastra" -Recurse -Force
# Remove from PATH manually via System Properties
```

### Clean Up Config (Optional)

```bash
rm -rf ~/.config/pinakastra
rm -rf ~/recon-results
```

---

## 🐛 Troubleshooting

### Command Not Found

**Check if Go bin is in PATH:**
```bash
echo $PATH | grep $(go env GOPATH)/bin
```

**Add to PATH:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH=$PATH:$(go env GOPATH)/bin
source ~/.bashrc
```

### Permission Denied

**Linux/macOS:**
```bash
chmod +x /usr/local/bin/pinakastra
# or
chmod +x $(go env GOPATH)/bin/pinakastra
```

### Build Errors

```bash
# Clear Go cache
go clean -cache
go clean -modcache

# Update dependencies
go mod tidy
go mod download

# Rebuild
go install github.com/who0xac/pinakastra@latest
```

---

## ✅ Verify Installation

```bash
# Check version and help
pinakastra -h

# Check installed tools
pinakastra -c

# Test with a domain
pinakastra -d example.com
```

---

## 📚 Next Steps

1. **Configure API keys** - Edit `~/.config/pinakastra/config.yaml`
2. **Install recon tools** - Use `pinakastra -c` to see what's missing
3. **Run your first scan** - `pinakastra -d target.com`

---

**For more information, see [README.md](README.md)**
