# Configuration Setup

Pinakastra supports two ways to configure API keys and settings.

## 1. Using Config File (Recommended)

Create a config file at `~/.config/pinakastra/config.yaml`:

```bash
# Create directory
mkdir -p ~/.config/pinakastra

# Copy example config
cp configs/config.example.yaml ~/.config/pinakastra/config.yaml

# Edit with your API keys
nano ~/.config/pinakastra/config.yaml
```

### Config File Format:

```yaml
# API Keys
api_keys:
  shodan_api_key: "YOUR_SHODAN_API_KEY"
  chaos_api_key: "YOUR_CHAOS_API_KEY"
  github_token: "YOUR_GITHUB_TOKEN"
  gitlab_token: "YOUR_GITLAB_TOKEN"
  telegram_bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
  telegram_chat_id: "YOUR_TELEGRAM_CHAT_ID"

# Paths
paths:
  resolvers: "~/.config/pinakastra/resolvers.txt"
  subdomains_wordlist: "~/.config/pinakastra/wordlists/subdomains.txt"
  directories_wordlist: "~/.config/pinakastra/wordlists/directories.txt"
  amass_config: "~/.config/amass/config.yaml"
  jsa_path: "~/tools/JSA"

# Storage
storage:
  base_path: "~/recon-results"

# Notifications
notifications:
  telegram: false  # Set to true to enable
  desktop: false   # Set to true to enable
```

## 2. Using Environment Variables

Environment variables take priority over config file settings:

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_shodan_key"
export CHAOS_API_KEY="your_chaos_key"
export GITHUB_TOKEN="your_github_token"
export GITLAB_TOKEN="your_gitlab_token"
export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"
export TELEGRAM_CHAT_ID="your_telegram_chat_id"
export AMASS_CONFIG="~/.config/amass/config.yaml"

# Reload shell
source ~/.bashrc
```

## API Key Sources

### Shodan (Required for shodan subdomain tool)
- Get API key: https://account.shodan.io/
- Used by: `shodan` subdomain enumeration
- Free tier: 100 results/month

### Chaos (ProjectDiscovery)
- Get API key: https://chaos.projectdiscovery.io/
- Used by: `chaos` subdomain enumeration
- Free tier available

### GitHub Token
- Create token: https://github.com/settings/tokens
- Permissions needed: `public_repo` (read-only)
- Used by: Various reconnaissance tools
- Optional but recommended

### GitLab Token
- Create token: https://gitlab.com/-/profile/personal_access_tokens
- Permissions needed: `read_api`
- Used by: Various reconnaissance tools
- Optional

### Telegram (For Notifications)
1. Create bot with [@BotFather](https://t.me/botfather)
2. Send `/newbot` and follow instructions
3. Copy the bot token
4. Start a chat with your bot
5. Get your chat ID from:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
6. Send a message to your bot, then check the URL above for your chat ID

## Configuration Priority

1. **Environment Variables** (highest priority)
2. **Config File** (`~/.config/pinakastra/config.yaml`)
3. **Default Values** (lowest priority)

## Amass Configuration

Create amass config at `~/.config/amass/config.yaml`:

```yaml
# Example Amass config
brute_force:
  enabled: true
  recursive: true
  minimum_for_recursive: 1

dns_resolvers:
  - 1.1.1.1
  - 8.8.8.8
  - 8.8.4.4

api_keys:
  - name: Shodan
    key: YOUR_SHODAN_KEY
  - name: GitHub
    key: YOUR_GITHUB_TOKEN
```

## Wordlists Setup

Download recommended wordlists:

```bash
# Create wordlists directory
mkdir -p ~/.config/pinakastra/wordlists

# Download subdomains wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -O ~/.config/pinakastra/wordlists/subdomains.txt

# Download directories wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -O ~/.config/pinakastra/wordlists/directories.txt

# Download resolvers
wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt \
  -O ~/.config/pinakastra/resolvers.txt
```

## Testing Configuration

```bash
# Run pinakastra with your config
pinakastra -d example.com

# Enable notifications for a scan
pinakastra -d example.com --nt
```

## Quick Setup Script

```bash
#!/bin/bash

# Create directories
mkdir -p ~/.config/pinakastra/wordlists
mkdir -p ~/.config/amass

# Copy config
cp configs/config.example.yaml ~/.config/pinakastra/config.yaml

# Download wordlists
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -O ~/.config/pinakastra/wordlists/subdomains.txt

wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -O ~/.config/pinakastra/wordlists/directories.txt

wget -q https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt \
  -O ~/.config/pinakastra/resolvers.txt

echo "✓ Setup complete! Edit ~/.config/pinakastra/config.yaml to add your API keys"
```
