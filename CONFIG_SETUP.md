# Configuration Setup

Pinakastra supports two ways to configure API keys and settings:

## 1. Using Config File (Recommended)

Create a config file at `~/.pinakastra/config.yaml`:

```bash
# Create directory
mkdir -p ~/.pinakastra

# Copy example config
cp configs/config.example.yaml ~/.pinakastra/config.yaml

# Edit with your API keys
nano ~/.pinakastra/config.yaml
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

# Paths (customize wordlist locations)
paths:
  resolvers: "~/.pinakastra/resolvers.txt"
  subdomains_wordlist: "~/.pinakastra/wordlists/subdomains.txt"
  directories_wordlist: "~/.pinakastra/wordlists/directories.txt"
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

# Reload shell
source ~/.bashrc
```

## API Key Sources:

### Shodan
- Get API key from: https://account.shodan.io/
- Used by: `shodan` tool for subdomain enumeration

### Chaos (ProjectDiscovery)
- Get API key from: https://chaos.projectdiscovery.io/
- Used by: `chaos` tool for subdomain enumeration

### GitHub
- Create token at: https://github.com/settings/tokens
- Used by: Various tools that leverage GitHub for recon

### GitLab
- Create token at: https://gitlab.com/-/profile/personal_access_tokens
- Used by: Various tools that leverage GitLab for recon

### Telegram (for notifications)
1. Create bot with [@BotFather](https://t.me/botfather)
2. Get bot token
3. Start chat with your bot
4. Get your chat ID from: https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates

## Priority Order:

1. **Environment Variables** (highest priority)
2. **Config File** (`~/.pinakastra/config.yaml`)
3. **Default Values** (lowest priority)

This means you can set defaults in the config file and override specific keys with environment variables when needed.

## Testing Configuration:

```bash
# Run pinakastra with your config
pinakastra -d example.com

# Enable notifications for a scan
pinakastra -d example.com --nt
```

## Optional: Wordlists Setup

Download recommended wordlists:

```bash
# Create wordlists directory
mkdir -p ~/.pinakastra/wordlists

# Download subdomains wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -O ~/.pinakastra/wordlists/subdomains.txt

# Download directories wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -O ~/.pinakastra/wordlists/directories.txt

# Download resolvers
wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt \
  -O ~/.pinakastra/resolvers.txt
```
