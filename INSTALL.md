# Pinakastra Installation Guide

## 🚀 Quick Install with Go

```bash
go install github.com/who0xac/pinakastra@latest
```

The `pinakastra` command will be globally available!

### Verify
```bash
pinakastra -h
```

### Add to PATH (if needed)
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

## 📦 Alternative Methods

### Installation Script
```bash
git clone https://github.com/who0xac/pinakastra.git
cd pinakastra
chmod +x install.sh
sudo ./install.sh
```

### Makefile
```bash
make install
```

## 📍 Paths

- Binary: `/usr/local/bin/pinakastra` or `$GOPATH/bin/pinakastra`
- Config: `~/.config/pinakastra/config.yaml`
- Results: `~/recon-results/`

## ⚙️ Setup

Create config file:
```bash
mkdir -p ~/.config/pinakastra
nano ~/.config/pinakastra/config.yaml
```

## 🗑️ Uninstall

```bash
rm $(go env GOPATH)/bin/pinakastra
# or
sudo rm /usr/local/bin/pinakastra
```
