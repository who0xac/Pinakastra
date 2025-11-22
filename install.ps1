# Pinakastra Installation Script for Windows
# Usage: Run as Administrator
# .\install.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→" -ForegroundColor Cyan
Write-Host "                    Pinakastra Global Installation" -ForegroundColor Cyan
Write-Host "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] This script requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "[!] Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Check if Go is installed
try {
    $goVersion = go version
    Write-Host "[✓] Go detected: $goVersion" -ForegroundColor Green
} catch {
    Write-Host "[✗] Go is not installed. Please install Go 1.21 or higher." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Build the binary
Write-Host "[+] Building Pinakastra..." -ForegroundColor Yellow
try {
    go build -o pinakastra.exe -ldflags="-s -w" .
    Write-Host "[✓] Build successful" -ForegroundColor Green
} catch {
    Write-Host "[✗] Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Create installation directory
$installPath = "$env:ProgramFiles\Pinakastra"
Write-Host "[+] Installing to $installPath..." -ForegroundColor Yellow

if (-not (Test-Path $installPath)) {
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
}

# Copy binary
Copy-Item -Path "pinakastra.exe" -Destination "$installPath\pinakastra.exe" -Force
Write-Host "[✓] Binary installed to $installPath" -ForegroundColor Green

# Add to PATH
Write-Host "[+] Adding to system PATH..." -ForegroundColor Yellow
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$installPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installPath", "Machine")
    Write-Host "[✓] Added to system PATH" -ForegroundColor Green
} else {
    Write-Host "[✓] Already in system PATH" -ForegroundColor Green
}

# Create config directory
$configDir = "$env:USERPROFILE\.config\pinakastra"
if (-not (Test-Path $configDir)) {
    Write-Host "[+] Creating config directory at $configDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null

    # Copy default config if exists
    if (Test-Path "configs\default.yaml") {
        Copy-Item -Path "configs\default.yaml" -Destination "$configDir\config.yaml" -Force
        Write-Host "[✓] Default config copied to $configDir\config.yaml" -ForegroundColor Green
    }
}

# Create results directory
$resultsDir = "$env:USERPROFILE\recon-results"
if (-not (Test-Path $resultsDir)) {
    Write-Host "[+] Creating results directory at $resultsDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
    Write-Host "[✓] Results directory created" -ForegroundColor Green
}

Write-Host ""
Write-Host "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→" -ForegroundColor Cyan
Write-Host "[✓] Installation Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Installation Summary:" -ForegroundColor Cyan
Write-Host "  • Binary     : $installPath\pinakastra.exe" -ForegroundColor Cyan
Write-Host "  • Config     : $configDir\config.yaml" -ForegroundColor Cyan
Write-Host "  • Results    : $resultsDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  pinakastra -d example.com     - Start a scan" -ForegroundColor Yellow
Write-Host "  pinakastra -c                 - Check installed tools" -ForegroundColor Yellow
Write-Host "  pinakastra -h                 - Show help" -ForegroundColor Yellow
Write-Host "→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→→" -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] IMPORTANT: Please restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""

# Clean up build artifact in current directory
if (Test-Path "pinakastra.exe") {
    Remove-Item "pinakastra.exe" -Force
}
