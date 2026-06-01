# Create project venv and install scapy (fixes Pylance "could not be resolved" errors)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}

Write-Host "Installing dependencies..."
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip install -r requirements.txt

Write-Host ""
Write-Host "Done. In Cursor/VS Code:"
Write-Host "  Ctrl+Shift+P -> Python: Select Interpreter -> .venv (Scripts\python.exe)"
Write-Host ""
Write-Host "Test: .\.venv\Scripts\python.exe network_sniffer.py --demo"
