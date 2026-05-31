# build_exe.ps1
#
# Build a versioned Windows EXE for VulnMalper using Nuitka + uv.
#
# Output:
#   dist\vulnmalper-vX.Y.Z.exe
#
# Version is automatically read from:
#   VERSION = "X.Y.Z"
# in vulnmalper.py

$ErrorActionPreference = "Stop"

try {
    Write-Host ""
    Write-Host "=== VulnMalper Windows Builder ==="
    Write-Host ""

    # Read version from vulnmalper.py
    $versionMatch = Select-String `
        -Path "vulnmalper.py" `
        -Pattern 'VERSION\s*=\s*"([^"]+)"'

    if (-not $versionMatch) {
        throw "Could not find VERSION in vulnmalper.py"
    }

    $version = $versionMatch.Matches[0].Groups[1].Value

    Write-Host "[+] Version detected: $version"

    # Create dist directory
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null

    # Create venv if missing
    if (-not (Test-Path ".venv")) {
        Write-Host "[+] Creating virtual environment..."
        uv venv
    }

    # Activate venv
    Write-Host "[+] Activating virtual environment..."
    & ".\.venv\Scripts\Activate.ps1"

    # Install/update Nuitka
    Write-Host "[+] Installing build dependencies..."
    uv pip install --upgrade "nuitka[onefile]"

    # Clean old Nuitka artifacts
    Write-Host "[+] Cleaning previous build artifacts..."

    @(
        "vulnmalper.build",
        "vulnmalper.dist",
        "vulnmalper.onefile-build"
    ) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -Recurse -Force $_
        }
    }

    # Remove previous root executable
    if (Test-Path "vulnmalper.exe") {
        Remove-Item -Force "vulnmalper.exe"
    }

    # Remove previous versioned EXEs from dist
    Get-ChildItem `
        -Path "dist" `
        -Filter "vulnmalper-v*.exe" `
        -ErrorAction SilentlyContinue |
        Remove-Item -Force

    # Build
    Write-Host "[+] Compiling executable..."
    Write-Host ""

    python -m nuitka `
        --onefile `
        --assume-yes-for-downloads `
        vulnmalper.py

    if (-not (Test-Path "vulnmalper.exe")) {
        throw "Build failed: vulnmalper.exe was not created."
    }

    # Move to dist
    $output = "dist\vulnmalper-v$version.exe"

    Move-Item `
        -Path "vulnmalper.exe" `
        -Destination $output `
        -Force

    Write-Host ""
    Write-Host "[+] Build complete!"
    Write-Host "[+] Output: $output"
    Write-Host ""
}
finally {
    # Deactivate virtual environment if active
    if (Get-Command deactivate -ErrorAction SilentlyContinue) {
        deactivate
        Write-Host "[+] Virtual environment deactivated."
    }
}