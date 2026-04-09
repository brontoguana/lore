# Lore CLI installer for Windows
$ErrorActionPreference = "Stop"

$Repo = if ($env:LORE_GITHUB_REPO) { $env:LORE_GITHUB_REPO } else { "brontoguana/lore" }
$Version = if ($env:LORE_VERSION) { $env:LORE_VERSION } else { "latest" }
$InstallDir = if ($env:LORE_INSTALL_DIR) { $env:LORE_INSTALL_DIR } else { "$env:LOCALAPPDATA\lore\bin" }
$BinaryName = "lore"

function Resolve-LatestVersion {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "lore-installer" }
    return $release.tag_name
}

function Get-CurrentVersion {
    $exe = Join-Path $InstallDir "$BinaryName.exe"
    if (Test-Path $exe) {
        try {
            $out = & $exe --version 2>&1
            return ($out -replace "^$BinaryName ", "").Trim()
        } catch {
            return "unknown"
        }
    }
    return "not installed"
}

# Resolve version
if ($Version -eq "latest") {
    $RemoteVersion = Resolve-LatestVersion
} else {
    $RemoteVersion = $Version
}

$CurrentVersion = Get-CurrentVersion

# Check if update is needed
if ($CurrentVersion -ne "not installed") {
    $remoteCmp = $RemoteVersion -replace "^v", ""
    $currentCmp = $CurrentVersion -replace "^v", ""
    if ($remoteCmp -eq $currentCmp) {
        Write-Host "$BinaryName is already at version $CurrentVersion - nothing to do."
        exit 0
    }
    Write-Host "Updating $BinaryName`: $CurrentVersion -> $RemoteVersion"
} else {
    Write-Host "Installing $BinaryName $RemoteVersion"
}

$Target = "x86_64-pc-windows-msvc"
$BaseUrl = "https://github.com/$Repo/releases/download/$RemoteVersion"
$ArchiveName = "$BinaryName-$Target.tar.gz"
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "lore-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"

try {
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

    $ArchivePath = Join-Path $TmpDir $ArchiveName
    $ChecksumPath = "$ArchivePath.sha256"

    Write-Host "Downloading $ArchiveName..."
    Invoke-WebRequest -Uri "$BaseUrl/$ArchiveName" -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/$ArchiveName.sha256" -OutFile $ChecksumPath -UseBasicParsing

    # Verify checksum
    $expected = (Get-Content $ChecksumPath).Split(" ")[0]
    $actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-Error "Checksum mismatch for $ArchiveName"
        exit 1
    }

    # Extract (tar is available on Windows 10+)
    tar -xzf $ArchivePath -C $TmpDir

    # Install
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $src = Join-Path $TmpDir "$BinaryName.exe"
    $dst = Join-Path $InstallDir "$BinaryName.exe"
    Copy-Item -Path $src -Destination $dst -Force

    if ($CurrentVersion -ne "not installed") {
        Write-Host "Updated $BinaryName to $RemoteVersion (was $CurrentVersion)"
    } else {
        Write-Host ""
        Write-Host " _      ____  _____  ______ "
        Write-Host "| |    / __ \|  __ \|  ____|"
        Write-Host "| |   | |  | | |__) | |__   "
        Write-Host "| |   | |  | |  _  /|  __|  "
        Write-Host "| |___| |__| | | \ \| |____ "
        Write-Host "|______\____/|_|  \_\______|"
        Write-Host ""
        Write-Host "Installed $BinaryName $RemoteVersion to $dst"
        Write-Host ""

        # Check if InstallDir is on PATH
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$InstallDir*") {
            Write-Host "Adding $InstallDir to your PATH..."
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
            $env:Path = "$env:Path;$InstallDir"
            Write-Host "Done. Restart your terminal for PATH changes to take effect."
        }

        Write-Host ""
        Write-Host "Quick start:"
        Write-Host "  lore setup https://your-server.com"
        Write-Host "  lore projects                # list projects"
        Write-Host "  lore agent my-agent           # start an agent"
        Write-Host ""
        Write-Host "Run lore --help for all commands."
    }
} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
