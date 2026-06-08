param(
    [string]$SemgrepVersion = "1.163.0",
    [string]$CodeqlRelease = "latest",
    [string]$ToolsDir = "tools",
    [switch]$SkipSemgrep,
    [switch]$SkipCodeQL
)

$ErrorActionPreference = "Stop"

function Resolve-Python {
    $localPython = Join-Path ".venv" "Scripts\python.exe"
    if (Test-Path $localPython) {
        return $localPython
    }
    return "python"
}

function Resolve-CodeQLAssetName {
    if ($IsMacOS) {
        return "codeql-bundle-osx64.tar.gz"
    }
    if ($IsLinux) {
        return "codeql-bundle-linux64.tar.gz"
    }
    return "codeql-bundle-win64.tar.gz"
}

function Invoke-Download {
    param(
        [string]$Uri,
        [string]$OutFile,
        [hashtable]$Headers
    )

    $curl = Get-Command "curl.exe" -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -L --fail --retry 3 --connect-timeout 20 -o $OutFile $Uri
        return
    }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $Headers
}

if (-not $SkipSemgrep) {
    $python = Resolve-Python
    & $python -m pip install "semgrep==$SemgrepVersion"
}

if (-not $SkipCodeQL) {
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $ToolsDir "downloads") | Out-Null

    $releaseUri = if ($CodeqlRelease -eq "latest") {
        "https://api.github.com/repos/github/codeql-action/releases/latest"
    } else {
        "https://api.github.com/repos/github/codeql-action/releases/tags/$CodeqlRelease"
    }
    $headers = @{ "User-Agent" = "verisec-agent-scanner-bootstrap" }
    $release = Invoke-RestMethod -Uri $releaseUri -Headers $headers
    $assetName = Resolve-CodeQLAssetName
    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    $checksumAsset = $release.assets |
        Where-Object { $_.name -eq "$assetName.checksum.txt" } |
        Select-Object -First 1
    if (-not $asset) {
        throw "CodeQL asset not found in release $($release.tag_name): $assetName"
    }
    if (-not $checksumAsset) {
        throw "CodeQL checksum asset not found in release $($release.tag_name): $assetName.checksum.txt"
    }

    $downloadPath = Join-Path $ToolsDir "downloads\$assetName"
    $checksumPath = Join-Path $ToolsDir "downloads\$assetName.checksum.txt"
    Invoke-Download -Uri $asset.browser_download_url -OutFile $downloadPath -Headers $headers
    Invoke-Download -Uri $checksumAsset.browser_download_url -OutFile $checksumPath -Headers $headers

    $expectedHash = ((Get-Content $checksumPath -Raw).Trim() -split "\s+")[0].ToUpperInvariant()
    $actualHash = (Get-FileHash -Algorithm SHA256 $downloadPath).Hash.ToUpperInvariant()
    if ($expectedHash -ne $actualHash) {
        throw "CodeQL checksum mismatch: expected $expectedHash, got $actualHash"
    }

    $targetDir = Join-Path $ToolsDir $release.tag_name
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    $codeqlExe = if ($IsWindows -or -not ($IsMacOS -or $IsLinux)) {
        Join-Path $targetDir "codeql\codeql.exe"
    } else {
        Join-Path $targetDir "codeql/codeql"
    }
    if (-not (Test-Path $codeqlExe)) {
        tar -xzf $downloadPath -C $targetDir
    }
    & $codeqlExe version
}
