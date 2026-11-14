Set-StrictMode -Version 3.0

function Read-RuntimeFileManifest {
    param([Parameter(Mandatory = $true)][string] $ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "runtime manifest가 없습니다: $ManifestPath"
    }

    $entries = @()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($rawLine in Get-Content -LiteralPath $ManifestPath) {
        $entry = ([string] $rawLine).Trim().Replace('\', '/')
        if (-not $entry) { continue }
        if (
            $entry.StartsWith('/') -or
            $entry.EndsWith('/') -or
            $entry -match '(^|/)\.{1,2}(/|$)' -or
            $entry -notmatch '^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$'
        ) {
            throw "runtime manifest에 안전하지 않은 경로가 있습니다: $entry"
        }
        if (-not $seen.Add($entry)) {
            throw "runtime manifest에 중복 경로가 있습니다: $entry"
        }
        $entries += $entry
    }

    if ($entries.Count -eq 0) { throw "runtime manifest가 비어 있습니다: $ManifestPath" }
    return $entries
}

function Assert-PathHasNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Boundary
    )

    $boundaryFull = [IO.Path]::GetFullPath($Boundary).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($boundaryFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "검사 경로가 허용 경계를 벗어났습니다: $pathFull"
    }

    $boundaryItem = Get-Item -LiteralPath $boundaryFull -Force
    if (($boundaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "runtime root가 reparse point입니다: $boundaryFull"
    }

    $relative = $pathFull.Substring($boundaryFull.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
    $current = $boundaryFull
    foreach ($segment in $relative -split '[\\/]') {
        if (-not $segment) { continue }
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "runtime 경로에 reparse point가 있습니다: $current"
        }
    }
}

function Assert-NoCredentialMaterial {
    param(
        [Parameter(Mandatory = $true)][string] $StageRoot,
        [Parameter(Mandatory = $true)][string[]] $RelativeFiles
    )

    $sensitiveLeafPattern = '(?i)(^\.env(?:\.|$)|firebase-adminsdk|serviceaccount|client_secret|google-services\.json|\.(pem|key|keystore|jks|p12|pfx)$)'
    $textExtensions = @('.py', '.json', '.sql', '.toml', '.txt', '.sh', '.service', '.timer', '.conf', '.md')
    foreach ($relative in $RelativeFiles) {
        $leaf = Split-Path -Leaf $relative
        if ($leaf -match $sensitiveLeafPattern) {
            throw "credential 파일은 운영 payload에 포함할 수 없습니다: $relative"
        }

        $extension = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
        if ($textExtensions -notcontains $extension) { continue }
        $fullPath = Join-Path $StageRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        $content = Get-Content -LiteralPath $fullPath -Raw
        if (
            $content -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----' -or
            $content -match '(?i)"private_key"\s*:\s*"-----BEGIN' -or
            $content -match '(?i)"client_secret"\s*:\s*"[^"<\s]{8,}"' -or
            $content -match 'AIza[0-9A-Za-z_-]{35}' -or
            $content -match 'sk-[A-Za-z0-9_-]{17,}'
        ) {
            throw "credential material이 운영 payload에서 검출됐습니다: $relative"
        }
    }
}

function Get-StageFilePaths {
    param([Parameter(Mandatory = $true)][string] $StageRoot)

    $rootFull = [IO.Path]::GetFullPath($StageRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $result = @()
    foreach ($item in Get-ChildItem -LiteralPath $rootFull -Recurse -Force) {
        Assert-PathHasNoReparsePoint -Path $item.FullName -Boundary $rootFull
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "staging tree에 reparse point가 있습니다: $($item.FullName)"
        }
        if ($item.PSIsContainer) { continue }
        if (-not ($item -is [IO.FileInfo])) {
            throw "일반 파일이 아닌 staging 항목이 있습니다: $($item.FullName)"
        }
        $result += $item.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
    }
    return @($result | Sort-Object)
}

function Assert-ExactFileSet {
    param(
        [Parameter(Mandatory = $true)][string[]] $Actual,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $missing = @($Expected | Where-Object { $Actual -notcontains $_ })
    $unexpected = @($Actual | Where-Object { $Expected -notcontains $_ })
    if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        $parts = @()
        if ($missing.Count -gt 0) { $parts += "missing:`n$($missing -join [Environment]::NewLine)" }
        if ($unexpected.Count -gt 0) { $parts += "unexpected:`n$($unexpected -join [Environment]::NewLine)" }
        throw "$Label exact file manifest 불일치:`n$($parts -join [Environment]::NewLine)"
    }
}

function Write-RuntimeHashManifest {
    param(
        [Parameter(Mandatory = $true)][string] $StageRoot,
        [Parameter(Mandatory = $true)][string[]] $RelativeFiles,
        [Parameter(Mandatory = $true)][string] $OutputRelativePath
    )

    $lines = foreach ($relative in $RelativeFiles) {
        $fullPath = Join-Path $StageRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        $hash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
    $outputPath = Join-Path $StageRoot ($OutputRelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))
    New-Item -ItemType Directory -Path (Split-Path -Parent $outputPath) -Force | Out-Null
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($outputPath, (($lines -join "`n") + "`n"), $utf8NoBom)
}

function Assert-RuntimeHashManifest {
    param(
        [Parameter(Mandatory = $true)][string] $StageRoot,
        [Parameter(Mandatory = $true)][string] $HashManifestRelativePath
    )

    $manifestPath = Join-Path $StageRoot ($HashManifestRelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))
    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "잘못된 SHA256 manifest 줄: $line" }
        $expectedHash = $Matches[1]
        $relative = $Matches[2]
        $fullPath = Join-Path $StageRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "SHA256 대상 누락: $relative" }
        $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) { throw "SHA256 불일치: $relative" }
    }
}

function Get-ExpectedArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][string[]] $RelativeFiles,
        [string] $Prefix = ''
    )

    $entries = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $cleanPrefix = $Prefix.Trim('/')
    if ($cleanPrefix) { [void] $entries.Add($cleanPrefix) }
    foreach ($relative in $RelativeFiles) {
        $entry = if ($cleanPrefix) { "$cleanPrefix/$relative" } else { $relative }
        [void] $entries.Add($entry)
        $parent = $entry
        while ($parent.Contains('/')) {
            $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
            if ($parent) { [void] $entries.Add($parent) }
        }
    }
    return @($entries | Sort-Object)
}

function Get-NormalizedArchiveEntries {
    param([Parameter(Mandatory = $true)][string] $ArchivePath)

    $rawEntries = @(& tar -tzf $ArchivePath 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "tar 목록 조회 실패: $ArchivePath" }
    $entries = @($rawEntries | ForEach-Object {
        $entry = ([string] $_).Trim().Replace('\', '/')
        while ($entry.StartsWith('./')) { $entry = $entry.Substring(2) }
        $entry.TrimEnd('/')
    } | Where-Object { $_ })

    $unique = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($entry in $entries) {
        if (-not $unique.Add($entry)) { throw "tar에 중복 entry가 있습니다: $entry" }
    }
    return $entries
}

function Assert-TarEntryTypes {
    param(
        [Parameter(Mandatory = $true)][string] $ArchivePath,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $verboseEntries = @(& tar -tvzf $ArchivePath 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "$Label tar verbose 목록 조회 실패" }
    foreach ($line in $verboseEntries) {
        $text = ([string] $line).TrimStart()
        if (-not $text) { continue }
        $type = $text.Substring(0, 1)
        if ($type -notin @('-', 'd')) {
            throw "$Label tar에 일반 파일/디렉터리가 아닌 entry가 있습니다: $text"
        }
    }
}

function Assert-ArchiveExactEntries {
    param(
        [Parameter(Mandatory = $true)][string[]] $Actual,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string] $Label
    )

    Assert-ExactFileSet -Actual $Actual -Expected $Expected -Label "$Label tar entry"
    foreach ($entry in $Actual) {
        if ($entry.StartsWith('/') -or $entry -match '(^|/)\.{1,2}(/|$)') {
            throw "$Label tar에 path traversal/absolute entry가 있습니다: $entry"
        }
    }
}
