param([string]$VersionName = '1.10')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This archive is also intended for public distribution. Only the explicit list
# below is eligible; do not replace it with a recursive project/docs/tests scan.
$projectPath = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$projectPrefix = $projectPath + [IO.Path]::DirectorySeparatorChar
$sourceExtensions = @('.java', '.xml', '.jpg', '.png', '.webp')
$rootFiles = @(
    'README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md',
    '.gitignore', 'build.ps1', 'package-source.ps1'
)
$docFiles = @('docs/BUILD.md', 'docs/FORMAT.md', 'docs/ERRORS.md')
$testFiles = @(
    'tests/CoreTests.java', 'tests/RepositoryTests.java', 'tests/RootNamespaceTests.java',
    'tests/LibraryMaskResolverTests.java', 'tests/ConfigCompatibilityTests.java', 'tests/GameTargetTests.java',
    'tests/run_core_tests.py', 'tests/run_repository_tests.ps1', 'tests/run_namespace_tests.ps1',
    'tests/README.md'
)

function Get-SafeProjectPath([string]$RelativePath) {
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath)) {
        throw 'Source path must be relative to the project.'
    }
    foreach ($part in ($RelativePath.Replace('\', '/') -split '/')) {
        if ($part -in @('', '.', '..') -or $part -match '[\x00-\x1f\x7f<>:"|?*]' -or
            $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'Unsafe or non-portable file name in source package.'
        }
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $projectPath $RelativePath))
    if (-not $candidate.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Source path escapes the project.'
    }
    return $candidate
}

function Assert-NoLinks([string]$Path) {
    $candidate = [IO.Path]::GetFullPath($Path)
    if ($candidate -ne $projectPath -and -not $candidate.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Source or output path escapes the project.'
    }
    while ($true) {
        $item = $null
        try { $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { }
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Symbolic links, junctions and reparse points are not allowed in source package paths.'
            }
        }
        if ($candidate -eq $projectPath) { break }
        $candidate = [IO.Path]::GetDirectoryName($candidate)
    }
}

function Get-SourceFile([string]$RelativePath) {
    $path = Get-SafeProjectPath $RelativePath
    Assert-NoLinks $path
    if (-not (Test-Path -LiteralPath $path)) { return }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw 'Expected an ordinary source file, found a directory.' }
    return $item
}

Assert-NoLinks $projectPath
if ($VersionName -notmatch '^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?$') {
    throw 'Invalid source version. Use a version such as 1.10 or 1.10.1.'
}
$files = [Collections.Generic.List[IO.FileInfo]]::new()
$appDirectory = Get-SafeProjectPath 'app/src/main'
Assert-NoLinks $appDirectory
if (-not (Test-Path -LiteralPath $appDirectory -PathType Container)) { throw 'app/src/main is missing.' }
$pending = [Collections.Generic.Stack[string]]::new()
$pending.Push($appDirectory)
while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    Assert-NoLinks $directory
    # Walk one directory at a time, checking reparse points before descending.
    foreach ($item in (Get-ChildItem -LiteralPath $directory -Force)) {
        $relativePath = $item.FullName.Substring($projectPrefix.Length).Replace('\', '/')
        $checkedPath = Get-SafeProjectPath $relativePath
        Assert-NoLinks $checkedPath
        if ($item.PSIsContainer) { $pending.Push($checkedPath) }
        elseif ($item.Extension.ToLowerInvariant() -in $sourceExtensions) { $files.Add($item) }
    }
}
foreach ($relativePath in ($rootFiles + $docFiles + $testFiles)) {
    $file = Get-SourceFile $relativePath
    if ($null -ne $file) { $files.Add($file) }
}
$selectedFiles = @($files | Sort-Object FullName -Unique)
if ($selectedFiles.Count -eq 0) { throw 'No public source files were selected.' }

$distPath = Get-SafeProjectPath 'dist'
Assert-NoLinks $distPath
if (-not (Test-Path -LiteralPath $distPath)) { New-Item -ItemType Directory -Path $distPath | Out-Null }
if (-not (Test-Path -LiteralPath $distPath -PathType Container)) { throw 'dist must be a directory.' }
$archivePath = Get-SafeProjectPath ("dist/DeltaConfig-$VersionName-source.zip")
Assert-NoLinks $archivePath
if (Test-Path -LiteralPath $archivePath -PathType Container) { throw 'Source archive output is a directory.' }
$temporaryPath = Get-SafeProjectPath ('dist/.source-' + [Guid]::NewGuid().ToString('N') + '.tmp')
Assert-NoLinks $temporaryPath
Add-Type -AssemblyName System.IO.Compression
try {
    $outputStream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $zipArchive = [IO.Compression.ZipArchive]::new($outputStream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in $selectedFiles) {
                $relativePath = $file.FullName.Substring($projectPrefix.Length).Replace('\', '/')
                $sourcePath = Get-SafeProjectPath $relativePath
                Assert-NoLinks $sourcePath
                $entry = $zipArchive.CreateEntry('DeltaConfig/' + $relativePath, [IO.Compression.CompressionLevel]::Optimal)
                $entryStream = $entry.Open()
                $inputStream = [IO.File]::Open($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try { $inputStream.CopyTo($entryStream) } finally { $inputStream.Dispose(); $entryStream.Dispose() }
                Assert-NoLinks $sourcePath
            }
        } finally { $zipArchive.Dispose() }
    } finally { $outputStream.Dispose() }
    Assert-NoLinks $archivePath
    Move-Item -LiteralPath $temporaryPath -Destination $archivePath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Assert-NoLinks $temporaryPath
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
[pscustomobject]@{
    sourceZip = $archivePath
    files = $selectedFiles.Count
    bytes = (Get-Item -LiteralPath $archivePath).Length
    sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    entries = @($selectedFiles | ForEach-Object { $_.FullName.Substring($projectPrefix.Length).Replace('\', '/') })
} | ConvertTo-Json -Depth 4
