param(
    [string]$ToolchainPath = (Join-Path $PSScriptRoot 'toolchain'),
    [string]$VersionName = '1.10',
    [int]$VersionCode = 11
)
$ErrorActionPreference = 'Stop'
$projectPath = $PSScriptRoot
$toolchainPath = [IO.Path]::GetFullPath($ToolchainPath)
$jdkCandidates = @()
if ($PSBoundParameters.ContainsKey('ToolchainPath') -and (Test-Path -LiteralPath $toolchainPath -PathType Container)) {
    $jdkCandidates += @(Get-ChildItem -LiteralPath $toolchainPath -Directory -Filter 'jdk-*' | Sort-Object Name -Descending | ForEach-Object FullName)
}
if ($env:JAVA_HOME) { $jdkCandidates += $env:JAVA_HOME }
if (Test-Path -LiteralPath $toolchainPath -PathType Container) {
    $jdkCandidates += $toolchainPath
    $jdkCandidates += @(Get-ChildItem -LiteralPath $toolchainPath -Directory -Filter 'jdk-*' | Sort-Object Name -Descending | ForEach-Object FullName)
}
$javacCommand = Get-Command javac.exe -ErrorAction SilentlyContinue
if ($javacCommand) { $jdkCandidates += Split-Path (Split-Path $javacCommand.Source -Parent) -Parent }
$jdkPath = $null
foreach ($candidatePath in $jdkCandidates) {
    if (Test-Path -LiteralPath (Join-Path $candidatePath 'bin\javac.exe') -PathType Leaf) { $jdkPath = $candidatePath; break }
}
if (-not $jdkPath) { throw 'JDK 17 is missing. Set JAVA_HOME, add its bin directory to PATH, or provide a toolchain directory. See docs/BUILD.md.' }
$javaPath = Join-Path $jdkPath 'bin\java.exe'
$javacPath = Join-Path $jdkPath 'bin\javac.exe'
$jarPath = Join-Path $jdkPath 'bin\jar.exe'
$keytoolPath = Join-Path $jdkPath 'bin\keytool.exe'
$sdkCandidates = @()
if ($PSBoundParameters.ContainsKey('ToolchainPath')) { $sdkCandidates += $toolchainPath }
if ($env:ANDROID_SDK_ROOT) { $sdkCandidates += $env:ANDROID_SDK_ROOT }
if ($env:ANDROID_HOME) { $sdkCandidates += $env:ANDROID_HOME }
$sdkCandidates += $toolchainPath
$sdkBuildPath = $null
$platformPath = $null
foreach ($candidatePath in $sdkCandidates) {
    $standardBuildPath = Join-Path $candidatePath 'build-tools\35.0.0'
    $standardPlatformPath = Join-Path $candidatePath 'platforms\android-35\android.jar'
    if ((Test-Path -LiteralPath (Join-Path $standardBuildPath 'aapt2.exe') -PathType Leaf) -and (Test-Path -LiteralPath $standardPlatformPath -PathType Leaf)) {
        $sdkBuildPath = $standardBuildPath; $platformPath = $standardPlatformPath; break
    }
    # Preserve the previously documented offline layout when explicitly supplied.
    $legacyBuildPath = Join-Path $candidatePath 'android-15'
    $legacyPlatformPath = Join-Path $candidatePath 'android-35\android.jar'
    if ((Test-Path -LiteralPath (Join-Path $legacyBuildPath 'aapt2.exe') -PathType Leaf) -and (Test-Path -LiteralPath $legacyPlatformPath -PathType Leaf)) {
        $sdkBuildPath = $legacyBuildPath; $platformPath = $legacyPlatformPath; break
    }
}
if (-not $sdkBuildPath) { throw 'Android SDK API 35 and Build Tools 35.0.0 are missing. Set ANDROID_SDK_ROOT/ANDROID_HOME or pass -ToolchainPath. See docs/BUILD.md.' }
foreach ($requiredPath in @($javaPath, $javacPath, $jarPath, $keytoolPath, $platformPath, (Join-Path $sdkBuildPath 'aapt2.exe'), (Join-Path $sdkBuildPath 'zipalign.exe'), (Join-Path $sdkBuildPath 'lib\d8.jar'), (Join-Path $sdkBuildPath 'lib\apksigner.jar'))) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Build input missing: $requiredPath" }
}
$buildPath = Join-Path $projectPath ('build\' + [Guid]::NewGuid().ToString('N'))
$classesPath = Join-Path $buildPath 'classes'
$generatedPath = Join-Path $buildPath 'generated'
$dexPath = Join-Path $buildPath 'dex'
$tempPath = Join-Path $buildPath 'tmp'
$distPath = Join-Path $projectPath 'dist'
$signingPath = Join-Path $projectPath 'signing'
foreach ($directoryPath in @($buildPath, $classesPath, $generatedPath, $dexPath, $tempPath, $distPath, $signingPath)) {
    New-Item -ItemType Directory -Force -Path $directoryPath | Out-Null
}
function Invoke-CheckedTool([string]$ExecutablePath, [string[]]$ToolArguments) {
    & $ExecutablePath @ToolArguments
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($ExecutablePath)) failed with exit code $LASTEXITCODE" }
}
$mainPath = Join-Path $projectPath 'app\src\main'
$inputHashes = [ordered]@{}
$inputFiles = @(Get-ChildItem -LiteralPath $mainPath -Recurse -File) + @(Get-Item -LiteralPath $PSCommandPath)
foreach ($inputFile in ($inputFiles | Sort-Object FullName)) {
    $relativePath = $inputFile.FullName.Substring($projectPath.Length + 1).Replace('\', '/')
    $inputHashes[$relativePath] = (Get-FileHash -LiteralPath $inputFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$previousTempPath = $env:TEMP
$previousTmpPath = $env:TMP
try {
    $env:TEMP = $tempPath
    $env:TMP = $tempPath
    $compiledPath = Join-Path $buildPath 'resources.zip'
    $unsignedPath = Join-Path $buildPath 'unsigned.apk'
    $alignedPath = Join-Path $buildPath 'aligned.apk'
    $apkPath = Join-Path $distPath ("鼠鼠工具箱-$VersionName.apk")
    # aapt2's version flags do not replace attributes already present in a source manifest.
    # Apply parameters to a build-local copy, leaving the repository's source unchanged.
    $buildManifestPath = Join-Path $tempPath 'AndroidManifest.xml'
    $buildManifest = New-Object Xml.XmlDocument
    $buildManifest.PreserveWhitespace = $true
    $buildManifest.Load((Join-Path $mainPath 'AndroidManifest.xml'))
    [void]$buildManifest.DocumentElement.SetAttribute('versionName', 'http://schemas.android.com/apk/res/android', $VersionName)
    [void]$buildManifest.DocumentElement.SetAttribute('versionCode', 'http://schemas.android.com/apk/res/android', [string]$VersionCode)
    $xmlSettings = New-Object Xml.XmlWriterSettings
    $xmlSettings.Encoding = [Text.UTF8Encoding]::new($false)
    $xmlSettings.NewLineHandling = [Xml.NewLineHandling]::None
    $xmlWriter = [Xml.XmlWriter]::Create($buildManifestPath, $xmlSettings)
    try { $buildManifest.Save($xmlWriter) } finally { $xmlWriter.Dispose() }
    Invoke-CheckedTool (Join-Path $sdkBuildPath 'aapt2.exe') @('compile', '--dir', (Join-Path $mainPath 'res'), '-o', $compiledPath)
    $linkArguments = @('link', '-o', $unsignedPath, '-I', $platformPath, '--manifest', $buildManifestPath, '--java', $generatedPath, '--min-sdk-version', '26', '--target-sdk-version', '35', '--version-code', "$VersionCode", '--version-name', $VersionName, $compiledPath)
    $assetsPath = Join-Path $mainPath 'assets'
    if (Test-Path -LiteralPath $assetsPath -PathType Container) { $linkArguments += @('-A', $assetsPath) }
    Invoke-CheckedTool (Join-Path $sdkBuildPath 'aapt2.exe') $linkArguments
    $sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $mainPath 'java'), $generatedPath -Recurse -File -Filter '*.java')
    if ($sourceFiles.Count -eq 0) { throw 'No Java source files.' }
    $argumentsPath = Join-Path $buildPath 'javac.args'
    # JDK's Java 8 release API includes javac's LambdaMetafactory bootstrap signatures.
    # Android classes come from the official SDK; D8 handles Android desugaring next.
    $argumentLines = @('-encoding', 'UTF-8', '--release', '8', '-classpath', ('"' + $platformPath.Replace('\', '/') + '"'), '-d', ('"' + $classesPath.Replace('\', '/') + '"'))
    $argumentLines += $sourceFiles | ForEach-Object { '"' + $_.FullName.Replace('\', '/') + '"' }
    [IO.File]::WriteAllLines($argumentsPath, $argumentLines, [Text.UTF8Encoding]::new($false))
    Invoke-CheckedTool $javacPath @('-J-Dfile.encoding=UTF-8', '-J-Duser.language=en', "@$argumentsPath")
    if (-not (Test-Path -LiteralPath (Join-Path $classesPath 'io\github\deltaconfig\MainActivity.class'))) { throw 'MainActivity class missing.' }
    $classesJarPath = Join-Path $buildPath 'classes.jar'
    Invoke-CheckedTool $jarPath @('cf', $classesJarPath, '-C', $classesPath, '.')
    Invoke-CheckedTool $javaPath @(("-Djava.io.tmpdir=$tempPath"), '-cp', (Join-Path $sdkBuildPath 'lib\d8.jar'), 'com.android.tools.r8.D8', '--lib', $platformPath, '--min-api', '26', '--output', $dexPath, $classesJarPath)
    $dexFiles = @(Get-ChildItem -LiteralPath $dexPath -File -Filter 'classes*.dex' | Sort-Object Name)
    if ($dexFiles.Count -eq 0) { throw 'D8 did not emit classes.dex.' }
    $jarArguments = @('uf', $unsignedPath)
    foreach ($dexFile in $dexFiles) { $jarArguments += @('-C', $dexPath, $dexFile.Name) }
    Invoke-CheckedTool $jarPath $jarArguments
    Invoke-CheckedTool (Join-Path $sdkBuildPath 'zipalign.exe') @('-f', '-p', '4', $unsignedPath, $alignedPath)
    foreach ($relativePath in $inputHashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $projectPath $relativePath) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHashes[$relativePath]) { throw "Source changed during build: $relativePath. Rebuild after edits finish." }
    }
    $keystorePath = Join-Path $signingPath 'deltaconfig-local.p12'
    $passwordPath = Join-Path $signingPath 'store-password.txt'
    if (-not (Test-Path -LiteralPath $keystorePath)) {
        if (Test-Path -LiteralPath $passwordPath) { throw 'Password file exists without a keystore. Preserve it and investigate before generating another identity.' }
        $randomBytes = New-Object byte[] 32
        $randomSource = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $randomSource.GetBytes($randomBytes) } finally { $randomSource.Dispose() }
        [IO.File]::WriteAllText($passwordPath, [Convert]::ToBase64String($randomBytes), [Text.UTF8Encoding]::new($false))
        Invoke-CheckedTool $keytoolPath @('-genkeypair', '-keystore', $keystorePath, '-storetype', 'PKCS12', '-storepass:file', $passwordPath, '-alias', 'deltaconfig', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '10000', '-dname', 'CN=DeltaConfig Local Build,OU=Local Apps,O=DeltaConfig,C=CN')
    }
    if (-not (Test-Path -LiteralPath $passwordPath)) { throw 'Signing password file is missing. The existing app signing identity must be preserved.' }
    Invoke-CheckedTool $javaPath @(("-Djava.io.tmpdir=$tempPath"), '-jar', (Join-Path $sdkBuildPath 'lib\apksigner.jar'), 'sign', '--ks', $keystorePath, '--ks-key-alias', 'deltaconfig', '--ks-pass', ('file:' + $passwordPath), '--min-sdk-version', '26', '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true', '--out', $apkPath, $alignedPath)
    Invoke-CheckedTool $javaPath @('-jar', (Join-Path $sdkBuildPath 'lib\apksigner.jar'), 'verify', '--verbose', '--print-certs', $apkPath) | Tee-Object -FilePath (Join-Path $distPath 'apk-signature-verification.txt')
    Invoke-CheckedTool (Join-Path $sdkBuildPath 'zipalign.exe') @('-c', '-p', '4', $apkPath)
    $badgingOutput = @(Invoke-CheckedTool (Join-Path $sdkBuildPath 'aapt2.exe') @('dump', 'badging', $apkPath))
    $badgingOutput | Tee-Object -FilePath (Join-Path $distPath 'apk-package-verification.txt')
    $packageLine = $badgingOutput | Where-Object { $_ -like 'package:*' } | Select-Object -First 1
    if (-not $packageLine -or $packageLine -notmatch ("versionCode='" + $VersionCode + "'") -or $packageLine -notmatch ("versionName='" + [Regex]::Escape($VersionName) + "'")) {
        throw 'Built APK version does not match the requested version parameters.'
    }
    $metadata = [ordered]@{ apk = $apkPath; sha256 = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash.ToLowerInvariant(); bytes = (Get-Item -LiteralPath $apkPath).Length; versionName = $VersionName; versionCode = $VersionCode; minSdk = 26; targetSdk = 35; builtAtUtc = [DateTime]::UtcNow.ToString('o'); inputSha256 = $inputHashes }
    [IO.File]::WriteAllText((Join-Path $distPath 'build-verification.json'), ($metadata | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    [pscustomobject]$metadata | Select-Object apk,sha256,bytes,versionName,versionCode,minSdk,targetSdk,builtAtUtc | ConvertTo-Json
} finally {
    $env:TEMP = $previousTempPath
    $env:TMP = $previousTmpPath
}
