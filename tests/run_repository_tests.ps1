param(
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$AndroidJar = ''
)
$ErrorActionPreference = 'Stop'
$projectPath = Split-Path $PSScriptRoot -Parent
if ($JavaHome) {
    $javacPath = Join-Path $JavaHome 'bin\javac.exe'
    $javaPath = Join-Path $JavaHome 'bin\java.exe'
} else {
    $javacCommand = Get-Command javac.exe -ErrorAction SilentlyContinue
    $javaCommand = Get-Command java.exe -ErrorAction SilentlyContinue
    if (-not $javacCommand -or -not $javaCommand) { throw 'Set JAVA_HOME or add JDK 17+ bin to PATH.' }
    $javacPath = $javacCommand.Source; $javaPath = $javaCommand.Source
}
if (-not $AndroidJar) {
    foreach ($sdkRoot in @($env:ANDROID_SDK_ROOT, $env:ANDROID_HOME)) {
        if (-not $sdkRoot) { continue }
        $candidate = Join-Path $sdkRoot 'platforms\android-35\android.jar'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $AndroidJar = $candidate; break }
    }
}
if (-not $AndroidJar) { throw 'Supply -AndroidJar or install API 35 and set ANDROID_SDK_ROOT/ANDROID_HOME.' }
foreach ($requiredPath in @($javacPath, $javaPath, $AndroidJar)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Test input missing: $requiredPath" }
}
$classesPath = Join-Path $PSScriptRoot 'repository-classes'
New-Item -ItemType Directory -Force -Path $classesPath | Out-Null
$sources = @(
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\RootShell.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\GameRepository.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\GameTarget.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\core\ConfigCrypto.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\core\ConfigPatcher.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\core\OperationFailure.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\core\LibraryMaskResolver.java'),
    (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\core\ConfigCompatibility.java'),
    (Join-Path $PSScriptRoot 'RepositoryTests.java')
)
& $javacPath '-J-Dfile.encoding=UTF-8' '-J-Duser.language=en' -encoding UTF-8 --release 8 -cp $AndroidJar -d $classesPath @sources
if ($LASTEXITCODE -ne 0) { throw 'Repository tests did not compile' }
& $javaPath -cp ($classesPath + [IO.Path]::PathSeparator + $AndroidJar) RepositoryTests
if ($LASTEXITCODE -ne 0) { throw 'Repository tests failed' }
