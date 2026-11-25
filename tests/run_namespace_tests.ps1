param([string]$JavaHome = $env:JAVA_HOME)
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
foreach ($requiredPath in @($javacPath, $javaPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "JDK tool missing: $requiredPath" }
}
$classesPath = Join-Path $PSScriptRoot 'namespace-classes'
New-Item -ItemType Directory -Force -Path $classesPath | Out-Null
& $javacPath '-J-Dfile.encoding=UTF-8' -encoding UTF-8 --release 8 -d $classesPath (Join-Path $projectPath 'app\src\main\java\io\github\deltaconfig\RootShell.java') (Join-Path $PSScriptRoot 'RootNamespaceTests.java')
if ($LASTEXITCODE -ne 0) { throw 'Root namespace tests did not compile' }
& $javaPath -cp $classesPath RootNamespaceTests
if ($LASTEXITCODE -ne 0) { throw 'Root namespace tests failed' }
