[CmdletBinding()]
param(
    [string]$JobDirectory,
    [string]$OracleHome = 'C:\Oracle\Middleware\FormsBuilder14c',
    [string]$JavaExe = 'C:\o\java\jdk-21.0.11+10-jre\bin\java.exe',
    [switch]$ReadableOnly
)
$ErrorActionPreference = 'Stop'
$FoxRoot = Split-Path -Parent $PSScriptRoot
$FoxPython = Join-Path $FoxRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $FoxPython)) { throw 'FOX Python environment missing.' }
$FoxArgs = @('-m', 'fox.extractor')
if ($JobDirectory) {
    $JobDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JobDirectory)
    $FoxArgs += @('verify', '--job', $JobDirectory)
} else {
    $FoxArgs += 'check'
    if (-not $ReadableOnly) { $FoxArgs += @('--oracle-home', $OracleHome, '--java', $JavaExe) }
}
Push-Location -LiteralPath $FoxRoot
try {
    & $FoxPython @FoxArgs
    if ($LASTEXITCODE -ne 0) { throw 'Extractor readiness or package integrity check failed.' }
} finally { Pop-Location }
