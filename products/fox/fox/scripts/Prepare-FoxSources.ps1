[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceDirectory,
    [string]$OutputDirectory,
    [string]$JobId,
    [string]$OracleHome = 'C:\Oracle\Middleware\FormsBuilder14c',
    [string]$JavaExe = 'C:\o\java\jdk-21.0.11+10-jre\bin\java.exe',
    [switch]$ReadableOnly
)
$ErrorActionPreference = 'Stop'
$FoxRoot = Split-Path -Parent $PSScriptRoot
$FoxPython = Join-Path $FoxRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $FoxPython)) { throw 'FOX Python environment missing. Follow README local setup.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $FoxRoot 'work\extractions' }
# Resolve user-relative paths before changing to the package directory.
$SourceDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SourceDirectory)
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$FoxArgs = @('-m', 'fox.extractor', 'prepare', '--source', $SourceDirectory, '--output', $OutputDirectory)
if ($JobId) { $FoxArgs += @('--job-id', $JobId) }
if (-not $ReadableOnly) { $FoxArgs += @('--oracle-home', $OracleHome, '--java', $JavaExe) }
Push-Location -LiteralPath $FoxRoot
try {
    & $FoxPython @FoxArgs
    if ($LASTEXITCODE -ne 0) { throw 'Extraction blocked. Check status.json in the new job folder, if created. No files uploaded.' }
    Write-Host 'Prepared locally only. Review the private manifest.json, inventory.json and every readable ready/ file.'
    Write-Host 'In FOX, select Prepared source set, choose all ready/ readable files plus fox-readable-upload.json, then Upload and assess. Keep private root files and raw inputs local.'
} finally { Pop-Location }
