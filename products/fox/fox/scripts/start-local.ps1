param(
    [ValidateRange(1024, 65535)][int]$Port = 8100,
    [string]$Username,
    [string]$OracleHome,
    [Alias('Java')][string]$JavaExe,
    [ValidatePattern('^session-[0-9a-f]{32}$')][string]$ResumeSession
)
$ErrorActionPreference = 'Stop'

function Get-FoxOwnedProcessIdentity {
    param([System.Diagnostics.Process]$Process)
    try {
        $Process.Refresh()
        if ($Process.HasExited) { return $null }
        return @{ Id = $Process.Id; StartTicks = $Process.StartTime.ToUniversalTime().Ticks }
    } catch {
        throw 'Local preview shutdown identity could not be verified; no process was targeted.'
    }
}

function Invoke-FoxOwnedTreeTermination {
    param([System.Diagnostics.ProcessStartInfo]$StartInfo)
    $terminator = $null
    try {
        $terminator = [System.Diagnostics.Process]::Start($StartInfo)
        $capturedOutput = $terminator.StandardOutput.ReadToEndAsync()
        $capturedError = $terminator.StandardError.ReadToEndAsync()
        if (!$terminator.WaitForExit(5000)) {
            $terminator.Kill() # This helper, not an unrelated process.
            $terminator.WaitForExit()
            throw 'Local preview process-tree shutdown did not complete; partial files are retained.'
        }
        $null = $capturedOutput.GetAwaiter().GetResult()
        $null = $capturedError.GetAwaiter().GetResult()
        return $terminator.ExitCode
    } catch {
        throw 'Local preview process-tree shutdown did not complete; partial files are retained.'
    } finally {
        if ($null -ne $terminator) { $terminator.Dispose() }
    }
}

function Stop-FoxOwnedProcessTree {
    param($Process, [int]$ExpectedId, [long]$ExpectedStartTicks)
    $treeStop = New-Object System.Diagnostics.ProcessStartInfo
    $treeStop.FileName = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\taskkill.exe'
    $treeStop.Arguments = '/PID ' + $ExpectedId + ' /T /F'
    $treeStop.UseShellExecute = $false
    $treeStop.CreateNoWindow = $true
    $treeStop.RedirectStandardOutput = $true
    $treeStop.RedirectStandardError = $true
    # Check the original Process handle immediately before the exact-PID action.
    # Never enumerate processes or select a target by image/name.
    $identity = Get-FoxOwnedProcessIdentity -Process $Process
    if ($null -eq $identity) { return }
    if ($ExpectedId -le 0 -or $ExpectedStartTicks -le 0 -or
        $identity.Id -ne $ExpectedId -or $identity.StartTicks -ne $ExpectedStartTicks) {
        throw 'Local preview shutdown identity could not be verified; no process was targeted.'
    }
    $stopCode = Invoke-FoxOwnedTreeTermination -StartInfo $treeStop
    if ($stopCode -ne 0 -and $null -ne (Get-FoxOwnedProcessIdentity -Process $Process)) {
        throw 'Local preview process-tree shutdown did not complete; partial files are retained.'
    }
    if (!$Process.WaitForExit(5000)) {
        throw 'Local preview process-tree shutdown did not complete; partial files are retained.'
    }
}

$foxHasOracleHome = $PSBoundParameters.ContainsKey('OracleHome')
$foxHasJava = $PSBoundParameters.ContainsKey('JavaExe')
$foxHasUsername = $PSBoundParameters.ContainsKey('Username')
if ($foxHasUsername -and ($null -eq $Username -or $Username -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._@+-]{0,99}\z')) {
    throw 'Local username must be 1-100 ASCII letters, digits, dots, underscores, @, + or hyphens, starting with a letter or digit.'
}
if ($foxHasOracleHome -ne $foxHasJava) { throw 'Supply OracleHome and JavaExe together, or omit both for readable preparation.' }
if ($foxHasOracleHome) {
    if ([string]::IsNullOrWhiteSpace($OracleHome) -or [string]::IsNullOrWhiteSpace($JavaExe)) { throw 'Explicit tool paths must not be empty.' }
    # Resolve relative startup paths against the caller, not the child cwd.
    $foxOracleHome = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OracleHome)
    $foxJavaExe = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($JavaExe)
}
$foxRoot = Split-Path $PSScriptRoot -Parent
$foxPython = Join-Path $foxRoot '.venv/Scripts/python.exe'
if (!(Test-Path -LiteralPath $foxPython) -or !(Test-Path -LiteralPath (Join-Path $foxRoot 'dist/index.html'))) {
    throw 'Install requirements into .venv and run npm ci followed by npm run build first.'
}
$foxPrompt = if ($PSBoundParameters.ContainsKey('ResumeSession')) { 'Enter the original password for this local FOX session' } else { 'Choose a password for this local FOX session' }
$foxSecret = Read-Host $foxPrompt -AsSecureString
$foxPtr = [IntPtr]::Zero
$foxProcess = $null
$foxOwnedId = 0
$foxOwnedStartTicks = 0
$foxRequest = $null
$foxInputBytes = $null
try {
    # Build a child-only environment. Do not import fox.app or change caller env.
    $foxStart = New-Object System.Diagnostics.ProcessStartInfo
    $foxStart.FileName = $foxPython
    $foxStart.Arguments = '-B -m fox.local_assessment'
    $foxStart.WorkingDirectory = $foxRoot
    $foxStart.UseShellExecute = $false
    $foxStart.CreateNoWindow = $true
    $foxStart.RedirectStandardInput = $true
    $foxStart.EnvironmentVariables.Clear()
    $foxAllowedEnvironment = @('SystemRoot', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'OS', 'LANG', 'LC_ALL', 'NUMBER_OF_PROCESSORS')
    foreach ($foxName in $foxAllowedEnvironment) {
        $foxValue = [Environment]::GetEnvironmentVariable($foxName, 'Process')
        if ($null -ne $foxValue) { $foxStart.EnvironmentVariables[$foxName] = $foxValue }
    }
    $foxStart.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $foxStart.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $foxStart.EnvironmentVariables['PYTHONUNBUFFERED'] = '1'
    $foxPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($foxSecret)
    $foxRequest = @{ port = $Port; password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($foxPtr) }
    if ($foxHasUsername) { $foxRequest.username = $Username }
    if ($foxHasOracleHome) {
        $foxRequest.oracle_home = $foxOracleHome
        $foxRequest.java_exe = $foxJavaExe
    }
    if ($PSBoundParameters.ContainsKey('ResumeSession')) { $foxRequest.resume_session = $ResumeSession }
    $foxProcess = [System.Diagnostics.Process]::Start($foxStart)
    $foxInitialIdentity = Get-FoxOwnedProcessIdentity -Process $foxProcess
    if ($null -eq $foxInitialIdentity) { throw 'Local preview ended before startup completed.' }
    $foxOwnedId = $foxInitialIdentity.Id
    $foxOwnedStartTicks = $foxInitialIdentity.StartTicks
    # Secret transport is redirected stdin, never environment, arguments or output.
    # BaseStream avoids Windows PowerShell/.NET default-code-page differences.
    $foxInputBytes = [System.Text.Encoding]::UTF8.GetBytes(($foxRequest | ConvertTo-Json -Compress))
    $foxProcess.StandardInput.BaseStream.Write($foxInputBytes, 0, $foxInputBytes.Length)
    $foxProcess.StandardInput.BaseStream.Flush()
    $foxProcess.StandardInput.BaseStream.Close()
    [Array]::Clear($foxInputBytes, 0, $foxInputBytes.Length)
    $foxInputBytes = $null
    $foxRequest.password = $null
    $foxRequest = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($foxPtr)
    $foxPtr = [IntPtr]::Zero
    while (!$foxProcess.WaitForExit(500)) { }
    if ($foxProcess.ExitCode -ne 0) { throw 'The local assessment preview stopped without starting successfully. No integration was enabled.' }
} finally {
    if ($null -ne $foxInputBytes) { [Array]::Clear($foxInputBytes, 0, $foxInputBytes.Length) }
    if ($null -ne $foxRequest) { $foxRequest.password = $null }
    if ($foxPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($foxPtr) }
    $foxSecret.Dispose()
    if ($null -ne $foxProcess) {
        try { Stop-FoxOwnedProcessTree -Process $foxProcess -ExpectedId $foxOwnedId -ExpectedStartTicks $foxOwnedStartTicks }
        finally { $foxProcess.Dispose() }
    }
}
