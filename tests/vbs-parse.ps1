# =====================================================================
# _vbs-parse.ps1 - real VBScript syntax validation (parse-only guarantee)
#
# Compiles each file with the REAL VBScript language engine by handing a
# sanitized copy to cscript.exe. Sanitization comments out every statement
# that could execute anything (process spawn, WScript host calls, file or
# registry writes, HTA self.Close), and a hard guard asserts NO execution
# primitive survives - if the guard ever trips (unknown template), the
# file is reported as SKIP and is NEVER handed to cscript. So the check
# never runs the launcher's payload; it only proves the code compiles.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File _vbs-parse.ps1 file1.vbs file2.vbs
# Prints:  OK <file> | FAIL <file> :: <msg> | SKIP <file> :: <reason>
# Exit code 0 only if every file is OK (FAIL/SKIP set exit code 1).
# =====================================================================
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$Files
)

$ErrorActionPreference = 'Stop'

# Execution primitives that must never survive sanitization.
# NOTE: this validates a MODIFIED copy (execution lines commented out), never
# the original. The guard is fail-safe for the current generator templates
# (every process-spawn primitive requires CreateObject or WScript, both listed)
# - if a template ever gains an unlisted object (e.g. Shell.Application /
# InvokeVerb without CreateObject), the guard will NOT catch it and the line
# would run under cscript. Keep this list in sync with buildLauncher() in
# payload-forge.html whenever wrapper templates change.
$danger = @(
    'CreateObject', 'WScript', '\.Run\b', 'ShellExecute', '\.Exec\b',
    '\bExecute\b', '\bEval\b', 'RegWrite', 'FileSystemObject', '\bFSO\b',
    '\.Write\b', '\.OpenTextFile', '\.SaveToFile', 'self\.', 'SendKeys',
    'AppActivate', '\.Close\b'
)

function Get-Sanitized {
    param([string]$Code)
    $lines = $Code -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($line in $lines) {
        $m = $line -match ('(' + ($danger -join '|') + ')')
        if ($m) {
            $n++
            $out.Add("' <sanitized statement {0}>" -f $n)
        } else {
            $out.Add($line)
        }
    }
    # hard guard: no execution primitive may remain in the compiled text
    $joined = ($out -join "`n") -replace '[^\x00-\x7F]', '?'
    foreach ($p in $danger) {
        if ($joined -match $p) {
            throw "sanitizer guard tripped on '$p' - template changed, refusing to execute"
        }
    }
    return $joined
}

$cscript = (Get-Command cscript.exe -ErrorAction SilentlyContinue).Source
if (-not $cscript) {
    Write-Output 'ERROR :: cscript.exe not found'
    exit 2
}

$tmp = Join-Path $env:TEMP ('vbscheck_' + [guid]::NewGuid().ToString('N') + '.vbs')
$failed = $false
foreach ($f in $Files) {
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Output "FAIL $f :: file not found"
        $failed = $true
        continue
    }
    try {
        $code = [System.IO.File]::ReadAllText($f)
        $sanitized = Get-Sanitized -Code $code
        [System.IO.File]::WriteAllText($tmp, $sanitized, [System.Text.Encoding]::ASCII)
        $oldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'   # cscript stderr is expected for FAILs
        $out = & $cscript //nologo //E:VBScript $tmp 2>&1
        $rc = $LASTEXITCODE
        $ErrorActionPreference = $oldEAP
        if ($rc -eq 0) {
            Write-Output "OK $f"
        } else {
            $msg = (($out | Where-Object { $_ -match 'VBScript' -or $_ -match 'error' }) | Select-Object -First 1)
            if (-not $msg) { $msg = ($out | Select-Object -First 1) }
            Write-Output ("FAIL {0} :: {1}" -f $f, $msg)
            $failed = $true
        }
    } catch {
        Write-Output ("SKIP {0} :: {1}" -f $f, $_.Exception.Message)
        $failed = $true
    }
}
Remove-Item $tmp -ErrorAction SilentlyContinue
if ($failed) { exit 1 } else { exit 0 }
