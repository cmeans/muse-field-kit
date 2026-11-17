# run-test.ps1 -- the user-side tests for ../handoff.ps1 (the Windows twin of
# run-test.sh's sections 3a and 5b).
#
# Runs on Windows PowerShell 5.1 and PowerShell 7, with age (age.exe) on PATH.
# Each case runs handoff.ps1 in a child process of the same PowerShell that
# runs this file, so exit codes and stdout and stderr are the real ones.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\run-test.ps1
#   pwsh -NoProfile -File test/run-test.ps1
#
# It checks:
#   - handoff.ps1's constants and recipient rule against handoff.sh (its twin);
#   - every recipient-file case in user-side-cases.json, the table run-test.sh
#     section 5b reads too (exit code, stderr text, nothing on stdout), and
#     every payload case in payload-cases.json (shared the same way);
#   - the cases that aren't a file's contents: -To NAME rules, arguments, the
#     near-miss allow-list, links and directories, the payload checks and cap,
#     -File and pipeline input, a missing or failing age, age's environment;
#   - no dummy value in handoff.ps1's own output;
#   - -CheckSetup (section 8): every check line, the failure paths (no age, no
#     age-keygen, a bad recipient file, an age that corrupts its output or
#     writes a second stanza, the header vectors), the output contract, and no
#     temporary folder left after an INT or TERM (the signal case is Linux and
#     macOS only; elsewhere it prints "n/a on this OS: <case>"; the age stubs
#     are shell scripts there and a compiled age.exe on Windows), and the host
#     surviving a failed run;
#   - on Windows: Mark of the Web and execution policy, and the documented
#     ways to run it (prints "n/a on this OS: <case>" elsewhere).
#
# Interop: blobs for the Linux interop job (consume.py decrypts them) go in
# $env:RUNNER_TEMP\handoff-ps-interop\<edition> (a temp directory when
# RUNNER_TEMP is unset): <name>.blob, and <name>.expect.json holding the field
# values the blob must decrypt to; <name>.payload, where present, is the exact
# payload bytes.
#
# This file and handoff.ps1 are ASCII only (Windows PowerShell 5.1 reads a
# script without a byte-order mark in the ANSI code page), and that's checked.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$Here = $PSScriptRoot
$Kit = Split-Path -Parent $Here
$HandoffPs1 = Join-Path $Kit 'handoff.ps1'
$OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$PSExe = (Get-Process -Id $PID).Path
$Major = $PSVersionTable.PSVersion.Major
$Utf8 = New-Object System.Text.UTF8Encoding $false

# The dummy values (expected.json's, and the marker every crafted value carries):
$U = 'dummy-user-Qx7'
$P = 'dummy-pass-K3z9w'
$MK = 'mk-Zq9'

function Say([string]$m) { [Console]::Out.WriteLine($m) }
function Fail([string]$m) { [Console]::Error.WriteLine("FAIL: $m"); exit 1 }
function NotHere([string]$case) { Say "n/a on this OS: $case" }

Say "PowerShell: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion) ($PSExe)"
$ageCmd = Get-Command -Name age -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $ageCmd) { Fail 'age not found on PATH; install it (README.md, Installing age)' }
$AgePath = $ageCmd.Path
$AgeDir = Split-Path -Parent $AgePath

# --- helpers ----------------------------------------------------------------

# Quote one argument for ProcessStartInfo.Arguments (the Windows rules, which
# .NET also applies on Linux).
function Join-Argv([string[]]$a) {
  $parts = foreach ($x in $a) {
    if ($x -ne '' -and $x -notmatch '[\s"]') { $x }
    else { '"' + (($x -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
  }
  return ($parts -join ' ')
}

# Run EXE with ARGV; stdin gets STDIN's bytes, then is closed. ENV entries
# replace (or with $null remove) the inherited ones. Returns Exit, Out, Err.
function Invoke-Proc {
  param([string]$Exe, [string[]]$Argv, [byte[]]$Stdin, [hashtable]$EnvSet, [string]$Cwd)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = Join-Argv $Argv
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  if ($Cwd) { $psi.WorkingDirectory = $Cwd }
  if ($EnvSet) {
    foreach ($k in @($EnvSet.Keys)) {
      if ($null -eq $EnvSet[$k]) { $psi.EnvironmentVariables.Remove($k) } else { $psi.EnvironmentVariables[$k] = [string]$EnvSet[$k] }
    }
  }
  $p = [System.Diagnostics.Process]::Start($psi)
  $outMs = New-Object System.IO.MemoryStream
  $errMs = New-Object System.IO.MemoryStream
  $t1 = $p.StandardOutput.BaseStream.CopyToAsync($outMs)
  $t2 = $p.StandardError.BaseStream.CopyToAsync($errMs)
  try {
    if ($Stdin -and $Stdin.Length -gt 0) { $p.StandardInput.BaseStream.Write($Stdin, 0, $Stdin.Length) }
    $p.StandardInput.Close()
  } catch { }
  if (-not $p.WaitForExit(180000)) { $p.Kill(); Fail "timed out: $Exe $($psi.Arguments)" }
  $t1.Wait(); $t2.Wait(); $p.WaitForExit()
  return New-Object PSObject -Property @{
    Exit = $p.ExitCode
    Out = $Utf8.GetString($outMs.ToArray())
    Err = $Utf8.GetString($errMs.ToArray())
  }
}

# A PowerShell single-quoted literal.
function Q([string]$s) { "'" + $s.Replace("'", "''") + "'" }

$script:drv = 0
# Run handoff.ps1 at SCRIPT in a child PowerShell, as `& SCRIPT ARGTEXT`
# (ARGTEXT is PowerShell argument text, e.g. "-To other -Fingerprint").
# -Pipe FILE pipes FILE's text in as one string; -PipeLines pipes it line by
# line (Get-Content). -Pre is PowerShell text run first. -PsArgs go before
# -File on the child's command line (default on Windows: -ExecutionPolicy
# Bypass, so the runner's policy doesn't decide the ordinary cases).
function Invoke-Handoff {
  param([string]$Script, [string]$ArgText = '', [string]$Pipe, [switch]$PipeLines, [string]$Pre = '',
        [hashtable]$EnvSet, [string]$Cwd, [byte[]]$Stdin, [string[]]$PsArgs, [string]$Call)
  $script:drv++
  $d = Join-Path $S "drv-$($script:drv).ps1"
  if (-not $Call) {
    $Call = "& $(Q $Script) $ArgText"
    if ($Pipe -and $PipeLines) { $Call = "Get-Content -LiteralPath $(Q $Pipe) -Encoding UTF8 | $Call" }
    elseif ($Pipe) { $Call = "[IO.File]::ReadAllText($(Q $Pipe), [Text.Encoding]::UTF8) | $Call" }
  }
  $text = @(
    '$ErrorActionPreference = ''Stop''',
    'try {',
    $Pre,
    '  $global:LASTEXITCODE = 0',
    "  $Call",
    '  exit $LASTEXITCODE',
    '} catch { [Console]::Error.WriteLine(''DRIVER: '' + $_.Exception.Message); exit 99 }'
  ) -join "`n"
  # With a byte-order mark: 5.1 reads a script without one in the ANSI code page.
  [IO.File]::WriteAllText($d, $text, (New-Object System.Text.UTF8Encoding $true))
  if ($null -eq $PsArgs) { if ($OnWindows) { $PsArgs = @('-ExecutionPolicy', 'Bypass') } else { $PsArgs = @() } }
  $argv = @('-NoProfile', '-NonInteractive') + $PsArgs + @('-File', $d)
  return Invoke-Proc -Exe $PSExe -Argv $argv -Stdin $Stdin -EnvSet $EnvSet -Cwd $Cwd
}

function No-Dummy([string]$desc, [string[]]$texts) {
  foreach ($t in $texts) {
    foreach ($m in @($U, $P, $MK)) {
      if ($t.Contains($m)) { Fail "${desc}: a dummy credential value appeared in handoff.ps1's own output" }
    }
  }
}

# A clean run: no PowerShell error record and no driver error on stderr (the
# twin of run-test.sh's "no traceback").
function No-Noise([string]$desc, $r) {
  if ($r.Err -match 'DRIVER:|At line:|Line \||CategoryInfo|FullyQualifiedErrorId|unexpected error') {
    [Console]::Error.WriteLine($r.Err); Fail "${desc}: a PowerShell error instead of a clean message"
  }
}

function Assert-Refusal([string]$desc, [int]$wantExit, [string]$wantMsg, $r) {
  if ($r.Exit -ne $wantExit) { [Console]::Error.WriteLine($r.Err); Fail "${desc}: exit $($r.Exit), expected $wantExit" }
  if (-not $r.Err.Contains($wantMsg)) { [Console]::Error.WriteLine($r.Err); Fail "${desc}: stderr lacks `"$wantMsg`"" }
  if ($r.Out.Length -ne 0) { Fail "${desc}: refusal printed to stdout: $($r.Out)" }
  No-Noise $desc $r
  No-Dummy $desc @($r.Out, $r.Err)
  Say "ok (refused: $desc)"
}

# A run that made a blob: exit 0, stdout one line of base64 and nothing else.
function Assert-Blob([string]$desc, $r) {
  if ($r.Exit -ne 0) { [Console]::Error.WriteLine($r.Err); Fail "${desc}: exit $($r.Exit), expected 0" }
  if ($r.Out -notmatch '\A[A-Za-z0-9+/]+={0,2}\r?\n\z') { Fail "${desc}: stdout is not one line of base64: $($r.Out)" }
  No-Noise $desc $r
  No-Dummy $desc @($r.Out, $r.Err)
  return $r.Out.Trim()
}

function Assert-True([bool]$cond, [string]$what) { if (-not $cond) { Fail $what } }

# A symbolic link at PATH to TARGET (which may not exist).
function New-Link([string]$path, [string]$target) {
  if ($OnWindows) {
    $r = Invoke-Proc -Exe "$env:ComSpec" -Argv @('/c', 'mklink', $path, $target)
    if ($r.Exit -ne 0) { Fail "test setup: mklink $path failed: $($r.Out) $($r.Err)" }
  } else {
    $r = Invoke-Proc -Exe 'ln' -Argv @('-s', '--', $target, $path)
    if ($r.Exit -ne 0) { Fail "test setup: ln -s $path failed: $($r.Err)" }
  }
}

# Install handoff.ps1 in DIR, with the recipient file SRC beside it as
# handoff-NAME.age when SRC is given.
function Install-Handoff([string]$dir, [string]$src, [string]$name = 'muse') {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item -LiteralPath $HandoffPs1 -Destination (Join-Path $dir 'handoff.ps1')
  if ($src) { Copy-Item -LiteralPath $src -Destination (Join-Path $dir "handoff-$name.age") }
  return (Join-Path $dir 'handoff.ps1')
}

$S = Join-Path ([IO.Path]::GetTempPath()) ('handoff-ps-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $S | Out-Null

# Interop output, kept after the run.
$IopBase = $env:RUNNER_TEMP
if (-not $IopBase) { $IopBase = [IO.Path]::GetTempPath() }
$Iop = Join-Path (Join-Path $IopBase 'handoff-ps-interop') ("ps$Major")
New-Item -ItemType Directory -Force -Path $Iop | Out-Null
Say "interop blobs: $Iop"
function Save-Interop([string]$name, [string]$blob, [string]$expectJson, [byte[]]$payload) {
  [IO.File]::WriteAllText((Join-Path $Iop "$name.blob"), "$blob`n", $Utf8)
  [IO.File]::WriteAllText((Join-Path $Iop "$name.expect.json"), $expectJson, $Utf8)
  if ($payload) { [IO.File]::WriteAllBytes((Join-Path $Iop "$name.payload"), $payload) }
}

try {

$Rcpt = ([IO.File]::ReadAllText((Join-Path $Here 'handoff-test.age'))).Trim()
$RcptFile = Join-Path $Here 'handoff-test.age'
$Want = "recipient: $Rcpt"
$Pay = '{"svc":"example","password":"mk-Zq9"}'
$PayFile = Join-Path $S 'pay.json'
[IO.File]::WriteAllText($PayFile, $Pay, $Utf8)
$Expected = Join-Path $Here 'expected.json'

# --- the scripts themselves -----------------------------------------------------
Say '== p1. handoff.ps1 and run-test.ps1: ASCII, LF, and they parse =='
foreach ($f in @($HandoffPs1, $PSCommandPath)) {
  if (-not (Test-Path -LiteralPath $f)) { Fail "$f not found" }
  $b = [IO.File]::ReadAllBytes($f)
  foreach ($x in $b) { if ($x -gt 127) { Fail "$f is not ASCII only (Windows PowerShell 5.1 would misread it)" } }
  if ([Array]::IndexOf($b, [byte]13) -ge 0) { Fail "$f has a CR: .gitattributes keeps *.ps1 LF" }
  $tok = $null; $errs = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$errs)
  if ($errs.Count -gt 0) { Fail "$f does not parse: $($errs[0].Message)" }
}
Say 'ok'

Say '== p2. the twin constants: handoff.ps1 against handoff.sh =='
$sh = [IO.File]::ReadAllText((Join-Path $Kit 'handoff.sh'))
$ps = [IO.File]::ReadAllText($HandoffPs1)
foreach ($pair in @(@('MAX_PAYLOAD', '(?m)^MAX_PAYLOAD=(\d+)', '(?m)^[ ]*\$MAX_PAYLOAD = (\d+)'),
                    @('MAX_KEY_BYTES', '(?m)^MAX_KEY_BYTES=(\d+)', '(?m)^[ ]*\$MAX_KEY_BYTES = (\d+)'),
                    @('MAX_NAME', '(?m)^MAX_NAME=(\d+)', '(?m)^[ ]*\$MAX_NAME = (\d+)'))) {
  $a = [regex]::Match($sh, $pair[1]); $b2 = [regex]::Match($ps, $pair[2])
  if (-not $a.Success -or -not $b2.Success) { Fail "test setup: $($pair[0]) not found in handoff.sh or handoff.ps1" }
  if ($a.Groups[1].Value -ne $b2.Groups[1].Value) { Fail "$($pair[0]): handoff.ps1 has $($b2.Groups[1].Value), handoff.sh $($a.Groups[1].Value)" }
}
$shKnown = [regex]::Match($sh, "(?m)^KNOWN_FIELDS='([a-z_ ]+)'$")
$psKnown = [regex]::Match($ps, "(?m)^[ ]*\`$KNOWN_FIELDS = '([a-z_ ]+)'$")
if (-not $shKnown.Success -or -not $psKnown.Success) { Fail 'test setup: KNOWN_FIELDS not found in handoff.sh or handoff.ps1' }
if ($shKnown.Groups[1].Value -cne $psKnown.Groups[1].Value) { Fail 'KNOWN_FIELDS differs between handoff.sh and handoff.ps1' }
$shRe = [regex]::Match($sh, "(?m)^[ ]*recipient_re='\^(age1\[[a-z0-9]+\]\{58\})\$'")
$psRe = [regex]::Match($ps, "(?m)^[ ]*\`$RECIPIENT_RE = '\^(age1\[[a-z0-9]+\]\{58\})\\z'")
if (-not $shRe.Success -or -not $psRe.Success) { Fail 'test setup: the recipient rule not found in handoff.sh or handoff.ps1' }
if ($shRe.Groups[1].Value -ne $psRe.Groups[1].Value) { Fail 'the recipient rule differs between handoff.sh and handoff.ps1' }
# A backstop only: with no recipient file there's no ciphertext (5b below).
if ($ps -cmatch 'age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}') { Fail 'handoff.ps1 embeds a recipient' }
Say 'ok'

Say '== p3. the console read: which keys end the input (Test-EndKey) =='
# The read loop needs a real console, so its decision is tested on its own:
# handoff.ps1's Test-EndKey, taken from its parse tree, fed made-up keys.
# Only the character a key produced ends the input, whatever the modifiers:
# AltGr is reported as Ctrl+Alt, and AltGr+Z types a letter.
$tok = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($HandoffPs1, [ref]$tok, [ref]$errs)
$fns = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-EndKey' }, $true))
Assert-True ($fns.Count -eq 1) "test setup: handoff.ps1 has $($fns.Count) Test-EndKey functions, expected 1"
. ([scriptblock]::Create($fns[0].Extent.Text))
# ConsoleKeyInfo(KeyChar, Key, shift, alt, control)
foreach ($c in @(@('Ctrl+Z', [char]26, [ConsoleKey]::Z, $false, $false, $true, $true),
                 @('Ctrl+D', [char]4, [ConsoleKey]::D, $false, $false, $true, $true),
                 @('AltGr+Z (Ctrl+Alt, z with dot above)', [char]0x017C, [ConsoleKey]::Z, $false, $true, $true, $false),
                 @('AltGr+D (Ctrl+Alt, d with stroke)', [char]0x0111, [ConsoleKey]::D, $false, $true, $true, $false),
                 @('Ctrl+Alt+Z producing KeyChar 26', [char]26, [ConsoleKey]::Z, $false, $true, $true, $true),
                 @('Ctrl+Z reported with no KeyChar', [char]0, [ConsoleKey]::Z, $false, $false, $true, $false),
                 @('plain z', [char]'z', [ConsoleKey]::Z, $false, $false, $false, $false),
                 @('plain D', [char]'D', [ConsoleKey]::D, $true, $false, $false, $false))) {
  $key = New-Object System.ConsoleKeyInfo $c[1], $c[2], $c[3], $c[4], $c[5]
  $got = [bool](Test-EndKey $key)
  Assert-True ($got -eq $c[6]) "Test-EndKey, $($c[0]): $got, expected $($c[6])"
}
Say 'ok'

# --- 3a: a blob from expected.json ------------------------------------------------
Say '== 3a. handoff.ps1 writes a blob (pipeline input) =='
$hd = Install-Handoff (Join-Path $S 'hd') $RcptFile
$r = Invoke-Handoff -Script $hd -Pipe $Expected
$blob = Assert-Blob '3a' $r
Assert-True ($r.Err.Contains("recipient: $Rcpt (from $(Join-Path (Join-Path $S 'hd') 'handoff-muse.age'))")) 'handoff.ps1 printed no recipient'
$expText = [IO.File]::ReadAllText($Expected)
Save-Interop 'expected' $blob $expText $Utf8.GetBytes($expText.TrimEnd("`r", "`n"))
Say 'ok'

# --- 5b: the recipient file -------------------------------------------------------
Say '== 5b. the recipient: handoff-NAME.age beside the script, and nothing else =='
$K = Join-Path $S 'hk'
$hk = Install-Handoff $K $null
$r = Invoke-Handoff -Script $hk -Pipe $PayFile
Assert-Refusal 'no recipient file' 1 "no recipient file for 'muse': $(Join-Path $K 'handoff-muse.age') doesn't exist" $r
Assert-Refusal '-Fingerprint with no recipient file' 1 "no recipient file for 'muse'" (Invoke-Handoff -Script $hk -ArgText '-Fingerprint')

# -To NAME picks handoff-NAME.age; -Fingerprint names the file it read.
Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $K 'handoff-other.age')
$r = Invoke-Handoff -Script $hk -ArgText '-To other -Fingerprint'
Assert-True ($r.Exit -eq 0 -and $r.Out.TrimEnd("`r", "`n") -ceq $Want) "-To other didn't read handoff-other.age: $($r.Out) $($r.Err)"
Assert-True ($r.Err -split "`r?`n" -ccontains "key file: $(Join-Path $K 'handoff-other.age')") "-Fingerprint didn't name the file it read: $($r.Err)"
No-Noise '-Fingerprint' $r
Assert-Refusal '-To a recipient with no file' 1 "no recipient file for 'nobody'" (Invoke-Handoff -Script $hk -ArgText '-To nobody -Fingerprint')
Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $K 'handoff-muse.age')
$r = Invoke-Handoff -Script $hk -ArgText '-Fingerprint'
Assert-True ($r.Out.TrimEnd("`r", "`n") -ceq $Want) "with no -To, handoff.ps1 didn't read handoff-muse.age"
Assert-True ($r.Err -split "`r?`n" -ccontains "key file: $(Join-Path $K 'handoff-muse.age')") 'with no -To, it did not name handoff-muse.age'
Remove-Item -LiteralPath (Join-Path $K 'handoff-muse.age')
Say 'ok (-To and -Fingerprint)'

# Encrypting names the recipient file beside the recipient, and the banner names both.
$r = Invoke-Handoff -Script $hk -ArgText "-To other -File $(Q $Expected)"
[void](Assert-Blob '-To other -File' $r)
Assert-True ($r.Err.Contains("$Want (from $(Join-Path $K 'handoff-other.age'))")) "the encrypt run didn't name its recipient file"
Assert-True ($r.Err.Contains("--- paste everything below into chat with other (recipient file $(Join-Path $K 'handoff-other.age')) ---")) "the paste banner didn't name the recipient"
Assert-True ($r.Err.Contains('--- end ---')) 'no end banner'
# -File is positional too.
[void](Assert-Blob 'FILE positional' (Invoke-Handoff -Script $hk -ArgText "$(Q $Expected) -To other"))
Say 'ok (encrypt names its recipient)'

# NAME rules: usage errors, exit 2.
$name64 = 'a' * 64
Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $K "handoff-$name64.age")
$r = Invoke-Handoff -Script $hk -ArgText "-To $name64 -Fingerprint"
Assert-True ($r.Exit -eq 0 -and $r.Out.TrimEnd("`r", "`n") -ceq $Want) 'handoff.ps1 refused a 64-character name'
$kelvin = [string][char]0x212A   # KELVIN SIGN: matches k when case is ignored
foreach ($c in @(@('a path', '../other', 'takes only letters, digits, _ and -'),
                 @('a backslash path', '..\other', 'takes only letters, digits, _ and -'),
                 @('an empty name', '', 'takes only letters, digits, _ and -'),
                 @('a non-ASCII name', ('oth' + [char]0xE9 + 'r'), 'takes only letters, digits, _ and -'),
                 @('a KELVIN SIGN', ('mus' + $kelvin), 'takes only letters, digits, _ and -'),
                 @('a trailing newline', "other`n", 'takes only letters, digits, _ and -'),
                 @('a 65-character name', ('a' * 65), '-To NAME is at most 64 characters'),
                 @('a name starting with -', '-muse', "-To NAME can't start with -"))) {
  Assert-Refusal "-To $($c[0])" 2 $c[2] (Invoke-Handoff -Script $hk -ArgText "-To $(Q $c[1]) -Fingerprint")
}
Assert-True ((Invoke-Handoff -Script $hk -ArgText "-To $(Q '../other') -Fingerprint").Err.Contains('Usage:')) 'a usage error did not print the usage'

# Arguments.
Assert-Refusal 'unknown option' 2 'unknown option -Bogus' (Invoke-Handoff -Script $hk -ArgText '-To other -Bogus')
Assert-Refusal 'two FILEs' 2 'at most one FILE' (Invoke-Handoff -Script $hk -ArgText "-To other $(Q $Expected) $(Q $Expected)")
Assert-Refusal '-File and a FILE' 2 'at most one FILE' (Invoke-Handoff -Script $hk -ArgText "-To other -File $(Q $Expected) $(Q $Expected)")
Assert-Refusal '-Fingerprint with a FILE' 2 '-Fingerprint takes no FILE' (Invoke-Handoff -Script $hk -ArgText "-To other -Fingerprint -File $(Q $Expected)")
$r = Invoke-Handoff -Script $hk -ArgText '-Help'
Assert-True ($r.Exit -eq 0 -and $r.Out.Length -eq 0 -and $r.Err.Contains('Usage:') -and $r.Err.Contains('handoff-NAME.age')) "-Help: exit $($r.Exit), usage on stderr only"

# Run from text, not a file: no directory to find the recipient file in.
$r = Invoke-Handoff -Call "& ([scriptblock]::Create([IO.File]::ReadAllText($(Q $hk)))) -To other -Fingerprint"
Assert-Refusal 'run as a script block, with no path' 1 'save handoff.ps1 to a file and run that file' $r

# Run by a relative path from another location: the file is beside the script.
$r = Invoke-Handoff -Call "Set-Location -LiteralPath $(Q $S); & (Join-Path (Join-Path '.' 'hk') 'handoff.ps1') -To other -Fingerprint" -Cwd $S
Assert-True ($r.Exit -eq 0 -and $r.Err.Contains('handoff-other.age')) "a relative run did not find the recipient file: $($r.Err)"
Say 'ok (arguments)'

# The near-miss allow-list.
$hn = Install-Handoff (Join-Path $S 'hn') $null
$NearDir = Join-Path $S 'hn'
function Clear-HN { Get-ChildItem -LiteralPath $NearDir -Force | Where-Object { $_.Name -ne 'handoff.ps1' } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force } }
foreach ($old in @('handoff-muse.age.old', 'handoff-muse.age.OLD', 'handoff-muse.age.bak', 'handoff-muse.age~', 'handoff-muse.age.2025-06-01', 'handoff-muse.age.save', 'handoff_muse.age.d', 'handoff_muse.age.lnk', 'handoffXmuse.age')) {
  Clear-HN
  if ($old -like '*.d') { New-Item -ItemType Directory -Path (Join-Path $NearDir 'handoff_muse.age') | Out-Null; $old = 'handoff_muse.age (a directory)' }
  elseif ($old -like '*.lnk') { New-Link (Join-Path $NearDir 'handoff_muse.age') $RcptFile }
  else { Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $NearDir $old) }
  Assert-Refusal "only $old beside it" 1 "handoff-muse.age doesn't exist. Save the agent's recipient there" (Invoke-Handoff -Script $hn -ArgText '-Fingerprint')
}
foreach ($near in @('handoff_muse.age', 'handoff.muse.age', 'HANDOFF_MUSE.age', 'handoff-muse.age.txt', 'handoff-muse.age.age')) {
  Clear-HN
  Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $NearDir $near)
  Assert-Refusal "$near beside it" 1 "but $near does. If that file is the agent's current recipient, rename it to handoff-muse.age, then compare -Fingerprint" (Invoke-Handoff -Script $hn -ArgText '-Fingerprint')
}
Clear-HN
Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $NearDir 'handoff-muse.age')
$r = Invoke-Handoff -Script $hn -ArgText '-To Muse -Fingerprint'
$caseFs = Test-Path -LiteralPath (Join-Path $NearDir 'HANDOFF-MUSE.AGE')
if ($caseFs) {
  # A case-insensitive file system (Windows): -To Muse opens handoff-muse.age.
  Assert-True ($r.Exit -eq 0 -and $r.Out.TrimEnd("`r", "`n") -ceq $Want) "-To Muse on a case-insensitive file system: $($r.Err)"
  Say 'ok (-To Muse opens handoff-muse.age here)'
} else {
  Assert-Refusal '-To Muse with handoff-muse.age beside it' 1 'but handoff-muse.age does. Names are case-sensitive: did you mean -To muse?' $r
}
Clear-HN
if (-not $OnWindows) {
  Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $NearDir "handoff`nmuse.age")
  Assert-Refusal 'a newline in place of the -' 1 "handoff-muse.age doesn't exist. Save the agent's recipient there" (Invoke-Handoff -Script $hn -ArgText '-Fingerprint')
  Clear-HN
} else { NotHere 'a newline in a file name (Windows file names cannot hold one)' }
# A 0.1.0 install: handoff-muse.pem and no .age.
# A PEM-shaped public key (made-up body: only the file's name matters to handoff.ps1).
$fakePem = "-----BEGIN PUBLIC KEY-----`nMIIBdummyDUMMYdummy0123456789+/abcdef`nDUMMYdummyDUMMYdummy0123456789+/ab==`n-----END PUBLIC KEY-----`n"
[IO.File]::WriteAllText((Join-Path $NearDir 'handoff-muse.pem'), $fakePem, $Utf8)
$r = Invoke-Handoff -Script $hn -Pipe $PayFile
Assert-Refusal 'a .pem and no .age' 1 '0.2.0 uses age' $r
Assert-True ($r.Err.Contains('ask your agent for its recipient')) "the .pem refusal doesn't say to ask for the recipient"
Assert-True ($r.Err.Contains('beside handoff.ps1')) 'the .pem refusal does not name handoff.ps1'
Assert-Refusal '-Fingerprint with a .pem and no .age' 1 '0.2.0 uses age' (Invoke-Handoff -Script $hn -ArgText '-Fingerprint')
Clear-HN
Say 'ok (near misses)'

# Recipient files that aren't a regular file, or aren't there; links that resolve.
New-Item -ItemType Directory -Path (Join-Path $K 'handoff-dir.age') | Out-Null
Assert-Refusal 'a directory' 1 'handoff-dir.age is not a regular file' (Invoke-Handoff -Script $hk -ArgText '-To dir -Fingerprint')
New-Link (Join-Path $K 'handoff-dangling.age') (Join-Path $K 'nowhere.age')
Assert-Refusal 'a dangling link' 1 "handoff-dangling.age is a symlink that doesn't resolve to a file" (Invoke-Handoff -Script $hk -ArgText '-To dangling -Fingerprint')
New-Link (Join-Path $K 'handoff-loop.age') (Join-Path $K 'handoff-loop.age')
Assert-Refusal 'a link loop' 1 "handoff-loop.age is a symlink that doesn't resolve to a file" (Invoke-Handoff -Script $hk -ArgText '-To loop -Fingerprint')
New-Link (Join-Path $K 'handoff-linked.age') $RcptFile
$r = Invoke-Handoff -Script $hk -ArgText '-To linked -Fingerprint'
Assert-True ($r.Exit -eq 0 -and $r.Out.TrimEnd("`r", "`n") -ceq $Want) "a link to a recipient file was refused: $($r.Err)"
Say 'ok (links and directories)'

# The shared table: the recipient-file cases that are a file's contents.
$ut = Install-Handoff (Join-Path $S 'ut') $null
$cases = @(ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Here 'user-side-cases.json'))))
# 5.1 may hand back the array as one element:
if ($cases.Count -eq 1 -and $cases[0] -is [array]) { $cases = @($cases[0]) }
Assert-True ($cases.Count -gt 0) 'user-side-cases.json is empty'
foreach ($c in $cases) {
  $keys = (@($c.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ','
  Assert-True ($keys -eq 'exit,file_bytes_b64,name,stderr_contains,to') "user-side-cases.json: case $($c.name) has the wrong keys ($keys)"
  $kf = Join-Path (Join-Path $S 'ut') "handoff-$($c.to).age"
  [IO.File]::WriteAllBytes($kf, [Convert]::FromBase64String($c.file_bytes_b64))
  $r = Invoke-Handoff -Script $ut -ArgText "-To $(Q $c.to)" -Pipe $PayFile
  if ([int]$c.exit -eq 0) {
    [void](Assert-Blob "case $($c.name)" $r)
    Assert-True ($r.Err.Contains($c.stderr_contains)) "case $($c.name): stderr lacks `"$($c.stderr_contains)`""
    $f = Invoke-Handoff -Script $ut -ArgText "-To $(Q $c.to) -Fingerprint"
    Assert-True ($f.Out.TrimEnd("`r", "`n") -ceq $Want) "case $($c.name): -Fingerprint shows another recipient"
    Say "ok (accepted: $($c.name))"
  } else {
    Assert-Refusal "recipient file case $($c.name)" ([int]$c.exit) $c.stderr_contains $r
  }
  Remove-Item -LiteralPath $kf
}

# --- the payload ----------------------------------------------------------------
Say '== 5b-ps. the payload: checks, cap, -File and pipeline input =='
Copy-Item -LiteralPath $RcptFile -Destination (Join-Path $K 'handoff-muse.age')
$jsonMsg = 'input must be a single JSON object with a string "svc" and string values only, aborting'
# The payload shapes, one table shared with run-test.sh (payload-cases.json):
# {name, payload or payload_base64 (bytes that aren't text), exit,
# stderr_contains}. A text case runs piped in and with -File; a bytes case
# with -File and as stdin's bytes (a pipeline carries text, not bytes). An
# accepted one's blob goes to interop, to open to the same bytes.
$pcases = @(ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $Here 'payload-cases.json'))))
if ($pcases.Count -eq 1 -and $pcases[0] -is [array]) { $pcases = @($pcases[0]) }
Assert-True ($pcases.Count -gt 0) 'payload-cases.json is empty'
foreach ($c in $pcases) {
  $keys = (@($c.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ','
  $f = Join-Path $S "pc-$($c.name).json"
  if ($keys -eq 'exit,name,payload,stderr_contains') {
    $isText = $true
    [IO.File]::WriteAllText($f, $c.payload, $Utf8)
  } elseif ($keys -eq 'exit,name,payload_base64,stderr_contains') {
    $isText = $false
    [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String($c.payload_base64))
  } else {
    Fail "payload-cases.json: case $($c.name) has the wrong keys ($keys)"
  }
  $raw = [IO.File]::ReadAllBytes($f)
  if ([int]$c.exit -eq 0) {
    if ($isText) { $r = Invoke-Handoff -Script $hk -Pipe $f } else { $r = Invoke-Handoff -Script $hk -Stdin $raw }
    $blob = Assert-Blob "payload $($c.name)" $r
    Assert-True ($r.Err.Contains($c.stderr_contains)) "payload $($c.name): stderr lacks `"$($c.stderr_contains)`""
    [void](Assert-Blob "payload $($c.name) (-File)" (Invoke-Handoff -Script $hk -ArgText "-File $(Q $f)"))
    # What age gets: the text without a leading byte-order mark (dropped) or
    # trailing line ends.
    $t = $Utf8.GetString($raw)
    if ($t.Length -gt 0 -and $t[0] -eq [char]0xFEFF) { $t = $t.Substring(1) }
    $t = $t.TrimEnd("`r", "`n")
    Save-Interop "payload-$($c.name)" $blob $t $Utf8.GetBytes($t)
    Say "ok (accepted: payload $($c.name))"
  } else {
    if ($isText) { $r = Invoke-Handoff -Script $hk -Pipe $f } else { $r = Invoke-Handoff -Script $hk -Stdin $raw }
    Assert-Refusal "payload $($c.name)" ([int]$c.exit) $c.stderr_contains $r
    Assert-Refusal "payload $($c.name) (-File)" ([int]$c.exit) $c.stderr_contains (Invoke-Handoff -Script $hk -ArgText "-File $(Q $f)")
  }
}
# A raw lone surrogate, which only a PowerShell string can hold (UTF-8 can't
# carry one): refused with the JSON message. The escaped forms are in the table.
Assert-Refusal 'payload: a raw lone surrogate in a piped string' 1 $jsonMsg (Invoke-Handoff -Call "('{`"svc`":`"example`",`"password`":`"mk-Zq9' + [char]0xD800 + '`"}') | & $(Q $hk)")
# Nothing piped and nothing on stdin: empty.
Assert-Refusal 'an empty pipeline' 1 'empty, aborting' (Invoke-Handoff -Call "@() | & $(Q $hk)")
Assert-Refusal 'no input at all' 1 'empty, aborting' (Invoke-Handoff -Script $hk)
Assert-Refusal '-File that is not there' 1 'cannot read' (Invoke-Handoff -Script $hk -ArgText "-File $(Q (Join-Path $S 'nothere.json'))")
Assert-Refusal '-File with an empty path' 1 'cannot read' (Invoke-Handoff -Script $hk -ArgText "-File ''")
Assert-Refusal '-File that is a folder' 1 'cannot read' (Invoke-Handoff -Script $hk -ArgText "-File $(Q $S)")

# Run in the caller's own session (& .\handoff.ps1 in-process), handoff.ps1
# leaves the caller's $Error as it found it: nothing a run records (an input
# fragment in an error text, say) stays behind, on any exit path.
$notJson = Join-Path $S 'pc-notjson.json'
foreach ($c in @(@('not JSON', $notJson, '', 1),
                 @('a payload that opens', $PayFile, '', 0),
                 @('no recipient file', $PayFile, '-To nobody', 1),
                 @('a usage error', $PayFile, "-To $(Q '../x')", 2),
                 @('-Fingerprint', '', '-Fingerprint', 0))) {
  $call = "& $(Q $hk) $($c[2])"
  if ($c[1]) { $call = "[IO.File]::ReadAllText($(Q $c[1]), [Text.Encoding]::UTF8) | $call" }
  $text = "try { throw 'handoff-test: an earlier error' } catch { }`n" +
          "  `$top = `$global:Error[0]; `$before = `$global:Error.Count`n" +
          "  $call`n" +
          "  `$code = `$LASTEXITCODE`n" +
          "  `$hit = @(`$global:Error | Where-Object { (`$_ | Out-String) -match 'mk-Zq9' }).Count`n" +
          "  [Console]::Error.WriteLine(`"ERRS same-top=`$([object]::ReferenceEquals(`$global:Error[0], `$top)) before=`$before after=`$(`$global:Error.Count) hit=`$hit`")`n" +
          "  exit `$code"
  $r = Invoke-Handoff -Call $text
  Assert-True ($r.Exit -eq $c[3]) "`$Error, $($c[0]): exit $($r.Exit), expected $($c[3]): $($r.Err)"
  Assert-True ($r.Err -match 'ERRS same-top=True before=(\d+) after=\1 hit=0') "`$Error, $($c[0]): the caller's `$Error changed: $(($r.Err -split "`r?`n" | Where-Object { $_ -like 'ERRS*' }) -join ' ')"
  No-Dummy "`$Error, $($c[0])" @($r.Out, $r.Err)
}
Say 'ok (the caller''s $Error is left as it was)'
Say 'ok (payload shape)'

# The cap: MAX_PAYLOAD bytes works, one more byte is refused, counted in
# UTF-8 bytes, not characters.
$max = [int]([regex]::Match($ps, '(?m)^[ ]*\$MAX_PAYLOAD = (\d+)').Groups[1].Value)
function Pad([int]$n, [string]$fill = 'y', [int]$fillBytes = 1) {
  $head = '{"svc":"example","private_key":"'; $tail = '"}'
  $room = $n - $head.Length - $tail.Length
  $s = $head + ($fill * [math]::Floor($room / $fillBytes)) + ('y' * ($room % $fillBytes)) + $tail
  if ($Utf8.GetByteCount($s) -ne $n) { Fail "test setup: padded payload is $($Utf8.GetByteCount($s)) bytes, not $n" }
  return $s
}
$f = Join-Path $S 'max.json'
[IO.File]::WriteAllText($f, (Pad $max), $Utf8)
[void](Assert-Blob "a $max-byte payload" (Invoke-Handoff -Script $hk -Pipe $f))
[IO.File]::WriteAllText($f, (Pad ($max + 1)), $Utf8)
$r = Invoke-Handoff -Script $hk -Pipe $f
Assert-Refusal 'one byte over the cap' 1 "payload is $($max + 1) bytes; the most handoff.ps1 sends is $max bytes." $r
Assert-True ($r.Err.Contains('Shorten the JSON.')) 'the cap message lacks the remedy'
$uu = [string][char]0xFC
$mb = Pad ($max + 1) $uu 2
Assert-True ($mb.Length -le $max) 'test setup: the multibyte payload is not shorter in characters'
[IO.File]::WriteAllText($f, $mb, $Utf8)
Assert-Refusal 'over the cap in bytes, under it in characters' 1 "payload is $($max + 1) bytes" (Invoke-Handoff -Script $hk -Pipe $f)
Say 'ok (the cap)'

# -File: relative to the PowerShell location, a UTF-8 BOM, UTF-16 (what
# Windows PowerShell 5.1's > writes), CRLF.
Copy-Item -LiteralPath $Expected -Destination (Join-Path $S 'rel.json')
$r = Invoke-Handoff -Call "Set-Location -LiteralPath $(Q $S); & $(Q $hk) -File rel.json"
[void](Assert-Blob '-File relative to the PowerShell location' $r)
$expBytes = $Utf8.GetBytes($expText)
# expected.json's values, on several lines, with CRLF line ends.
$mlText = "{`r`n  `"svc`": `"example`",`r`n  `"username`": `"$U`",`r`n  `"password`": `"$P`"`r`n}`r`n"
$i = 0
foreach ($enc in @(@('UTF-8 with a BOM', ([byte[]](0xEF, 0xBB, 0xBF) + $expBytes)),
                   @('UTF-16LE with a BOM, CRLF', ([byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes($mlText))),
                   @('UTF-16BE with a BOM, CRLF', ([byte[]](0xFE, 0xFF) + [Text.Encoding]::BigEndianUnicode.GetBytes($mlText))),
                   @('UTF-8, CRLF', $Utf8.GetBytes($mlText)))) {
  $i++
  $f = Join-Path $S "enc-$i.json"
  [IO.File]::WriteAllBytes($f, [byte[]]$enc[1])
  $blob = Assert-Blob "-File $($enc[0])" (Invoke-Handoff -Script $hk -ArgText "-File $(Q $f)")
  Save-Interop "file-enc-$i" $blob $expText $null
}
[IO.File]::WriteAllBytes($f, [byte[]](0x7B, 0xFF, 0x7D))
Assert-Refusal '-File not UTF-8' 1 $jsonMsg (Invoke-Handoff -Script $hk -ArgText "-File $(Q $f)")
# Pipeline input line by line (Get-Content), joined with newlines.
$f = Join-Path $S 'lines.json'
[IO.File]::WriteAllText($f, "{`n  `"svc`": `"example`",`n  `"username`": `"$U`",`n  `"password`": `"$P`"`n}`n", $Utf8)
$blob = Assert-Blob 'pipeline line by line' (Invoke-Handoff -Script $hk -Pipe $f -PipeLines)
Save-Interop 'lines' $blob $expText $null
# Bytes on stdin with no pipeline (cmd's <, or a pipe from a native program).
$blob = Assert-Blob 'stdin bytes' (Invoke-Handoff -Script $hk -Stdin $expBytes)
Save-Interop 'stdin' $blob $expText $Utf8.GetBytes($expText.TrimEnd("`r", "`n"))
Say 'ok (-File and pipeline input)'

# --- interop payloads -----------------------------------------------------------
Say '== interop. non-ASCII values and a private_key with a CRLF PEM =='
$na = 'p' + [char]0xE4 + 'ssw' + [char]0xF6 + 'rd-' + [char]0xFC + '-' + [char]0x65E5 + [char]0x672C
$naJson = '{"svc":"example","username":"' + $U + '","password":"' + $na + '"}'
$naFile = Join-Path $S 'nonascii.json'
[IO.File]::WriteAllText($naFile, $naJson, $Utf8)
$blob = Assert-Blob 'non-ASCII values' (Invoke-Handoff -Script $hk -Pipe $naFile)
Save-Interop 'nonascii' $blob $naJson $Utf8.GetBytes($naJson)
# A PEM with CRLF line ends, as [IO.File]::ReadAllText keeps them, built into
# the payload the way README shows (ConvertTo-Json -Compress into handoff.ps1).
# Not Get-Content -Raw: 5.1's ConvertTo-Json can serialize the note properties
# it adds as a nested object, which handoff.ps1 refuses.
$pem = "-----BEGIN PRIVATE KEY-----`r`nmk-Zq9-pem-line-one-AAAA`r`nmk-Zq9-pem-line-two-BBBB`r`n-----END PRIVATE KEY-----`r`n"
$pemDir = Join-Path $S 'pem'
$hp = Install-Handoff $pemDir $RcptFile
[IO.File]::WriteAllText((Join-Path $pemDir 'dummy.pem'), $pem, $Utf8)
$docCall = "@{svc='test'; private_key=[IO.File]::ReadAllText((Resolve-Path .\dummy.pem)); app_id='12345'; installation_id='67890'} | ConvertTo-Json -Compress | .\handoff.ps1"
$pkExpect = '{"svc":"test","private_key":' + (ConvertTo-Json -InputObject $pem -Compress) + ',"app_id":"12345","installation_id":"67890"}'
$r = Invoke-Handoff -Call $docCall -Cwd $pemDir
if ($r.Exit -ne 0 -and $r.Err.Contains($jsonMsg)) {
  Fail "the documented private_key pipeline was refused as not all strings under $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion): the form README shows needs changing"
}
$blob = Assert-Blob 'a private_key payload, as the docs build it' $r
Save-Interop 'private-key' $blob $pkExpect $null
Say 'ok'

# Windows PowerShell 5.1 with a console input encoding that has a preamble
# (UTF-8 with a BOM, code page 65001): .NET Framework would write that BOM
# into age's stdin ahead of the payload. The blob must open to the payload's
# bytes exactly (interop), and the caller's input encoding is put back.
$enc51 = 'Windows PowerShell 5.1 with a UTF-8 (BOM) console input encoding: no byte-order mark reaches age'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
  $r = Invoke-Handoff -Call ("[Console]::InputEncoding = New-Object System.Text.UTF8Encoding `$true`n" +
    "  if ([Console]::InputEncoding.GetPreamble().Length -eq 0) { throw 'test setup: the input encoding has no preamble' }`n" +
    "  [IO.File]::ReadAllText($(Q $naFile), [Text.Encoding]::UTF8) | & $(Q $hk)`n" +
    "  `$code = `$LASTEXITCODE`n" +
    "  if ([Console]::InputEncoding.GetPreamble().Length -eq 0) { [Console]::Error.WriteLine('INPUT ENCODING NOT RESTORED') }`n" +
    "  exit `$code")
  $blob = Assert-Blob $enc51 $r
  Assert-True (-not $r.Err.Contains('INPUT ENCODING NOT RESTORED')) 'handoff.ps1 did not put the caller''s input encoding back'
  Save-Interop 'utf8-input-encoding' $blob $naJson $Utf8.GetBytes($naJson)
  Say "ok ($enc51)"
} else { NotHere $enc51 }

# --- age: missing, failing, its environment ---------------------------------------
Say '== 5b-age. age: missing, failing, and what it is given =='
# A PATH with no age (PowerShell itself is run by its full path).
$noAge = Join-Path $S 'noage'
New-Item -ItemType Directory -Path $noAge | Out-Null
$pathNoAge = $noAge
if ($OnWindows) { $pathNoAge = "$noAge;$env:SystemRoot\system32;$env:SystemRoot" }
$r = Invoke-Handoff -Script $hk -Pipe $PayFile -EnvSet @{ PATH = $pathNoAge }
Assert-Refusal 'no age' 1 'age not found. Install it (README.md, Installing age)' $r
Assert-True (-not $r.Err.Contains('Paste or type')) 'a prompt came before the age refusal'
Assert-Refusal '-Fingerprint with no age' 1 'age not found' (Invoke-Handoff -Script $hk -ArgText '-Fingerprint' -EnvSet @{ PATH = $pathNoAge })

# Stubs named age, first on PATH: one that logs its environment and arguments
# and runs the real age; one that fails everything; one that fails on data.
$stub = Join-Path $S 'stub'
New-Item -ItemType Directory -Path $stub | Out-Null
$sep = [IO.Path]::PathSeparator
$log = Join-Path $S 'age-env.log'
function Write-Stub([string]$kind) {
  if ($OnWindows) {
    $f = Join-Path $stub 'age.cmd'
    switch ($kind) {
      'log'   { $t = "@echo off`r`nset >>`"$log`"`r`necho ARGV: %* >>`"$log`"`r`n`"$AgePath`" %*`r`n" }
      'fail'  { $t = "@echo off`r`nif `"%~1`"==`"--version`" (echo v9.9.9-test& exit /b 0)`r`nexit /b 1`r`n" }
      'data'  { $t = "@echo off`r`nif `"%~1`"==`"--version`" (echo v9.9.9-test& exit /b 0)`r`nset X=`r`nset /p X=`r`nif defined X exit /b 1`r`nexit /b 0`r`n" }
    }
  } else {
    $f = Join-Path $stub 'age'
    switch ($kind) {
      'log'   { $t = "#!/bin/sh`n{ env; echo `"ARGV: `$*`"; } >>'$log'`nexec '$AgePath' `"`$@`"`n" }
      'fail'  { $t = "#!/bin/sh`nif [ `"`$1`" = --version ]; then echo v9.9.9-test; exit 0; fi`nexit 1`n" }
      'data'  { $t = "#!/bin/sh`nif [ `"`$1`" = --version ]; then echo v9.9.9-test; exit 0; fi`n[ `"`$(wc -c)`" = 0 ]`n" }
    }
  }
  [IO.File]::WriteAllText($f, $t, $Utf8)
  if (-not $OnWindows) { [void](Invoke-Proc -Exe 'chmod' -Argv @('755', $f)) }
}
$stubPath = "$stub$sep$env:PATH"
Write-Stub 'log'
if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log }
$envSet = @{ PATH = $stubPath; AGE_PASSPHRASE = 'x'; AGE_PASSPHRASE_FD = '3'; AGE_PASSPHRASE_WORK_FACTOR = '5'; AGE_PASSPHRASE_MAX_WORK_FACTOR = '5'; AGEDEBUG = '1'; SECRET_JSON = 'leak'; HANDOFF_TEST_MARK = 'leak' }
[void](Assert-Blob 'age variables set' (Invoke-Handoff -Script $hk -Pipe $PayFile -EnvSet $envSet))
Assert-True (Test-Path -LiteralPath $log) "the stub age didn't run"
$logText = [IO.File]::ReadAllText($log)
# What the shell running the stub adds itself: sh sets PWD, SHLVL and _;
# cmd sets PROMPT and the like. Windows keeps SystemRoot (handoff.ps1 says why).
$allowed = '^(PATH|PWD|OLDPWD|SHLVL|_|ARGV|SystemRoot|PROMPT|PATHEXT|COMSPEC)[=:]'
$extra = @($logText -split "`r?`n" | Where-Object { $_ -ne '' -and $_ -notmatch $allowed })
if ($OnWindows) { $extra = @($extra | Where-Object { $_ -inotmatch $allowed }) }
Assert-True ($extra.Count -eq 0) "unexpected variables reached age: $(($extra | ForEach-Object { ($_ -split '=')[0] }) -join ' ')"
Assert-True (-not ($logText.Contains('leak') -or $logText.Contains($MK))) "the secret reached age's environment or arguments"
Say 'ok (age gets only PATH)'

Write-Stub 'fail'
Assert-Refusal 'an age that rejects the recipient' 1 'is not a valid age recipient: age v9.9.9-test did not accept it' (Invoke-Handoff -Script $hk -Pipe $PayFile -EnvSet @{ PATH = $stubPath })
Write-Stub 'data'
Assert-Refusal 'an age that fails to encrypt' 1 'age failed to encrypt (age v9.9.9-test)' (Invoke-Handoff -Script $hk -Pipe $PayFile -EnvSet @{ PATH = $stubPath })

# The caller's own tracing (Set-PSDebug -Trace 2 shows every assignment)
# never prints the secret.
# (The trace itself goes to stdout, up to handoff.ps1's Set-PSDebug -Off.)
$r = Invoke-Handoff -Script $hk -Pipe $PayFile -Pre '  Set-PSDebug -Trace 2'
Assert-True ($r.Exit -eq 0) "under Set-PSDebug -Trace 2: exit $($r.Exit) $($r.Err)"
Assert-True ($r.Out.Contains('DEBUG:')) 'test setup: Set-PSDebug -Trace 2 traced nothing'
Assert-True (($r.Out.TrimEnd("`r", "`n") -split "`r?`n")[-1] -match '\A[A-Za-z0-9+/]+={0,2}\z') 'under Set-PSDebug -Trace 2: no blob on the last line'
No-Dummy 'under Set-PSDebug -Trace 2' @($r.Out, $r.Err)
Say 'ok (failing age, tracing)'

# --- -CheckSetup ------------------------------------------------------------------
Say '== 8. -CheckSetup: age works here, proved by running it =='
$C8 = Join-Path $S 'c8'
$T8 = Join-Path $S 'tmp8'
New-Item -ItemType Directory -Path $T8 | Out-Null
$h8 = Install-Handoff $C8 $RcptFile
$tmpEnv = @{ TMPDIR = $T8; TEMP = $T8; TMP = $T8 }
function Join-Env([hashtable]$extra) { $h = @{}; foreach ($k in $tmpEnv.Keys) { $h[$k] = $tmpEnv[$k] }; foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] }; return $h }
# The payload the check encrypts, in the forms that must never be printed.
$leaks = @(('p' + [char]0xE4 + 'ssw' + [char]0xF6 + 'rd'), ([string][char]0x65E5 + [char]0x672C), '"svc":"check"')
# A -CheckSetup run: every stdout line is a check line, nothing else is on
# stdout or stderr, the payload is nowhere, and the temporary folder is gone.
function Assert-Checks([string]$desc, [int]$wantExit, $r) {
  if ($r.Exit -ne $wantExit) { [Console]::Error.WriteLine($r.Out + $r.Err); Fail "${desc}: exit $($r.Exit), expected $wantExit" }
  $lines = @($r.Out -split "`r?`n" | Where-Object { $_ -ne '' })
  foreach ($l in $lines) {
    if ($l -cnotmatch '\A(PASS|INFO|FAIL) [a-z0-9][a-z0-9. -]*: .+\z') { [Console]::Error.WriteLine($r.Out); Fail "${desc}: not a check line: $l" }
    if ($l.Contains('skip:')) { Fail "${desc}: a skip: line" }
  }
  $failed = @($lines | Where-Object { $_.StartsWith('FAIL ') }).Count
  Assert-True (($failed -gt 0) -eq ($wantExit -ne 0)) "${desc}: the exit code and the FAIL lines disagree"
  foreach ($t in @($r.Out, $r.Err)) { foreach ($m in $leaks) { Assert-True (-not $t.Contains($m)) "${desc}: the test payload appeared in the output" } }
  Assert-True ($r.Err.Length -eq 0) "${desc}: wrote to stderr: $($r.Err)"
  Assert-True (@(Get-ChildItem -LiteralPath $T8 -Force).Count -eq 0) "${desc}: the temporary folder was left behind"
  return $lines
}
function Assert-Has([string]$desc, $lines, [string]$pattern) {
  Assert-True (@($lines | Where-Object { $_ -cmatch ('\A' + $pattern) }).Count -ge 1) "${desc}: no line matching '$pattern' in: $($lines -join ' | ')"
}
function Assert-HasNot([string]$desc, $lines, [string]$pattern) {
  Assert-True (@($lines | Where-Object { $_ -cmatch ('\A' + $pattern) }).Count -eq 0) "${desc}: unexpected line '$pattern' in: $($lines -join ' | ')"
}
function Run-Check([string]$script, [string]$argText, [hashtable]$extra = @{}) {
  return Invoke-Handoff -Script $script -ArgText $argText -EnvSet (Join-Env $extra)
}

$lines = Assert-Checks '-CheckSetup' 0 (Run-Check $h8 '-CheckSetup')
foreach ($n in @('powershell', 'age', 'age-keygen', 'round trip', 'header', 'base64', 'recipient')) { Assert-Has '-CheckSetup' $lines "PASS ${n}: " }
Assert-HasNot '-CheckSetup' $lines '(FAIL|INFO) '
Assert-True ($lines.Count -eq 7) "-CheckSetup: not seven lines: $($lines -join ' | ')"
Say 'ok (-CheckSetup)'

# Usage errors.
Assert-Refusal '-CheckSetup with a FILE' 2 '-CheckSetup takes no FILE' (Invoke-Handoff -Script $h8 -ArgText '-CheckSetup x.json')
Assert-Refusal '-CheckSetup -Fingerprint' 2 'one mode at a time' (Invoke-Handoff -Script $h8 -ArgText '-CheckSetup -Fingerprint')
$r = Invoke-Handoff -Script $h8 -ArgText '-Help'
Assert-True ($r.Err.Contains('-CheckSetup')) '-Help does not list -CheckSetup'

# The recipient file: missing is INFO, a bad one FAIL.
$lines = Assert-Checks '-CheckSetup -To nosuch' 0 (Run-Check $h8 '-CheckSetup -To nosuch')
Assert-Has 'nosuch' $lines 'INFO recipient: '
Assert-Has 'nosuch' $lines 'PASS round trip: '
[IO.File]::WriteAllText((Join-Path $C8 'handoff-bad.age'), "age1notarecipient`n", $Utf8)
$lines = Assert-Checks 'a bad recipient file' 1 (Run-Check $h8 '-CheckSetup -To bad')
Assert-Has 'bad recipient' $lines 'FAIL recipient: '
Assert-Has 'bad recipient' $lines 'PASS round trip: '
[IO.File]::WriteAllText((Join-Path $C8 'handoff-bad.age'), ($Rcpt.Substring(0, $Rcpt.Length - 1) + 'q' + "`n"), $Utf8)
$lines = Assert-Checks 'a recipient with a bad checksum' 1 (Run-Check $h8 '-CheckSetup -To bad')
Assert-Has 'bad checksum' $lines 'FAIL recipient: '
Say 'ok (recipient file)'

# A PATH without age: FAIL age. A PATH with age alone: INFO age-keygen, an
# encrypt-only round trip, header and base64 still checked.
$sys = ''
if ($OnWindows) { $sys = ";$env:SystemRoot\system32;$env:SystemRoot" }
$lines = Assert-Checks 'no age' 1 (Run-Check $h8 '-CheckSetup' @{ PATH = "$noAge$sys" })
Assert-Has 'no age' $lines 'FAIL age: '
Assert-HasNot 'no age' $lines 'PASS (round trip|header|base64): '
# With no age only the recipient file's shape can be checked: INFO, not a blame.
Assert-Has 'no age' $lines 'INFO recipient: .*checksum is not checked \(no age\)'
Assert-HasNot 'no age' $lines 'FAIL recipient'
[IO.File]::WriteAllText((Join-Path $C8 'handoff-bad.age'), "age1notarecipient`n", $Utf8)
$lines = Assert-Checks 'no age, a recipient file of the wrong shape' 1 (Run-Check $h8 '-CheckSetup -To bad' @{ PATH = "$noAge$sys" })
Assert-Has 'no age, bad shape' $lines 'FAIL recipient: '
$onlyAge = Join-Path $S 'onlyage'
New-Item -ItemType Directory -Path $onlyAge | Out-Null
Copy-Item -LiteralPath $AgePath -Destination (Join-Path $onlyAge (Split-Path -Leaf $AgePath))
if (-not $OnWindows) { [void](Invoke-Proc -Exe 'chmod' -Argv @('755', (Join-Path $onlyAge (Split-Path -Leaf $AgePath)))) }
$lines = Assert-Checks 'no age-keygen' 0 (Run-Check $h8 '-CheckSetup' @{ PATH = "$onlyAge$sys" })
Assert-Has 'no age-keygen' $lines 'INFO age-keygen: '
Assert-Has 'no age-keygen' $lines 'INFO round trip: .*decrypt skipped'
Assert-Has 'no age-keygen' $lines 'PASS header: '
Assert-Has 'no age-keygen' $lines 'PASS base64: '
$lines = Assert-Checks 'no age-keygen, no recipient file' 0 (Run-Check $h8 '-CheckSetup -To nosuch' @{ PATH = "$onlyAge$sys" })
Assert-Has 'no keygen, no file' $lines 'INFO round trip: '
Say 'ok (age, age-keygen)'

# Stubs first on PATH that make age misbehave: one that changes a byte of its
# output, one that writes a second stanza, one whose decrypt returns other
# (valid) bytes, and one that writes a given file (the header rule against the
# vectors). On Linux and macOS they are shell scripts; on Windows a tiny
# age.exe compiled here with the csc that ships with .NET Framework, which
# reads its mode and the real age's path from a file beside it (Invoke-Age
# gives a child only PATH and SystemRoot, so nothing can come by environment).
$stubNames = @('an age that changes a byte of its output: FAIL round trip',
               'an age that writes a second stanza: FAIL header',
               'an age that decrypts to other bytes: FAIL round trip',
               'the header vectors, through an age that writes the vector',
               'a signal in the middle of a run leaves no temporary folder')
$st8 = Join-Path $S 'stub8'
New-Item -ItemType Directory -Path $st8 | Out-Null
$stub8Path = "$st8$sep$env:PATH"
$stubCs = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
public static class AgeStub {
  static string Quote(string a) {
    if (a.Length > 0 && a.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) return a;
    return "\"" + a.Replace("\"", "\\\"") + "\"";
  }
  static void Emit(byte[] b) {
    Stream so = Console.OpenStandardOutput();
    so.Write(b, 0, b.Length);
    so.Flush();
  }
  public static int Main(string[] args) {
    string[] cfg = File.ReadAllLines(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "age-stub.txt"));
    string mode = cfg[0], real = cfg[1], arg = cfg.Length > 2 ? cfg[2] : "";
    string first = args.Length > 0 ? args[0] : "";
    bool decrypt = first == "-d";
    bool version = first == "--version";
    if (mode == "differ" && decrypt) {
      Console.OpenStandardInput().CopyTo(Stream.Null);
      Emit(Encoding.UTF8.GetBytes("{\"svc\":\"check\",\"password\":\"other\"}"));
      return 0;
    }
    if (mode == "file" && !version && !decrypt) {
      Console.OpenStandardInput().CopyTo(Stream.Null);
      Emit(File.ReadAllBytes(arg));
      return 0;
    }
    StringBuilder sb = new StringBuilder();
    foreach (string a in args) { if (sb.Length > 0) sb.Append(' '); sb.Append(Quote(a)); }
    if (mode == "two" && !version && !decrypt) sb.Append(" -r ").Append(arg);
    ProcessStartInfo psi = new ProcessStartInfo(real, sb.ToString());
    psi.UseShellExecute = false;
    psi.RedirectStandardInput = true;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    Process p = Process.Start(psi);
    MemoryStream outMs = new MemoryStream();
    var t1 = p.StandardOutput.BaseStream.CopyToAsync(outMs);
    var t2 = p.StandardError.ReadToEndAsync();
    try {
      using (Stream i = Console.OpenStandardInput()) { i.CopyTo(p.StandardInput.BaseStream); }
      p.StandardInput.Close();
    } catch (IOException) { }
    t1.Wait();
    t2.Wait();
    p.WaitForExit();
    byte[] o = outMs.ToArray();
    if (mode == "flip" && !version && !decrypt && o.Length > 0) o[o.Length - 1] = (byte)(o[o.Length - 1] ^ 1);
    Emit(o);
    return p.ExitCode;
  }
}
'@
if ($OnWindows) {
  $cscs = @("$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe")
  $csc = $cscs | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $csc) { Fail 'test setup: csc.exe (.NET Framework 4) not found, so the age stub cannot be built' }
  $csFile = Join-Path $S 'agestub.cs'
  [IO.File]::WriteAllText($csFile, $stubCs, $Utf8)
  $r = Invoke-Proc -Exe $csc -Argv @('/nologo', '/optimize', "/out:$(Join-Path $st8 'age.exe')", $csFile)
  if ($r.Exit -ne 0) { Fail "test setup: the age stub did not compile: $($r.Out) $($r.Err)" }
}
$stubTpl = @{
  flip = @'
#!/bin/sh
case "$1" in --version|-d) exec '@REAL@' "$@" ;; esac
f=$(mktemp)
"@REAL@" "$@" >"$f"
n=$(wc -c <"$f" | tr -d ' ')
last=$(tail -c 1 "$f" | od -An -c | tr -d ' ')
head -c $((n - 1)) "$f"
if [ "$last" = X ]; then printf Y; else printf X; fi
rm -f "$f"
'@
  two = @'
#!/bin/sh
case "$1" in --version|-d) exec '@REAL@' "$@" ;; esac
exec '@REAL@' "$@" -r @ARG@
'@
  differ = @'
#!/bin/sh
case "$1" in -d) cat >/dev/null; printf '%s' '{"svc":"check","password":"other"}'; exit 0 ;; esac
exec '@REAL@' "$@"
'@
  file = @'
#!/bin/sh
case "$1" in --version|-d) exec '@REAL@' "$@" ;; esac
cat >/dev/null
cat '@ARG@'
'@
}
function Set-Stub8([string]$mode, [string]$arg = '') {
  if ($OnWindows) {
    [IO.File]::WriteAllLines((Join-Path $st8 'age-stub.txt'), [string[]]@($mode, $AgePath, $arg), $Utf8)
  } else {
    $f = Join-Path $st8 'age'
    [IO.File]::WriteAllText($f, $stubTpl[$mode].Replace('@REAL@', $AgePath).Replace('@ARG@', $arg), $Utf8)
    [void](Invoke-Proc -Exe 'chmod' -Argv @('755', $f))
  }
}

Set-Stub8 'flip'
$lines = Assert-Checks $stubNames[0] 1 (Run-Check $h8 '-CheckSetup' @{ PATH = $stub8Path })
Assert-Has 'flip' $lines 'FAIL round trip: .*could not decrypt'
Say "ok ($($stubNames[0]))"
Set-Stub8 'two' $Rcpt
$lines = Assert-Checks $stubNames[1] 1 (Run-Check $h8 '-CheckSetup' @{ PATH = $stub8Path })
Assert-Has 'second stanza' $lines 'FAIL header: '
Assert-Has 'second stanza' $lines 'PASS round trip: '
Say "ok ($($stubNames[1]))"
# A real age's MAC makes "decrypts to other bytes" unreachable, so the branch
# is pinned by an age whose decrypt returns valid but different text.
Set-Stub8 'differ'
$lines = Assert-Checks $stubNames[2] 1 (Run-Check $h8 '-CheckSetup' @{ PATH = $stub8Path })
Assert-Has 'differ' $lines 'FAIL round trip: .*differ'
Say "ok ($($stubNames[2]))"

# The vectors (test/vectors/ and the real blobs, from make-vectors.sh): refused
# ones, then the two real blobs (accepted; the decrypt then fails, as they're
# not for the throwaway key).
$vec = Join-Path $S 'vec8'
New-Item -ItemType Directory -Path $vec | Out-Null
function Test-Vector([string]$name, [string]$file, [bool]$accepted) {
  Set-Stub8 'file' $file
  $lines = Assert-Checks "header vector $name" 1 (Run-Check $h8 '-CheckSetup' @{ PATH = $stub8Path })
  if ($accepted) { Assert-Has $name $lines 'PASS header: '; Assert-Has $name $lines 'PASS base64: ' }
  else { Assert-Has $name $lines 'FAIL header: ' }
}
foreach ($v in @('scrypt', 'two-x25519', 'grease-only', 'plugin-stanza', 'pq-stanza', 'ssh-stanza', 'unknown-stanza', 'armored-b64')) {
  $f = Join-Path $vec "$v.bin"
  [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String(([IO.File]::ReadAllText((Join-Path (Join-Path $Here 'vectors') "$v.txt"))).Trim()))
  Test-Vector $v $f $false
}
Test-Vector 'armored-raw' (Join-Path (Join-Path $Here 'vectors') 'armored-raw.txt') $false
foreach ($v in @('blob-age', 'blob-age-rage')) {
  $f = Join-Path $vec "$v.bin"
  [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String(([IO.File]::ReadAllText((Join-Path $Here "$v.txt"))).Trim()))
  Test-Vector $v $f $true
}
$f = Join-Path $vec 'noend.bin'
[IO.File]::WriteAllText($f, "age-encryption.org/v1`n-> X25519 abc`nAAAA`n", $Utf8)
Test-Vector 'no end line' $f $false
# Stanza types are split on a single space, as consume.py does: two spaces, a
# tab, or a leading tab don't make an X25519 stanza.
foreach ($c in @(@('two-spaces', "age-encryption.org/v1`n->  X25519 abc`nAAAA`n--- abc`n"),
                 @('tab-after', "age-encryption.org/v1`n-> X25519`tabc`nAAAA`n--- abc`n"),
                 @('tab-before', "age-encryption.org/v1`n-> `tX25519 a`nAAAA`n--- abc`n"))) {
  $f = Join-Path $vec "$($c[0]).bin"
  [IO.File]::WriteAllText($f, $c[1], $Utf8)
  Test-Vector $c[0] $f $false
}
Say "ok ($($stubNames[3]))"

# The run stays in the caller's PowerShell: a run that ends in FAIL (here a
# corrupting age, then a temporary folder that can't be made) exits 1 through
# the script's own exit, the session lives on, no PipelineStoppedException
# text, and $Error has no entry the run added.
Set-Stub8 'flip'
$aFile = Join-Path $S 'a-file'
[IO.File]::WriteAllText($aFile, 'x', $Utf8)
foreach ($c in @(@('a failing check', @{ PATH = $stub8Path }), @('a temporary folder that cannot be made', @{ PATH = $stub8Path; TMPDIR = $aFile; TEMP = $aFile; TMP = $aFile }))) {
  $call = "`$before = `$global:Error.Count`n" +
    "  & $(Q $h8) -CheckSetup | Out-Null`n" +
    "  `$code = `$LASTEXITCODE`n" +
    "  [Console]::Out.WriteLine('SURVIVED ' + `$code + ' ' + (`$global:Error.Count - `$before))`n" +
    "  exit `$code"
  $r = Invoke-Handoff -Call $call -EnvSet (Join-Env $c[1])
  Assert-True ($r.Exit -eq 1) "$($c[0]), in process: exit $($r.Exit), expected 1: $($r.Out) $($r.Err)"
  Assert-True ($r.Out.Contains('SURVIVED 1 0')) "$($c[0]), in process: the session did not survive, or `$Error changed: $($r.Out)"
  Assert-True (-not ($r.Out + $r.Err).Contains('PipelineStoppedException')) "$($c[0]), in process: PipelineStoppedException text"
}
Say 'ok (in process: the host survives, exit 1, $Error untouched)'

# A signal while age is running: the temporary folder is removed. (Windows has
# no TERM and no way to send Ctrl-C to a child here.)
if (-not $OnWindows) {
  # The script's own folders in the temp area. The .NET runtime keeps files there
  # too (clr-debug-pipe-*, dotnet-diagnostic-*), which .NET 10 (PowerShell 7.6)
  # leaves behind when a TERM ends it: not the script's, and nothing secret.
  function Get-OwnFolders { return @(Get-ChildItem -LiteralPath $T8 -Force | Where-Object { $_.Name -like 'handoff-check-*' }) }
  function Get-AllNames { return ((@(Get-ChildItem -LiteralPath $T8 -Force) | ForEach-Object { $_.Name }) -join ' ') }
  function Test-Signal([string]$sig) {
    $marker = Join-Path $S 'age-started'
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker }
    $f = Join-Path $st8 'age'
    [IO.File]::WriteAllText($f, "#!/bin/sh`ncase `"`$1`" in --version|-d) exec '$AgePath' `"`$@`" ;; esac`n: >'$marker'`nsleep 4`nexec '$AgePath' `"`$@`"`n", $Utf8)
    [void](Invoke-Proc -Exe 'chmod' -Argv @('755', $f))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PSExe
    $psi.Arguments = Join-Argv @('-NoProfile', '-NonInteractive', '-File', $h8, '-CheckSetup')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    foreach ($k in $tmpEnv.Keys) { $psi.EnvironmentVariables[$k] = $tmpEnv[$k] }
    $psi.EnvironmentVariables['PATH'] = $stub8Path
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Close()
    $tries = 0
    while (-not (Test-Path -LiteralPath $marker) -and $tries -lt 200) { Start-Sleep -Milliseconds 100; $tries++ }
    Assert-True (Test-Path -LiteralPath $marker) "$sig test: the run never reached age"
    Assert-True (@(Get-OwnFolders).Count -gt 0) "$sig test: no temporary folder while the run was going (in the temp area: $(Get-AllNames))"
    [void](Invoke-Proc -Exe 'sh' -Argv @('-c', "kill -$sig $($p.Id)"))
    if (-not $p.WaitForExit(60000)) { $p.Kill(); Fail "$sig test: the run did not end" }
    # PowerShell's own status for an interrupted script is what the caller
    # sees for INT; TERM ends the process (143).
    if ($sig -eq 'TERM') { Assert-True ($p.ExitCode -ne 0) "$sig test: the interrupted run exited 0" }
    $out = $o.Result + $e.Result
    foreach ($m in $leaks) { Assert-True (-not $out.Contains($m)) "$sig test: the test payload appeared in the output" }
    $tries = 0
    while (@(Get-OwnFolders).Count -gt 0 -and $tries -lt 30) { Start-Sleep -Milliseconds 100; $tries++ }
    Assert-True (@(Get-OwnFolders).Count -eq 0) "$sig test: the temporary folder was left behind (in the temp area: $(Get-AllNames))"
  }
  Test-Signal 'INT'
  Test-Signal 'TERM'
  Say "ok ($($stubNames[4]))"
} else {
  NotHere $stubNames[4]
}

# An execution-policy block, with the ANSI escapes removed: Windows PowerShell
# 5.1's FullyQualifiedErrorId UnauthorizedAccess together with its category
# PSSecurityException, or (PowerShell 7's concise view prints neither) a phrase
# only an execution-policy error has. A generic access-denied error has
# neither. The callers also require a non-zero exit.
function Test-PolicyBlock($r) {
  $esc = [string][char]27
  $e = ([string]$r.Err) -replace ($esc + '\[[0-9;]*m'), ''
  if (($e -match 'UnauthorizedAccess') -and ($e -match 'PSSecurityException|SecurityError')) { return $true }
  return [bool]($e -match 'running scripts is disabled|is not digitally signed|about_Execution_Policies')
}

# --- Windows: Mark of the Web and execution policy --------------------------------
Say '== win. Mark of the Web, execution policy, the documented invocations =='
$epCases = @('a Mark-of-the-Web copy is blocked under RemoteSigned',
             'any copy is refused under Restricted',
             'Set-ExecutionPolicy -Scope Process Bypass, then the non-ASCII pipeline into .\handoff.ps1',
             'Set-ExecutionPolicy -Scope Process Bypass, then the private_key pipeline into .\handoff.ps1',
             '-ExecutionPolicy Bypass -File .\handoff.ps1 -File secrets.json')
if ($OnWindows) {
  $mw = Join-Path $S 'mw'
  $hm = Install-Handoff $mw $RcptFile
  [IO.File]::WriteAllText((Join-Path $mw 'dummy.pem'), $pem, $Utf8)
  Copy-Item -LiteralPath $naFile -Destination (Join-Path $mw 'nonascii.json')
  $un = Join-Path $S 'unmarked'
  $hu = Install-Handoff $un $RcptFile
  Set-Content -LiteralPath $hm -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"
  Assert-True ((Get-Content -LiteralPath $hm -Stream Zone.Identifier) -contains 'ZoneId=3') 'test setup: the Mark of the Web was not written'

  $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $hm, '-Fingerprint') -Cwd $mw
  Assert-True ($r.Exit -ne 0 -and $r.Out.Length -eq 0 -and (Test-PolicyBlock $r)) "RemoteSigned ran a marked copy: exit $($r.Exit) $($r.Err)"
  # The same copy, unmarked, runs under RemoteSigned (so the block above is the mark's).
  $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $hu, '-Fingerprint') -Cwd $un
  Assert-True ($r.Exit -eq 0 -and $r.Out.TrimEnd("`r", "`n") -ceq $Want) "RemoteSigned refused an unmarked copy: $($r.Err)"
  Say "ok ($($epCases[0]))"

  foreach ($h in @($hm, $hu)) {
    $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Restricted', '-File', $h, '-Fingerprint') -Cwd (Split-Path $h)
    Assert-True ($r.Exit -ne 0 -and $r.Out.Length -eq 0 -and (Test-PolicyBlock $r)) "Restricted ran $h : exit $($r.Exit) $($r.Err)"
    $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Restricted', '-Command', '.\handoff.ps1 -Fingerprint') -Cwd (Split-Path $h)
    Assert-True ($r.Exit -ne 0 -and $r.Out.Length -eq 0 -and (Test-PolicyBlock $r)) "Restricted ran .\handoff.ps1 in $h : $($r.Err)"
  }
  Say "ok ($($epCases[1]))"

  # The documented route, on a machine under Restricted: this window only
  # (Set-ExecutionPolicy -Scope Process; -Force stands in for the user's "Y"),
  # then .\handoff.ps1 as usual, with pipeline input. -Command, not a driver
  # file: Restricted would refuse the driver itself.
  $bp = 'Set-ExecutionPolicy -Scope Process Bypass -Force; '
  foreach ($c in @(@(2, 'ep-nonascii', "[IO.File]::ReadAllText('nonascii.json', [Text.Encoding]::UTF8) | .\handoff.ps1", $naJson),
                   @(3, 'ep-private-key', $docCall, $pkExpect))) {
    $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Restricted', '-Command', ($bp + $c[2] + '; exit $LASTEXITCODE')) -Cwd $mw
    $blob = Assert-Blob $epCases[$c[0]] $r
    $pl = $null; if ($c[0] -eq 2) { $pl = $Utf8.GetBytes($naJson) }
    Save-Interop $c[1] $blob $c[3] $pl
    Say "ok ($($epCases[$c[0]]))"
  }
  # The interactive paste's form, fed by -File (the console can't be driven here).
  $r = Invoke-Proc -Exe $PSExe -Argv @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\handoff.ps1', '-File', 'nonascii.json') -Cwd $mw
  $blob = Assert-Blob $epCases[4] $r
  Save-Interop 'ep-file' $blob $naJson $Utf8.GetBytes($naJson)
  Say "ok ($($epCases[4]))"
} else {
  foreach ($c in $epCases) { NotHere $c }
}

Say 'PASS'
} finally {
  Remove-Item -LiteralPath $S -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
