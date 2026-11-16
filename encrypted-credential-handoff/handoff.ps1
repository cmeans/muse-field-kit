# handoff.ps1 -- securely pass a secret to your AI agent's machine, from
# Windows. The twin of handoff.sh: the same recipient file, rules and
# messages, for Windows PowerShell 5.1 and PowerShell 7, with age.exe and
# nothing else (no bash, Git or jq).
#
# The plaintext never enters the chat: it is encrypted with age (X25519) on
# THIS machine and only the ciphertext is pasted in. The matching private
# key (an age identity) lives in a locked-down file on the agent's machine
# and never enters chat.
#
# The plaintext never touches disk in the interactive path, but it does live
# in this PowerShell's memory while the script runs and could in principle be
# paged out. That is the residual exposure; "shredding" is not claimed.
#
# SETUP: save the recipient printed by agent-setup.sh on the agent's machine
# (one line, age1...) as handoff-<recipient>.age in the same folder as this
# script (for an agent called muse, the default: handoff-muse.age), and
# confirm the -Fingerprint output matches the recipient the agent reports
# for its key. At a rotation, replace that file; this script itself never
# changes.
#
# Needs age on PATH (README.md, "Installing age").
#
# Usage: handoff.ps1 -Help (the usage text below is the one copy).
#
# stdout is ONLY the base64 ciphertext; all prompts go to stderr, so
#   .\handoff.ps1 -File secrets.json | Set-Clipboard
# yields a clean blob.
#
# This file is ASCII only: Windows PowerShell 5.1 reads a script without a
# byte-order mark in the ANSI code page.

[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$To = 'muse',
  [Parameter(Position = 0)][string]$File,
  [switch]$Fingerprint,
  [switch]$Help,
  # The payload as pipeline input: one string (ConvertTo-Json's output), or
  # lines (Get-Content's), joined with newlines.
  [Parameter(ValueFromPipeline = $true)][AllowNull()][AllowEmptyString()][string]$InputObject,
  # Anything else, so it can be refused with handoff.sh's message and exit 2.
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

begin {
  # A caller's Set-PSDebug -Trace 2 would print every assignment, the secret
  # included (handoff.sh's set +x). This turns the caller's tracing off.
  Set-PSDebug -Off
  Set-StrictMode -Version 2
  $ErrorActionPreference = 'Stop'
  # An error nobody planned for gets a fixed message: PowerShell's own error
  # text can quote the input.
  trap { [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); exit 1 }

  $OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

  # Twins of handoff.sh's values (keep them equal; run-test.ps1 checks):
  # consume.py's MAX_KEY_FILE and agent-setup.sh's MAX_KEY_BYTES;
  $MAX_KEY_BYTES = 16384
  # NAME's length cap;
  $MAX_NAME = 64
  # the largest payload, in bytes, handed to age (handoff.sh has the arithmetic:
  # MAX_BLOB_FILE / 4 * 3 - 168 - 32 - 256 = 48696);
  $MAX_PAYLOAD = 48696
  # an X25519 recipient exactly: age1 and 58 lowercase bech32 characters. \z,
  # not $, which .NET also matches before a final newline.
  $RECIPIENT_RE = '^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}\z'

  $EndKey = 'Ctrl-D'
  if ($OnWindows) { $EndKey = 'Ctrl-Z' }

  function Write-Usage {
    [Console]::Error.WriteLine(@"
Usage:
  handoff.ps1 [-To NAME]                 paste or type JSON, then Enter and $EndKey
  handoff.ps1 [-To NAME] -File FILE      read JSON from FILE
  ... | handoff.ps1 [-To NAME]           read JSON from the pipeline
  handoff.ps1 [-To NAME] -Fingerprint    print the agent's recipient and exit
  handoff.ps1 -Help                      print this usage and exit
NAME (default muse; up to 64 letters, digits, _ and -, not starting with -)
picks the agent's recipient file, handoff-NAME.age, in this script's
folder.
stdout is ONLY the base64 ciphertext; all prompts go to stderr.
"@)
  }
  function Stop-Usage([string]$m) { [Console]::Error.WriteLine("handoff.ps1: $m"); Write-Usage; exit 2 }
  function Stop-Run([string]$m) { [Console]::Error.WriteLine("handoff.ps1: $m"); exit 1 }
  function Format-Name([string]$s) { "'" + $s.Replace("'", "''") + "'" }

  # --- arguments ----------------------------------------------------------
  if ($Help) { Write-Usage; exit 0 }
  $fileGiven = $PSBoundParameters.ContainsKey('File')
  foreach ($x in @($Rest)) {
    if ($null -eq $x) { continue }
    if ($x.StartsWith('-')) { Stop-Usage "unknown option $x" }
    Stop-Usage 'at most one FILE'
  }
  if ($Fingerprint -and $fileGiven) { Stop-Usage '-Fingerprint takes no FILE' }

  # The name becomes part of a file name: ASCII letters, digits, _ and - only
  # (-cmatch: a case-blind match lets the KELVIN SIGN pass for k), so it can't
  # name another folder; not starting with -, so it never reads as an option.
  if ($To.StartsWith('-')) { Stop-Usage "-To NAME can't start with - (got $(Format-Name $To))" }
  if ($To -cnotmatch '^[A-Za-z0-9_-]+\z') { Stop-Usage "-To NAME takes only letters, digits, _ and - (got $(Format-Name $To))" }
  if ($To.Length -gt $MAX_NAME) { Stop-Usage "-To NAME is at most $MAX_NAME characters" }

  # --- age: refused here, before any prompt or file is read ---------------
  $ageCmd = Get-Command -Name age -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $ageCmd) { Stop-Run 'age not found. Install it (README.md, Installing age)' }
  $AgePath = $ageCmd.Path

  # Run age with ARGS, BYTES on its stdin; returns @{ Exit; Out } or $null if
  # it didn't start. Bytes both ways, never the PowerShell pipeline (5.1, and
  # 7 before 7.4, re-encode a string piped to a native command and add a
  # newline, and decode its stdout as text). The environment holds only PATH,
  # as handoff.sh's env -i PATH=... (never AGE_PASSPHRASE, AGEDEBUG and the
  # like); on Windows also SystemRoot, without which Win32 and .NET can fail
  # to start a process or load system libraries. The recipient is public, so
  # it can be an argument; the secret only ever goes in on stdin.
  function Invoke-Age([string]$Arguments, [byte[]]$Bytes) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $AgePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables.Clear()
    $path = [Environment]::GetEnvironmentVariable('PATH')
    if ($null -eq $path) { $path = '' }
    $psi.EnvironmentVariables['PATH'] = $path
    if ($OnWindows -and $env:SystemRoot) { $psi.EnvironmentVariables['SystemRoot'] = $env:SystemRoot }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try { [void]$p.Start() } catch { return $null }
    try {
      $out = New-Object System.IO.MemoryStream
      # stdout and stderr are read while stdin is written, so no pipe fills.
      $outTask = $p.StandardOutput.BaseStream.CopyToAsync($out)
      $errTask = $p.StandardError.ReadToEndAsync()
      try {
        if ($null -ne $Bytes -and $Bytes.Length -gt 0) { $p.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length) }
        $p.StandardInput.Close()
      } catch { }   # age stopped reading: its exit code says why
      $outTask.Wait()
      [void]$errTask.Wait()
      $p.WaitForExit()
      return @{ Exit = $p.ExitCode; Out = $out.ToArray() }
    } catch { return $null } finally { $p.Dispose() }
  }

  # Read once, for the messages when age fails.
  $AgeVersion = ''
  $v = Invoke-Age '--version' $null
  if ($null -ne $v) {
    $AgeVersion = ((New-Object System.Text.UTF8Encoding $false).GetString($v.Out) -split "`r?`n")[0].Trim()
  }
  if (-not $AgeVersion) { $AgeVersion = '(version unknown)' }

  # --- the agent's recipient, from handoff-NAME.age beside this script --------
  # The recipient is public: what matters is that it's the agent's (the user
  # compares it with what the agent reports) and that it's the only recipient
  # this script can use. There's none in the script and no fallback: without a
  # usable recipient file, nothing is encrypted.
  $dir = $PSScriptRoot
  # Run from text (a script block, or pasted in), it has no folder to find the
  # file in, and the current location isn't a stand-in for one.
  if (-not $dir) { Stop-Run 'save handoff.ps1 to a file and run that file: its recipient file is found beside it' }
  $keyfile = Join-Path $dir "handoff-$To.age"

  $attrs = $null
  try { $attrs = [IO.File]::GetAttributes($keyfile) } catch { }   # the entry itself, link or not
  $stream = $null
  try { $stream = [IO.File]::Open($keyfile, 'Open', 'Read', 'ReadWrite') } catch { }   # follows links
  if ($null -eq $stream) {
    if ([IO.Directory]::Exists($keyfile)) { Stop-Run "$keyfile is not a regular file" }
    # A link (symbolic link or junction) whose target won't open. A link that
    # resolves to a file is used, as handoff.sh follows a symlink; so is a
    # OneDrive placeholder, also a reparse point, once it opens.
    if ($null -ne $attrs -and ($attrs -band [IO.FileAttributes]::ReparsePoint)) { Stop-Run "$keyfile is a symlink that doesn't resolve to a file" }
    if ($null -ne $attrs) { Stop-Run "cannot read $keyfile" }

    # A near miss beside it is named, from a short allow-list only: a _ or . in
    # place of the -, another case (handoff_muse.age, handoff-Muse.age), or an
    # editor's extra extension (handoff-muse.age.txt, handoff-muse.age.age).
    # Anything else, such as a kept old file (handoff-muse.age.old), isn't
    # offered, and the hint asks for a check, never a rename on its own.
    $near = $null
    $names = @()
    try { $names = @([IO.Directory]::GetFileSystemEntries($dir) | ForEach-Object { [IO.Path]::GetFileName($_) }) } catch { }
    $opts = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
    $base = 'handoff[-_.]' + [regex]::Escape($To) + '\.age'
    foreach ($suffix in @('', '\.txt', '\.age')) {
      $re = New-Object System.Text.RegularExpressions.Regex ('^' + $base + $suffix + '\z'), $opts
      foreach ($n in @($names | Where-Object { $re.IsMatch($_) } | Sort-Object -CaseSensitive)) {
        if ($n -ceq "handoff-$To.age") { continue }
        $a = $null
        try { $a = [IO.File]::GetAttributes((Join-Path $dir $n)) } catch { }
        if ($null -ne $a -and -not ($a -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) { $near = $n; break }
      }
      if ($near) { break }
    }
    if ($near) {
      # Only NAME's case differs (-To Muse, with handoff-muse.age there): the
      # remedy is the other -To, not a rename the default run would then miss.
      if ($near.StartsWith('handoff-', [StringComparison]::Ordinal) -and $near.EndsWith('.age', [StringComparison]::Ordinal)) {
        $nm = $near.Substring(8, $near.Length - 12)
        if ($nm -cne $To -and $nm.ToLowerInvariant() -ceq $To.ToLowerInvariant()) {
          Stop-Run "no recipient file for '$To': $keyfile doesn't exist, but $near does. Names are case-sensitive: did you mean -To $($nm)?"
        }
      }
      Stop-Run "no recipient file for '$To': $keyfile doesn't exist, but $near does. If that file is the agent's current recipient, rename it to handoff-$To.age, then compare -Fingerprint with the recipient the agent reports"
    }
    # A 0.1.0 install: the RSA public key is beside it, the age recipient isn't.
    if ([IO.File]::Exists((Join-Path $dir "handoff-$To.pem"))) {
      Stop-Run "found handoff-$To.pem but no $keyfile. Version 0.2.0 uses age, not RSA keys: ask your agent for its recipient (agent-setup.sh --fingerprint prints it) and save it as handoff-$To.age beside handoff.ps1"
    }
    Stop-Run "no recipient file for '$To': $keyfile doesn't exist. Save the agent's recipient there (SETUP.md, setup step 3), or name another agent with -To NAME"
  }

  # One bounded read, and the size checked on what was read.
  $buf = New-Object byte[] ($MAX_KEY_BYTES + 1)
  $size = 0
  $readOk = $true
  try {
    while ($size -lt $buf.Length) {
      $got = $stream.Read($buf, $size, $buf.Length - $size)
      if ($got -le 0) { break }
      $size += $got
    }
  } catch { $readOk = $false } finally { $stream.Dispose() }
  if (-not $readOk) { Stop-Run "cannot read $keyfile" }
  if ($size -gt $MAX_KEY_BYTES) { Stop-Run "$keyfile is over $MAX_KEY_BYTES bytes; not a recipient file" }
  if ($size -ge 2 -and (($buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) -or ($buf[0] -eq 0xFE -and $buf[1] -eq 0xFF))) {
    Stop-Run "$keyfile is saved as UTF-16: save it as UTF-8 or plain text"
  }
  $start = 0
  if ($size -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { $start = 3 }   # a UTF-8 byte-order mark
  # Byte for character (ISO-8859-1), as handoff.sh works on bytes: anything
  # not ASCII fails the checks below as it does there.
  $text = [Text.Encoding]::GetEncoding(28591).GetString($buf, $start, $size - $start)
  # A copy saved on Windows or by an editor, or copied from an indented block,
  # can carry CRLF line endings, leading or trailing blanks or blank lines: drop
  # them before the checks.
  $lines = @($text.Replace("`r", '').Split("`n") | ForEach-Object { $_.Trim([char[]]@(' ', "`t")) } | Where-Object { $_ -ne '' })
  # An identity (private key) here means it left the agent's machine.
  foreach ($l in $lines) {
    if ($l.StartsWith('AGE-SECRET-KEY-', [StringComparison]::Ordinal) -or $l.StartsWith('AGE-PLUGIN-', [StringComparison]::Ordinal)) {
      Stop-Run "$keyfile holds a private key. Only the agent's recipient (age1...) belongs here: delete this file now. If it's the agent's identity, it has left the agent's machine: treat it as leaked (README.md, Rotation, and compromise)"
    }
  }
  if ($lines.Count -ne 1) { Stop-Run "$keyfile must hold exactly one age recipient line (age1...), as agent-setup.sh prints it" }
  $RECIPIENT = $lines[0]
  if ($RECIPIENT -cnotmatch $RECIPIENT_RE) {
    Stop-Run "$keyfile is not an age X25519 recipient (age1 and 58 more lowercase characters), as agent-setup.sh prints it"
  }
  # The bech32 checksum: age itself rejects a recipient that fails it. Asked
  # now, on nothing, so a mistyped file is refused before the secret is typed.
  $chk = Invoke-Age "-r $RECIPIENT" $null
  if ($null -eq $chk -or $chk.Exit -ne 0) {
    Stop-Run "$keyfile is not a valid age recipient: age $AgeVersion did not accept it. Check the file for a typo and copy it again from the agent, or check that age itself runs (age --version)"
  }

  if ($Fingerprint) {
    [Console]::Error.WriteLine("key file: $keyfile")
    Write-Output "recipient: $RECIPIENT"
    exit 0
  }

  $piped = New-Object System.Collections.Generic.List[string]
}

process {
  trap { [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); exit 1 }
  if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) { $piped.Add($InputObject) }
}

end {
  trap { [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); exit 1 }
  $jsonMsg = 'input must be a single JSON object with a string "svc" and string values only, aborting'
  $strict = New-Object System.Text.UTF8Encoding $false, $true

  # Text from bytes: a byte-order mark picks UTF-8 or UTF-16 (5.1's > writes
  # UTF-16); otherwise strict UTF-8. $null if it isn't valid.
  function ConvertFrom-Bytes([byte[]]$b) {
    try {
      if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return $strict.GetString($b, 3, $b.Length - 3) }
      if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return (New-Object System.Text.UnicodeEncoding $false, $false, $true).GetString($b, 2, $b.Length - 2) }
      if ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { return (New-Object System.Text.UnicodeEncoding $true, $false, $true).GetString($b, 2, $b.Length - 2) }
      return $strict.GetString($b)
    } catch { return $null }
  }

  # --- read the secret --------------------------------------------------
  # -File, the pipeline, stdin's bytes (cmd's <), or the console. At the
  # console the JSON is read key by key with [Console]::ReadKey($true): echo
  # off, multi-line, and outside PowerShell's host, so neither PSReadLine's
  # history nor Start-Transcript sees it (Read-Host -AsSecureString would be
  # hidden too, but takes one line, and a multi-line paste would leave the rest
  # for the prompt to run). It ends at Ctrl-Z (Ctrl-D off Windows).
  $secret = $null
  if ($fileGiven) {
    # Relative to the PowerShell location, not the process's working directory.
    $bytes = $null
    try {   # note: plaintext is already on disk in this path
      $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)
      $bytes = [IO.File]::ReadAllBytes($path)
    } catch { }
    if ($null -eq $bytes) { Stop-Run "cannot read $File" }
    $secret = ConvertFrom-Bytes $bytes
  } elseif ($piped.Count -gt 0 -or $MyInvocation.ExpectingInput) {
    $secret = [string]::Join("`n", $piped.ToArray())
  } elseif ([Console]::IsInputRedirected) {
    $ms = New-Object System.IO.MemoryStream
    $in = [Console]::OpenStandardInput()
    try { $in.CopyTo($ms) } finally { $in.Dispose() }
    $secret = ConvertFrom-Bytes $ms.ToArray()
  } else {
    [Console]::Error.WriteLine("Paste or type the JSON, then press Enter and $EndKey.")
    [Console]::Error.WriteLine('Example: {"svc": "example", "username": "u", "password": "p"}  or  {"svc": "example", "api_key_id": "k", "api_key_secret": "s"}')
    [Console]::Error.WriteLine('(input is hidden and is not written to PowerShell history)')
    $sb = New-Object System.Text.StringBuilder
    try {
      while ($true) {
        $k = [Console]::ReadKey($true)
        $c = $k.KeyChar
        if ($c -eq [char]26 -or $c -eq [char]4) { break }
        if (($k.Modifiers -band [ConsoleModifiers]::Control) -and ($k.Key -eq [ConsoleKey]::Z -or $k.Key -eq [ConsoleKey]::D)) { break }
        if ($k.Key -eq [ConsoleKey]::Enter) { [void]$sb.Append("`n"); continue }
        if ($k.Key -eq [ConsoleKey]::Backspace) { if ($sb.Length -gt 0) { [void]$sb.Remove($sb.Length - 1, 1) }; continue }
        if ($c -ne [char]0) { [void]$sb.Append($c) }
      }
    } catch {
      Stop-Run 'cannot read from this console: pipe the JSON in, or use -File'
    }
    [Console]::Error.WriteLine()
    $secret = $sb.ToString()
    [void]$sb.Clear()
  }
  if ($null -eq $secret) { Stop-Run $jsonMsg }
  $secret = $secret.TrimEnd([char[]]@("`r", "`n"))
  if ($secret.Trim().Length -eq 0) { Stop-Run 'empty, aborting' }

  # --- validate ---------------------------------------------------------
  # Exactly one JSON value, an object, carrying a non-empty string "svc" and
  # only string values (handoff.sh's jq filter): a payload that fails the
  # consume side's binding or shape checks should fail here, early, where the
  # human can see why. PowerShell 6 and later parse with System.Text.Json,
  # which keeps every string a string (7's ConvertFrom-Json turns an
  # ISO-date-like string into a DateTime) and refuses trailing text; 5.1 uses
  # ConvertFrom-Json. The first character rules out an array, which
  # ConvertFrom-Json would unwrap.
  function Test-Payload([string]$s) {
    if (-not $s.TrimStart(" `t`r`n".ToCharArray()).StartsWith('{')) { return $false }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      $doc = $null
      try { $doc = [System.Text.Json.JsonDocument]::Parse($s, (New-Object System.Text.Json.JsonDocumentOptions)) } catch { return $false }
      try {
        $root = $doc.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $false }
        $svc = $null
        foreach ($prop in $root.EnumerateObject()) {
          if ($prop.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { return $false }
          if ($prop.Name -ceq 'svc') { $svc = $prop.Value.GetString() }
        }
        return ($null -ne $svc -and $svc.Length -gt 0)
      } finally { $doc.Dispose() }
    }
    $o = $null
    try { $o = ConvertFrom-Json -InputObject $s } catch { return $false }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $svc = $null
    foreach ($prop in $o.PSObject.Properties) {
      if ($prop.Value -isnot [string]) { return $false }
      if ($prop.Name -ceq 'svc') { $svc = $prop.Value }
    }
    return ($null -ne $svc -and $svc.Length -gt 0)
  }
  if (-not (Test-Payload $secret)) { Stop-Run $jsonMsg }

  $bytes = $null
  try { $bytes = $strict.GetBytes($secret) } catch { Stop-Run $jsonMsg }   # a lone surrogate
  $secret = $null
  # The cap (MAX_PAYLOAD, above) keeps the blob within consume.py's limit.
  if ($bytes.Length -gt $MAX_PAYLOAD) {
    $n = $bytes.Length
    [Array]::Clear($bytes, 0, $bytes.Length)
    [Console]::Error.WriteLine("handoff.ps1: payload is $n bytes; the most handoff.ps1 sends is $MAX_PAYLOAD bytes.")
    [Console]::Error.WriteLine('Shorten the JSON. (Larger payloads need a larger limit on both sides;')
    [Console]::Error.WriteLine('see README.md.)')
    exit 1
  }

  # --- encrypt (no plaintext ever touches disk) -------------------------
  # age writes the binary format; base64 makes it one line.
  $enc = Invoke-Age "-r $RECIPIENT" $bytes
  [Array]::Clear($bytes, 0, $bytes.Length)
  if ($null -eq $enc -or $enc.Exit -ne 0 -or $enc.Out.Length -eq 0) { Stop-Run "age failed to encrypt (age $AgeVersion), aborting" }
  $blob = [Convert]::ToBase64String($enc.Out)
  [Console]::Error.WriteLine("recipient: $RECIPIENT (from $keyfile)  <- compare with the recipient")
  [Console]::Error.WriteLine('   your agent reports for its key before trusting this output')
  [Console]::Error.WriteLine("--- paste everything below into chat with $To (recipient file $keyfile) ---")
  Write-Output $blob
  [Console]::Error.WriteLine('--- end ---')
  exit 0
}
