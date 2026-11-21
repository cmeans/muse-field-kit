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
  [switch]$CheckSetup,
  [switch]$Help,
  # The payload as pipeline input: one string (ConvertTo-Json's output), or
  # lines (Get-Content's), joined with newlines. A pipeline carries text that
  # PowerShell has already decoded: 5.1's Get-Content without -Encoding UTF8
  # reads a UTF-8 file with no byte-order mark in the ANSI code page, so for a
  # file, -File (its bytes) is the safe way.
  [Parameter(ValueFromPipeline = $true)][AllowNull()][AllowEmptyString()][string]$InputObject,
  # Anything else, so it can be refused with handoff.sh's message and exit 2.
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

begin {
  # A caller's Set-PSDebug -Trace 2 would print every assignment, the secret
  # included (handoff.sh's set +x). Set-PSDebug is session-wide: this turns
  # the caller's tracing off for the rest of that PowerShell session too.
  Set-PSDebug -Off
  Set-StrictMode -Version 2
  $ErrorActionPreference = 'Stop'

  # Every error this run records lands in the caller's $Error, where an error
  # text could keep a fragment of the input. The newest entry before the run
  # is noted; every exit (Exit-Handoff) removes what was added in front of it.
  # (By reference, not by count: a full $Error drops its oldest entries.)
  $ErrTop = $null
  if ($global:Error.Count -gt 0) { $ErrTop = $global:Error[0] }
  function Exit-Handoff([int]$code) {
    try {
      $e = $global:Error
      $guard = 0
      while ($e.Count -gt 0 -and -not [object]::ReferenceEquals($e[0], $ErrTop) -and $guard -lt 100000) { $e.RemoveAt(0); $guard++ }
    } catch { }
    exit $code
  }
  # An error nobody planned for gets a fixed message: PowerShell's own error
  # text can quote the input.
  trap {
    if ($_.Exception.GetType().Name -ceq 'PipelineStoppedException') { Exit-Handoff 130 }
    [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); Exit-Handoff 1
  }

  # Windows PowerShell 5.1 and PowerShell 7 are the two this is tested on.
  $ver = $PSVersionTable.PSVersion
  if ($ver.Major -lt 5 -or ($ver.Major -eq 5 -and $ver.Minor -lt 1) -or $ver.Major -eq 6) {
    # -CheckSetup answers in its own words, on stdout.
    if ($CheckSetup) { [Console]::Out.WriteLine("FAIL powershell: needs Windows PowerShell 5.1 or PowerShell 7 (this is $ver)") }
    else { [Console]::Error.WriteLine("handoff.ps1: needs Windows PowerShell 5.1 or PowerShell 7 (this is $ver)") }
    Exit-Handoff 1
  }
  $Desktop = $PSVersionTable.PSEdition -eq 'Desktop'

  $OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

  # Twins of handoff.sh's values (keep them equal; run-test.ps1 checks):
  # consume.py's MAX_KEY_FILE and agent-setup.sh's MAX_KEY_BYTES;
  $MAX_KEY_BYTES = 16384
  # NAME's length cap;
  $MAX_NAME = 64
  # the largest payload, in bytes, handed to age (handoff.sh has the arithmetic:
  # MAX_BLOB_FILE / 4 * 3 - 168 - 32 - 256 = 48696);
  $MAX_PAYLOAD = 48696
  # the bounded read: MAX_PAYLOAD and room for what is dropped before the
  # count (a byte-order mark, trailing line ends), as in handoff.sh;
  $READ_CAP = $MAX_PAYLOAD + 4096
  # the credential fields: consume.py's DEFAULT_ENV_MAP's keys, in its order;
  $KNOWN_FIELDS = 'username password api_key_id api_key_secret token_id token_secret private_key app_id installation_id'
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
  handoff.ps1 [-To NAME] -CheckSetup     check that age works on this machine
  handoff.ps1 -Help                      print this usage and exit
For a payload in a file, use -File FILE. To pipe one in with Get-Content,
add -Encoding UTF8 (Windows PowerShell 5.1 otherwise reads the file in the
ANSI code page and changes non-ASCII characters).
NAME (default muse; up to 64 letters, digits, _ and -, not starting with -)
picks the agent's recipient file, handoff-NAME.age, in this script's
folder.
stdout is ONLY the base64 ciphertext; all prompts go to stderr.
"@)
  }
  function Stop-Usage([string]$m) { [Console]::Error.WriteLine("handoff.ps1: $m"); Write-Usage; Exit-Handoff 2 }
  function Stop-Run([string]$m) { [Console]::Error.WriteLine("handoff.ps1: $m"); Exit-Handoff 1 }
  # Text from the user's folder, file names or command line, made safe to print
  # (handoff.sh's has_ctl and qp): each control, bidi or invisible character
  # (C0, DEL, C1, U+00AD, U+061C, U+200B-U+200F, U+2028-U+202E, U+2060-U+2064,
  # U+2066-U+2069, U+FEFF) is shown as <U+XXXX>, so a name like u<U+202E>x
  # can't reorder or hide part of a message line. Anything else is unchanged.
  function Format-Shown([string]$s) {
    if ($null -eq $s) { return $s }
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
      $v = [int]$ch
      if ($v -lt 0x20 -or ($v -ge 0x7F -and $v -le 0x9F) -or $v -eq 0xAD -or $v -eq 0x61C -or
          ($v -ge 0x200B -and $v -le 0x200F) -or ($v -ge 0x2028 -and $v -le 0x202E) -or
          ($v -ge 0x2060 -and $v -le 0x2064) -or ($v -ge 0x2066 -and $v -le 0x2069) -or $v -eq 0xFEFF) {
        [void]$sb.Append('<U+' + $v.ToString('X4') + '>')
      } else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
  }
  # A PowerShell single-quoted string: PowerShell also ends one at U+2018-U+201B,
  # so each of those is doubled too, as ' is (a folder named Chris<U+2019>s kit
  # must not end the string, or a crafted one run code when pasted).
  function Format-Name([string]$s) {
    $q = "['" + [char]0x2018 + [char]0x2019 + [char]0x201A + [char]0x201B + ']'
    "'" + ((Format-Shown $s) -replace $q, '$0$0') + "'"
  }

  # --- arguments ----------------------------------------------------------
  if ($Help) { Write-Usage; Exit-Handoff 0 }
  $fileGiven = $PSBoundParameters.ContainsKey('File')
  $ToGiven = $PSBoundParameters.ContainsKey('To')
  foreach ($x in @($Rest)) {
    if ($null -eq $x) { continue }
    if ($x.StartsWith('-')) { Stop-Usage "unknown option $(Format-Shown $x)" }
    Stop-Usage 'at most one FILE'
  }
  if ($Fingerprint -and $CheckSetup) { Stop-Usage 'one mode at a time' }
  if ($Fingerprint -and $fileGiven) { Stop-Usage '-Fingerprint takes no FILE' }
  if ($CheckSetup -and $fileGiven) { Stop-Usage '-CheckSetup takes no FILE' }

  # The name becomes part of a file name: ASCII letters, digits, _ and - only
  # (-cmatch: a case-blind match lets the KELVIN SIGN pass for k), so it can't
  # name another folder; not starting with -, so it never reads as an option.
  if ($To.StartsWith('-')) { Stop-Usage "-To NAME can't start with - (got $(Format-Name $To))" }
  if ($To -cnotmatch '^[A-Za-z0-9_-]+\z') { Stop-Usage "-To NAME takes only letters, digits, _ and - (got $(Format-Name $To))" }
  if ($To.Length -gt $MAX_NAME) { Stop-Usage "-To NAME is at most $MAX_NAME characters" }

  # --- age: refused here, before any prompt or file is read ---------------
  # (-CheckSetup reports a missing age itself.)
  $ageCmd = Get-Command -Name age -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $ageCmd -and -not $CheckSetup) { Stop-Run 'age not found. Install it (README.md, Installing age)' }
  $AgePath = $null
  if ($null -ne $ageCmd) { $AgePath = $ageCmd.Path }

  # Run age with ARGS, BYTES on its stdin; returns @{ Exit; Out } or $null if
  # it didn't start. Bytes both ways, never the PowerShell pipeline (5.1, and
  # 7 before 7.4, re-encode a string piped to a native command and add a
  # newline, and decode its stdout as text). The environment holds only PATH,
  # as handoff.sh's env -i PATH=... (never AGE_PASSPHRASE, AGEDEBUG and the
  # like); on Windows also SystemRoot, without which Win32 and .NET can fail
  # to start a process or load system libraries. The recipient is public, so
  # it can be an argument; the secret only ever goes in on stdin.
  # EXE is age's path unless another tool of the age package is asked for.
  function Invoke-Age([string]$Arguments, [byte[]]$Bytes, [string]$Exe = '') {
    if (-not $Exe) { $Exe = $AgePath }
    if (-not $Exe) { return $null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
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
    # On .NET Framework (5.1), Start() wraps stdin in a writer in
    # Console.InputEncoding, and with code page 65001 that writer puts a UTF-8
    # byte-order mark in front of the bytes written below: age would encrypt
    # EF BB BF {...}, which the consume side can't parse. So around Start(),
    # an input encoding without a preamble, then the caller's back. (Setting it
    # can throw where there's no console: then there's no preamble to fear
    # from a console, and nothing is changed.)
    $savedIn = $null
    if ($Desktop) {
      try {
        if ([Console]::InputEncoding.GetPreamble().Length -gt 0) {
          $savedIn = [Console]::InputEncoding
          [Console]::InputEncoding = New-Object System.Text.UTF8Encoding $false
        }
      } catch { $savedIn = $null }
    }
    $started = $false
    try { [void]$p.Start(); $started = $true } catch { } finally {
      if ($null -ne $savedIn) { try { [Console]::InputEncoding = $savedIn } catch { } }
    }
    if (-not $started) { $p.Dispose(); return $null }
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
  # The agent's recipient, read and checked from handoff-NAME.age. Sets
  # $script:keyfile and $script:RECIPIENT. A refusal is Stop-Run (exit 1), or
  # under -CheckSetup a thrown 'INFO|text' (no file yet) or 'FAIL|text'.
  function Stop-Key([string]$m, [bool]$Absent = $false) {
    if (-not $CheckSetup) { Stop-Run $m }
    if ($Absent) { throw "INFO|$m" }
    throw "FAIL|$m"
  }
  function Get-Recipient {
    $dir = $PSScriptRoot
    # Run from text (a script block, or pasted in), it has no folder to find the
    # file in, and the current location isn't a stand-in for one.
    if (-not $dir) { Stop-Key 'save handoff.ps1 to a file and run that file: its recipient file is found beside it' $true }
    $keyfile = Join-Path $dir "handoff-$To.age"
    $kf = Format-Shown $keyfile   # for messages only

    $attrs = $null
    try { $attrs = [IO.File]::GetAttributes($keyfile) } catch { }   # the entry itself, link or not
    # A symbolic link or junction is refused, resolving or not, as handoff.sh
    # refuses a symlink: whoever can repoint it changes the recipient without
    # touching the file the user checked. (A OneDrive placeholder is a reparse
    # point too, but not a link: it is used once it opens.)
    $isLink = $false
    if ($null -ne $attrs -and ($attrs -band [IO.FileAttributes]::ReparsePoint)) {
      $li = $null
      try { $li = Get-Item -LiteralPath $keyfile -Force -ErrorAction Stop } catch { }
      if ($null -ne $li -and ($li.PSObject.Properties.Name -contains 'LinkType') -and ($li.LinkType -ceq 'SymbolicLink' -or $li.LinkType -ceq 'Junction')) { $isLink = $true }
    }
    $stream = $null
    try { $stream = [IO.File]::Open($keyfile, 'Open', 'Read', 'ReadWrite') } catch { }   # follows links
    if ($isLink) {
      if ($null -ne $stream) { $stream.Dispose() }
      # The remedy says to remove the link first: saving "there"
      # (Set-Content, Copy-Item) writes through it and leaves the link.
      if ($null -eq $stream) {
        # A link to a folder (a junction, or a directory symlink): Remove-Item on
        # it asks to recurse in Windows PowerShell 5.1, and yes deletes the
        # folder's contents (issue #83). Delete() removes only the link.
        if ($li.LinkType -ceq 'Junction' -or $li.PSIsContainer) {
          # The command names the full path only if it's printable ASCII: a
          # character Format-Shown changes isn't the path any more, and Windows
          # PowerShell 5.1 writes stderr in the console's code page, which turns
          # a typographic quote into ' or ` (the pasted path then names nothing).
          # Otherwise it's run from the script's folder, by the ASCII name.
          if ($keyfile -cmatch '^[\x20-\x7E]*\z') { $del = "(Get-Item -LiteralPath $(Format-Name $keyfile) -Force).Delete()" }
          else { $del = "(Get-Item -LiteralPath '.\handoff-$To.age' -Force).Delete(), run in this script's folder" }
          Stop-Key "$kf is a link to a folder (a junction or a directory symlink): remove only the link with $del, then save the agent's recipient there as a plain file. Don't use Remove-Item on it: in Windows PowerShell 5.1 it can delete the folder's contents"
        }
        Stop-Key "$kf is a symlink that doesn't resolve to a file: remove the link itself (Remove-Item), then save the agent's recipient there as a plain file"
      }
      Stop-Key "$kf is a symlink: remove the link itself (Remove-Item, which leaves its target alone), then save the agent's recipient there as a plain file (a link can be repointed without its target changing)"
    }
    if ($null -eq $stream) {
      if ([IO.Directory]::Exists($keyfile)) { Stop-Key "$kf is not a regular file" }
      # A reparse point whose target won't open (a link Get-Item couldn't name).
      if ($null -ne $attrs -and ($attrs -band [IO.FileAttributes]::ReparsePoint)) { Stop-Key "$kf is a symlink that doesn't resolve to a file" }
      if ($null -ne $attrs) { Stop-Key "cannot read $kf" }

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
          # ASCII names only: a case-blind match lets a look-alike such as the
          # KELVIN SIGN pass for k.
          if ($n -cnotmatch '^[A-Za-z0-9._-]+\z') { continue }
          $a = $null
          try { $a = [IO.File]::GetAttributes((Join-Path $dir $n)) } catch { }
          if ($null -ne $a -and -not ($a -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) { $near = $n; break }
        }
        if ($near) { break }
      }
      if ($near) {
        # The NAME in the near miss's own spelling: handoff and its separator
        # off the front, the .age (and an editor's extra extension) off the end.
        $nm = $near.Substring(8)
        if ($nm -imatch '\.age\.(txt|age)\z') { $nm = $nm.Substring(0, $nm.Length - 8) }
        elseif ($nm -imatch '\.age\z') { $nm = $nm.Substring(0, $nm.Length - 4) }
        # For a NAME given with -To (other than the default) whose case differs
        # from the file's, the remedy keeps the file's own NAME (handoff.sh).
        # With no -To, or -To naming the default, the rename to the default
        # name below: a "did you mean -To Muse" would put -To on every run.
        if ($nm -cne $To -and $ToGiven -and $To -cne 'muse') {
          # Only NAME's case differs (-To Muse, with handoff-muse.age there): the
          # remedy is the other -To, not a rename the default run would then miss.
          if ($near -ceq "handoff-$nm.age") {
            Stop-Key "no recipient file for '$To': $kf doesn't exist, but $near does. Names are case-sensitive: did you mean -To $($nm)?" $true
          }
          # The case and something else differ (handoff_muse.age for -To Muse).
          Stop-Key "no recipient file for '$To': $kf doesn't exist, but $near does. If that file is the agent's current recipient, rename it to handoff-$nm.age and run with -To $nm (names are case-sensitive), then compare -Fingerprint with the recipient the agent reports" $true
        }
        Stop-Key "no recipient file for '$To': $kf doesn't exist, but $near does. If that file is the agent's current recipient, rename it to handoff-$To.age, then compare -Fingerprint with the recipient the agent reports" $true
      }
      # A 0.1.0 install: the RSA public key is beside it, the age recipient isn't.
      if ([IO.File]::Exists((Join-Path $dir "handoff-$To.pem"))) {
        Stop-Key "found handoff-$To.pem but no $kf. Version 0.2.0 uses age, not RSA keys: ask your agent for its recipient (agent-setup.sh --fingerprint prints it) and save it as handoff-$To.age beside handoff.ps1" $true
      }
      Stop-Key "no recipient file for '$To': $kf doesn't exist. Save the agent's recipient there (SETUP.md, setup step 3), or name another agent with -To NAME" $true
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
    if (-not $readOk) { Stop-Key "cannot read $kf" }
    if ($size -gt $MAX_KEY_BYTES) { Stop-Key "$kf is over $MAX_KEY_BYTES bytes; not a recipient file" }
    if ($size -ge 2 -and (($buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) -or ($buf[0] -eq 0xFE -and $buf[1] -eq 0xFF))) {
      Stop-Key "$kf is saved as UTF-16: save it as UTF-8 or plain text"
    }
    $start = 0
    if ($size -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { $start = 3 }   # a UTF-8 byte-order mark
    # Byte for character (ISO-8859-1), as handoff.sh works on bytes: anything
    # not ASCII fails the checks below as it does there.
    $text = [Text.Encoding]::GetEncoding(28591).GetString($buf, $start, $size - $start)
    # A copy saved on Windows or by an editor, or copied from an indented block,
    # can carry CRLF line endings, leading or trailing blanks or blank lines: drop
    # them before the checks.
    # (Length, not -ne '': a culture comparison takes a line of only a soft
    # hyphen, U+00AD, for an empty one.)
    $lines = @($text.Replace("`r", '').Split("`n") | ForEach-Object { $_.Trim([char[]]@(' ', "`t")) } | Where-Object { $_.Length -gt 0 })
    # An identity (private key) here means it left the agent's machine.
    foreach ($l in $lines) {
      if ($l.StartsWith('AGE-SECRET-KEY-', [StringComparison]::Ordinal) -or $l.StartsWith('AGE-PLUGIN-', [StringComparison]::Ordinal)) {
        Stop-Key "$kf holds a private key. Only the agent's recipient (age1...) belongs here: delete this file now. If it's the agent's identity, it has left the agent's machine: treat it as leaked (README.md, Rotation, and compromise)"
      }
    }
    # Copied with more than the recipient: the "recipient: " agent-setup.sh
    # prints before it, or quotes or backticks around it. Said in the refusals
    # below (the file is the user's to fix; nothing is stripped).
    $extra = ''
    # (Typographic quotes in UTF-8, as a chat app pastes them, read byte for
    # character here: E2 80 then 98, 99, 9C or 9D.)
    if ($text -cmatch '[Rr]ecipient:|["''`]|\xE2\u0080[\u0098\u0099\u009C\u009D]') { $extra ='. Keep only the age1... text, without "recipient:", quotes or backticks' }
    if ($lines.Count -ne 1) { Stop-Key "$kf must hold exactly one age recipient line (age1...), as agent-setup.sh prints it$extra" }
    $RECIPIENT = $lines[0]
    if ($RECIPIENT -cnotmatch $RECIPIENT_RE) {
      Stop-Key "$kf is not an age X25519 recipient (age1 and 58 more lowercase characters), as agent-setup.sh prints it$extra"
    }
    # The bech32 checksum: age itself rejects a recipient that fails it. Asked
    # now, on nothing, so a mistyped file is refused before the secret is typed.
    # (-CheckSetup with no working age checks the file and its shape alone.)
    $chk = $null
    if (-not ($CheckSetup -and $script:CsNoAge)) { $chk = Invoke-Age "-r $RECIPIENT" $null }
    if (($null -eq $chk -or $chk.Exit -ne 0) -and -not ($CheckSetup -and $script:CsNoAge)) {
      Stop-Key "$kf is not a valid age recipient: age $AgeVersion did not accept it. Check the file for a typo and copy it again from the agent, or check that age itself runs (age --version)"
    }
    $script:keyfile = $keyfile
    $script:kf = $kf
    $script:RECIPIENT = $RECIPIENT
  }
  # --- -CheckSetup: prove the tools work on this machine, by running them -------
  # One line per check on stdout (PASS, INFO or FAIL, a name, a detail), nothing
  # else there; exit 0 unless a line is FAIL. The round trip uses a throwaway
  # identity in a private temporary folder, removed on every exit. No prompt,
  # no stdin, no real key. The names and details match handoff.sh --check-setup.
  $script:CsFailed = $false
  $script:CsNoAge = $false   # set once age has been tried: the checksum needs it
  function Write-Check([string]$Status, [string]$Name, [string]$Detail) {
    [Console]::Out.WriteLine("$Status ${Name}: $($Detail -replace '\s*\r?\n\s*', ' ')")
    if ($Status -ceq 'FAIL') { $script:CsFailed = $true }
  }
  # consume.py's check_age_header: a binary age file for exactly one X25519
  # recipient (other stanzas only "*-grease"). Returns the reason it is
  # refused, or '' if it's fine.
  function Test-AgeHeader([byte[]]$Raw) {
    $lines = [Text.Encoding]::GetEncoding(28591).GetString($Raw).Split("`n")
    # Every comparison ordinal, as consume.py's: -ceq compares by culture,
    # which skips format characters such as U+00AD.
    $ord = [StringComparison]::Ordinal
    if ([string]::Equals($lines[0], '-----BEGIN AGE ENCRYPTED FILE-----', $ord)) { return 'armored (ASCII) age text, not the binary format' }
    if (-not [string]::Equals($lines[0], 'age-encryption.org/v1', $ord)) { return 'not a binary age file' }
    $x = 0
    $inStanza = $false
    $done = $false
    for ($i = 1; $i -lt $lines.Length; $i++) {
      $l = $lines[$i]
      if ([string]::Equals($l, '---', $ord) -or $l.StartsWith('--- ', $ord)) { $done = $true; break }
      if ($l.StartsWith('-> ', [StringComparison]::Ordinal)) {
        $inStanza = $true
        $kind = $l.Substring(3).Split(' ')[0]
        if ([string]::Equals($kind, 'X25519', $ord)) { $x++ }
        elseif (-not $kind.EndsWith('-grease', [StringComparison]::Ordinal)) { return 'a recipient kind other than X25519' }
        continue
      }
      if (-not $inStanza) { return 'the header is malformed' }
    }
    if (-not $done) { return 'the header has no end line' }
    if ($x -ne 1) { return "expected exactly one X25519 stanza, found $x" }
    return ''
  }
  function Test-BytesEqual([byte[]]$A, [byte[]]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true
  }
  function Invoke-CheckSetup {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    Write-Check PASS powershell "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    $tmp = $null
    $haveAge = $false
    $haveKeygen = $false
    try {
      try {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('handoff-check-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($tmp)
        # Windows: the new folder inherits the user's temp folder's access list.
        # Elsewhere the mode is set by hand (the umask can't be relied on):
        # .NET's own call where it has one, else chmod.
        if (-not $OnWindows) {
          try { [IO.File]::SetUnixFileMode($tmp, [IO.UnixFileMode]448) } catch { & chmod 700 $tmp }
        }
      } catch {
        Write-Check FAIL tempdir 'cannot make a private temporary folder (check TEMP)'
        if ($null -ne $tmp) { try { [IO.Directory]::Delete($tmp, $true) } catch { } }
        $tmp = $null
        return
      }
      # A TERM ends the process without running finally: a process-exit handler
      # in compiled code (a script block has no runspace to run in at that
      # point) removes the folder then. Not on Windows, which has no TERM: there
      # Ctrl-C runs finally, and Add-Type on Windows PowerShell 5.1 would leave
      # its compiled assembly in the user's TEMP. Where the runtime has
      # PosixSignalRegistration (PowerShell 7.2 and later), a SIGTERM handler
      # removes it too, before the runtime's own handling: whether a TERM
      # reaches the process-exit event first differs between PowerShell
      # releases, and this does not depend on it.
      if (-not $OnWindows) { try {
        if (-not ('HandoffCheckCleanup' -as [type])) {
          $sigField = ''; $sigArm = ''
          if ('System.Runtime.InteropServices.PosixSignalRegistration' -as [type]) {
            $sigField = 'static object reg;'
            $sigArm = 'reg = System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGTERM, ctx => { Clean(); });'
          }
          Add-Type -TypeDefinition @"
public static class HandoffCheckCleanup {
  static string dir;
  $sigField
  static void Clean() {
    try { if (dir != null) System.IO.Directory.Delete(dir, true); } catch { }
  }
  public static void Arm(string d) {
    dir = d;
    System.AppDomain.CurrentDomain.ProcessExit += delegate { Clean(); };
    $sigArm
  }
}
"@
        }
        [HandoffCheckCleanup]::Arm($tmp)
      } catch { } }

      if ($null -ne $AgePath) {
        $v = Invoke-Age '--version' $null
        $ver = ''
        if ($null -ne $v -and $v.Exit -eq 0) { $ver = ((New-Object System.Text.UTF8Encoding $false).GetString($v.Out) -split "`r?`n")[0].Trim() }
        if ($ver) { Write-Check PASS age $ver; $haveAge = $true }
        else { Write-Check FAIL age "found at $AgePath, but 'age --version' did not run; reinstall age (README.md, Installing age)" }
      } else {
        Write-Check FAIL age 'not found on PATH; install it (README.md, Installing age)'
      }

      $script:CsNoAge = -not $haveAge

      # age-keygen: the user side never needs it, so a missing one is INFO.
      $kg = Get-Command -Name age-keygen -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
      $idFile = Join-Path $tmp 'id.txt'
      if ($null -ne $kg) {
        $m = Invoke-Age "-o `"$idFile`"" $null $kg.Path
        if ($null -ne $m -and $m.Exit -eq 0 -and [IO.File]::Exists($idFile)) {
          $v = Invoke-Age '--version' $null $kg.Path
          $ver = 'made a throwaway identity'
          if ($null -ne $v -and $v.Exit -eq 0) {
            $t = ((New-Object System.Text.UTF8Encoding $false).GetString($v.Out) -split "`r?`n")[0].Trim()
            if ($t) { $ver = $t }
          }
          Write-Check PASS age-keygen $ver
          $haveKeygen = $true
        } else {
          Write-Check FAIL age-keygen "found at $($kg.Path), but it did not make an identity; reinstall age"
        }
      } else {
        Write-Check INFO age-keygen 'not found; this side never needs it. The round trip below is encrypt-only (decrypt skipped)'
      }

      # The saved recipient file, read by the same code as -Fingerprint.
      $probe = ''      # PASS, INFO or FAIL
      $probeMsg = ''
      $saved = $null
      try {
        Get-Recipient
        $probe = 'PASS'
        $probeMsg = "$kf is a valid age X25519 recipient"
        if (-not $haveAge) {
          $probe = 'INFO'
          $probeMsg = "$kf has the shape of an age X25519 recipient; its checksum is not checked (no age)"
        }
        $saved = $script:RECIPIENT
      } catch {
        $m = $_.Exception.Message
        if ($m -clike 'INFO|*' -or $m -clike 'FAIL|*') { $probe = $m.Substring(0, 4); $probeMsg = $m.Substring(5) }
        else { $probe = 'FAIL'; $probeMsg = 'the recipient check failed' }
      }

      # The round trip. With age-keygen: a throwaway recipient, encrypt as
      # handoff.ps1 does (bytes both ways, Invoke-Age), decrypt with age -d -i.
      # Without it: encrypt to the saved recipient, and check the blob only.
      if ($haveAge) {
        $nonAscii = ([string][char]0xE4) + 'ssw' + [char]0xF6 + 'rd-' + [char]0xFC + '-' + [char]0x65E5 + [char]0x672C
        $payload = $Utf8NoBom.GetBytes('{"svc":"check","password":"p' + $nonAscii + '"}')
        $rcpt = $null
        $rt = $null
        if ($haveKeygen) {
          $y = Invoke-Age "-y `"$idFile`"" $null $kg.Path
          if ($null -ne $y -and $y.Exit -eq 0) { $rcpt = ($Utf8NoBom.GetString($y.Out) -split "`r?`n")[0].Trim() }
          if ($rcpt -cnotmatch $RECIPIENT_RE) { $rcpt = $null; $rt = @('FAIL', 'age-keygen -y did not print a recipient for the throwaway identity') }
        } elseif ($null -ne $saved) {
          $rcpt = $saved
        } else {
          $rt = @('INFO', 'skipped: with no age-keygen there is no throwaway recipient, and no usable recipient file to encrypt to')
        }
        $hdr = $null
        $b64 = $null
        if ($null -ne $rcpt) {
          $enc = Invoke-Age "-r $rcpt" $payload
          if ($null -eq $enc -or $enc.Exit -ne 0 -or $enc.Out.Length -eq 0) {
            $rt = @('FAIL', 'age failed to encrypt to the recipient')
          } else {
            $blob = [Convert]::ToBase64String($enc.Out)
            $back = $null
            try { $back = [Convert]::FromBase64String($blob) } catch { }
            if ($null -ne $back -and (Test-BytesEqual $back $enc.Out)) { $b64 = @('PASS', "the blob decodes and re-encodes to itself ($($enc.Out.Length) bytes)") }
            else { $b64 = @('FAIL', 'base64 does not round-trip the blob here') }
            $why = Test-AgeHeader $enc.Out
            if (-not $why) { $hdr = @('PASS', 'exactly one X25519 stanza') } else { $hdr = @('FAIL', $why) }
            if ($haveKeygen) {
              $dec = Invoke-Age "-d -i `"$idFile`"" $enc.Out
              if ($null -eq $dec -or $dec.Exit -ne 0) { $rt = @('FAIL', 'age could not decrypt what it had just encrypted') }
              elseif (Test-BytesEqual $dec.Out $payload) { $rt = @('PASS', "encrypted and decrypted $($payload.Length) bytes of UTF-8, unchanged") }
              else { $rt = @('FAIL', 'the decrypted bytes differ from what was encrypted') }
            } else {
              $rt = @('INFO', "encrypt-only: decrypt skipped (no age-keygen here, so no throwaway key); the blob's header and base64 are checked")
            }
          }
        }
        if ($null -ne $rt) { Write-Check $rt[0] 'round trip' $rt[1] }
        if ($null -ne $hdr) { Write-Check $hdr[0] 'header' $hdr[1] }
        if ($null -ne $b64) { Write-Check $b64[0] 'base64' $b64[1] }
      }

      Write-Check $probe 'recipient' $probeMsg
    } finally {
      if ($null -ne $tmp) { try { [IO.Directory]::Delete($tmp, $true) } catch { } }
    }
  }

  if ($CheckSetup) {
    Invoke-CheckSetup
    if ($script:CsFailed) { Exit-Handoff 1 }
    Exit-Handoff 0
  }
  Get-Recipient

  if ($Fingerprint) {
    [Console]::Error.WriteLine("key file: $kf")
    Write-Output "recipient: $RECIPIENT"
    Exit-Handoff 0
  }

  function Stop-TooBig([string]$size) {
    [Console]::Error.WriteLine("handoff.ps1: payload is $size bytes; the most handoff.ps1 sends is $MAX_PAYLOAD bytes.")
    [Console]::Error.WriteLine('Shorten the JSON. (Larger payloads need a larger limit on both sides;')
    [Console]::Error.WriteLine('see README.md.)')
    Exit-Handoff 1
  }

  $piped = New-Object System.Collections.Generic.List[string]
  $pipedLen = 0
}

process {
  trap { [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); Exit-Handoff 1 }
  if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
    # Bounded: a UTF-8 byte or more per character, so past READ_CAP characters
    # the payload is over the cap whatever it holds.
    $pipedLen += $InputObject.Length + 1
    if ($pipedLen -gt $READ_CAP) { $piped.Clear(); Stop-TooBig "over $READ_CAP" }
    $piped.Add($InputObject)
  }
}

end {
  trap { [Console]::Error.WriteLine("handoff.ps1: unexpected error ($($_.Exception.GetType().Name)), aborting"); Exit-Handoff 1 }
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

  # Whether a key read at the console ends the input: only the character it
  # produced, Ctrl+Z (26) or Ctrl+D (4), whatever the modifiers say. Windows
  # reports AltGr as LeftCtrl+RightAlt, and a ConsoleKeyInfo can't tell that
  # from a real Ctrl+Alt, so a rule on Modifiers and Key would either end the
  # input on AltGr+Z or AltGr+D, which types a character in some layouts
  # (Polish z with dot above, Croatian d with stroke), or ignore a real
  # Ctrl+Alt+Z. The produced character is the signal Windows itself uses:
  # AltGr+Z arrives as that letter, and is typed. (run-test.ps1 tests this
  # function on its own.)
  function Test-EndKey([ConsoleKeyInfo]$k) {
    return ($k.KeyChar -eq [char]26 -or $k.KeyChar -eq [char]4)
  }

  # --- read the secret --------------------------------------------------
  # -File, the pipeline, stdin's bytes (cmd's <), or the console. At the
  # console the JSON is read key by key with [Console]::ReadKey($true): echo
  # off, multi-line, and outside PowerShell's host, so neither PSReadLine's
  # history nor Start-Transcript sees it (Read-Host -AsSecureString would be
  # hidden too, but takes one line, and a multi-line paste would leave the rest
  # for the prompt to run). It ends at Ctrl-Z (Ctrl-D off Windows).
  # A bounded read of STREAM (disposed): at most 2 * READ_CAP + 3 bytes, so an
  # endless file or pipe ends here. The input may then be READ_CAP bytes, or
  # twice that and its mark for UTF-16 with a byte-order mark (which takes up
  # to twice the bytes of the same text in UTF-8); anything over is refused,
  # and the size is checked again once decoded, as every payload's is. $null
  # if the read failed.
  function Read-Capped([IO.Stream]$stream) {
    $buf = New-Object byte[] (2 * $READ_CAP + 3)
    $size = 0
    try {
      while ($size -lt $buf.Length) {
        $got = $stream.Read($buf, $size, $buf.Length - $size)
        if ($got -le 0) { break }
        $size += $got
      }
    } catch { return $null } finally { $stream.Dispose() }
    $limit = $READ_CAP
    if ($size -ge 2 -and (($buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) -or ($buf[0] -eq 0xFE -and $buf[1] -eq 0xFF))) { $limit = 2 * $READ_CAP + 2 }
    if ($size -gt $limit) { [Array]::Clear($buf, 0, $buf.Length); Stop-TooBig "over $limit" }
    $b = New-Object byte[] $size
    [Array]::Copy($buf, $b, $size)
    [Array]::Clear($buf, 0, $buf.Length)
    return ,$b
  }
  # A UTF-16 file without a byte-order mark: NULs alternating with the first
  # two characters, the first a { or blank (strict UTF-8 would take the
  # NULs). One raw NUL beside the { alone is a control character, refused
  # with the JSON message. With a mark, it's read as UTF-16.
  function Test-Utf16NoBom([byte[]]$b) {
    if ($b.Length -lt 4) { return $false }
    $lead = @(0x7B, 0x20, 0x09, 0x0D, 0x0A)
    return (($lead -contains $b[0] -and $b[1] -eq 0 -and $b[3] -eq 0) -or ($b[0] -eq 0 -and $lead -contains $b[1] -and $b[2] -eq 0))
  }
  $utf16Msg = 'the payload is saved as UTF-16 without a byte-order mark: save it as UTF-8, aborting'
  $secret = $null
  if ($fileGiven) {
    # Relative to the PowerShell location, not the process's working directory.
    $bytes = $null
    $path = $null
    # (An empty FILE resolves to the current location: it gets "cannot read".)
    if ($File.Length -gt 0) { try { $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File) } catch { } }
    if ($null -ne $path -and [IO.Directory]::Exists($path)) { Stop-Run "$(Format-Shown $File) is a directory, not a payload file" }
    $fs = $null
    try { $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite') } catch { }   # note: plaintext is already on disk in this path
    if ($null -ne $fs) { $bytes = Read-Capped $fs }
    if ($null -eq $bytes) { Stop-Run "cannot read $(Format-Shown $File)" }
    if (Test-Utf16NoBom $bytes) { Stop-Run $utf16Msg }
    $secret = ConvertFrom-Bytes $bytes
    [Array]::Clear($bytes, 0, $bytes.Length)
  } elseif ($piped.Count -gt 0) {
    $secret = [string]::Join("`n", $piped.ToArray())
    # One leading byte-order mark is dropped, as ConvertFrom-Bytes does for
    # bytes (and handoff.sh for its input); a second is refused below.
    if ($secret.Length -gt 0 -and $secret[0] -eq [char]0xFEFF) { $secret = $secret.Substring(1) }
    # BOM-less UTF-16 read as single-byte text (Get-Content without -Encoding
    # on such a file) arrives with a NUL after or before each character: the
    # same test as Test-Utf16NoBom, on the characters (#85).
    if ($secret.Length -ge 4) {
      $lead = @(0x7B, 0x20, 0x09, 0x0D, 0x0A)
      $c = @([int]$secret[0], [int]$secret[1], [int]$secret[2], [int]$secret[3])
      if (($lead -contains $c[0] -and $c[1] -eq 0 -and $c[3] -eq 0) -or ($c[0] -eq 0 -and $lead -contains $c[1] -and $c[2] -eq 0)) {
        $secret = $null; $piped.Clear(); Stop-Run $utf16Msg
      }
    }
  } elseif ([Console]::IsInputRedirected -and (-not $MyInvocation.ExpectingInput -or
            ($MyInvocation.PipelinePosition -eq 1 -and $MyInvocation.PipelineLength -gt 1))) {
    # stdin's bytes, when nothing is piped in (ExpectingInput false), or when
    # the host itself feeds the script's pipeline: Windows PowerShell 5.1 run
    # as powershell -File handoff.ps1 < payload.json (or type payload.json |)
    # sets ExpectingInput, position 1 of a pipeline of 2, but binds nothing
    # (probed on 5.1.26100: an empty-pipeline reading refused every such
    # payload as empty). Not after a pipe: @() | .\handoff.ps1 is position 1
    # of 1 and an empty Get-Content | .\handoff.ps1 position 2, and there the
    # process's stdin is someone else's input; reading it would encrypt what
    # the user didn't give.
    $bytes = Read-Capped ([Console]::OpenStandardInput())
    if ($null -eq $bytes) { Stop-Run 'cannot read stdin' }
    if (Test-Utf16NoBom $bytes) { Stop-Run $utf16Msg }
    $secret = ConvertFrom-Bytes $bytes
    [Array]::Clear($bytes, 0, $bytes.Length)
  } elseif ($MyInvocation.ExpectingInput) {
    $secret = ''   # an empty pipeline (@() | .\handoff.ps1): "empty" below
  } else {
    [Console]::Error.WriteLine("Paste or type the JSON, then press Enter and $EndKey.")
    [Console]::Error.WriteLine('Example: {"svc": "example", "username": "u", "password": "p"}  or  {"svc": "example", "api_key_id": "k", "api_key_secret": "s"}')
    [Console]::Error.WriteLine('(input is hidden and is not written to PowerShell history)')
    $sb = New-Object System.Text.StringBuilder
    $over = $false
    try {
      while ($true) {
        $k = [Console]::ReadKey($true)
        $c = $k.KeyChar
        if (Test-EndKey $k) { break }
        # Past the cap, the rest is read to the end key and dropped, so none
        # of a paste is left for the prompt to run.
        if ($over) { continue }
        if ($sb.Length -gt $READ_CAP) { $over = $true; [void]$sb.Clear(); continue }
        if ($k.Key -eq [ConsoleKey]::Enter) { [void]$sb.Append("`n"); continue }
        if ($k.Key -eq [ConsoleKey]::Backspace) { if ($sb.Length -gt 0) { [void]$sb.Remove($sb.Length - 1, 1) }; continue }
        if ($c -ne [char]0) { [void]$sb.Append($c) }
      }
    } catch {
      Stop-Run 'cannot read from this console: pipe the JSON in, or use -File'
    }
    [Console]::Error.WriteLine()
    if ($over) { Stop-TooBig "over $READ_CAP" }
    $secret = $sb.ToString()
    [void]$sb.Clear()
  }
  if ($null -eq $secret) { Stop-Run $jsonMsg }
  $secret = $secret.TrimEnd([char[]]@("`r", "`n"))
  if ($secret.Trim().Length -eq 0) { Stop-Run 'empty, aborting' }

  # --- validate ---------------------------------------------------------
  # Exactly one JSON value, an object, carrying a non-empty string "svc" and
  # only string values (handoff.sh's jq filter), then the fields consume.py
  # refuses (its check_payload; handoff.sh's second jq filter): a NUL in any
  # value, an empty credential field, no known credential field. With the
  # strict UTF-8 below, this refuses every payload consume.py would refuse for
  # its shape or fields, here, early, where the human can see why; only the
  # label match is left to consume.py.
  #
  # One hand-written check, the same on 5.1 and 7, and no cmdlet ever gets the
  # plaintext: 5.1's Module Logging records cmdlet parameters in the event log,
  # and ConvertFrom-Json differs by edition (5.1 takes single quotes and turns
  # "\/Date(0)\/" into a date, and refuses keys that differ only in case; 7
  # turns ISO-date-like strings into dates). RFC 8259, strictly: whitespace is
  # space, tab, CR and LF; strings in double quotes, with no control
  # characters and only the standard escapes; surrogates only in pairs. As in
  # jq, a repeated "svc" counts the last one, and keys that differ only in case
  # are different keys. It only checks: age gets $strict.GetBytes of the text
  # it checked (a byte-order mark dropped, trailing line ends trimmed, UTF-16
  # transcoded to UTF-8).
  # Returns $null for a payload that passes, else the refusal (fixed text,
  # nothing from the payload).
  function Test-Payload([string]$s) {
    $ws = New-Object System.Text.RegularExpressions.Regex '\G[ \t\r\n]*'
    # A string token. Atomic, so a long string that fails can't backtrack.
    $str = New-Object System.Text.RegularExpressions.Regex '\G"(?>(?:[^"\\\x00-\x1F]+|\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4})*)"'
    $esc = New-Object System.Text.RegularExpressions.Regex '\\(?:u([0-9A-Fa-f]{4})|(.))'
    # Half a surrogate pair, written raw or as \uXXXX.
    $lone = New-Object System.Text.RegularExpressions.Regex '[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'
    # A token's text, escapes decoded; $null if it holds a lone surrogate.
    function Get-TokenText([string]$t) {
      $body = $t.Substring(1, $t.Length - 2)
      if ($body.IndexOf([char]0x5C) -ge 0) {
        $body = $esc.Replace($body, [System.Text.RegularExpressions.MatchEvaluator] {
          param($m)
          if ($m.Groups[1].Success) { return [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) }
          switch -CaseSensitive ($m.Groups[2].Value) {
            'b' { return [string][char]8 }
            'f' { return [string][char]12 }
            'n' { return "`n" }
            'r' { return "`r" }
            't' { return "`t" }
            default { return $m.Groups[2].Value }   # " \ /
          }
        })
      }
      if ($lone.IsMatch($body)) { return $null }
      return $body
    }
    $n = $s.Length
    $i = $ws.Match($s, 0).Length
    if ($i -ge $n -or $s[$i] -cne '{') { return $jsonMsg }
    $i = $i + 1
    $i = $i + $ws.Match($s, $i).Length
    $svc = $null
    $vals = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    while ($true) {
      $k = $str.Match($s, $i)
      if (-not $k.Success) { return $jsonMsg }   # also {} and a trailing comma
      $i = $i + $k.Length
      $i = $i + $ws.Match($s, $i).Length
      if ($i -ge $n -or $s[$i] -cne ':') { return $jsonMsg }
      $i = $i + 1
      $i = $i + $ws.Match($s, $i).Length
      $v = $str.Match($s, $i)
      if (-not $v.Success) { return $jsonMsg }   # any value that isn't a string
      $i = $i + $v.Length
      $key = Get-TokenText $k.Value
      $val = Get-TokenText $v.Value
      if ($null -eq $key -or $null -eq $val) { return $jsonMsg }
      # Ordinal: PowerShell's -ceq compares by culture, which skips format
      # characters, so "s<U+202E>vc" -ceq "svc" is true (jq and consume.py
      # see another key).
      if ([string]::Equals($key, 'svc', [StringComparison]::Ordinal)) { $svc = $val }
      $vals[$key] = $val
      $i = $i + $ws.Match($s, $i).Length
      if ($i -ge $n) { return $jsonMsg }
      if ($s[$i] -ceq ',') { $i = $i + 1; $i = $i + $ws.Match($s, $i).Length; continue }
      if ($s[$i] -ceq '}') { $i = $i + 1; break }
      return $jsonMsg
    }
    $i = $i + $ws.Match($s, $i).Length
    if ($i -ne $n -or $null -eq $svc -or $svc.Length -eq 0) { return $jsonMsg }   # nothing after the object
    # The values as consume.py sees them: a repeated key counts the last one.
    $known = $KNOWN_FIELDS.Split(' ')
    foreach ($v in $vals.Values) { if ($v.IndexOf([char]0) -ge 0) { return 'a value contains a NUL character (\u0000), aborting' } }
    foreach ($f in $known) { if ($vals.ContainsKey($f) -and $vals[$f].Length -eq 0) { return 'a credential field is empty, aborting' } }
    # The field names, for the note on unknown ones (names, never values).
    $script:PayloadKeys = @($vals.Keys)
    foreach ($f in $known) { if ($vals.ContainsKey($f)) { return $null } }
    return "no known credential field (one of: $($KNOWN_FIELDS.Replace(' ', ', '))), aborting"
  }
  # The cap (MAX_PAYLOAD, above) keeps the blob within consume.py's limit:
  # checked first, on the bytes age would get, before the JSON check and the
  # note, as in handoff.sh.
  $bytes = $null
  try { $bytes = $strict.GetBytes($secret) } catch { Stop-Run $jsonMsg }   # a lone surrogate
  if ($bytes.Length -gt $MAX_PAYLOAD) {
    $n = $bytes.Length
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secret = $null
    Stop-TooBig $n
  }
  $script:PayloadKeys = @()
  $refusal = Test-Payload $secret
  if ($refusal -ceq $jsonMsg) {
    # A hint for the likeliest causes it can see (fixed text, nothing from the
    # payload), as handoff.sh gives.
    [Console]::Error.WriteLine("handoff.ps1: $jsonMsg")
    if ($secret.Length -gt 0 -and $secret[0] -eq [char]0xFEFF) {
      [Console]::Error.WriteLine('handoff.ps1: it starts with a second byte-order mark (U+FEFF): save the file as UTF-8 without them')
    }
    if ($secret.IndexOfAny([char[]]@([char]0x2018, [char]0x2019, [char]0x201C, [char]0x201D)) -ge 0) {
      [Console]::Error.WriteLine('handoff.ps1: it has typographic quotes (U+2018, U+2019, U+201C or U+201D): JSON takes only straight quotes (") around a name or a value, so retype any that are meant as those (some editors and chat apps change them); inside a value, they''re part of it')
    }
    $secret = $null
    [Array]::Clear($bytes, 0, $bytes.Length)
    Exit-Handoff 1
  }
  if ($null -ne $refusal) { [Array]::Clear($bytes, 0, $bytes.Length); Stop-Run $refusal }
  # A string's code points (Test-Payload has refused a lone surrogate), so the
  # edit distance below counts characters as handoff.sh's jq explode does,
  # not UTF-16 units.
  function Get-CodePoints([string]$s) {
    $cp = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $s.Length; $i++) {
      $cp.Add([char]::ConvertToUtf32($s, $i))
      if ([char]::IsHighSurrogate($s[$i])) { $i++ }
    }
    return ,$cp.ToArray()
  }
  # The edit distance between two code-point arrays (handoff.sh's lev, in jq).
  function Get-EditDistance([int[]]$a, [int[]]$b) {
    $prev = New-Object int[] ($b.Length + 1)
    for ($j = 0; $j -le $b.Length; $j++) { $prev[$j] = $j }
    for ($i = 0; $i -lt $a.Length; $i++) {
      $cur = New-Object int[] ($b.Length + 1)
      $cur[0] = $i + 1
      for ($j = 0; $j -lt $b.Length; $j++) {
        $cost = 1
        if ($a[$i] -eq $b[$j]) { $cost = 0 }
        $cur[$j + 1] = [Math]::Min([Math]::Min($prev[$j + 1] + 1, $cur[$j] + 1), $prev[$j] + $cost)
      }
      $prev = $cur
    }
    return $prev[$b.Length]
  }
  # Fields consume.py doesn't know are ignored there, so a misspelled one
  # never reaches the agent: counted here, before encrypting (handoff.sh's
  # note). Nothing from the payload is printed, its names included: a value
  # typed in a name's place can be a secret, and common passwords are a few
  # edits from "password". So the note names the KNOWN field each likely
  # misspelling is close to (within two edits, ignoring ASCII case, counted
  # in characters; the closest, the first in KNOWN_FIELDS on a tie). (A name
  # longer than the longest known field plus 2 can't be within two edits, so
  # the distance isn't computed for it: that only saves time.)
  $knownList = @($KNOWN_FIELDS.Split(' '))
  $knownCps = @($knownList | ForEach-Object { ,(Get-CodePoints $_) })
  $longest = ($knownList | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 2
  # Ordinal, as in Test-Payload: -ccontains compares by culture, which skips
  # format characters ("pass<U+202E>word" would pass for password).
  $knownSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($f in ($knownList + @('svc'))) { [void]$knownSet.Add($f) }
  $unknown = @($script:PayloadKeys | Where-Object { -not $knownSet.Contains($_) })
  $script:PayloadKeys = @()
  if ($unknown.Count -gt 0) {
    $closeCount = 0
    $closeIdx = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($n in $unknown) {
      $chars = $n.ToCharArray()
      for ($c = 0; $c -lt $chars.Length; $c++) { $v = [int]$chars[$c]; if ($v -ge 65 -and $v -le 90) { $chars[$c] = [char]($v + 32) } }
      $low = Get-CodePoints (New-Object string (,$chars))
      if ($low.Length -gt $longest) { continue }
      $best = -1; $bestD = 3
      for ($i = 0; $i -lt $knownCps.Count; $i++) {
        $d = Get-EditDistance $low $knownCps[$i]
        if ($d -lt $bestD) { $bestD = $d; $best = $i }
      }
      if ($best -ge 0) { $closeCount++; [void]$closeIdx.Add($best) }
    }
    $text = "consume.py ignores $($unknown.Count) field(s) it doesn't know"
    if ($closeCount -gt 0) { $text += ", $closeCount of them close to " + ((@($closeIdx | ForEach-Object { '"' + $knownList[$_] + '"' })) -join ', ') + ' (misspelled?)' }
    [Console]::Error.WriteLine("handoff.ps1: note: $text. It uses: $($KNOWN_FIELDS.Replace(' ', ', ')). If one is misspelled, fix it and run again: an ignored field never reaches the agent")
  }

  $secret = $null

  # --- encrypt (no plaintext ever touches disk) -------------------------
  # age writes the binary format; base64 makes it one line.
  $enc = Invoke-Age "-r $RECIPIENT" $bytes
  [Array]::Clear($bytes, 0, $bytes.Length)
  if ($null -eq $enc -or $enc.Exit -ne 0 -or $enc.Out.Length -eq 0) { Stop-Run "age failed to encrypt (age $AgeVersion), aborting" }
  $blob = [Convert]::ToBase64String($enc.Out)
  [Console]::Error.WriteLine("recipient: $RECIPIENT (from $kf)  <- compare with the recipient")
  [Console]::Error.WriteLine('   your agent reports for its key before trusting this output')
  [Console]::Error.WriteLine("--- paste everything below into chat with $To (recipient file $kf) ---")
  Write-Output $blob
  [Console]::Error.WriteLine('--- end ---')
  Exit-Handoff 0
}
