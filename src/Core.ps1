# Core engine for Sabel Threat Detection: finding model, shared helpers, storage, alerts.
# IMPORTANT: Sabel Threat Detection is READ-ONLY. Nothing in this project may modify, delete,
# quarantine or "fix" anything on the system. The only things it ever writes are its
# own files under %LOCALAPPDATA%\Sabel_Threat_Detection and (on request) its own scheduled task.

$script:SabelVersion = '1.0.0'
$script:DataDir      = Join-Path $env:LOCALAPPDATA 'Sabel_Threat_Detection'
$script:ReportDir    = Join-Path $script:DataDir 'reports'
$script:BaselineFile = Join-Path $script:DataDir 'baseline.json'
$script:TrustedFile  = Join-Path $script:DataDir 'trusted.json'
$script:ConfigFile   = Join-Path $script:DataDir 'config.json'

$script:SeverityRank = @{ Info = 0; Low = 1; Medium = 2; High = 3 }
$script:SigCache     = @{}

function Initialize-SabelState {
    $script:Findings     = New-Object System.Collections.Generic.List[object]
    $script:Skipped      = New-Object System.Collections.Generic.List[object]
    $script:Inventory    = @{}
    $script:OldBaseline  = $null
    if (Test-Path -LiteralPath $script:BaselineFile) {
        try { $script:OldBaseline = Get-Content -LiteralPath $script:BaselineFile -Raw | ConvertFrom-Json } catch { $script:OldBaseline = $null }
    }
}

# ---------------------------------------------------------------- common advice

$script:FixCheckFile = @(
    'Do not open or run the file while you investigate.',
    'Search the exact file name and folder online to see whether it belongs to software you installed.',
    'Upload the file (or paste its SHA256 hash) at https://www.virustotal.com to have ~70 antivirus engines check it.',
    'If it is unknown or flagged: open Windows Security > Virus & threat protection > Scan options > "Microsoft Defender Offline scan" and run it.'
)
$script:FixAutoruns = 'For a deeper look, Microsoft''s free Sysinternals Autoruns tool (https://learn.microsoft.com/sysinternals/downloads/autoruns) shows every startup location and can check files against VirusTotal.'
$script:FixIfYouTrust = 'If you recognise this and trust it, run:  sabel trust <id>  so it stops alerting you.'

# ---------------------------------------------------------------- findings

function Get-StableId([string]$Text) {
    $sha = [Security.Cryptography.SHA1]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant()))
    (($bytes[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Info','Low','Medium','High')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [string[]]$Evidence = @(),
        [string]$Why = '',
        [string[]]$Fix = @(),
        [string]$Key,
        [string]$Target,      # file the finding is about (lets "sabel act" offer a Defender scan of it)
        [switch]$IsChange
    )
    if (-not $Key) { $Key = $Title }
    $script:Findings.Add([pscustomobject]@{
        Id       = Get-StableId "$Category|$Key"
        Severity = $Severity
        Category = $Category
        Title    = $Title
        Evidence = @($Evidence | Where-Object { $_ })
        Why      = $Why
        Fix      = @($Fix | Where-Object { $_ })
        IsChange = [bool]$IsChange
        Target   = $Target
        Trusted  = $false
    })
}

function Add-Skipped([string]$Check, [string]$Reason) {
    $script:Skipped.Add([pscustomobject]@{ Check = $Check; Reason = $Reason })
}

function Get-MaxSeverity([string]$A, [string]$B) {
    if ($script:SeverityRank[$A] -ge $script:SeverityRank[$B]) { $A } else { $B }
}

function Get-LowerSeverity([string]$Severity) {
    switch ($Severity) { 'High' { 'Medium' } 'Medium' { 'Low' } default { 'Info' } }
}

# ---------------------------------------------------------------- baseline / change detection

# Records an item for change detection. Returns $true when the item did not exist
# in the previous scan (and a previous scan of this kind exists).
function Add-InventoryItem([string]$Kind, [string]$Key, [string]$Label) {
    if (-not $script:Inventory.ContainsKey($Kind)) { $script:Inventory[$Kind] = @{} }
    $script:Inventory[$Kind][$Key] = $Label
    if (-not $script:OldBaseline) { return $false }
    $old = $script:OldBaseline.PSObject.Properties[$Kind]
    if (-not $old) { return $false }
    return -not ($old.Value.PSObject.Properties.Name -contains $Key)
}

# Marks a kind as collected even when it is empty (so "nothing" is remembered too).
function Register-InventoryKind([string]$Kind) {
    if (-not $script:Inventory.ContainsKey($Kind)) { $script:Inventory[$Kind] = @{} }
}

function Save-Baseline {
    $out = [ordered]@{}
    # keep kinds that were not collected this run (e.g. skipped without admin)
    if ($script:OldBaseline) {
        foreach ($p in $script:OldBaseline.PSObject.Properties) { $out[$p.Name] = $p.Value }
    }
    foreach ($k in $script:Inventory.Keys) { $out[$k] = $script:Inventory[$k] }
    $out | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:BaselineFile -Encoding UTF8
}

# ---------------------------------------------------------------- registry & file helpers

function Get-RegValue([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Test-File([string]$Path) {
    if (-not $Path) { return $false }
    try { return [IO.File]::Exists($Path) } catch { return $false }
}

function Test-UnderWindows([string]$Path) {
    if (-not $Path) { return $false }
    $Path.ToLowerInvariant().StartsWith($env:windir.ToLowerInvariant() + '\')
}

# Pulls the executable path out of a command line such as
#   "C:\Program Files\App\app.exe" --flag     or    C:\Program Files\App\app.exe -x
function Resolve-CommandTarget([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    $exe = $null
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        $exe = if ($end -gt 1) { $cmd.Substring(1, $end - 1) } else { $cmd.Trim('"') }
    } else {
        $parts = $cmd -split ' '
        for ($i = 1; $i -le [Math]::Min($parts.Count, 12); $i++) {
            $cand = ($parts[0..($i - 1)] -join ' ').TrimEnd(',')
            if (Test-File $cand) { $exe = $cand; break }
            if (Test-File "$cand.exe") { $exe = "$cand.exe"; break }
        }
        if (-not $exe) { $exe = $parts[0].TrimEnd(',') }
    }
    $exe = $exe -replace '^\\\?\?\\', ''
    $exe = $exe -replace '^(?i)\\SystemRoot\\', "$env:windir\"
    $exe = $exe -replace '^(?i)system32\\', "$env:windir\System32\"
    $rooted = $false
    try { $rooted = [IO.Path]::IsPathRooted($exe) } catch { }
    if (-not $rooted) {
        foreach ($dir in @("$env:windir\System32", $env:windir, "$env:windir\SysWOW64", "$env:windir\System32\wbem", "$env:windir\System32\WindowsPowerShell\v1.0")) {
            foreach ($c in @((Join-Path $dir $exe), (Join-Path $dir "$exe.exe"))) {
                if (Test-File $c) { return $c }
            }
        }
    }
    return $exe
}

# Finds a script/DLL path handed to a host program (rundll32, wscript, powershell -File, ...)
function Get-PayloadPath([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine)
    $m = [regex]::Matches($cmd, '(?i)("[^"]+\.(dll|vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|cpl|scr)"|[^\s",]+\.(dll|vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|cpl|scr))')
    foreach ($x in $m) {
        $p = $x.Value.Trim('"')
        if ($p -match '^[a-zA-Z]:\\' -or $p -match '^\\\\') { return $p }
    }
    return $null
}

# Folders where legitimate installed software rarely lives but malware often does.
function Get-LocationRisk([string]$Path) {
    if (-not $Path) { return $null }
    $p = $Path.ToLowerInvariant()
    $rules = @(
        @('\\appdata\\local\\temp\\',          'a Temp folder'),
        @('\\windows\\temp\\',                 'the Windows Temp folder'),
        @('\\temp\\|\\tmp\\',                  'a Temp folder'),
        @('\\downloads\\',                     'the Downloads folder'),
        @('\\users\\public\\',                 'the Public user folder'),
        @('\\\$recycle\.bin\\',                'the Recycle Bin'),
        @('^[a-z]:\\perflogs\\',               'C:\PerfLogs'),
        @('\\desktop\\',                       'a Desktop folder'),
        @('\\programdata\\[^\\]+$',            'the root of C:\ProgramData'),
        @('\\appdata\\roaming\\[^\\]+$',       'the root of AppData\Roaming'),
        @('\\appdata\\local\\[^\\]+$',         'the root of AppData\Local'),
        @('\\windows\\(tasks|debug|fonts|help|tracing)\\', 'an unusual Windows sub-folder'),
        @('^[a-z]:\\[^\\]+$',                  'the root of a drive')
    )
    foreach ($r in $rules) { if ($p -match $r[0]) { return $r[1] } }
    return $null
}

function Get-FileSignatureInfo([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Exists = $false; Status = 'Missing'; Signer = $null; IsMicrosoft = $false; Sha256 = $null } }
    $k = $Path.ToLowerInvariant()
    if ($script:SigCache.ContainsKey($k)) { return $script:SigCache[$k] }
    $info = [pscustomobject]@{ Exists = $false; Status = 'Missing'; Signer = $null; IsMicrosoft = $false; Sha256 = $null
                               IsScript = ($k -match '\.(bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1)$') }
    if (Test-File $Path) {
        $info.Exists = $true
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $info.Status = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $info.Signer = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            }
            $info.IsMicrosoft = ($info.Status -eq 'Valid' -and $info.Signer -match '^Microsoft')
        } catch { $info.Status = 'Unreadable' }
        if ($info.Status -ne 'Valid') {
            try { $info.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        }
    }
    $script:SigCache[$k] = $info
    return $info
}

function Format-Signature($Sig) {
    if (-not $Sig.Exists) { return 'file not found' }
    if ($Sig.Status -ne 'Valid' -and $Sig.IsScript) { return 'a script file - not signed, so its author cannot be verified' }
    switch ($Sig.Status) {
        'Valid'        { "signed by $($Sig.Signer)" }
        'NotSigned'    { 'NOT digitally signed' }
        'HashMismatch' { 'signature BROKEN - file was changed after signing' }
        default        { "signature status: $($Sig.Status)" }
    }
}

# Looks for well-known attacker tricks inside a command line or script text.
function Get-CommandLineRisk([string]$Text) {
    $hits = New-Object System.Collections.Generic.List[object]
    if (-not $Text) { return $hits }
    $rules = @(
        @('High',   '(?i)(powershell|pwsh)(\.exe)?["'']?\s.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}', 'runs a hidden, base64-encoded PowerShell command'),
        @('High',   '(?i)\b(iex|invoke-expression)\b.*\b(downloadstring|downloaddata|invoke-webrequest|iwr|invoke-restmethod|irm|net\.webclient)\b|\b(downloadstring|downloaddata|invoke-webrequest|iwr|invoke-restmethod|irm|net\.webclient)\b.*\b(iex|invoke-expression)\b', 'downloads code from the internet and runs it immediately'),
        @('High',   '(?i)frombase64string', 'decodes hidden (base64) data at run time'),
        @('High',   '(?i)\bmshta(\.exe)?\b', 'uses mshta.exe, a Windows tool often abused to run malicious scripts'),
        @('High',   '(?i)\bregsvr32(\.exe)?\b.*(/i:\s*https?|scrobj)', 'uses regsvr32 to load a remote script ("Squiblydoo" technique)'),
        @('High',   '(?i)\brundll32(\.exe)?\b.*(javascript:|vbscript:|mshtml)', 'uses rundll32 to run script code'),
        @('High',   '(?i)\bcertutil(\.exe)?\b.*(-urlcache|-decode|-split)', 'uses certutil to download or decode files'),
        @('High',   '(?i)\bbitsadmin(\.exe)?\b.*/(transfer|addfile)', 'uses bitsadmin to download files'),
        @('Medium', '(?i)(powershell|pwsh)(\.exe)?["'']?\s.*-w(indowstyle)?\s+h(idden)?\b', 'starts PowerShell in a hidden window'),
        @('Medium', '(?i)\b(downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|net\.webclient)\b', 'downloads something from the internet'),
        @('Medium', '(?i)\b(wscript|cscript)(\.exe)?\b', 'runs a script through Windows Script Host'),
        @('Medium', '(?i)https?://[^\s"'']+', 'contains a web address')
    )
    foreach ($r in $rules) {
        if ($Text -match $r[1]) { $hits.Add([pscustomobject]@{ Severity = $r[0]; Reason = $r[2] }) }
    }
    return $hits
}

# Scores an automatically-started program (run key, task, service, startup item).
function Measure-AutoStart([string]$CommandLine) {
    $res = [pscustomobject]@{ Severity = 'Info'; Reasons = New-Object System.Collections.Generic.List[string]; Target = $null; Sig = $null; Payload = $null }
    $res.Target = Resolve-CommandTarget $CommandLine
    foreach ($h in (Get-CommandLineRisk $CommandLine)) {
        $res.Reasons.Add($h.Reason); $res.Severity = Get-MaxSeverity $res.Severity $h.Severity
    }
    $res.Sig = Get-FileSignatureInfo $res.Target
    if (-not $res.Sig.Exists) {
        $res.Reasons.Add('the program it points to does not exist (leftover from uninstalled software, or a removed threat)')
        $res.Severity = Get-MaxSeverity $res.Severity 'Low'
    } else {
        $loc = Get-LocationRisk $res.Target
        if ($res.Sig.Status -eq 'HashMismatch') {
            $res.Reasons.Add('its digital signature is broken - the file was modified after it was signed')
            $res.Severity = 'High'
        } elseif ($res.Sig.Status -ne 'Valid') {
            if ($loc) { $res.Reasons.Add("an unsigned program in $loc"); $res.Severity = 'High' }
            elseif (-not (Test-UnderWindows $res.Target)) {
                $what = if ($res.Sig.IsScript) { 'it runs a script file, which cannot be verified by a digital signature' } else { 'the program is not digitally signed' }
                $res.Reasons.Add($what); $res.Severity = Get-MaxSeverity $res.Severity 'Low'
            }
        } elseif ($loc) {
            $res.Reasons.Add("it lives in $loc (signed by $($res.Sig.Signer))"); $res.Severity = Get-MaxSeverity $res.Severity 'Low'
        }
    }
    # Host programs (rundll32, wscript, powershell -File ...) - judge what they load
    $payload = Get-PayloadPath $CommandLine
    if ($payload -and $payload -ne $res.Target) {
        $res.Payload = $payload
        $pSig = Get-FileSignatureInfo $payload
        $pLoc = Get-LocationRisk $payload
        if ($pSig.Exists -and $pSig.Status -ne 'Valid' -and $pLoc) {
            $res.Reasons.Add("it loads an unsigned file from $pLoc ($payload)"); $res.Severity = Get-MaxSeverity $res.Severity 'High'
        } elseif ($pSig.Exists -and $pSig.Status -ne 'Valid' -and -not (Test-UnderWindows $payload)) {
            $res.Reasons.Add("it loads an unsigned script/library ($payload)"); $res.Severity = Get-MaxSeverity $res.Severity 'Low'
        }
    }
    return $res
}

function Get-Levenshtein([string]$A, [string]$B) {
    # Optimal-string-alignment distance: swapped neighbours ("scvhost") count as one edit.
    $prev2 = $null
    $prev = 0..$B.Length
    for ($i = 1; $i -le $A.Length; $i++) {
        $cur = @($i) * ($B.Length + 1)
        for ($j = 1; $j -le $B.Length; $j++) {
            $cost = if ($A[$i - 1] -eq $B[$j - 1]) { 0 } else { 1 }
            $cur[$j] = [Math]::Min([Math]::Min($prev[$j] + 1, $cur[$j - 1] + 1), $prev[$j - 1] + $cost)
            if ($i -gt 1 -and $j -gt 1 -and $A[$i - 1] -eq $B[$j - 2] -and $A[$i - 2] -eq $B[$j - 1]) {
                $cur[$j] = [Math]::Min($cur[$j], $prev2[$j - 2] + 1)
            }
        }
        $prev2 = $prev
        $prev = $cur
    }
    $prev[$B.Length]
}

function Get-RecentEvents([hashtable]$Filter, [int]$Max = 500) {
    try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ($_.Exception.Message -match 'No events were found') { @() } else { throw }
    }
}

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- config / trust list

function Get-SabelConfig {
    $cfg = [ordered]@{ AlertMinSeverity = 'Medium'; Sound = $true; Toast = $true; KeepReports = 60 }
    if (Test-Path -LiteralPath $script:ConfigFile) {
        try {
            $j = Get-Content -LiteralPath $script:ConfigFile -Raw | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
        } catch { }
    } else {
        $cfg | ConvertTo-Json | Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8
    }
    return $cfg
}

function Get-TrustedList {
    if (Test-Path -LiteralPath $script:TrustedFile) {
        try { return @(Get-Content -LiteralPath $script:TrustedFile -Raw | ConvertFrom-Json) } catch { }
    }
    return @()
}

function Save-TrustedList($List) {
    ConvertTo-Json -InputObject @($List) -Depth 4 | Set-Content -LiteralPath $script:TrustedFile -Encoding UTF8
}

# ---------------------------------------------------------------- alerts

function Invoke-SabelTune {
    # A short rising-falling "attention" melody, played twice.
    $notes = @(@(659, 140), @(784, 140), @(988, 220), @(784, 140), @(988, 360))
    try {
        foreach ($round in 1..2) {
            foreach ($n in $notes) { [Console]::Beep($n[0], $n[1]) }
            Start-Sleep -Milliseconds 250
        }
    } catch {
        try { [System.Media.SystemSounds]::Exclamation.Play(); Start-Sleep -Milliseconds 900 } catch { }
    }
}

function Show-SabelToast([string]$Title, [string]$Message) {
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $t = [Security.SecurityElement]::Escape($Title)
        $m = [Security.SecurityElement]::Escape($Message)
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast duration='long'><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual><audio silent='true'/></toast>")
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
        return $true
    } catch { return $false }
}
