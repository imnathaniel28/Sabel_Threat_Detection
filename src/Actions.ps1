# "Level 1" actions: Sabel Threat Detection itself still never deletes, moves or edits anything.
# These commands only ASK MICROSOFT DEFENDER to scan, remove or update. Anything that can
# lead to a file being quarantined or removed requires TWO separate confirmations, and
# is refused outright when nobody is at the keyboard (scheduled runs, piped input).

$script:ActionLog = Join-Path $script:DataDir 'actions.log'

function Write-ActionLog([string]$Message) {
    try { Add-Content -LiteralPath $script:ActionLog -Value "$((Get-Date).ToString('s'))  $Message" -Encoding UTF8 } catch { }
}

function Test-CanAskUser {
    if ($script:IsScheduledRun) { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return [Environment]::UserInteractive
}

# Two-step consent. Returns $true only if the user says yes AND then types CONFIRM.
function Confirm-TwoStep([string]$Action, [string[]]$Details = @(), [string[]]$Warnings = @()) {
    if (-not (Test-CanAskUser)) {
        Write-Host '  Refused: this action needs a person at the keyboard to confirm it twice.' -ForegroundColor Yellow
        Write-ActionLog "REFUSED (no interactive user): $Action"
        return $false
    }
    Write-Host ''
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host "  You are about to: $Action" -ForegroundColor Yellow
    foreach ($d in $Details) { Write-Wrapped $d 4 'Gray' '- ' }
    Write-Host ''
    foreach ($w in @($Warnings) + 'If Microsoft Defender decides something is malicious, it may QUARANTINE or REMOVE it. Quarantined items can be restored from Windows Security > Virus & threat protection > Protection history.') {
        Write-Wrapped $w 4 'Yellow' '! '
    }
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor Yellow
    $a = Read-Host '  Step 1 of 2 - Do you want to continue? (y/N)'
    if ($a -notmatch '^\s*(y|yes)\s*$') { Write-Host '  Cancelled. Nothing was done.' -ForegroundColor Green; Write-ActionLog "Cancelled at step 1: $Action"; return $false }
    $b = Read-Host '  Step 2 of 2 - Are you sure? Type CONFIRM to go ahead'
    if ($b.Trim() -ne 'CONFIRM') { Write-Host '  Cancelled. Nothing was done.' -ForegroundColor Green; Write-ActionLog "Cancelled at step 2: $Action"; return $false }
    Write-ActionLog "CONFIRMED twice: $Action"
    return $true
}

function Test-DefenderAvailable {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($s.AntivirusEnabled -and $s.AMRunningMode -eq 'Normal') { return $true }
        Write-Host "  Microsoft Defender is not the active antivirus on this PC (mode: $($s.AMRunningMode))." -ForegroundColor Yellow
        Write-Host '  Use your installed antivirus to scan or remove threats instead.' -ForegroundColor Yellow
    } catch {
        Write-Host '  Microsoft Defender is not available on this PC. Use your installed antivirus instead.' -ForegroundColor Yellow
    }
    return $false
}

function Write-DefenderError($Err) {
    $msg = $Err.Exception.Message
    Write-Host "  Defender reported an error: $msg" -ForegroundColor Red
    if ($msg -match 'denied|0x80070005|privilege|administrator') {
        Write-Host '  This action needs administrator rights: right-click Terminal > "Run as administrator" and try again.' -ForegroundColor Yellow
    }
    Write-ActionLog "Error: $msg"
}

# Shows what Defender detected since $Since (used after a scan).
function Show-NewDetections([datetime]$Since) {
    $new = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $Since.AddSeconds(-5) -or $_.LastThreatStatusChangeTime -ge $Since.AddSeconds(-5) })
    if (-not $new) {
        Write-Host '  Result: Defender found nothing malicious.' -ForegroundColor Green
        Write-ActionLog 'Result: nothing found'
        return
    }
    $names = @{}; foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $names[[string]$t.ThreatID] = $t.ThreatName }
    $status = @{ 1 = 'detected'; 2 = 'cleaned'; 3 = 'quarantined'; 4 = 'removed'; 5 = 'allowed'; 6 = 'blocked'; 102 = 'quarantine FAILED'; 103 = 'remove FAILED'; 107 = 'block FAILED' }
    Write-Host "  Result: Defender detected $($new.Count) threat(s):" -ForegroundColor Red
    foreach ($d in $new) {
        $n = $names[[string]$d.ThreatID]; if (-not $n) { $n = "Threat ID $($d.ThreatID)" }
        $s = $status[[int]$d.ThreatStatusID]; if (-not $s) { $s = "status $($d.ThreatStatusID)" }
        Write-Host "    - $n  ->  $s" -ForegroundColor White
        foreach ($r in @($d.Resources) | Select-Object -First 3) { Write-Host "        $($r -replace '^[a-z]+:_', '')" -ForegroundColor DarkGray }
        Write-ActionLog "Detected: $n -> $s"
    }
    Write-Host '  See Windows Security > Virus & threat protection > Protection history for details or to restore an item.' -ForegroundColor DarkGray
}

function Invoke-DefenderFileScan([string]$Path) {
    if (-not (Test-DefenderAvailable)) { return }
    if (-not (Test-File $Path) -and -not (Test-Path -LiteralPath $Path -PathType Container)) { Write-Host "  File not found: $Path" -ForegroundColor Yellow; return }
    if (-not (Confirm-TwoStep "ask Microsoft Defender to scan: $Path" @('Defender checks this one file or folder against its virus database.'))) { return }
    $start = Get-Date
    Write-Host '  Scanning...' -ForegroundColor Cyan
    try { Start-MpScan -ScanType CustomScan -ScanPath $Path -ErrorAction Stop; Show-NewDetections $start } catch { Write-DefenderError $_ }
}

function Invoke-DefenderScan([ValidateSet('QuickScan', 'FullScan')][string]$Type) {
    if (-not (Test-DefenderAvailable)) { return }
    $details = if ($Type -eq 'QuickScan') { @('Defender checks the places malware usually hides (a few minutes).') } else { @('Defender checks every file on every drive. This can take an hour or more; you can keep using the PC.') }
    if (-not (Confirm-TwoStep "run a Microsoft Defender $(if ($Type -eq 'QuickScan') {'quick'} else {'full'}) scan" $details)) { return }
    $start = Get-Date
    Write-Host '  Scanning... (leave this window open)' -ForegroundColor Cyan
    try { Start-MpScan -ScanType $Type -ErrorAction Stop; Show-NewDetections $start } catch { Write-DefenderError $_ }
}

function Invoke-DefenderRemoveThreats {
    if (-not (Test-DefenderAvailable)) { return }
    $active = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object IsActive)
    if (-not $active) { Write-Host '  Defender has no active (unremoved) threats on record. Nothing to remove.' -ForegroundColor Green; return }
    $list = $active | ForEach-Object { "$($_.ThreatName)  -  $((@($_.Resources) | Select-Object -First 2 | ForEach-Object { $_ -replace '^[a-z]+:_', '' }) -join ', ')" }
    if (-not (Confirm-TwoStep 'ask Microsoft Defender to REMOVE these active threats' $list @('Defender will quarantine or delete the items listed above.'))) { return }
    $start = Get-Date
    try { Remove-MpThreat -ErrorAction Stop; Write-Host '  Defender has processed the threats.' -ForegroundColor Green; Show-NewDetections $start } catch { Write-DefenderError $_ }
}

function Invoke-DefenderOfflineScan {
    if (-not (Test-DefenderAvailable)) { return }
    if (-not (Confirm-TwoStep 'start a Microsoft Defender OFFLINE scan' @(
            'Your PC will RESTART within about a minute, start a special scanner before Windows loads, and scan for ~15 minutes.',
            'This catches rootkits and malware that hide while Windows is running.',
            'Afterwards Windows starts normally; results are in Windows Security > Protection history.') @('SAVE AND CLOSE ALL YOUR WORK FIRST.'))) { return }
    try { Start-MpWDOScan -ErrorAction Stop; Write-Host '  Offline scan scheduled. The PC will restart shortly.' -ForegroundColor Cyan } catch { Write-DefenderError $_ }
}

function Invoke-DefenderUpdate {
    if (-not (Test-DefenderAvailable)) { return }
    # Updating definitions removes nothing, so no confirmation is needed.
    Write-Host '  Updating Microsoft Defender virus definitions...' -ForegroundColor Cyan
    try {
        Update-MpSignature -ErrorAction Stop
        Write-Host "  Done. Definitions dated: $((Get-MpComputerStatus).AntivirusSignatureLastUpdated)" -ForegroundColor Green
        Write-ActionLog 'Updated Defender definitions'
    } catch { Write-DefenderError $_ }
}

# Interactive menu for one finding: "sabel act <id>"
function Show-ActionMenu([string]$Id) {
    $f = Find-ReportItem $Id
    if (-not $f) { return }
    Write-Host ''
    Show-Finding $f -Full
    $target = if ($f.PSObject.Properties['Target']) { $f.Target } else { $null }
    $options = New-Object System.Collections.Generic.List[object]
    if ($target -and (Test-File $target)) { $options.Add(@("Ask Defender to scan this file ($target)", 'file')) }
    if ($f.Title -match 'NOT fully removed|ALLOWED to run') { $options.Add(@('Ask Defender to remove its active threats', 'remove')) }
    if ($f.Title -match 'definitions') { $options.Add(@('Update Defender virus definitions', 'update')) }
    $options.Add(@('Run a Defender quick scan of the whole PC', 'quick'))
    $options.Add(@('Run a Defender Offline scan (restarts the PC)', 'offline'))
    Write-Host '  What would you like to do? (Sabel Threat Detection only asks Microsoft Defender; it never deletes anything itself)' -ForegroundColor Cyan
    for ($i = 0; $i -lt $options.Count; $i++) { Write-Host "    [$($i + 1)] $($options[$i][0])" }
    Write-Host '    [0] Nothing - just leave it'
    if (-not (Test-CanAskUser)) { Write-Host '  (Run this in an interactive terminal to choose an option.)' -ForegroundColor Yellow; return }
    $choice = Read-Host '  Choose'
    $n = 0
    if (-not [int]::TryParse($choice, [ref]$n) -or $n -lt 1 -or $n -gt $options.Count) { Write-Host '  Nothing was done.' -ForegroundColor Green; return }
    switch ($options[$n - 1][1]) {
        'file'    { Invoke-DefenderFileScan $target }
        'remove'  { Invoke-DefenderRemoveThreats }
        'update'  { Invoke-DefenderUpdate }
        'quick'   { Invoke-DefenderScan 'QuickScan' }
        'offline' { Invoke-DefenderOfflineScan }
    }
}
