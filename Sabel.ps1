<#
.SYNOPSIS
    Sabel Threat Detection - a read-only daily security check for Windows.

.DESCRIPTION
    Looks for signs of malware, risky settings and system problems, and explains what
    you can do about each one. It never deletes, quarantines, or changes anything.
    Run "sabel help" for commands.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Target,
    [Parameter(Position = 2)][string]$Path,
    [switch]$Scheduled,
    [switch]$Quiet,
    [switch]$Detailed,
    [string]$Time = '12:00',
    [switch]$Elevated
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:SabelRoot = $PSScriptRoot

. (Join-Path $PSScriptRoot 'src\Core.ps1')
. (Join-Path $PSScriptRoot 'src\Checks.Protection.ps1')
. (Join-Path $PSScriptRoot 'src\Checks.Persistence.ps1')
. (Join-Path $PSScriptRoot 'src\Checks.Activity.ps1')
. (Join-Path $PSScriptRoot 'src\Checks.Health.ps1')
. (Join-Path $PSScriptRoot 'src\Report.ps1')
. (Join-Path $PSScriptRoot 'src\Scheduler.ps1')
. (Join-Path $PSScriptRoot 'src\Actions.ps1')

$script:IsScheduledRun = [bool]$Scheduled

New-Item -ItemType Directory -Force -Path $script:ReportDir | Out-Null

function Show-Help {
    Write-Host ''
    Write-Host '  SABEL THREAT DETECTION' -ForegroundColor Cyan -NoNewline
    Write-Host "  v$script:SabelVersion - finds problems and explains them. It never deletes anything itself." -ForegroundColor DarkGray
    Write-Host ''
    $rows = @(
        @('scan',               'Run a security check now and show the results'),
        @('scan -Detailed',     'Same, with full explanations for every item'),
        @('report',             'Show the most recent results again'),
        @('explain <id>',       'Full details and step-by-step advice for one item'),
        @('act <id>',           'Choose what Microsoft Defender should do about one item'),
        @('defender quickscan', 'Ask Defender to quick-scan the PC (also: fullscan)'),
        @('defender scanfile <path>', 'Ask Defender to scan one file or folder'),
        @('defender remove',    'Ask Defender to remove threats it found but did not clean'),
        @('defender offline',   'Ask Defender to run an Offline scan (restarts the PC)'),
        @('defender update',    'Update Defender virus definitions'),
        @('trust <id>',         'Mark an item as known-good so it stops alerting'),
        @('untrust <id>',       'Undo a trust'),
        @('trusted',            'List trusted items'),
        @('history',            'List past scans'),
        @('install [-Time 18:30] [-Elevated]', 'Run the check automatically every day'),
        @('uninstall',          'Remove the daily check'),
        @('status',             'Show whether the daily check is installed'),
        @('test-alert',         'Play the alert tune and show a test notification')
    )
    foreach ($r in $rows) { Write-Host ('   sabel {0,-36}' -f $r[0]) -ForegroundColor White -NoNewline; Write-Host $r[1] -ForegroundColor Gray }
    Write-Host ''
    Write-Host '  Tip: run from an administrator terminal (or install with -Elevated) to include the checks' -ForegroundColor DarkGray
    Write-Host '  that Windows only allows admins to read, such as antivirus exclusions.' -ForegroundColor DarkGray
    Write-Host '  Anything that could quarantine or remove a file asks you to confirm TWICE first.' -ForegroundColor DarkGray
    Write-Host '  In PowerShell, type .\sabel instead of sabel when you are in this folder.' -ForegroundColor DarkGray
    Write-Host ''
}

function Write-SabelLog([string]$Message) {
    try { Add-Content -LiteralPath (Join-Path $script:DataDir 'sabel.log') -Value "$((Get-Date).ToString('s'))  $Message" -Encoding UTF8 } catch { }
}

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and -not $Scheduled) {
    Write-Host '  Note: running in 32-bit PowerShell; some 64-bit registry locations may be missed. Use sabel.cmd to start the 64-bit version.' -ForegroundColor DarkYellow
}

switch ($Command.ToLowerInvariant()) {
    'scan' {
        $cfg = Get-SabelConfig
        if ($Scheduled) {
            try {
                $report = Invoke-SabelScan -Silent
                $alert = @(Get-AlertFindings $report)
                Write-SabelLog "Scheduled scan finished: $(@($report.Findings).Count) findings, $($alert.Count) need attention."
                if ($alert.Count) {
                    $top = ($alert | Select-Object -First 3 | ForEach-Object { "- $($_.Title)" }) -join "`n"
                    if ($cfg.Toast) { $null = Show-SabelToast "Sabel Threat Detection: $($alert.Count) issue(s) found" "$top`nOpen a terminal and run: $(Join-Path $script:SabelRoot 'sabel.cmd') report" }
                    if ($cfg.Sound) { Invoke-SabelTune }
                }
            } catch { Write-SabelLog "Scheduled scan failed: $($_.Exception.Message)" }
            break
        }
        Write-Host ''
        Write-Host '  Sabel Threat Detection is checking your PC (read-only, nothing will be changed)...' -ForegroundColor Cyan
        Write-Host ''
        $report = Invoke-SabelScan
        Show-Report $report -Detailed:$Detailed
        if (@(Get-AlertFindings $report).Count -and $cfg.Sound -and -not $Quiet) { Invoke-SabelTune }
    }
    'report' {
        $r = Get-LatestReport
        if ($r) { Show-Report $r -Detailed:$Detailed } else { Write-Host '  No report yet. Run: sabel scan' -ForegroundColor Yellow }
    }
    'explain' {
        if (-not $Target) { Write-Host '  Usage: sabel explain <id>' -ForegroundColor Yellow; break }
        $f = Find-ReportItem $Target
        if ($f) { Write-Host ''; Show-Finding $f -Full; Write-Host "  To ask Microsoft Defender to scan or remove it:  sabel act $($f.Id)" -ForegroundColor DarkGray; Write-Host '' }
    }
    'trust'      { if ($Target) { Set-SabelTrust $Target } else { Write-Host '  Usage: sabel trust <id>' -ForegroundColor Yellow } }
    'untrust'    { if ($Target) { Set-SabelTrust $Target -Remove } else { Write-Host '  Usage: sabel untrust <id>' -ForegroundColor Yellow } }
    'act'        { if ($Target) { Show-ActionMenu $Target } else { Write-Host '  Usage: sabel act <id>' -ForegroundColor Yellow } }
    'defender'   {
        $sub = if ($Target) { $Target.ToLowerInvariant() } else { '' }
        switch ($sub) {
            'quickscan' { Invoke-DefenderScan 'QuickScan' }
            'fullscan'  { Invoke-DefenderScan 'FullScan' }
            'scanfile'  { if ($Path) { Invoke-DefenderFileScan $Path } else { Write-Host '  Usage: sabel defender scanfile <path>' -ForegroundColor Yellow } }
            'remove'    { Invoke-DefenderRemoveThreats }
            'offline'   { Invoke-DefenderOfflineScan }
            'update'    { Invoke-DefenderUpdate }
            default     { Write-Host '  Usage: sabel defender quickscan | fullscan | scanfile <path> | remove | offline | update' -ForegroundColor Yellow }
        }
    }
    'trusted'    { Show-TrustedList }
    'history'    { Show-History }
    'install'    { Install-SabelSchedule -Time $Time -Elevated:$Elevated }
    'uninstall'  { Uninstall-SabelSchedule }
    'status'     { Show-SabelStatus }
    'test-alert' {
        Write-Host '  Playing the alert tune...'
        $ok = Show-SabelToast 'Sabel Threat Detection (test)' 'This is what a daily-scan alert looks like.'
        Invoke-SabelTune
        if (-not $ok) { Write-Host '  (Desktop notifications are not available here; the tune alone will be used.)' -ForegroundColor DarkGray }
    }
    default { Show-Help }
}
