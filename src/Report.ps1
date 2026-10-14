# Runs the checks, saves reports, and renders them in the terminal.

$script:CheckList = @(
    @('Antivirus status',                          'Test-Antivirus'),
    @('Recent threat detections',                  'Test-DefenderThreats'),
    @('Antivirus exclusions',                      'Test-DefenderExclusions'),
    @('Firewall',                                  'Test-Firewall'),
    @('User Account Control',                      'Test-Uac'),
    @('Windows Update',                            'Test-WindowsUpdate'),
    @('Windows version support',                   'Test-WindowsSupport'),
    @('Network exposure (SMBv1, RDP, Secure Boot)', 'Test-NetworkExposure'),
    @('Startup programs (registry)',               'Test-RunKeys'),
    @('Startup folders',                           'Test-StartupFolders'),
    @('Scheduled tasks',                           'Test-ScheduledTasks'),
    @('Services',                                  'Test-Services'),
    @('Drivers',                                   'Test-Drivers'),
    @('Hijack points (IFEO, Winlogon, AppInit)',   'Test-HijackPoints'),
    @('WMI event subscriptions',                   'Test-WmiPersistence'),
    @('PowerShell profiles',                       'Test-PowerShellProfiles'),
    @('Running programs',                          'Test-RunningProcesses'),
    @('Network connections',                       'Test-NetworkActivity'),
    @('Hosts file',                                'Test-HostsFile'),
    @('Proxy settings',                            'Test-ProxySettings'),
    @('User accounts',                             'Test-Accounts'),
    @('Browser extensions',                        'Test-BrowserExtensions'),
    @('Disk space',                                'Test-DiskSpace'),
    @('Disk health',                               'Test-DiskHealth'),
    @('Crash history',                             'Test-Crashes'),
    @('Pending restart',                           'Test-PendingRestart')
)

$script:SevColor = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'DarkGray' }

function Invoke-SabelScan([switch]$Silent) {
    Initialize-SabelState
    $start = Get-Date
    $isAdmin = Test-IsAdmin
    $i = 0
    foreach ($c in $script:CheckList) {
        $i++
        if (-not $Silent) { Write-Host ("  [{0,2}/{1}] {2,-45}" -f $i, $script:CheckList.Count, $c[0]) -NoNewline }
        $before = $script:Findings.Count
        $t0 = Get-Date
        try {
            $null = & $c[1]
            if (-not $Silent) {
                $n = $script:Findings.Count - $before
                $msg = if ($n) { "$n note(s)" } else { 'ok' }
                Write-Host ("{0,-10} {1,5:0.0}s" -f $msg, ((Get-Date) - $t0).TotalSeconds) -ForegroundColor DarkGray
            }
        } catch {
            Add-Skipped $c[0] "Check failed: $($_.Exception.Message)"
            if (-not $Silent) { Write-Host 'skipped' -ForegroundColor DarkYellow }
        }
    }

    $trusted = @(Get-TrustedList | ForEach-Object { $_.Id })
    foreach ($f in $script:Findings) { if ($trusted -contains $f.Id) { $f.Trusted = $true } }

    $firstRun = -not $script:OldBaseline
    Save-Baseline

    $sorted = @($script:Findings | Sort-Object @{ e = { $script:SeverityRank[$_.Severity] }; Descending = $true }, Category, Title)
    $report = [pscustomobject]@{
        Version         = $script:SabelVersion
        Computer        = $env:COMPUTERNAME
        User            = $env:USERNAME
        IsAdmin         = $isAdmin
        Started         = $start.ToString('s')
        DurationSeconds = [Math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        BaselineCreated = $firstRun
        Findings        = $sorted
        Skipped         = $script:Skipped.ToArray()   # @(emptyList) throws in PS 5.1
    }
    $file = Join-Path $script:ReportDir ("scan-{0}.json" -f $start.ToString('yyyyMMdd-HHmmss'))
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file -Encoding UTF8

    $keep = [int](Get-SabelConfig).KeepReports
    Get-ChildItem -LiteralPath $script:ReportDir -Filter 'scan-*.json' | Sort-Object Name -Descending | Select-Object -Skip $keep | Remove-Item -ErrorAction SilentlyContinue
    return $report
}

function Get-LatestReportFile {
    if (-not (Test-Path -LiteralPath $script:ReportDir)) { return $null }
    Get-ChildItem -LiteralPath $script:ReportDir -Filter 'scan-*.json' | Sort-Object Name -Descending | Select-Object -First 1
}

function Get-LatestReport {
    $f = Get-LatestReportFile
    if (-not $f) { return $null }
    Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
}

function Get-AlertFindings($Report) {
    $min = $script:SeverityRank[[string](Get-SabelConfig).AlertMinSeverity]
    @($Report.Findings | Where-Object { -not $_.Trusted -and $script:SeverityRank[$_.Severity] -ge $min })
}

function Get-ConsoleWidth {
    try { $w = $Host.UI.RawUI.WindowSize.Width; if ($w -ge 40) { return [Math]::Min($w, 140) } } catch { }
    return 100
}

function Write-Wrapped([string]$Text, [int]$Indent, [string]$Color = 'Gray', [string]$FirstPrefix = '') {
    $width = (Get-ConsoleWidth) - $Indent - 1
    $pad = ' ' * $Indent
    $first = $true
    $line = ''
    foreach ($word in ($Text -split '\s+')) {
        $prefixLen = if ($first) { $FirstPrefix.Length } else { $FirstPrefix.Length }
        if (($line.Length + $word.Length + 1 + $prefixLen) -gt $width -and $line) {
            $p = if ($first) { $FirstPrefix } else { ' ' * $FirstPrefix.Length }
            Write-Host "$pad$p$line" -ForegroundColor $Color
            $line = $word; $first = $false
        } else { $line = if ($line) { "$line $word" } else { $word } }
    }
    if ($line) { $p = if ($first) { $FirstPrefix } else { ' ' * $FirstPrefix.Length }; Write-Host "$pad$p$line" -ForegroundColor $Color }
}

function Show-Finding($F, [switch]$Full) {
    $tag = ('[' + $F.Severity.ToUpper() + ']').PadRight(9)
    Write-Host "  $tag" -ForegroundColor $script:SevColor[$F.Severity] -NoNewline
    if ($F.IsChange -and $F.Title -notmatch '^new ') { Write-Host 'NEW ' -ForegroundColor Magenta -NoNewline }
    Write-Host $F.Title -ForegroundColor White -NoNewline
    Write-Host "   (id $($F.Id))" -ForegroundColor DarkGray
    if (-not $Full) {
        foreach ($e in @($F.Evidence) | Select-Object -First 2) { Write-Wrapped $e 11 'DarkGray' }
        return
    }
    Write-Host "           Category: $($F.Category)" -ForegroundColor DarkGray
    foreach ($e in @($F.Evidence)) { Write-Wrapped $e 11 'Gray' '- ' }
    if ($F.Why) {
        Write-Host '           Why it matters:' -ForegroundColor DarkCyan
        Write-Wrapped $F.Why 13 'Gray'
    }
    $steps = @($F.Fix)
    if ($steps) {
        Write-Host '           What you can do (Sabel Threat Detection never changes anything itself):' -ForegroundColor DarkCyan
        $n = 0
        foreach ($s in $steps) { $n++; Write-Wrapped ($s -replace '<id>', $F.Id) 13 'Gray' "$n. " }
    }
    Write-Host ''
}

function Show-Report($Report, [switch]$Detailed) {
    $all = @($Report.Findings)
    $shown = @($all | Where-Object { -not $_.Trusted })
    $trustedCount = $all.Count - $shown.Count
    $alert = @(Get-AlertFindings $Report)
    $count = @{}; foreach ($s in 'High', 'Medium', 'Low', 'Info') { $count[$s] = @($shown | Where-Object Severity -eq $s).Count }
    $w = [Math]::Min((Get-ConsoleWidth), 100)

    Write-Host ''
    Write-Host ('  ' + ('=' * ($w - 4))) -ForegroundColor DarkCyan
    Write-Host '   SABEL THREAT DETECTION' -ForegroundColor Cyan -NoNewline
    Write-Host "  - read-only security check  v$($Report.Version)" -ForegroundColor DarkGray
    $rights = if ($Report.IsAdmin) { 'administrator (full coverage)' } else { 'standard user' }
    Write-Host "   $([datetime]$Report.Started)  |  $($Report.Computer)\$($Report.User)  |  $rights  |  $($Report.DurationSeconds)s" -ForegroundColor DarkGray
    Write-Host ('  ' + ('=' * ($w - 4))) -ForegroundColor DarkCyan
    Write-Host ''
    if ($alert.Count) {
        Write-Host "   RESULT: $($alert.Count) issue(s) need your attention" -ForegroundColor Red
    } else {
        Write-Host '   RESULT: All clear - nothing needs your attention' -ForegroundColor Green
    }
    Write-Host ("   High: {0}   Medium: {1}   Low: {2}   Info: {3}" -f $count.High, $count.Medium, $count.Low, $count.Info) -ForegroundColor Gray
    if ($Report.BaselineCreated) {
        Write-Host '   First scan: a baseline of your startup items, tasks, services, accounts and extensions was saved.' -ForegroundColor DarkCyan
        Write-Host '   From now on, anything NEW that appears will be pointed out.' -ForegroundColor DarkCyan
    }

    $groups = @(
        @('NEEDS ATTENTION', @($shown | Where-Object { $_.Severity -in 'High', 'Medium' }), $true),
        @('WORTH A LOOK', @($shown | Where-Object Severity -eq 'Low'), [bool]$Detailed),
        @('FOR YOUR INFORMATION', @($shown | Where-Object Severity -eq 'Info'), [bool]$Detailed)
    )
    foreach ($g in $groups) {
        if (-not $g[1].Count) { continue }
        Write-Host ''
        Write-Host "  -- $($g[0]) ($($g[1].Count)) " -ForegroundColor White
        Write-Host ''
        foreach ($f in $g[1]) { Show-Finding $f -Full:$g[2] }
    }
    if (@($Report.Skipped).Count) {
        Write-Host ''
        Write-Host '  -- NOT CHECKED' -ForegroundColor White
        foreach ($s in $Report.Skipped) { Write-Wrapped "$($s.Check): $($s.Reason)" 4 'DarkYellow' '- ' }
    }
    Write-Host ''
    if ($trustedCount) { Write-Host "  $trustedCount item(s) you marked as trusted are hidden (sabel trusted)." -ForegroundColor DarkGray }
    Write-Host '  sabel explain <id>   full details and advice for one item' -ForegroundColor DarkGray
    Write-Host '  sabel act <id>       ask Microsoft Defender to scan or remove it (asks you twice first)' -ForegroundColor DarkGray
    Write-Host '  sabel trust <id>     stop alerting about an item you recognise' -ForegroundColor DarkGray
    if (-not $Detailed) { Write-Host '  sabel report -Detailed   show full advice for every item' -ForegroundColor DarkGray }
    Write-Host ''
}

function Find-ReportItem([string]$Id) {
    $r = Get-LatestReport
    if (-not $r) { Write-Host '  No report yet. Run: sabel scan' -ForegroundColor Yellow; return $null }
    $hit = @($r.Findings | Where-Object { $_.Id -like "$Id*" })
    if ($hit.Count -ne 1) { Write-Host "  No single item with id '$Id' in the latest report." -ForegroundColor Yellow; return $null }
    return $hit[0]
}

function Set-SabelTrust([string]$Id, [switch]$Remove) {
    $list = @(Get-TrustedList)
    if ($Remove) {
        $new = @($list | Where-Object { $_.Id -notlike "$Id*" })
        if ($new.Count -eq $list.Count) { Write-Host "  '$Id' is not in the trusted list." -ForegroundColor Yellow; return }
        Save-TrustedList $new
        Write-Host '  Removed from the trusted list. It will be reported again.' -ForegroundColor Green
        return
    }
    $f = Find-ReportItem $Id
    if (-not $f) { return }
    if ($list | Where-Object Id -eq $f.Id) { Write-Host '  Already trusted.'; return }
    $list += [pscustomobject]@{ Id = $f.Id; Title = $f.Title; TrustedOn = (Get-Date).ToString('s') }
    Save-TrustedList $list
    Write-Host "  Trusted: $($f.Title)" -ForegroundColor Green
    Write-Host '  It will no longer trigger alerts. If the item changes (e.g. points to a different file) it gets a new id and is reported again.' -ForegroundColor DarkGray
}

function Show-TrustedList {
    $list = @(Get-TrustedList)
    if (-not $list) { Write-Host '  Nothing is marked as trusted.'; return }
    foreach ($t in $list) { Write-Host "  $($t.Id)  $($t.Title)  (since $($t.TrustedOn))" }
    Write-Host '  Remove one with: sabel untrust <id>' -ForegroundColor DarkGray
}

function Show-History {
    $files = @(Get-ChildItem -LiteralPath $script:ReportDir -Filter 'scan-*.json' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if (-not $files) { Write-Host '  No scans yet.'; return }
    Write-Host ''
    foreach ($f in $files | Select-Object -First 30) {
        try { $r = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        $a = @(Get-AlertFindings $r).Count
        $color = if ($a) { 'Yellow' } else { 'Green' }
        $state = if ($a) { "$a need attention" } else { 'all clear' }
        Write-Host ("  {0}   {1,-20} {2} findings total" -f ([datetime]$r.Started).ToString('yyyy-MM-dd HH:mm'), $state, @($r.Findings).Count) -ForegroundColor $color
    }
    Write-Host ''
}
