# Registers/removes the daily scan in Windows Task Scheduler (the only system change the tool makes,
# and only when you ask for it with "sabel install").

$script:TaskName = 'Daily Scan'
$script:TaskPath = '\Sabel_Threat_Detection\'

function Install-SabelSchedule([string]$Time = '12:00', [switch]$Elevated) {
    if ($Elevated -and -not (Test-IsAdmin)) {
        Write-Host '  -Elevated needs an administrator terminal. Right-click Terminal > "Run as administrator" and run the command again.' -ForegroundColor Yellow
        return
    }
    try { $at = [datetime]::ParseExact($Time, 'HH:mm', $null) } catch {
        Write-Host "  Time must look like 09:30 or 18:00 (24-hour clock). Got: $Time" -ForegroundColor Yellow; return
    }
    $ps = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    $script = Join-Path $script:SabelRoot 'Sabel.ps1'
    $arg = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" scan -Scheduled"
    $action = New-ScheduledTaskAction -Execute $ps -Argument $arg -WorkingDirectory $script:SabelRoot
    $trigger = New-ScheduledTaskTrigger -Daily -At $at
    # StartWhenAvailable: if the PC was off/asleep at scan time, run as soon as it is back on.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
    $level = if ($Elevated) { 'Highest' } else { 'Limited' }
    # Interactive logon = runs in your session, so the alert tune and notification reach you.
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel $level
    Register-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal -Description 'Sabel Threat Detection read-only daily security check. Plays a tune if it finds something. Remove with: sabel uninstall' -Force | Out-Null
    Write-Host "  Daily scan scheduled at $($at.ToString('HH:mm')) ($(if ($Elevated) {'with admin rights - full coverage'} else {'standard rights'}))." -ForegroundColor Green
    Write-Host '  If the PC is off at that time, the scan runs as soon as it is next turned on.'
    Write-Host '  Check it with:  sabel status      Remove it with:  sabel uninstall'
}

function Uninstall-SabelSchedule {
    $t = Get-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
    if (-not $t) { Write-Host '  No daily scan is scheduled.'; return }
    try {
        Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -Confirm:$false -ErrorAction Stop
        Write-Host '  Daily scan removed. Your reports are still in:' $script:DataDir -ForegroundColor Green
    } catch {
        Write-Host '  Could not remove the task (an elevated task needs an administrator terminal to remove).' -ForegroundColor Yellow
    }
}

function Show-SabelStatus {
    $t = Get-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
    Write-Host ''
    if ($t) {
        $i = $t | Get-ScheduledTaskInfo
        Write-Host '  Daily scan : ' -NoNewline; Write-Host 'INSTALLED' -ForegroundColor Green
        Write-Host "  Runs at    : $(([datetime]$t.Triggers[0].StartBoundary).ToString('HH:mm')) every day  (rights: $($t.Principal.RunLevel))"
        if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { Write-Host "  Last run   : $($i.LastRunTime)  (result code $($i.LastTaskResult))" }
        Write-Host "  Next run   : $($i.NextRunTime)"
    } else {
        Write-Host '  Daily scan : ' -NoNewline; Write-Host 'not installed' -ForegroundColor Yellow -NoNewline; Write-Host '   (run: sabel install)'
    }
    $latest = Get-LatestReportFile
    if ($latest) { Write-Host "  Last report: $($latest.LastWriteTime)  ($($latest.FullName))" }
    Write-Host "  Data folder: $script:DataDir"
    Write-Host ''
}
