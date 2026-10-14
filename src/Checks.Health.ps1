# Checks for "bugs": failing disks, crashes, low space, pending restarts.

function Test-DiskSpace {
    $cat = 'System health'
    foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        if (-not $d.Size) { continue }
        $freeGB = [Math]::Round($d.FreeSpace / 1GB, 1)
        $pct = [Math]::Round(100 * $d.FreeSpace / $d.Size, 1)
        $sev = if ($freeGB -lt 5 -or $pct -lt 5) { 'Medium' } elseif ($pct -lt 10) { 'Low' } else { $null }
        if ($sev) {
            Add-Finding -Severity $sev -Category $cat -Title "Drive $($d.DeviceID) is almost full ($freeGB GB / $pct% free)" -Key "disk|$($d.DeviceID)" `
                -Why 'When the system drive is nearly full, Windows updates fail, programs crash and the PC slows down. A sudden drop in free space can also come from runaway logs or unwanted software.' `
                -Fix @('Open Settings > System > Storage and run "Cleanup recommendations".', 'Empty the Recycle Bin and uninstall programs you no longer use (Settings > Apps > Installed apps).', 'Use "Storage Sense" to clean temporary files automatically.')
        }
    }
}

function Test-DiskHealth {
    $cat = 'System health'
    foreach ($pd in @(Get-PhysicalDisk -ErrorAction Stop)) {
        if ($pd.HealthStatus -and $pd.HealthStatus -ne 'Healthy') {
            Add-Finding -Severity High -Category $cat -Title "Disk '$($pd.FriendlyName)' reports health: $($pd.HealthStatus)" -Evidence @("Operational status: $($pd.OperationalStatus)", "Media: $($pd.MediaType)") -Key "pdisk|$($pd.FriendlyName)" `
                -Why 'The drive itself says it is failing or degraded. Drives in this state can stop working without further warning.' `
                -Fix @('BACK UP YOUR FILES NOW to an external drive or cloud storage.', 'Check the drive with your manufacturer''s tool (Samsung Magician, WD Dashboard, Crucial Storage Executive, etc.) or CrystalDiskInfo.', 'Plan to replace the drive.')
        }
    }
    $since = (Get-Date).AddDays(-7)
    $events = Get-RecentEvents @{ LogName = 'System'; ProviderName = 'disk', 'Ntfs', 'stornvme', 'storahci'; Id = 7, 11, 51, 55, 153; StartTime = $since } 200
    if ($events) {
        $g = $events | Group-Object ProviderName, Id | ForEach-Object { "$($_.Count) x $($_.Name) (last: $(($_.Group | Select-Object -First 1).TimeCreated))" }
        $bad = $events | Where-Object { $_.Id -in 7, 55, 11 }
        $sev = if ($bad) { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category $cat -Title "Disk errors were logged in the last 7 days ($($events.Count) events)" -Evidence $g -Key 'disk-errors' `
            -Why 'Bad blocks (event 7), file-system corruption (Ntfs 55) and I/O retries (153) are early warnings of a failing drive or loose cable.' `
            -Fix @('Back up important files first.', 'Check the drive''s SMART status with your manufacturer''s tool or CrystalDiskInfo.', 'In an administrator terminal you can run:  chkdsk C: /scan   (read-only online check; you decide whether to run it).')
    }
}

function Test-Crashes {
    $cat = 'System health'
    $since = (Get-Date).AddDays(-14)
    $bsod = Get-RecentEvents @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since } 50
    if ($bsod) {
        $ev = $bsod | Select-Object -First 5 | ForEach-Object { "$($_.TimeCreated): $(($_.Message -split "`n")[0])" }
        Add-Finding -Severity Medium -Category $cat -Title "Windows crashed (blue screen) $($bsod.Count) time(s) in the last 14 days" -Evidence $ev -Key 'bsod' `
            -Why 'Blue screens usually come from faulty drivers, failing hardware (RAM, disk) or overheating. Rarely, rootkits cause them too.' `
            -Fix @('Install pending Windows and driver updates (Settings > Windows Update > Advanced options > Optional updates).', 'Look up the "bugcheck" code shown above online to see which driver is usually responsible.', 'Test your memory: search Start for "Windows Memory Diagnostic".')
    }
    $power = Get-RecentEvents @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = (Get-Date).AddDays(-7) } 50
    if ($power.Count -ge 2) {
        Add-Finding -Severity Low -Category $cat -Title "The PC shut down unexpectedly $($power.Count) times in the last 7 days" -Key 'kernel-power' `
            -Why 'Event 41 means Windows did not shut down cleanly: power loss, holding the power button, a freeze or overheating.' `
            -Fix @('If this was not you holding the power button, check that vents are not blocked and fans work.', 'Update drivers and BIOS from your PC maker''s website.')
    }
    $apps = Get-RecentEvents @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = (Get-Date).AddDays(-7) } 500
    $top = $apps | Group-Object { $_.Properties[0].Value } | Where-Object Count -ge 5 | Sort-Object Count -Descending
    if ($top) {
        Add-Finding -Severity Low -Category $cat -Title "$(@($top).Count) program(s) crashed 5+ times this week" -Evidence ($top | ForEach-Object { "$($_.Name): $($_.Count) crashes" }) -Key 'app-crashes' `
            -Why 'Repeated crashes usually mean a bug or a corrupted install. A security program crashing repeatedly can also mean something is interfering with it.' `
            -Fix @('Update the program, or repair/reinstall it from Settings > Apps > Installed apps.', 'Details are in Event Viewer > Windows Logs > Application (source "Application Error").')
    }
}

function Test-PendingRestart {
    $cat = 'System health'
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update is waiting for a restart' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Windows component servicing is waiting for a restart' }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $days = [int]((Get-Date) - $boot).TotalDays
    if ($reasons -and $days -ge 3) {
        Add-Finding -Severity Low -Category $cat -Title "A restart is needed to finish installing updates (up for $days days)" -Evidence $reasons -Key 'pending-restart' `
            -Why 'Security updates are not active until the PC restarts.' `
            -Fix @('Save your work and restart the PC (Start > Power > Update and restart).')
    }
}
