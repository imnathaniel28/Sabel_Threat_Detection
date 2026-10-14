# Checks that your built-in protections (antivirus, firewall, UAC, updates) are working.

function Test-Antivirus {
    $cat = 'Antivirus'
    $others = @()
    try {
        foreach ($p in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)) {
            # productState: middle byte 0x10/0x11 = enabled; low byte 0x10 = definitions out of date
            $state = [int]$p.productState
            $enabled  = (($state -shr 8) -band 0x10) -ne 0
            $outdated = ($state -band 0xFF) -eq 0x10
            if ($enabled -and $p.displayName -notmatch 'Defender') { $others += $p.displayName }
            if ($enabled -and $outdated) {
                Add-Finding -Severity Medium -Category $cat -Title "$($p.displayName) reports out-of-date virus definitions" `
                    -Why 'Antivirus software can only recognise threats it has definitions for. Old definitions miss new malware.' `
                    -Fix @("Open $($p.displayName) and run its 'Update' option.", 'Make sure the PC is connected to the internet and restart if the update fails.')
            }
        }
    } catch { }

    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }

    if (-not $mp -or -not $mp.AntivirusEnabled -or -not $mp.AMServiceEnabled) {
        if ($others) {
            Add-Finding -Severity Info -Category $cat -Title "Antivirus provided by: $($others -join ', ')" `
                -Why 'Microsoft Defender steps aside when another antivirus is installed. That is normal.' `
                -Fix @('Keep that product updated and its subscription active. If it expires, uninstall it so Microsoft Defender turns back on automatically.')
        } else {
            Add-Finding -Severity High -Category $cat -Title 'No active antivirus protection was found' `
                -Evidence @('Microsoft Defender is not running and no other antivirus is registered with Windows Security.') `
                -Why 'Without antivirus, malware can run with nothing to stop it. Some malware turns Defender off as its first step.' `
                -Fix @('Open Windows Security > Virus & threat protection and click "Turn on".', 'If it turns itself off again, that is a strong sign of infection: run "Microsoft Defender Offline scan" from Scan options, or boot a rescue disk from a trusted vendor.', 'If you use another antivirus, check that it is installed and its licence is active.')
        }
    } else {
        if (-not $mp.RealTimeProtectionEnabled) {
            Add-Finding -Severity High -Category $cat -Title 'Microsoft Defender real-time protection is OFF' `
                -Why 'Real-time protection checks files as they are downloaded or opened. With it off, malware is only caught by a manual scan.' `
                -Fix @('Open Windows Security > Virus & threat protection > Manage settings and turn "Real-time protection" on.', 'If you did not turn it off yourself (or it keeps turning off), run a "Microsoft Defender Offline scan".')
        }
        if ($mp.BehaviorMonitorEnabled -eq $false) {
            Add-Finding -Severity Medium -Category $cat -Title 'Defender behaviour monitoring is off' `
                -Why 'Behaviour monitoring catches malware by what it does, even when it is brand new and has no signature yet.' `
                -Fix @('Turn real-time protection off and on again in Windows Security, or check for a group policy that disables it (see other findings).')
        }
        if ($mp.AntivirusSignatureAge -ge 7 -and $mp.AntivirusSignatureAge -lt 10000) {
            Add-Finding -Severity Medium -Category $cat -Title "Virus definitions are $($mp.AntivirusSignatureAge) days old" `
                -Evidence @("Last updated: $($mp.AntivirusSignatureLastUpdated)") `
                -Why 'Definitions normally update several times a day. Old ones miss recent threats; malware sometimes blocks updates on purpose.' `
                -Fix @('Open Windows Security > Virus & threat protection > Protection updates > "Check for updates".', 'If updating fails repeatedly, run Windows Update and check that your internet connection and date/time are correct.')
        }
        if ($mp.IsTamperProtected -eq $false) {
            Add-Finding -Severity Medium -Category $cat -Title 'Tamper Protection is off' `
                -Why 'Tamper Protection stops malicious programs from switching Defender off behind your back.' `
                -Fix @('Open Windows Security > Virus & threat protection > Manage settings and turn on "Tamper Protection".')
        }
        $ages = @($mp.QuickScanAge, $mp.FullScanAge) | Where-Object { $_ -lt 10000 }
        $last = if ($ages) { ($ages | Measure-Object -Minimum).Minimum } else { $null }
        if ($null -eq $last -or $last -ge 14) {
            $txt = if ($null -eq $last) { 'No antivirus scan has ever completed' } else { "Last antivirus scan was $last days ago" }
            Add-Finding -Severity Low -Category $cat -Title $txt -Key 'scan-age' `
                -Why 'Windows normally runs a quick scan by itself when the PC is idle. If it never gets to, files already on disk are not re-checked with new definitions.' `
                -Fix @('Open Windows Security > Virus & threat protection and click "Quick scan".', 'Leaving the PC on (but idle) for a while lets Windows run its maintenance scans.')
        }
    }

    # Group-policy switches that malware (and "debloat" scripts) use to disable Defender
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $flags = @(
        @($pol, 'DisableAntiSpyware'), @($pol, 'DisableAntiVirus'),
        @("$pol\Real-Time Protection", 'DisableRealtimeMonitoring'), @("$pol\Real-Time Protection", 'DisableBehaviorMonitoring'),
        @("$pol\Real-Time Protection", 'DisableIOAVProtection'), @("$pol\Real-Time Protection", 'DisableOnAccessProtection')
    )
    $set = @()
    foreach ($f in $flags) { if ((Get-RegValue $f[0] $f[1]) -eq 1) { $set += "$($f[0])\$($f[1]) = 1" } }
    if ($set) {
        Add-Finding -Severity High -Category $cat -Title 'A policy is forcing parts of Microsoft Defender off' -Evidence $set `
            -Why 'Home PCs normally have no Defender policies. Malware often writes these values so Defender cannot be turned back on. Some "Windows tweak/debloat" tools do it too.' `
            -Fix @('If you did not run a tweak/debloat tool, treat this PC as possibly infected: run a "Microsoft Defender Offline scan" or a second-opinion scanner such as Malwarebytes or ESET Online Scanner.', 'An administrator can then delete these values with regedit (Sabel Threat Detection never edits the registry itself).')
    }
}

function Test-DefenderThreats {
    $cat = 'Antivirus'
    $detections = @(Get-MpThreatDetection -ErrorAction Stop)
    $names = @{}
    foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $names[[string]$t.ThreatID] = $t }
    $cutoff = (Get-Date).AddDays(-30)
    foreach ($d in $detections) {
        if ($d.InitialDetectionTime -lt $cutoff) { continue }
        $t = $names[[string]$d.ThreatID]
        $name = if ($t) { $t.ThreatName } else { "Threat ID $($d.ThreatID)" }
        $files = @($d.Resources | ForEach-Object { $_ -replace '^[a-z]+:_', '' })
        $status = [int]$d.ThreatStatusID
        $ev = @("Detected: $($d.InitialDetectionTime)  Status code: $status") + ($files | Select-Object -First 6 | ForEach-Object { "Item: $_" })
        if (($t -and $t.IsActive) -or $status -eq 1 -or $status -ge 100) {
            Add-Finding -Severity High -Category $cat -Title "Threat NOT fully removed: $name" -Evidence $ev -Key "threat|$($d.DetectionID)" -Target ($files | Select-Object -First 1) `
                -Why 'Microsoft Defender found this threat but could not quarantine or remove it, so it may still be active.' `
                -Fix @('Open Windows Security > Virus & threat protection > Protection history and choose the recommended action for this item.', 'Run a "Microsoft Defender Offline scan" (Scan options), which cleans threats that hide while Windows is running.', 'Change important passwords from a different, clean device if the threat is a password stealer or remote-access tool.')
        } elseif ($status -eq 5) {
            Add-Finding -Severity Medium -Category $cat -Title "A detected threat was ALLOWED to run: $name" -Evidence $ev -Key "threat|$($d.DetectionID)" -Target ($files | Select-Object -First 1) `
                -Why 'Someone chose "Allow on device" for this detection, so Defender now ignores it.' `
                -Fix @('If you did not allow it on purpose, open Windows Security > Protection history > Allowed threats, remove it from the allowed list, and scan again.')
        } else {
            Add-Finding -Severity Low -Category $cat -Title "Defender blocked or removed: $name" -Evidence $ev -Key "threat|$($d.DetectionID)" `
                -Why 'Defender handled this one, but it tells you something malicious reached the PC.' `
                -Fix @('Look at the file path to see where it came from (a download, USB stick, email attachment...) and avoid that source.', 'Run a Quick scan to confirm nothing else is left behind.')
        }
    }
}

function Test-DefenderExclusions {
    $cat = 'Antivirus'
    $pref = Get-MpPreference -ErrorAction Stop
    if ($pref.PUAProtection -eq 0) {
        Add-Finding -Severity Low -Category $cat -Title 'Protection against unwanted apps (adware, bundleware) is off' `
            -Why 'Potentially Unwanted App (PUA) blocking stops adware, browser hijackers, fake optimisers and bundled toolbars.' `
            -Fix @('Open Windows Security > App & browser control > Reputation-based protection settings and turn on "Potentially unwanted app blocking".')
    }
    $all = @()
    foreach ($x in @($pref.ExclusionPath))      { if ($x) { $all += [pscustomobject]@{ Type = 'Folder/file'; Value = $x } } }
    foreach ($x in @($pref.ExclusionProcess))   { if ($x) { $all += [pscustomobject]@{ Type = 'Process'; Value = $x } } }
    foreach ($x in @($pref.ExclusionExtension)) { if ($x) { $all += [pscustomobject]@{ Type = 'Extension'; Value = $x } } }
    if ($all | Where-Object { $_.Value -like 'N/A*' }) {
        Add-Skipped 'Defender exclusions' 'Windows only shows the exclusion list to administrators. Run as admin, or install the daily schedule with -Elevated.'
        return
    }
    Register-InventoryKind 'DefenderExclusion'
    $plain = @()
    foreach ($e in $all) {
        $v = $e.Value.ToLowerInvariant()
        $isNew = Add-InventoryItem 'DefenderExclusion' "$($e.Type)|$v" "$($e.Type): $($e.Value)"
        $risky = ($v -match '^[a-z]:\\?$') -or ($v -match '\\(users|windows|programdata|program files( \(x86\))?)\\?$') -or
                 ($v -match '\\(temp|tmp|downloads|appdata|public|desktop)(\\|$)') -or
                 ($e.Type -eq 'Extension' -and $v.TrimStart('.') -in @('exe','dll','ps1','bat','cmd','vbs','js','scr','hta','msi','lnk')) -or
                 ($e.Type -eq 'Process' -and $v -match '(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|explorer|svchost)(\.exe)?$')
        if ($risky -or $isNew) {
            $sev = if ($risky) { 'High' } else { 'Medium' }
            $what = if ($isNew) { 'NEW antivirus exclusion' } else { 'Dangerous antivirus exclusion' }
            Add-Finding -Severity $sev -Category $cat -Title "$($what): $($e.Value)" -Evidence @("Type: $($e.Type)") -Key "excl|$($e.Type)|$v" -IsChange:$isNew `
                -Why 'Defender never scans anything that is excluded. Adding exclusions is one of the first things malware does, and broad exclusions (a whole drive, Temp, AppData, .exe files) leave huge blind spots.' `
                -Fix @('If you did not add this yourself, remove it: Windows Security > Virus & threat protection > Manage settings > Exclusions > Add or remove exclusions.', 'Then run a Full scan, since whatever sat in the excluded location was never checked.', $script:FixIfYouTrust)
        } else { $plain += "$($e.Type): $($e.Value)" }
    }
    if ($plain) {
        Add-Finding -Severity Info -Category $cat -Title "$($plain.Count) antivirus exclusion(s) configured" -Evidence $plain -Key 'excl-list' `
            -Why 'Exclusions are sometimes needed (games, developer folders), but everything in them goes unscanned.' `
            -Fix @('Review the list in Windows Security > Virus & threat protection > Manage settings > Exclusions and remove any you no longer need.')
    }
}

function Test-Firewall {
    $cat = 'Firewall'
    $thirdParty = @()
    try {
        foreach ($p in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop)) {
            if ((([int]$p.productState -shr 8) -band 0x10) -ne 0) { $thirdParty += $p.displayName }
        }
    } catch { }
    foreach ($prof in @(Get-NetFirewallProfile -ErrorAction Stop)) {
        if (-not $prof.Enabled) {
            if ($thirdParty) {
                Add-Finding -Severity Info -Category $cat -Title "Windows Firewall ($($prof.Name)) is off; $($thirdParty -join ', ') is managing the firewall" -Key "fw|$($prof.Name)" `
                    -Why 'This is normal when a security suite provides its own firewall.' -Fix @('Keep that product active and updated.')
            } else {
                $sev = if ($prof.Name -eq 'Public') { 'High' } else { 'Medium' }
                Add-Finding -Severity $sev -Category $cat -Title "Windows Firewall is OFF for $($prof.Name) networks" -Key "fw|$($prof.Name)" `
                    -Why 'The firewall blocks other devices on the network (or the internet) from connecting to services on your PC. Public networks such as cafes and hotels are the riskiest.' `
                    -Fix @('Open Windows Security > Firewall & network protection and turn the firewall on for this network type.', 'If it turns off again without your action, scan the PC for malware.')
            }
        } elseif ($prof.DefaultInboundAction -eq 'Allow') {
            Add-Finding -Severity Medium -Category $cat -Title "Firewall ($($prof.Name)) allows ALL incoming connections by default" -Key "fwin|$($prof.Name)" `
                -Why 'The normal setting blocks unsolicited incoming connections. "Allow" means the firewall is on but barely protecting you.' `
                -Fix @('Open Windows Security > Firewall & network protection > "Restore firewalls to default", or set Inbound connections to "Block" in "Windows Defender Firewall with Advanced Security" > Properties.')
        }
    }
}

function Test-Uac {
    $cat = 'System settings'
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ((Get-RegValue $k 'EnableLUA') -eq 0) {
        Add-Finding -Severity High -Category $cat -Title 'User Account Control (UAC) is disabled' `
            -Why 'UAC is the "Do you want to allow this app to make changes?" prompt. Without it, any program you run gets full admin power silently.' `
            -Fix @('Search Start for "Change User Account Control settings" and move the slider to the default (second from top). Restart the PC.')
    } elseif ((Get-RegValue $k 'ConsentPromptBehaviorAdmin') -eq 0) {
        Add-Finding -Severity Medium -Category $cat -Title 'UAC never asks before programs get admin rights' `
            -Why 'Programs can elevate to administrator without any prompt, so malware gains full control of the system silently.' `
            -Fix @('Search Start for "Change User Account Control settings" and move the slider back to the default (second from top).')
    } elseif ((Get-RegValue $k 'PromptOnSecureDesktop') -eq 0) {
        Add-Finding -Severity Low -Category $cat -Title 'UAC prompts are not shown on the secure desktop' `
            -Why 'The dimmed "secure desktop" stops other programs from clicking "Yes" on the prompt for you.' `
            -Fix @('Set the UAC slider back to the default level (second from top).')
    }
}

function Test-WindowsUpdate {
    $cat = 'Updates'
    $svc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartMode -eq 'Disabled') {
        Add-Finding -Severity High -Category $cat -Title 'The Windows Update service is disabled' `
            -Why 'With Windows Update disabled, security holes are never patched. Some malware disables it on purpose to stay effective.' `
            -Fix @('Press Win+R, type services.msc, open "Windows Update", set Startup type to "Manual" and click Start.', 'Then go to Settings > Windows Update and click "Check for updates".')
    }
    $pause = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
    if ($pause) {
        try {
            $until = [datetime]::Parse($pause, [Globalization.CultureInfo]::InvariantCulture)
            if ($until -gt (Get-Date)) {
                Add-Finding -Severity Low -Category $cat -Title "Windows updates are paused until $($until.ToString('yyyy-MM-dd'))" -Key 'paused' `
                    -Why 'While paused, security fixes are not installed.' `
                    -Fix @('Go to Settings > Windows Update and click "Resume updates" when you can.')
            }
        } catch { }
    }
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    $lastOk = $null; $failed = @{}
    if ($count -gt 0) {
        foreach ($h in $searcher.QueryHistory(0, [Math]::Min($count, 200))) {
            if ($h.Operation -ne 1) { continue }
            if ($h.ResultCode -eq 2 -and ($null -eq $lastOk -or $h.Date -gt $lastOk)) { $lastOk = $h.Date }
            if ($h.ResultCode -in 4, 5 -and $h.Date -gt (Get-Date).AddDays(-30)) { $failed[$h.Title] = 1 + [int]$failed[$h.Title] }
        }
    }
    if ($null -eq $lastOk -or $lastOk -lt (Get-Date).AddDays(-40)) {
        $txt = if ($lastOk) { "No Windows updates installed for $([int]((Get-Date) - $lastOk).TotalDays) days" } else { 'No successful Windows update found in the update history' }
        Add-Finding -Severity Medium -Category $cat -Title $txt -Key 'update-age' `
            -Why 'Microsoft releases security fixes every month (second Tuesday). A PC that falls behind is exposed to publicly known attacks.' `
            -Fix @('Open Settings > Windows Update and click "Check for updates", then install and restart.', 'If updates keep failing, run Settings > System > Troubleshoot > Other troubleshooters > Windows Update.')
    }
    $repeat = @($failed.Keys | Where-Object { $failed[$_] -ge 2 })
    if ($repeat) {
        Add-Finding -Severity Low -Category $cat -Title "$($repeat.Count) update(s) failed repeatedly in the last 30 days" -Evidence $repeat -Key 'update-fail' `
            -Why 'An update that keeps failing leaves its fix uninstalled and can point to a damaged Windows component.' `
            -Fix @('Run Settings > System > Troubleshoot > Other troubleshooters > Windows Update.', 'Then, in an admin terminal: "DISM /Online /Cleanup-Image /RestoreHealth" followed by "sfc /scannow" (these repair Windows files; run them yourself if you choose to).')
    }
}

function Test-WindowsSupport {
    $cat = 'Updates'
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int](Get-RegValue $cv 'CurrentBuildNumber')
    $display = Get-RegValue $cv 'DisplayVersion'
    $edition = Get-RegValue $cv 'EditionID'
    # End of security updates for Home/Pro editions (Microsoft lifecycle policy)
    $eos = @{ 19045 = '2025-10-14'; 22000 = '2023-10-10'; 22621 = '2024-10-08'; 22631 = '2025-11-11'; 26100 = '2026-10-13'; 26200 = '2027-10-12' }
    $name = if ($build -lt 22000) { "Windows 10 $display" } else { "Windows 11 $display" }
    if ($build -lt 19045) { $end = [datetime]'2023-06-13' }
    elseif ($eos.ContainsKey($build)) { $end = [datetime]$eos[$build] }
    else { return }
    if ($edition -match 'Enterprise|Education') { $end = $end.AddYears(1) }
    $days = [int]($end - (Get-Date)).TotalDays
    if ($days -lt 0) {
        $sev = if ($build -lt 22000 -and $days -gt -1100) { 'Medium' } else { 'High' }
        $extra = if ($build -lt 22000) { ' (unless enrolled in Extended Security Updates)' } else { '' }
        Add-Finding -Severity $sev -Category $cat -Title "$name no longer receives security updates$extra" -Evidence @("Build $build, $edition edition, support ended $($end.ToString('yyyy-MM-dd'))") -Key 'eos' `
            -Why 'After end of support, newly discovered security holes are never fixed on this version.' `
            -Fix @('Open Settings > Windows Update. If a feature update to the latest version is offered, install it.', 'If your hardware cannot run Windows 11, look at Microsoft''s Extended Security Updates (ESU) program.')
    } elseif ($days -le 60) {
        Add-Finding -Severity Low -Category $cat -Title "$name stops receiving security updates in $days days" -Evidence @("Build $build, $edition edition, support ends $($end.ToString('yyyy-MM-dd'))") -Key 'eos' `
            -Why 'After that date this version gets no more security fixes.' `
            -Fix @('Open Settings > Windows Update and install the newest feature update when offered (Home/Pro PCs are usually upgraded automatically).')
    }
}

function Test-NetworkExposure {
    $cat = 'System settings'
    $smb1 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
    $smb1Server = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    if (($null -ne $smb1 -and $smb1 -ne 4) -or $smb1Server -eq 1) {
        Add-Finding -Severity Medium -Category $cat -Title 'The outdated SMBv1 file-sharing protocol is enabled' `
            -Why 'SMBv1 is the 30-year-old protocol exploited by the WannaCry and NotPetya ransomware outbreaks. Modern Windows does not need it.' `
            -Fix @('Search Start for "Turn Windows features on or off", untick "SMB 1.0/CIFS File Sharing Support", click OK and restart.')
    }
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -eq 0 -and (Get-Service TermService -ErrorAction SilentlyContinue)) {
        $nla = Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
        $sev = if ($nla -eq 0) { 'Medium' } else { 'Low' }
        $ev = if ($nla -eq 0) { @('Network Level Authentication is OFF') } else { @() }
        Add-Finding -Severity $sev -Category $cat -Title 'Remote Desktop is turned on' -Evidence $ev `
            -Why 'Remote Desktop lets people log in to this PC over the network. It is a very common target for password-guessing and ransomware gangs.' `
            -Fix @('If you do not use it: Settings > System > Remote Desktop > turn it Off.', 'If you do: use a strong password and keep "Require devices to use Network Level Authentication" ticked.', $script:FixIfYouTrust)
    }
    $sb = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    if ($sb -eq 0) {
        Add-Finding -Severity Low -Category $cat -Title 'Secure Boot is turned off' `
            -Why 'Secure Boot stops "bootkits" (malware that loads before Windows) from starting.' `
            -Fix @('Secure Boot is enabled in the PC''s UEFI/BIOS setup (Settings > System > Recovery > Advanced startup > UEFI Firmware Settings). Check your PC maker''s instructions first.')
    }
}
