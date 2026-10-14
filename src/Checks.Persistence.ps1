# Checks the places malware uses to restart itself every time Windows boots or you log in
# (MITRE ATT&CK "Persistence": run keys, startup folder, scheduled tasks, services,
#  WMI subscriptions, IFEO/Winlogon hijacks, PowerShell profiles).

$script:AutoStartText = @{
    'Startup item'   = @{ Why = 'Programs in startup locations run automatically every time you log in. This is the most common way malware keeps itself running.'
                          Fix = 'To stop it from starting: Task Manager (Ctrl+Shift+Esc) > Startup apps > right-click it > Disable. Disabling is reversible, unlike deleting.' }
    'Scheduled task' = @{ Why = 'Scheduled tasks can silently run a program on a timer or at logon. Malware hides tasks here, sometimes with names that look like Microsoft ones.'
                          Fix = 'Open Task Scheduler (search Start), find the task at the path shown, look at its Actions tab, and right-click > Disable it if it is not something you recognise.' }
    'Service'        = @{ Why = 'Services run in the background with high privileges, often before you even log in. Malware that installs a service survives reboots.'
                          Fix = 'Press Win+R, type services.msc, open the service, and set Startup type to "Disabled" if it is not something you recognise (needs admin).' }
    'Driver'         = @{ Why = 'Drivers run inside the Windows kernel with total control of the PC. Rootkits install themselves as drivers.'
                          Fix = 'Look up the driver name and the company that made it. Unknown unsigned drivers should be checked with a "Microsoft Defender Offline scan".' }
}

# Shared reporting for anything that starts automatically.
function Add-AutoStartFinding {
    param([string]$Kind, [string]$Name, [string]$Where, [string]$CommandLine, [bool]$IsNew,
          [bool]$Disabled, [string[]]$ExtraReasons = @(), [string]$ExtraSeverity = 'Info', $Measure)
    $m = if ($Measure) { $Measure } else { Measure-AutoStart $CommandLine }
    $txt = $script:AutoStartText[$Kind]
    $kindLower = $Kind.ToLower()
    $key = "$Kind|$Where|$Name|$CommandLine"
    $ev = @("Where: $Where", "Runs: $CommandLine")
    $cmdRisk = @(Get-CommandLineRisk $CommandLine)

    # Case 1: points at a file that no longer exists and nothing else is odd -> harmless leftover.
    if (-not $m.Sig.Exists -and -not $cmdRisk -and $ExtraSeverity -eq 'Info' -and -not $m.Payload) {
        # Windows ships tasks/services for optional components that are not installed; ignore those.
        if ((Test-UnderWindows $m.Target) -or $Disabled) { return }
        Add-Finding -Severity Low -Category 'Startup & persistence' -Title "$Kind points to a missing file: $Name" -Evidence $ev -Key $key -IsChange:$IsNew `
            -Why "This $kindLower tries to start a file that does not exist, so it cannot run. It is usually left behind by uninstalled software. Occasionally it is what remains after antivirus removed a threat." `
            -Fix @("If you recognise the name, it is safe to ignore. To tidy up: $($txt.Fix)", 'If the name looks random or unfamiliar, run a Quick scan to make sure nothing else was left behind.', $script:FixIfYouTrust)
        return
    }

    $sev = Get-MaxSeverity $m.Severity $ExtraSeverity
    $reasons = @($ExtraReasons) + @($m.Reasons)
    if ($IsNew) {
        $reasons = @('it appeared since the last scan') + $reasons
        $newSev = if ($m.Sig.Status -eq 'Valid') { 'Info' } else { 'Medium' }
        $sev = Get-MaxSeverity $sev $newSev
    }
    if ($sev -eq 'Info' -and -not $IsNew) { return }
    if ($Disabled) {
        if (-not $IsNew -and $sev -eq 'Low') { return }
        if ($sev -ne 'Info') { $sev = Get-LowerSeverity $sev }
        $reasons += 'note: it is currently DISABLED, so it does not run right now'
    }
    if ($m.Target -and $m.Sig.Exists) { $ev += "File: $($m.Target) ($(Format-Signature $m.Sig))" }
    if ($m.Sig.Sha256) { $ev += "SHA256: $($m.Sig.Sha256)" }
    $ev += ($reasons | ForEach-Object { "Flag: $_" })

    # Case 2: only a configuration weakness (e.g. unquoted service path) on an otherwise normal, signed program.
    if ($m.Severity -eq 'Info' -and -not $IsNew -and $ExtraReasons -match 'unquoted') {
        Add-Finding -Severity $sev -Category 'System settings' -Title "Service with an unquoted path: $Name" -Evidence $ev -Key $key `
            -Why 'This is a configuration weakness, not malware. If a program with the right name were placed in one of the parent folders, Windows could start it with service privileges. Standard users cannot normally write to those folders, so the real risk is small.' `
            -Fix @('Update the software. Newer versions usually fix this.', 'An administrator can put quotes around the path in HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath (Sabel Threat Detection never edits the registry).', $script:FixIfYouTrust)
        return
    }

    $prefix = if ($IsNew -and $sev -eq 'Info') { "New $kindLower" }
              elseif ($sev -in 'High', 'Medium') { if ($IsNew) { "NEW suspicious $kindLower" } else { "Suspicious $kindLower" } }
              else { if ($IsNew) { "New $kindLower to review" } else { "$Kind to review" } }
    $fix = if ($sev -eq 'Info') { @('Nothing to do if you just installed or updated this software.', $txt.Fix) } else { @($script:FixCheckFile) + @($txt.Fix, $script:FixAutoruns, $script:FixIfYouTrust) }
    Add-Finding -Severity $sev -Category 'Startup & persistence' -Title "$($prefix): $Name" -Evidence $ev -Why $txt.Why -Fix $fix -Key $key -IsChange:$IsNew -Target $(if ($m.Payload) { $m.Payload } else { $m.Target })
}

function Test-RunKeys {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    Register-InventoryKind 'Autorun'
    foreach ($k in $keys) {
        $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $hive = $k.Substring(0, 4)
        $approvedKey = if ($k -match 'WOW6432Node') { 'Run32' } else { 'Run' }
        foreach ($name in $item.GetValueNames()) {
            if (-not $name) { continue }
            $cmd = [string]$item.GetValue($name)
            if (-not $cmd) { continue }
            $isNew = Add-InventoryItem 'Autorun' "$k|$name|$cmd" "$name -> $cmd"
            $approved = Get-RegValue "$($hive):\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$approvedKey" $name
            $disabled = ($approved -is [byte[]] -and $approved.Length -gt 0 -and ($approved[0] -band 1) -eq 1)
            $extra = @(); $extraSev = 'Info'
            if ($k -match 'Policies') { $extra += 'it uses the rarely-used Policies\Explorer\Run key, a known malware hiding spot'; $extraSev = 'Medium' }
            Add-AutoStartFinding -Kind 'Startup item' -Name $name -Where ($k -replace ':', '') -CommandLine $cmd -IsNew $isNew -Disabled $disabled -ExtraReasons $extra -ExtraSeverity $extraSev
        }
    }
    # Logon script hijack (T1037.001)
    $mpr = Get-RegValue 'HKCU:\Environment' 'UserInitMprLogonScript'
    if ($mpr) {
        Add-AutoStartFinding -Kind 'Startup item' -Name 'UserInitMprLogonScript' -Where 'HKCU\Environment' -CommandLine $mpr -IsNew $false -Disabled $false `
            -ExtraReasons @('a logon script is set in HKCU\Environment - rarely used by normal software') -ExtraSeverity 'Medium'
    }
}

function Test-StartupFolders {
    $folders = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) | Where-Object { $_ }
    $shell = New-Object -ComObject WScript.Shell
    Register-InventoryKind 'Autorun'
    foreach ($f in $folders) {
        foreach ($file in @(Get-ChildItem -LiteralPath $f -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            $ext = $file.Extension.ToLowerInvariant()
            $extra = @(); $extraSev = 'Info'
            if ($ext -eq '.lnk') {
                $lnk = $shell.CreateShortcut($file.FullName)   # read-only: never .Save()'d
                $cmd = if ($lnk.Arguments) { "`"$($lnk.TargetPath)`" $($lnk.Arguments)" } else { "`"$($lnk.TargetPath)`"" }
            } else {
                $cmd = "`"$($file.FullName)`""
                if ($ext -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.ps1', '.scr', '.pif') {
                    $extra += "a $ext script placed directly in the Startup folder"; $extraSev = 'Medium'
                    try {
                        $body = Get-Content -LiteralPath $file.FullName -TotalCount 400 -ErrorAction Stop | Out-String
                        foreach ($h in (Get-CommandLineRisk $body)) { $extra += "script content: $($h.Reason)"; $extraSev = Get-MaxSeverity $extraSev $h.Severity }
                    } catch { }
                }
            }
            $isNew = Add-InventoryItem 'Autorun' "$f|$($file.Name)|$cmd" "$($file.Name) -> $cmd"
            Add-AutoStartFinding -Kind 'Startup item' -Name $file.Name -Where $f -CommandLine $cmd -IsNew $isNew -Disabled $false -ExtraReasons $extra -ExtraSeverity $extraSev
        }
    }
}

function Test-ScheduledTasks {
    $self = (Join-Path $script:SabelRoot 'Sabel.ps1').ToLowerInvariant()
    Register-InventoryKind 'Task'
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        foreach ($a in @($t.Actions)) {
            if (-not $a.PSObject.Properties['Execute'] -or -not $a.Execute) { continue }   # COM-handler actions
            $exe = $a.Execute.Trim().Trim('"')
            $cmd = if ($a.Arguments) { "`"$exe`" $($a.Arguments)" } else { "`"$exe`"" }
            if ($t.TaskPath -eq '\Sabel_Threat_Detection\' -and $cmd.ToLowerInvariant().Contains($self)) { continue }
            $full = "$($t.TaskPath)$($t.TaskName)"
            $isNew = Add-InventoryItem 'Task' "$full|$cmd" $full
            $m = Measure-AutoStart $cmd
            # Microsoft's own tasks running Microsoft-signed programs are fine unless the command line itself is suspicious
            if ($t.TaskPath -like '\Microsoft\*' -and $m.Sig.IsMicrosoft -and -not $m.Payload -and -not (Get-CommandLineRisk $cmd | Where-Object Severity -eq 'High') -and -not $isNew) { continue }
            $extra = @(); $extraSev = 'Info'
            if ($t.Settings.Hidden -and $t.TaskPath -notlike '\Microsoft\*' -and $m.Sig.Status -ne 'Valid') { $extra += 'the task is marked as hidden'; $extraSev = 'Low' }
            if ($t.TaskPath -like '\Microsoft\*' -and $m.Sig.Exists -and -not $m.Sig.IsMicrosoft -and -not (Test-UnderWindows $m.Target)) {
                $extra += 'it sits in the \Microsoft\ task folder but runs a non-Microsoft program'; $extraSev = 'Medium'
            }
            Add-AutoStartFinding -Kind 'Scheduled task' -Name $full -Where "Task Scheduler $($t.TaskPath)" -CommandLine $cmd -IsNew $isNew `
                -Disabled ($t.State -eq 'Disabled') -ExtraReasons $extra -ExtraSeverity $extraSev -Measure $m
        }
    }
}

function Test-Services {
    Register-InventoryKind 'Service'
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
        if (-not $s.PathName) { continue }
        $isNew = Add-InventoryItem 'Service' "$($s.Name)|$($s.PathName)" "$($s.DisplayName) -> $($s.PathName)"
        $m = Measure-AutoStart $s.PathName
        if ($m.Sig.IsMicrosoft -and (Test-UnderWindows $m.Target) -and -not $isNew -and $m.Severity -eq 'Info') { continue }
        $extra = @(); $extraSev = 'Info'
        if ($s.PathName -notmatch '^\s*"' -and $s.PathName -match '^[a-zA-Z]:\\[^"]*\s[^"]*\.exe' -and -not (Test-UnderWindows $m.Target)) {
            $extra += 'unquoted path containing spaces - a known privilege-escalation weakness'
            $extraSev = 'Low'
        }
        $where = "Service '$($s.Name)' (start: $($s.StartMode), state: $($s.State))"
        Add-AutoStartFinding -Kind 'Service' -Name $s.DisplayName -Where $where -CommandLine $s.PathName -IsNew $isNew `
            -Disabled ($s.StartMode -eq 'Disabled') -ExtraReasons $extra -ExtraSeverity $extraSev -Measure $m
    }
}

function Test-Drivers {
    Register-InventoryKind 'Driver'
    foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)) {
        if (-not $d.PathName) { continue }
        $isNew = Add-InventoryItem 'Driver' "$($d.Name)|$($d.PathName)" "$($d.DisplayName) -> $($d.PathName)"
        # Only check signatures of new drivers or drivers outside the Windows folder (keeps the scan fast)
        if (-not $isNew -and (Test-UnderWindows $d.PathName)) { continue }
        $m = Measure-AutoStart $d.PathName
        if (-not $m.Sig.Exists -and $d.State -ne 'Running') { continue }
        Add-AutoStartFinding -Kind 'Driver' -Name $d.DisplayName -Where "Driver '$($d.Name)' (state: $($d.State))" -CommandLine $d.PathName -IsNew $isNew `
            -Disabled ($d.StartMode -eq 'Disabled') -Measure $m
    }
}

function Test-HijackPoints {
    $cat = 'Startup & persistence'
    $fixRegistry = @('Search the exact value online to see whether software you use is known to set it.', 'If not, treat the PC as infected: run a "Microsoft Defender Offline scan" and a second-opinion scanner (e.g. Malwarebytes, ESET Online Scanner).', 'After cleaning, an administrator can remove the value with regedit. Sabel Threat Detection never edits the registry.', $script:FixAutoruns)

    # Image File Execution Options: "Debugger" makes Windows launch something else instead of a program
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($sub in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $dbg = $sub.GetValue('Debugger')
            if ($dbg) {
                Add-Finding -Severity High -Category $cat -Title "Program launch hijack (IFEO Debugger) on $($sub.PSChildName)" -Evidence @("Key: $($sub.Name)", "Debugger = $dbg") `
                    -Why "Whenever $($sub.PSChildName) is started, Windows runs the 'debugger' program instead. Malware uses this to hijack programs or block antivirus from starting. Developer tools occasionally set it legitimately." `
                    -Fix $fixRegistry
            }
        }
    }
    foreach ($sub in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue)) {
        $mon = $sub.GetValue('MonitorProcess')
        if ($mon) {
            Add-Finding -Severity High -Category $cat -Title "Hidden launch trigger when $($sub.PSChildName) exits" -Evidence @("Key: $($sub.Name)", "MonitorProcess = $mon") `
                -Why 'Windows is told to start another program every time this one closes, a known stealthy persistence technique.' -Fix $fixRegistry
        }
    }

    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = [string](Get-RegValue $wl 'Shell')
    if ($shell -and $shell.Trim().TrimEnd(',').ToLowerInvariant() -notin 'explorer.exe', "$($env:windir.ToLowerInvariant())\explorer.exe") {
        Add-Finding -Severity High -Category $cat -Title 'The Windows desktop shell has been changed' -Evidence @("$wl\Shell = $shell") `
            -Why 'This value should be just "explorer.exe". Anything added here starts with your desktop at every logon.' -Fix $fixRegistry
    }
    $userShell = Get-RegValue 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell'
    if ($userShell) {
        Add-Finding -Severity High -Category $cat -Title 'A per-user desktop shell override is set' -Evidence @("HKCU\...\Winlogon\Shell = $userShell") `
            -Why 'Normal PCs do not have this value. It replaces or adds to the desktop program for your account.' -Fix $fixRegistry
    }
    $ui = [string](Get-RegValue $wl 'Userinit')
    $uiNorm = ($ui.Trim().TrimEnd(',')).ToLowerInvariant()
    if ($ui -and $uiNorm -notin "$($env:windir.ToLowerInvariant())\system32\userinit.exe", 'userinit.exe', 'c:\windows\system32\userinit.exe') {
        Add-Finding -Severity High -Category $cat -Title 'The Windows logon program (Userinit) has extra entries' -Evidence @("$wl\Userinit = $ui") `
            -Why 'This value should only contain userinit.exe. Extra programs listed here run at every logon.' -Fix $fixRegistry
    }

    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $dlls = Get-RegValue $k 'AppInit_DLLs'
        if ($dlls -and $dlls.Trim()) {
            $load = Get-RegValue $k 'LoadAppInit_DLLs'
            $sev = if ($load -eq 1) { 'High' } else { 'Low' }
            Add-Finding -Severity $sev -Category $cat -Title 'AppInit_DLLs are configured (DLL injected into programs)' -Evidence @("$k\AppInit_DLLs = $dlls", "LoadAppInit_DLLs = $load") `
                -Why 'AppInit_DLLs are loaded into almost every program that starts. This outdated feature is mostly abused by malware and adware.' -Fix $fixRegistry
        }
    }

    $boot = @(Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute') | Where-Object { $_ -and $_ -notmatch '^autocheck autochk \*$' }
    if ($boot) {
        Add-Finding -Severity Medium -Category $cat -Title 'Extra programs run during Windows boot (BootExecute)' -Evidence $boot `
            -Why 'BootExecute normally only contains the disk checker "autocheck autochk *". Some disk and antivirus tools add entries, but so do rootkits.' -Fix $fixRegistry
    }

    # Accessibility tools replaced (e.g. sticky keys -> cmd.exe) give a login-screen backdoor
    foreach ($n in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:windir\System32" $n
        if (-not (Test-File $p)) { continue }
        $orig = (Get-Item -LiteralPath $p).VersionInfo.OriginalFilename
        $sig = Get-FileSignatureInfo $p
        $swapped = $orig -and ($orig -replace '\.mui$', '') -match '^(cmd|powershell|explorer|taskmgr)\.exe$'
        if ($swapped -or -not $sig.IsMicrosoft) {
            Add-Finding -Severity High -Category $cat -Title "Accessibility tool $n has been replaced" -Evidence @("File: $p", "Original file name: $orig", (Format-Signature $sig)) `
                -Why 'Attackers replace accessibility tools (such as Sticky Keys) so they can open an admin command prompt from the lock screen without a password.' `
                -Fix @('Run "sfc /scannow" in an administrator terminal to restore the original Windows file.', 'Treat the PC as compromised: run a "Microsoft Defender Offline scan" and change your passwords.')
        }
    }
}

function Test-WmiPersistence {
    Register-InventoryKind 'WmiConsumer'
    try { $consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop) }
    catch { Add-Skipped 'WMI event subscriptions' 'Could not read root\subscription (needs administrator rights on some PCs).'; return }
    foreach ($c in $consumers) {
        $class = $c.CimClass.CimClassName
        $payload = switch ($class) {
            'CommandLineEventConsumer'  { (@($c.ExecutablePath, $c.CommandLineTemplate) | Where-Object { $_ }) -join ' ' }
            'ActiveScriptEventConsumer' { if ($c.ScriptFileName) { $c.ScriptFileName } else { ([string]$c.ScriptText).Substring(0, [Math]::Min(300, ([string]$c.ScriptText).Length)) } }
            default { '' }
        }
        $isNew = Add-InventoryItem 'WmiConsumer' "$class|$($c.Name)|$payload" "$($c.Name) ($class)"
        if ($c.Name -eq 'SCM Event Log Consumer' -and $class -eq 'NTEventLogEventConsumer') { continue }   # built into Windows
        if ($c.Name -eq 'BVTConsumer' -and $payload -match 'KernCap\.vbs') { continue }                    # legacy Windows default
        $sev = if ($class -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { 'High' } elseif ($isNew) { 'Medium' } else { 'Low' }
        Add-Finding -Severity $sev -Category 'Startup & persistence' -Title "WMI event subscription: $($c.Name) ($class)" -Evidence @("Payload: $payload") -Key "wmi|$class|$($c.Name)" -IsChange:$isNew `
            -Why 'WMI subscriptions can run commands automatically when something happens (a timer, logon, a program starting). They are invisible in Task Manager and are a favourite of "fileless" malware. A few management tools (Dell, HP, Lenovo, backup software) use them legitimately.' `
            -Fix @('Search the subscription name online together with your PC maker or installed software.', 'If unknown, run a "Microsoft Defender Offline scan" and Sysinternals Autoruns (WMI tab), which can show and remove it.', $script:FixIfYouTrust)
    }
}

function Test-PowerShellProfiles {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    $paths = @(
        "$docs\WindowsPowerShell\profile.ps1", "$docs\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$docs\PowerShell\profile.ps1", "$docs\PowerShell\Microsoft.PowerShell_profile.ps1",
        "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"
    )
    Register-InventoryKind 'PSProfile'
    foreach ($p in $paths) {
        if (-not (Test-File $p)) { continue }
        $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        $isNew = Add-InventoryItem 'PSProfile' "$p|$hash" $p
        $body = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
        $hits = @(Get-CommandLineRisk $body)
        $sev = 'Info'; foreach ($h in $hits) { $sev = Get-MaxSeverity $sev $h.Severity }
        if ($isNew) { $sev = Get-MaxSeverity $sev 'Low' }
        if ($sev -eq 'Info') { continue }
        $what = if ($isNew) { 'PowerShell profile created or changed' } else { 'Suspicious code in PowerShell profile' }
        Add-Finding -Severity $sev -Category 'Startup & persistence' -Title "$($what): $p" -Evidence (@("SHA256: $hash") + ($hits | ForEach-Object { "Flag: $($_.Reason)" })) -Key "psprofile|$p|$hash" -IsChange:$isNew -Target $p `
            -Why 'A PowerShell profile runs automatically every time PowerShell starts. Attackers add code here to re-infect a machine quietly.' `
            -Fix @("Open the file in Notepad (notepad `"$p`") and read what it does. If you did not write it, rename it to profile.ps1.bak and scan the PC.", $script:FixIfYouTrust)
    }
}
