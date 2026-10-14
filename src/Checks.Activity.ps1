# Checks what is running right now, network settings, accounts and browser add-ons.

$script:SystemProcessNames = @(
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe',
    'explorer.exe', 'taskhostw.exe', 'spoolsv.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe',
    'runtimebroker.exe', 'sihost.exe', 'ctfmon.exe', 'fontdrvhost.exe', 'dwm.exe', 'searchindexer.exe',
    'audiodg.exe', 'wuauclt.exe', 'msmpeng.exe', 'lsaiso.exe', 'taskmgr.exe', 'regsvr32.exe'
)

function Test-RunningProcesses {
    $cat = 'Running programs'
    $winDirs = @($env:windir, "$env:ProgramData\Microsoft\Windows Defender", "$env:ProgramFiles\Windows Defender") | ForEach-Object { $_.ToLowerInvariant() + '\' }
    $seen = @{}
    $noPath = 0
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        if ($p.ProcessId -eq $PID) { continue }
        $name = ([string]$p.Name).ToLowerInvariant()
        $path = $p.ExecutablePath
        if (-not $path) { $noPath++; continue }
        $lp = $path.ToLowerInvariant()

        # Command-line tricks (only visible for your own processes without admin)
        if ($p.CommandLine) {
            $strong = @(Get-CommandLineRisk $p.CommandLine | Where-Object Severity -eq 'High')
            if ($strong) {
                Add-Finding -Severity High -Category $cat -Title "Running process uses an attacker technique: $($p.Name) (PID $($p.ProcessId))" `
                    -Evidence (@("Path: $path", "Command line: $($p.CommandLine)") + ($strong | ForEach-Object { "Flag: $($_.Reason)" })) -Key "proccmd|$lp|$($p.CommandLine)" `
                    -Why 'Encoded or download-and-run commands are rarely used by normal software and are typical of malware loaders.' `
                    -Fix @('Note the PID, then in Task Manager > Details right-click the process > "Open file location" and "Search online".', 'If it is not something you started (a script you ran, a developer tool), disconnect from the internet and run a "Microsoft Defender Offline scan".')
            }
        }
        if ($seen.ContainsKey($lp)) { continue }
        $seen[$lp] = $true

        $inWin = $false; foreach ($w in $winDirs) { if ($lp.StartsWith($w)) { $inWin = $true } }
        if ($script:SystemProcessNames -contains $name -and -not $inWin) {
            Add-Finding -Severity High -Category $cat -Title "Fake system process: $($p.Name) running from the wrong folder" -Evidence @("Path: $path", (Format-Signature (Get-FileSignatureInfo $path))) -Key "masq|$lp" -Target $path `
                -Why "The real $($p.Name) only ever runs from the Windows folder. Malware copies system process names so it blends in with Task Manager." `
                -Fix (@($script:FixCheckFile) + 'In Task Manager > Details you can right-click it and choose "Open file location" to see it (Sabel Threat Detection will not stop or delete it for you).')
            continue
        }
        if ($script:SystemProcessNames -notcontains $name -and $name.Length -ge 8) {
            $look = $script:SystemProcessNames | Where-Object { (Get-Levenshtein $name $_) -eq 1 } | Select-Object -First 1
            if ($look) {
                $sig = Get-FileSignatureInfo $path
                if ($sig.Status -ne 'Valid') {
                    Add-Finding -Severity High -Category $cat -Title "Look-alike process name: $($p.Name) (imitates $look)" -Evidence @("Path: $path", (Format-Signature $sig)) -Key "lookalike|$lp" -Target $path `
                        -Why 'Names one letter away from a Windows process (e.g. "scvhost.exe") are a classic malware disguise.' -Fix $script:FixCheckFile
                    continue
                }
            }
        }
        $loc = Get-LocationRisk $path
        $sig = $null
        if ($loc) {
            $sig = Get-FileSignatureInfo $path
            if ($sig.Status -ne 'Valid') {
                Add-Finding -Severity Medium -Category $cat -Title "Unsigned program running from $($loc): $($p.Name)" -Evidence @("Path: $path", (Format-Signature $sig), "SHA256: $($sig.Sha256)") -Key "procloc|$lp" -Target $path `
                    -Why 'Legitimate installed software lives in Program Files. Unsigned programs running from Temp, Downloads or similar folders are often droppers or freshly downloaded malware - though they can also be a program you just downloaded and opened.' `
                    -Fix (@('If you just downloaded and opened this yourself, this is expected.') + $script:FixCheckFile + $script:FixIfYouTrust)
            }
        }
        if (-not (Test-File $path)) {
            Add-Finding -Severity Medium -Category $cat -Title "Running program whose file has been deleted: $($p.Name)" -Evidence @("Path: $path", "PID: $($p.ProcessId)") -Key "procgone|$lp" `
                -Why 'Malware sometimes deletes its own file after starting to avoid being scanned. It can also just be an app that updated itself while running.' `
                -Fix @('Restart the PC. If the program was an app update, it will be gone. If this finding comes back, scan with "Microsoft Defender Offline scan".')
        }
    }
    if ($noPath -gt 0 -and -not (Test-IsAdmin)) {
        Add-Skipped 'Process paths' "$noPath system processes could only be inspected with administrator rights."
    }
}

function Test-NetworkActivity {
    $cat = 'Network'
    Register-InventoryKind 'Listener'
    $procPath = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) { try { $procPath[$p.Id] = $p.Path } catch { } }
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' })
    foreach ($g in ($listen | Group-Object OwningProcess)) {
        $path = $procPath[[int]$g.Name]
        if (-not $path -or (Test-UnderWindows $path)) { continue }
        $ports = ($g.Group | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ', '
        $isNew = Add-InventoryItem 'Listener' $path.ToLowerInvariant() $path
        if (-not $isNew) { continue }
        $sig = Get-FileSignatureInfo $path
        $sev = if ($sig.Status -eq 'Valid') { 'Info' } else { 'Medium' }
        Add-Finding -Severity $sev -Category $cat -Title "New program accepting network connections: $([IO.Path]::GetFileName($path))" -Evidence @("Path: $path", "Ports: $ports", (Format-Signature $sig)) -Key "listen|$path" -IsChange -Target $path `
            -Why 'This program opened a port that other devices can connect to. Games, chat apps and file-sharing tools do this normally; remote-access malware (RATs) and backdoors do too.' `
            -Fix (@('If you recently installed or started software that shares files, streams or hosts games, this is expected.', 'Otherwise check the file (see steps below) and, if unknown, block it: Windows Security > Firewall & network protection > Allow an app through firewall, and untick it.') + $script:FixCheckFile)
    }
    $badPorts = @{ 4444 = 'Metasploit default'; 1337 = 'common hacker tool port'; 31337 = 'Back Orifice / "elite" port'; 6667 = 'IRC (botnet control)'; 6666 = 'IRC (botnet control)'; 5552 = 'njRAT default'; 1604 = 'DarkComet RAT default' }
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        if ($badPorts.ContainsKey([int]$c.RemotePort)) {
            $path = $procPath[[int]$c.OwningProcess]
            Add-Finding -Severity Medium -Category $cat -Title "Connection to a port often used by remote-control malware ($($c.RemotePort))" `
                -Evidence @("Remote: $($c.RemoteAddress):$($c.RemotePort) ($($badPorts[[int]$c.RemotePort]))", "Program: $path (PID $($c.OwningProcess))") -Key "badport|$path|$($c.RemotePort)" `
                -Why 'Some ports are default settings for hacking tools and remote-access trojans. It can be innocent (a game server or chat client), so look at which program owns the connection.' `
                -Fix (@('Look up the remote address at https://www.abuseipdb.com to see if it is reported as malicious.') + $script:FixCheckFile)
        }
    }
}

function Test-HostsFile {
    $cat = 'Network'
    $hosts = "$env:windir\System32\drivers\etc\hosts"
    if (-not (Test-File $hosts)) { return }
    $entries = @(Get-Content -LiteralPath $hosts -ErrorAction Stop | ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
        Where-Object { $_ -and $_ -notmatch '^(127\.0\.0\.1|::1)\s+localhost$' })
    if (-not $entries) { return }
    $security = $entries | Where-Object { $_ -match '(?i)(microsoft|windowsupdate|update\.|defender|avast|avg\.|kaspersky|norton|symantec|mcafee|eset|malwarebytes|bitdefender|virustotal|sophos|trendmicro|google\.|bank|paypal)' }
    if ($security) {
        Add-Finding -Severity High -Category $cat -Title 'Hosts file redirects security, update or banking websites' -Evidence $security -Key 'hosts-security' `
            -Why 'The hosts file overrides normal internet name lookups. Malware uses it to block antivirus updates or send you to fake banking/login pages.' `
            -Fix @("Open Notepad as administrator, open $hosts, and look at the listed lines. Lines you did not add can be removed (or start them with #).", 'Then scan the PC, since something wrote these lines.')
    } else {
        $isNew = $false
        Register-InventoryKind 'Hosts'
        foreach ($e in $entries) { if (Add-InventoryItem 'Hosts' $e $e) { $isNew = $true } }
        $sev = if ($isNew) { 'Low' } else { 'Info' }
        Add-Finding -Severity $sev -Category $cat -Title "Hosts file contains $($entries.Count) custom entr$(if ($entries.Count -eq 1) {'y'} else {'ies'})" -Evidence ($entries | Select-Object -First 15) -Key 'hosts' -IsChange:$isNew `
            -Why 'Custom hosts entries are normal for ad-blockers, developers and some software (e.g. Docker), but malware can also add them.' `
            -Fix @("Review $hosts in Notepad and make sure you recognise the entries.")
    }
}

function Test-ProxySettings {
    $cat = 'Network'
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $pac = Get-RegValue $k 'AutoConfigURL'
    if ($pac) {
        Add-Finding -Severity Medium -Category $cat -Title 'A proxy auto-config script controls your web traffic' -Evidence @("AutoConfigURL = $pac") -Key "pac|$pac" `
            -Why 'A proxy script decides where your browser traffic goes. Workplaces use it, but on a home PC it is a known way for malware to intercept or redirect browsing.' `
            -Fix @('Open Settings > Network & internet > Proxy. If you do not use a proxy, turn off "Use setup script".', $script:FixIfYouTrust)
    }
    if ((Get-RegValue $k 'ProxyEnable') -eq 1) {
        $srv = Get-RegValue $k 'ProxyServer'
        $sev = if ($srv -match '^(localhost|127\.)') { 'Low' } else { 'Medium' }
        Add-Finding -Severity $sev -Category $cat -Title "Web traffic goes through a proxy: $srv" -Evidence @("ProxyServer = $srv") -Key "proxy|$srv" `
            -Why 'All browser traffic is sent through this server, which can read or change it. VPNs, ad-blockers and debugging tools (Fiddler) set local proxies; malware sets them to spy.' `
            -Fix @('Open Settings > Network & internet > Proxy. If you do not recognise this, turn "Use a proxy server" off.', $script:FixIfYouTrust)
    }
}

function Get-AdminMembers {
    try {
        return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name })
    } catch {
        # Get-LocalGroupMember fails when the group contains orphaned SIDs; fall back to ADSI
        $grp = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        return @(([ADSI]"WinNT://$env:COMPUTERNAME/$grp,group").Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
    }
}

function Test-Accounts {
    $cat = 'Accounts'
    Register-InventoryKind 'Admin'; Register-InventoryKind 'User'
    foreach ($a in Get-AdminMembers) {
        if (Add-InventoryItem 'Admin' $a $a) {
            Add-Finding -Severity High -Category $cat -Title "NEW administrator account: $a" -Key "newadmin|$a" -IsChange `
                -Why 'An account was added to the Administrators group since the last scan. Attackers create or promote accounts so they can get back in.' `
                -Fix @('If you (or someone you trust) did not do this, open Settings > Accounts > Other users, or run "lusrmgr.msc" (Pro), and remove admin rights from it.', 'Change your own password afterwards and scan the PC.', $script:FixIfYouTrust)
        }
    }
    foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
        $sid = $u.SID.Value
        if ((Add-InventoryItem 'User' $sid $u.Name) -and $u.Enabled) {
            Add-Finding -Severity Medium -Category $cat -Title "New user account: $($u.Name)" -Key "newuser|$sid" -IsChange `
                -Why 'A local account was created since the last scan.' `
                -Fix @('If you did not create it, disable it in Settings > Accounts > Other users and scan the PC.', $script:FixIfYouTrust)
        }
        if (-not $u.Enabled) { continue }
        if ($sid -like '*-501') {
            Add-Finding -Severity Medium -Category $cat -Title 'The Guest account is enabled' -Key 'guest' `
                -Why 'The Guest account lets anyone log in without a password.' `
                -Fix @('In an administrator terminal run:  net user Guest /active:no   (you decide whether to run it).')
        } elseif ($sid -like '*-500') {
            Add-Finding -Severity Low -Category $cat -Title 'The built-in Administrator account is enabled' -Key 'builtin-admin' `
                -Why 'This hidden account is disabled by default and is a common password-guessing target.' `
                -Fix @('If you do not use it, in an administrator terminal run:  net user Administrator /active:no')
        } elseif (-not $u.PasswordRequired -and $null -eq $u.PasswordLastSet -and $u.PrincipalSource -eq 'Local') {
            Add-Finding -Severity Low -Category $cat -Title "Account '$($u.Name)' may have no password" -Key "nopw|$sid" `
                -Why 'An account without a password can be used by anyone with physical or network access.' `
                -Fix @('Set a password or PIN in Settings > Accounts > Sign-in options.')
        }
    }
}

function Get-ExtensionName([string]$Dir, $Manifest) {
    $name = [string]$Manifest.name
    if ($name -match '^__MSG_(.+)__$') {
        $keyName = $Matches[1]
        foreach ($loc in @($Manifest.default_locale, 'en', 'en_US') | Where-Object { $_ }) {
            $f = Join-Path $Dir "_locales\$loc\messages.json"
            if (Test-File $f) {
                try {
                    $msgs = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
                    $hit = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $keyName } | Select-Object -First 1
                    if ($hit) { return $hit.Value.message }
                } catch { }
            }
        }
    }
    return $name
}

function Test-BrowserExtensions {
    $cat = 'Browser'
    Register-InventoryKind 'BrowserExtension'
    $browsers = [ordered]@{
        'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        'Edge'   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        'Brave'  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    }
    $broad = '<all_urls>|^\*://\*/\*$|^https?://\*/\*$'
    $powerful = 'webRequest|cookies|nativeMessaging|debugger|proxy|clipboardRead|history|management'
    foreach ($b in $browsers.Keys) {
        $root = $browsers[$b]
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($prof in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
            foreach ($ext in @(Get-ChildItem -LiteralPath (Join-Path $prof.FullName 'Extensions') -Directory -ErrorAction SilentlyContinue)) {
                $ver = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if (-not $ver) { continue }
                $mf = Join-Path $ver.FullName 'manifest.json'
                if (-not (Test-File $mf)) { continue }
                try { $manifest = Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json } catch { continue }
                $name = Get-ExtensionName $ver.FullName $manifest
                $perms = @($manifest.permissions) + @($manifest.host_permissions) + @($manifest.optional_permissions) | Where-Object { $_ -is [string] }
                $risky = @($perms | Where-Object { $_ -match $broad -or $_ -match $powerful })
                $label = "$b ($($prof.Name)): $name"
                $isNew = Add-InventoryItem 'BrowserExtension' "$b|$($prof.Name)|$($ext.Name)" $label
                if (-not $isNew) { continue }
                $sev = if ($risky) { 'Medium' } else { 'Low' }
                Add-Finding -Severity $sev -Category $cat -Title "New browser extension: $label" -Key "ext|$b|$($prof.Name)|$($ext.Name)" -IsChange `
                    -Evidence (@("Extension ID: $($ext.Name)", "Version: $($ver.Name)") + $(if ($risky) { "Powerful permissions: $($risky -join ', ')" })) `
                    -Why 'Malicious or hijacked browser extensions can read everything you do on websites, steal passwords and session cookies, and inject ads. Extensions with access to "all sites" plus cookies/webRequest are the most dangerous.' `
                    -Fix @("If you did not install it, open $b > Extensions (address: $($b.ToLower())://extensions) and click Remove.", "Look the ID up in the $b web store to check the publisher and reviews.", $script:FixIfYouTrust)
            }
        }
    }
    $ff = "$env:APPDATA\Mozilla\Firefox\Profiles"
    foreach ($prof in @(Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue)) {
        $json = Join-Path $prof.FullName 'extensions.json'
        if (-not (Test-File $json)) { continue }
        try { $addons = (Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).addons } catch { continue }
        foreach ($a in @($addons | Where-Object { $_.location -eq 'app-profile' -and $_.type -eq 'extension' })) {
            $label = "Firefox ($($prof.Name)): $($a.defaultLocale.name)"
            if (Add-InventoryItem 'BrowserExtension' "Firefox|$($prof.Name)|$($a.id)" $label) {
                Add-Finding -Severity Low -Category $cat -Title "New browser extension: $label" -Key "ext|firefox|$($a.id)" -IsChange -Evidence @("Add-on ID: $($a.id)") `
                    -Why 'Browser extensions can read and change the websites you visit.' `
                    -Fix @('If you did not install it, open Firefox > Settings > Extensions & Themes and remove it.', $script:FixIfYouTrust)
            }
        }
    }
}
