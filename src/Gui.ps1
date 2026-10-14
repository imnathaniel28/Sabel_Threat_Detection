# Sabel Threat Detection - graphical front end.
# The window only shows status and offers options. Every action runs in its own pop-up
# terminal, so all output - and every two-step confirmation - happens where you can see it.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# There is no console behind this window, so show any startup error in a message box.
trap {
    $msg = "Sabel Threat Detection could not open its window:`n`n$($_.Exception.Message)`n`nYou can still use it from a terminal:  .\sabel scan"
    try { Add-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'Sabel_Threat_Detection\gui-error.log') -Value "$((Get-Date).ToString('s'))  $($_ | Out-String)" } catch { }
    [Windows.Forms.MessageBox]::Show($msg, 'Sabel Threat Detection', 'OK', 'Error') | Out-Null
    exit 1
}
try {
    Add-Type -Namespace SabelGui -Name Native -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'
    $null = [SabelGui.Native]::SetProcessDPIAware()
} catch { }
[Windows.Forms.Application]::EnableVisualStyles()

$root = Split-Path $PSScriptRoot -Parent
$script:SabelRoot = $root
. (Join-Path $root 'src\Core.ps1')
. (Join-Path $root 'src\Report.ps1')
. (Join-Path $root 'src\Scheduler.ps1')
$script:SabelPs1 = Join-Path $root 'Sabel.ps1'
New-Item -ItemType Directory -Force -Path $script:ReportDir | Out-Null

$script:Running = New-Object System.Collections.ArrayList
$script:LastReportName = $null

# ------------------------------------------------------------------ pop-up terminal

function Start-SabelTerminal([string]$Title, [string[]]$SabelArgs, [switch]$Admin) {
    $quote = { param($s) "'" + ($s -replace "'", "''") + "'" }
    # switches (-Detailed, -Time ...) must stay unquoted; values are single-quoted
    $argText = ($SabelArgs | ForEach-Object { if ($_ -match '^-[A-Za-z]+$') { $_ } else { & $quote $_ } }) -join ' '
    $cmd = "`$Host.UI.RawUI.WindowTitle = 'Sabel Threat Detection - $Title'; & $(& $quote $script:SabelPs1) $argText; " +
           "Write-Host ''; Write-Host '  Finished. Press Enter to close this window.' -ForegroundColor DarkGray; `$null = Read-Host"
    $start = @{
        FilePath     = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
        ArgumentList = "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
        PassThru     = $true
    }
    if ($Admin -or $chkAdmin.Checked) { $start.Verb = 'RunAs' }
    try {
        $p = Start-Process @start
        [void]$script:Running.Add($p)
        $lblHint.Text = "Opened: $Title. The results appear in the new window."
    } catch {
        [Windows.Forms.MessageBox]::Show('The window was not opened (administrator permission was declined or failed).', 'Sabel Threat Detection', 'OK', 'Information') | Out-Null
    }
}

function Get-SelectedId {
    if ($lv.SelectedItems.Count -eq 1) { return [string]$lv.SelectedItems[0].Tag }
    return $null
}

# ------------------------------------------------------------------ refresh

$sevColor = @{
    High   = [Drawing.Color]::FromArgb(192, 0, 0)
    Medium = [Drawing.Color]::FromArgb(204, 102, 0)
    Low    = [Drawing.Color]::FromArgb(0, 102, 153)
    Info   = [Drawing.Color]::DimGray
}

function Update-Schedule {
    $t = Get-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
    if ($t) {
        $at = ([datetime]$t.Triggers[0].StartBoundary)
        $rights = if ($t.Principal.RunLevel -eq 'Highest') { 'with admin rights' } else { 'standard rights' }
        $lblSchedule.Text = "ON - every day at $($at.ToString('HH:mm')) ($rights)"
        $lblSchedule.ForeColor = [Drawing.Color]::FromArgb(0, 120, 60)
        $dtp.Value = [datetime]::Today.Add($at.TimeOfDay)
        $chkElevated.Checked = ($t.Principal.RunLevel -eq 'Highest')
        $script:TaskIsElevated = ($t.Principal.RunLevel -eq 'Highest')
    } else {
        $lblSchedule.Text = 'OFF - not scheduled yet'
        $lblSchedule.ForeColor = [Drawing.Color]::FromArgb(204, 102, 0)
        $script:TaskIsElevated = $false
    }
}

function Update-View {
    $file = Get-LatestReportFile
    $script:LastReportName = if ($file) { $file.Name } else { $null }
    $lv.BeginUpdate()
    $lv.Items.Clear()
    if ($file) {
        $r = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $alert = @(Get-AlertFindings $r)
        if ($alert.Count) {
            $lblResult.Text = "$($alert.Count) issue(s) need your attention"
            $lblResult.ForeColor = $sevColor.High
        } else {
            $lblResult.Text = 'All clear - nothing needs your attention'
            $lblResult.ForeColor = [Drawing.Color]::FromArgb(0, 120, 60)
        }
        $rights = if ($r.IsAdmin) { 'administrator - full coverage' } else { 'standard user' }
        $lblLast.Text = "Last check: $(([datetime]$r.Started).ToString('dddd d MMMM yyyy, HH:mm'))   ($rights, $(@($r.Findings).Count) findings)"
        foreach ($f in @($r.Findings)) {
            if ($f.Trusted -and -not $chkTrusted.Checked) { continue }
            $title = $f.Title
            if ($f.IsChange -and $title -notmatch '^new ') { $title = "NEW  $title" }
            if ($f.Trusted) { $title += '   (trusted)' }
            $it = New-Object Windows.Forms.ListViewItem($f.Severity.ToUpper())
            [void]$it.SubItems.Add($title)
            [void]$it.SubItems.Add($f.Category)
            [void]$it.SubItems.Add($f.Id)
            $it.ForeColor = if ($f.Trusted) { [Drawing.Color]::Gray } else { $sevColor[$f.Severity] }
            $it.Tag = $f.Id
            $it.ToolTipText = (@($f.Evidence) | Select-Object -First 3) -join "`n"
            [void]$lv.Items.Add($it)
        }
    } else {
        $lblResult.Text = 'No check has been run yet'
        $lblResult.ForeColor = [Drawing.Color]::DimGray
        $lblLast.Text = 'Click "Run a check now" to start.'
    }
    $lv.EndUpdate()
    Resize-Columns
    Update-Schedule
    Update-SelectionButtons
}

function Update-SelectionButtons {
    $has = [bool](Get-SelectedId)
    foreach ($b in $btnExplain, $btnAct, $btnTrust) { $b.Enabled = $has }
    $btnTrust.Text = if ($has -and $lv.SelectedItems[0].SubItems[1].Text -like '*(trusted)') { 'Stop trusting it' } else { 'I trust this - stop alerting' }
}

function Resize-Columns {
    $fixed = $lv.Columns[0].Width + $lv.Columns[2].Width + $lv.Columns[3].Width
    $w = $lv.ClientSize.Width - $fixed - 4
    if ($w -gt 100) { $lv.Columns[1].Width = $w }
}

# ------------------------------------------------------------------ layout helpers

$fontBase = New-Object Drawing.Font('Segoe UI', 9.5)
$tooltip = New-Object Windows.Forms.ToolTip -Property @{ AutoPopDelay = 15000; InitialDelay = 400 }

function New-Button([string]$Text, [scriptblock]$OnClick, [string]$Tip, [int]$Width = 250) {
    $b = New-Object Windows.Forms.Button -Property @{
        Text = $Text; Width = $Width; Height = 34; TextAlign = 'MiddleLeft'
        Margin = (New-Object Windows.Forms.Padding(3, 3, 3, 3)); Padding = (New-Object Windows.Forms.Padding(6, 0, 0, 0))
    }
    $b.Add_Click($OnClick)
    if ($Tip) { $tooltip.SetToolTip($b, $Tip) }
    return $b
}

function New-Group([string]$Title, [object[]]$Controls) {
    $g = New-Object Windows.Forms.GroupBox -Property @{ Text = $Title; AutoSize = $true; AutoSizeMode = 'GrowAndShrink'; Padding = (New-Object Windows.Forms.Padding(8, 6, 8, 8)); Margin = (New-Object Windows.Forms.Padding(0, 0, 0, 10)) }
    $flow = New-Object Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'TopDown'; WrapContents = $false; AutoSize = $true; AutoSizeMode = 'GrowAndShrink'; Dock = 'Fill' }
    foreach ($c in $Controls) { $flow.Controls.Add($c) }
    $g.Controls.Add($flow)
    return $g
}

# ------------------------------------------------------------------ form

$form = New-Object Windows.Forms.Form -Property @{
    Text = 'Sabel Threat Detection'; StartPosition = 'CenterScreen'; Font = $fontBase
    Size = (New-Object Drawing.Size(1120, 800)); MinimumSize = (New-Object Drawing.Size(940, 620))
    BackColor = [Drawing.Color]::White
}
$form.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96)
$form.AutoScaleMode = 'Dpi'
$icoPath = Join-Path $root 'assets\sabel.ico'
if (Test-Path -LiteralPath $icoPath) { $form.Icon = New-Object Drawing.Icon($icoPath) }
$form.SuspendLayout()

# Centre: findings list
$center = New-Object Windows.Forms.Panel -Property @{ Dock = 'Fill'; Padding = (New-Object Windows.Forms.Padding(16, 8, 8, 8)) }
$lv = New-Object Windows.Forms.ListView -Property @{
    View = 'Details'; FullRowSelect = $true; MultiSelect = $false; HideSelection = $false; Dock = 'Fill'
    ShowItemToolTips = $true; GridLines = $false; BorderStyle = 'FixedSingle'
}
[void]$lv.Columns.Add('Level', 80)
[void]$lv.Columns.Add('Finding', 400)
[void]$lv.Columns.Add('Area', 150)
[void]$lv.Columns.Add('Id', 95)
$lv.Add_SelectedIndexChanged({ Update-SelectionButtons })
$lv.Add_DoubleClick({ $id = Get-SelectedId; if ($id) { Start-SabelTerminal "Details $id" @('explain', $id) } })
$lv.Add_Resize({ Resize-Columns })

$lblFindings = New-Object Windows.Forms.Label -Property @{ Text = 'Findings from the last check  (double-click one for details and advice)'; Dock = 'Top'; Height = 28; Font = (New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)) }

$btnExplain = New-Button 'Explain this finding' { $id = Get-SelectedId; if ($id) { Start-SabelTerminal "Details $id" @('explain', $id) } } 'Full explanation and step-by-step advice' 190
$btnAct = New-Button 'What can I do about it?' { $id = Get-SelectedId; if ($id) { Start-SabelTerminal "Options for $id" @('act', $id) } } 'Shows options, e.g. ask Microsoft Defender to scan this file. Anything that could remove a file asks you twice.' 210
$btnTrust = New-Button 'I trust this - stop alerting' {
    $id = Get-SelectedId
    if (-not $id) { return }
    if ($btnTrust.Text -eq 'Stop trusting it') { Start-SabelTerminal "Untrust $id" @('untrust', $id) } else { Start-SabelTerminal "Trust $id" @('trust', $id) }
} 'Use this for things you recognise, such as your own scripts or software you installed.' 230
$chkTrusted = New-Object Windows.Forms.CheckBox -Property @{ Text = 'Show trusted items'; AutoSize = $true; Margin = (New-Object Windows.Forms.Padding(10, 10, 3, 3)) }
$chkTrusted.Add_CheckedChanged({ Update-View })
$selBar = New-Object Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Bottom'; AutoSize = $true; Padding = (New-Object Windows.Forms.Padding(0, 6, 0, 0)) }
$selBar.Controls.AddRange(@($btnExplain, $btnAct, $btnTrust, $chkTrusted))

$center.Controls.Add($lv)
$center.Controls.Add($selBar)
$center.Controls.Add($lblFindings)

# Right: options
$right = New-Object Windows.Forms.FlowLayoutPanel -Property @{
    Dock = 'Right'; FlowDirection = 'TopDown'; WrapContents = $false; AutoScroll = $true; AutoSize = $true
    Padding = (New-Object Windows.Forms.Padding(8, 8, 16, 8))
}

$grpCheck = New-Group 'Security check' @(
    (New-Button 'Run a check now' { Start-SabelTerminal 'Security check' @('scan') } 'Runs all 26 read-only checks (about 15-30 seconds).'),
    (New-Button 'Show full report' { Start-SabelTerminal 'Full report' @('report', '-Detailed') } 'Shows every finding with full explanations.')
)

$lblTwice = New-Object Windows.Forms.Label -Property @{ Text = 'Asks you twice before anything can be removed.'; AutoSize = $true; ForeColor = [Drawing.Color]::DimGray; MaximumSize = (New-Object Drawing.Size(250, 0)); Margin = (New-Object Windows.Forms.Padding(3, 0, 3, 4)) }
$grpDefender = New-Group 'Microsoft Defender' @(
    $lblTwice,
    (New-Button 'Quick scan' { Start-SabelTerminal 'Defender quick scan' @('defender', 'quickscan') } 'Checks the places malware usually hides. Takes a few minutes.'),
    (New-Button 'Full scan' { Start-SabelTerminal 'Defender full scan' @('defender', 'fullscan') } 'Checks every file. Can take an hour or more.'),
    (New-Button 'Scan a file or folder...' {
        $dlg = New-Object Windows.Forms.OpenFileDialog -Property @{ Title = 'Choose a file for Microsoft Defender to scan'; Filter = 'All files (*.*)|*.*' }
        if ($dlg.ShowDialog($form) -eq 'OK') { Start-SabelTerminal 'Scan a file' @('defender', 'scanfile', $dlg.FileName) }
    } 'Pick one file for Defender to check.'),
    (New-Button 'Update virus definitions' { Start-SabelTerminal 'Update definitions' @('defender', 'update') } 'Downloads the newest virus definitions. Removes nothing.'),
    (New-Button 'Remove threats Defender found' { Start-SabelTerminal 'Remove threats' @('defender', 'remove') } 'Only acts on threats Defender already detected but did not clean up. Often needs administrator rights.'),
    (New-Button 'Offline scan (restarts PC)' { Start-SabelTerminal 'Offline scan' @('defender', 'offline') } 'Restarts the PC and scans before Windows loads - catches hidden malware. Save your work first.')
)

$dtp = New-Object Windows.Forms.DateTimePicker -Property @{ Format = 'Custom'; CustomFormat = 'HH:mm'; ShowUpDown = $true; Width = 90; Value = [datetime]::Today.AddHours(12) }
$lblAt = New-Object Windows.Forms.Label -Property @{ Text = 'Time:'; AutoSize = $true; Margin = (New-Object Windows.Forms.Padding(3, 7, 3, 3)) }
$timeRow = New-Object Windows.Forms.FlowLayoutPanel -Property @{ AutoSize = $true; WrapContents = $false; Margin = (New-Object Windows.Forms.Padding(0)) }
$timeRow.Controls.AddRange(@($lblAt, $dtp))
$chkElevated = New-Object Windows.Forms.CheckBox -Property @{ Text = 'With admin rights (full coverage)'; AutoSize = $true }
$tooltip.SetToolTip($chkElevated, 'Lets the daily check read things only administrators can see, such as antivirus exclusions. Windows will ask for permission.')
$lblSchedule = New-Object Windows.Forms.Label -Property @{ AutoSize = $true; MaximumSize = (New-Object Drawing.Size(250, 0)); Margin = (New-Object Windows.Forms.Padding(3, 0, 3, 4)); Font = (New-Object Drawing.Font('Segoe UI', 9.5, [Drawing.FontStyle]::Bold)) }
$grpDaily = New-Group 'Daily check' @(
    $lblSchedule, $timeRow, $chkElevated,
    (New-Button 'Turn on / update daily check' {
        $args2 = @('install', '-Time', $dtp.Value.ToString('HH:mm'))
        if ($chkElevated.Checked) { $args2 += '-Elevated' }
        Start-SabelTerminal 'Daily check' $args2 -Admin:$chkElevated.Checked
    } 'Schedules the check every day at this time. If the PC is off then, it runs as soon as it is back on.'),
    (New-Button 'Turn off daily check' { Start-SabelTerminal 'Daily check' @('uninstall') -Admin:$script:TaskIsElevated } 'Removes the scheduled check. Your reports are kept.')
)

$right.Controls.AddRange(@($grpCheck, $grpDefender, $grpDaily))

# Bottom bar
$bottom = New-Object Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Bottom'; AutoSize = $true; BackColor = [Drawing.Color]::FromArgb(243, 245, 248); Padding = (New-Object Windows.Forms.Padding(12, 6, 12, 6)) }
$chkAdmin = New-Object Windows.Forms.CheckBox -Property @{ Text = 'Open windows as administrator'; AutoSize = $true; Margin = (New-Object Windows.Forms.Padding(3, 5, 20, 3)) }
$tooltip.SetToolTip($chkAdmin, 'Gives checks full coverage and lets Defender remove threats. Windows will ask for permission each time.')
$btnRefresh = New-Button 'Refresh' { Update-View } 'Reload the latest results.' 100
$btnRefresh.TextAlign = 'MiddleCenter'
$lblHint = New-Object Windows.Forms.Label -Property @{ Text = ''; AutoSize = $true; ForeColor = [Drawing.Color]::DimGray; Margin = (New-Object Windows.Forms.Padding(12, 9, 3, 3)) }
$bottomButtons = @(
    (New-Button 'Past checks' { Start-SabelTerminal 'History' @('history') } 'List of previous checks.' 110),
    (New-Button 'Trusted items' { Start-SabelTerminal 'Trusted items' @('trusted') } 'Things you told Sabel Threat Detection not to alert about.' 120),
    (New-Button 'Play alert tune' { Start-SabelTerminal 'Alert test' @('test-alert') } 'This is what you will hear when the daily check finds something.' 130),
    (New-Button 'Reports folder' { Start-Process explorer.exe $script:DataDir } 'Where reports and logs are saved.' 125)
)
foreach ($b in $bottomButtons) { $b.TextAlign = 'MiddleCenter'; $b.Padding = (New-Object Windows.Forms.Padding(0)) }
$bottom.Controls.AddRange(@($chkAdmin, $btnRefresh) + $bottomButtons + @($lblHint))

# Status (top, under header)
$status = New-Object Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; FlowDirection = 'TopDown'; WrapContents = $false; AutoSize = $true; Padding = (New-Object Windows.Forms.Padding(16, 10, 16, 2)) }
$lblResult = New-Object Windows.Forms.Label -Property @{ AutoSize = $true; Font = (New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)) }
$lblLast = New-Object Windows.Forms.Label -Property @{ AutoSize = $true; ForeColor = [Drawing.Color]::DimGray; Margin = (New-Object Windows.Forms.Padding(3, 4, 3, 0)) }
$status.Controls.AddRange(@($lblResult, $lblLast))

# Header
$header = New-Object Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; FlowDirection = 'LeftToRight'; WrapContents = $true; AutoSize = $true; BackColor = [Drawing.Color]::FromArgb(16, 42, 67); Padding = (New-Object Windows.Forms.Padding(12, 8, 16, 8)) }
$lblTitle = New-Object Windows.Forms.Label -Property @{ Text = 'SABEL THREAT DETECTION'; AutoSize = $true; ForeColor = [Drawing.Color]::White; Font = (New-Object Drawing.Font('Segoe UI', 18, [Drawing.FontStyle]::Bold)) }
$lblSub = New-Object Windows.Forms.Label -Property @{ Text = "Finds problems and explains them. Anything that could remove a file asks you twice first.   v$script:SabelVersion"; AutoSize = $true; ForeColor = [Drawing.Color]::FromArgb(170, 200, 225); Margin = (New-Object Windows.Forms.Padding(12, 14, 3, 3)) }
$header.Controls.AddRange(@($lblTitle, $lblSub))

# Docking order: Fill first, then edges; the last-added Top control ends up on top.
$form.Controls.Add($center)
$form.Controls.Add($right)
$form.Controls.Add($bottom)
$form.Controls.Add($status)
$form.Controls.Add($header)
$form.ResumeLayout()

# Refresh when a pop-up closes or a new report appears (e.g. from the daily check)
$timer = New-Object Windows.Forms.Timer -Property @{ Interval = 2000 }
$timer.Add_Tick({
    $changed = $false
    foreach ($p in @($script:Running)) { if ($p.HasExited) { $script:Running.Remove($p); $changed = $true } }
    $f = Get-LatestReportFile
    $name = if ($f) { $f.Name } else { $null }
    if ($name -ne $script:LastReportName) { $changed = $true }
    if ($changed) { Update-View }
})
$form.Add_Shown({
    Update-View
    $timer.Start()
    # Test hook: save a picture of the window and close (used to check the layout).
    if ($env:SABEL_GUI_SNAPSHOT) {
        [Windows.Forms.Application]::DoEvents()
        $bmp = New-Object Drawing.Bitmap($form.Width, $form.Height)
        $form.DrawToBitmap($bmp, (New-Object Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
        $bmp.Save($env:SABEL_GUI_SNAPSHOT, [Drawing.Imaging.ImageFormat]::Png)
        $form.Close()
    }
})
$form.Add_FormClosed({ $timer.Stop() })

[void]$form.ShowDialog()
