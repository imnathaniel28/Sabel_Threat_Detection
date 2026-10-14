# Builds assets\sabel.ico and "Sabel_Threat_Detection.exe" (the double-click launcher).
# Uses only what ships with Windows: System.Drawing and the .NET Framework C# compiler.
#   powershell -ExecutionPolicy Bypass -File tools\Build-Launcher.ps1

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = Split-Path $PSScriptRoot -Parent
$assets = Join-Path $root 'assets'
New-Item -ItemType Directory -Force -Path $assets | Out-Null

# --- draw a shield icon at several sizes (PNG-compressed ICO, supported since Windows Vista)
function New-ShieldPng([int]$Size) {
    $bmp = New-Object Drawing.Bitmap($Size, $Size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([Drawing.Color]::Transparent)
    $s = $Size / 64.0
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $path.AddLine(32 * $s, 3 * $s, 57 * $s, 12 * $s)
    $path.AddBezier(57 * $s, 12 * $s, 57 * $s, 38 * $s, 48 * $s, 52 * $s, 32 * $s, 61 * $s)
    $path.AddBezier(32 * $s, 61 * $s, 16 * $s, 52 * $s, 7 * $s, 38 * $s, 7 * $s, 12 * $s)
    $path.CloseFigure()
    $brush = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.PointF(0, 0)), (New-Object Drawing.PointF(0, $Size)),
        [Drawing.Color]::FromArgb(36, 110, 170), [Drawing.Color]::FromArgb(16, 42, 67))
    $g.FillPath($brush, $path)
    $pen = New-Object Drawing.Pen([Drawing.Color]::FromArgb(200, 225, 245), [Math]::Max(1, 2.5 * $s))
    $g.DrawPath($pen, $path)
    # check mark
    $tick = New-Object Drawing.Pen([Drawing.Color]::White, [Math]::Max(1.5, 6 * $s))
    $tick.StartCap = 'Round'; $tick.EndCap = 'Round'; $tick.LineJoin = 'Round'
    $g.DrawLines($tick, [Drawing.PointF[]]@([Drawing.PointF]::new(20 * $s, 32 * $s), [Drawing.PointF]::new(29 * $s, 41 * $s), [Drawing.PointF]::new(45 * $s, 23 * $s)))
    $g.Dispose()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 256
$images = foreach ($sz in $sizes) { , (New-ShieldPng $sz) }
$ico = New-Object IO.MemoryStream
$w = New-Object IO.BinaryWriter($ico)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$images[$i].Length); $w.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $w.Write($img) }
$w.Flush()
$icoPath = Join-Path $assets 'sabel.ico'
[IO.File]::WriteAllBytes($icoPath, $ico.ToArray())
Write-Host "Icon written: $icoPath"

# --- compile the launcher
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$out = Join-Path $root 'Sabel_Threat_Detection.exe'
& $csc /nologo /target:winexe /platform:anycpu /optimize+ "/win32icon:$icoPath" "/out:$out" /r:System.Windows.Forms.dll (Join-Path $PSScriptRoot 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw "Compiler failed ($LASTEXITCODE)" }
Write-Host "Launcher built: $out"
