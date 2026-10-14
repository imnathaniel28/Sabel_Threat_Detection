// Tiny double-clickable launcher for the Sabel Threat Detection window.
// It starts src\Gui.ps1 with PowerShell WITHOUT a console window (so no empty terminal
// is left open behind the app). It does nothing else.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("Sabel Threat Detection")]
[assembly: AssemblyProduct("Sabel Threat Detection")]
[assembly: AssemblyDescription("Launches the Sabel Threat Detection security check window")]
[assembly: AssemblyVersion("1.1.0.0")]

static class Launcher
{
    [STAThread]
    static void Main()
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string gui = Path.Combine(dir, "src", "Gui.ps1");
        if (!File.Exists(gui))
        {
            MessageBox.Show("Could not find:\n" + gui + "\n\nKeep 'Sabel_Threat_Detection.exe' inside the Sabel Threat Detection folder.",
                "Sabel Threat Detection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"WindowsPowerShell\v1.0\powershell.exe");
        var psi = new ProcessStartInfo(ps, "-NoProfile -ExecutionPolicy Bypass -STA -File \"" + gui + "\"");
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.WorkingDirectory = dir;
        try { Process.Start(psi); }
        catch (Exception e)
        {
            MessageBox.Show("Could not start PowerShell:\n" + e.Message, "Sabel Threat Detection", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
