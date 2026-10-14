// Double-clickable launcher for the Sabel Threat Detection window.
//
// The scripts are embedded in this .exe, so it works as a single download:
//  - If it sits next to a "src" folder (the cloned repo), it runs those scripts directly.
//  - Otherwise it unpacks its embedded scripts to %LOCALAPPDATA%\Sabel_Threat_Detection\app
//    (plain, readable .ps1 files) and runs them from there.
// It then starts src\Gui.ps1 with PowerShell WITHOUT a console window. It does nothing else.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("Sabel Threat Detection")]
[assembly: AssemblyProduct("Sabel Threat Detection")]
[assembly: AssemblyDescription("Daily read-only security checkup for Windows")]
[assembly: AssemblyVersion("1.0.1.0")]

static class Launcher
{
    const string ResourcePrefix = "app/";

    [STAThread]
    static void Main()
    {
        try
        {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            if (!File.Exists(Path.Combine(root, "src", "Gui.ps1")))
            {
                root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sabel_Threat_Detection", "app");
                Unpack(root);
            }
            string gui = Path.Combine(root, "src", "Gui.ps1");
            string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            var psi = new ProcessStartInfo(ps, "-NoProfile -ExecutionPolicy Bypass -STA -File \"" + gui + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = root;
            Process.Start(psi);
        }
        catch (Exception e)
        {
            MessageBox.Show("Sabel Threat Detection could not start:\n\n" + e.Message, "Sabel Threat Detection", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // Writes each embedded file to disk, skipping files that are already identical.
    static void Unpack(string root)
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        foreach (string name in asm.GetManifestResourceNames())
        {
            if (!name.StartsWith(ResourcePrefix)) continue;
            string target = Path.Combine(root, name.Substring(ResourcePrefix.Length).Replace('/', Path.DirectorySeparatorChar));
            byte[] data;
            using (Stream s = asm.GetManifestResourceStream(name))
            using (var ms = new MemoryStream()) { s.CopyTo(ms); data = ms.ToArray(); }
            if (File.Exists(target) && SameBytes(File.ReadAllBytes(target), data)) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            File.WriteAllBytes(target, data);
        }
    }

    static bool SameBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
}
