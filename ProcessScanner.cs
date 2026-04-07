using System;
using System.Diagnostics;

namespace ThreatWatch
{
    internal class ProcessScanner
    {
        private static readonly string[] SuspiciousExtensions = { ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".scr", ".dll", ".js", ".jse", ".msi", ".lnk", ".zip" };
        private const string ReportFile = "FinalReport.txt";

        public void ScanProcesses()
        {
            Whitelist whitelist = new Whitelist("domains.json");
            Console.WriteLine("Scanning running processes for suspicious activity...\n");

            int noAccessCount = 0;

            using (StreamWriter writer = new StreamWriter(ReportFile, false))
            {
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        if (process.MainModule != null)
                        {
                            string path = process.MainModule.FileName;
                            string name = process.ProcessName;
                            string fileName = Path.GetFileName(path);
                            long memory = process.WorkingSet64;

                            bool isTrusted = whitelist.IsTrusted(name) || whitelist.IsTrusted(fileName);

                            int points = CalculatePoints(path, name, fileName, whitelist);
                            string trustedText = isTrusted ? "(Whitelisted)" : "";

                            string reportLine = $"File: {name} | Path: {path} | Memory: {memory / 1024} KB | Points: {points} {trustedText}";

                            Console.WriteLine(reportLine);
                            writer.WriteLine(reportLine);
                        }
                    }
                    catch (System.ComponentModel.Win32Exception ex)
                    {
                        noAccessCount++;
                        string inaccessibleLine = $"File: {process.ProcessName} (PID: {process.Id}) | Cannot Access | Reason: {ex.Message}";
                        Console.WriteLine(inaccessibleLine);
                        writer.WriteLine(inaccessibleLine);
                    }
                }

                writer.WriteLine($"\nScan complete. {noAccessCount} processes could not be accessed.");
            }

            Console.WriteLine($"\nReport saved to {ReportFile}");
        }

        private static int CalculatePoints(string path, string name, string fileName, Whitelist whitelist)
        {
            int points = 0;
            string extension = Path.GetExtension(path).ToLower();
            string parentFolder = Directory.GetParent(path)?.Name ?? "";
            DateTime created = File.GetCreationTime(path);
            FileAttributes attributes = File.GetAttributes(path);
            string startupPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

            if (path.StartsWith(startupPath, StringComparison.OrdinalIgnoreCase)) points += 4;
            if ((DateTime.Now - created).TotalHours < 24) points += 2;
            if (attributes.HasFlag(FileAttributes.Hidden)) points += 3;
            if (parentFolder.Length > 6 && parentFolder.Any(char.IsDigit)) points += 3;

            if (path.Contains("Temp")) points += 3;
            else if (path.StartsWith(@"C:\Program Files")) points -= 3;
            else if (path.StartsWith(@"C:\Windows\System32")) points -= 4;

            if (extension == ".exe") points += 5;
            else if (Array.Exists(SuspiciousExtensions, e => e == extension)) points += 1;

            return points;
        }
    }
}
