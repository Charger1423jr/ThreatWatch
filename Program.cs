namespace ThreatWatch
{
    internal class Program
    {
        static void Main()
        {
            ProcessScanner scanner = new ProcessScanner();
            scanner.ScanProcesses();
        }
    }
}
