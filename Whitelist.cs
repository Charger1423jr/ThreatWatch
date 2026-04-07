namespace ThreatWatch
{
    public class Whitelist
    {
        private readonly HashSet<string> _trusted;

        public Whitelist(string filePath)
        {
            _trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Whitelist file not found: {filePath}");
                return;
            }

            foreach (var line in File.ReadAllLines(filePath))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    _trusted.Add(trimmed);
            }
        }

        public bool IsTrusted(string fileName) => _trusted.Contains(fileName);
    }
}
