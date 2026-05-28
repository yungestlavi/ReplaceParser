using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SSForensic.Services
{
    /// <summary>
    /// Lightweight YARA-style scanner. Parses a subset of YARA rule syntax
    /// (strings + simple boolean conditions) and matches against file bytes.
    /// No native dependencies - pure managed code.
    /// </summary>
    public class YaraEngine : IDisposable
    {
        private readonly List<CompiledRule> _rules = new();
        private readonly List<string> _ruleErrors = new();

        public IReadOnlyList<string> RuleErrors => _ruleErrors;
        public int LoadedRuleCount => _rules.Count;

        private class CompiledRule
        {
            public string Name = "";
            public List<string> Tags = new();
            public Dictionary<string, byte[]> Strings = new();
            public bool NoCase;
            public string Condition = "";
            public int MinHits;
        }

        public void LoadRules(string rulesFolder)
        {
            _rules.Clear();
            _ruleErrors.Clear();

            if (!Directory.Exists(rulesFolder))
            {
                _ruleErrors.Add($"Rules folder not found: {rulesFolder}");
                return;
            }

            var files = new List<string>();
            files.AddRange(Directory.GetFiles(rulesFolder, "*.yar", SearchOption.AllDirectories));
            files.AddRange(Directory.GetFiles(rulesFolder, "*.yara", SearchOption.AllDirectories));

            foreach (var file in files)
            {
                try
                {
                    string content = File.ReadAllText(file);
                    foreach (var rule in ParseFile(content))
                        _rules.Add(rule);
                }
                catch (Exception ex)
                {
                    _ruleErrors.Add($"{Path.GetFileName(file)}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Parses rules directly from a string (used for embedded rules).
        /// </summary>
        public void LoadRulesFromString(string content)
        {
            try
            {
                foreach (var rule in ParseFile(content))
                    _rules.Add(rule);
            }
            catch (Exception ex)
            {
                _ruleErrors.Add("embedded rules: " + ex.Message);
            }
        }

        /// <summary>
        /// Loads rules from embedded resources first (so a single-file .exe needs
        /// no external Rules\ folder), then merges any *.yar files found next to the
        /// executable so users can still drop in extra rules.
        /// </summary>
        public void LoadRulesAuto()
        {
            _rules.Clear();
            _ruleErrors.Clear();

            // 1) Embedded resources (compiled into the assembly).
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                foreach (var name in asm.GetManifestResourceNames())
                {
                    if (name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                    {
                        using var stream = asm.GetManifestResourceStream(name);
                        if (stream == null) continue;
                        using var reader = new StreamReader(stream);
                        LoadRulesFromString(reader.ReadToEnd());
                    }
                }
            }
            catch (Exception ex)
            {
                _ruleErrors.Add("embedded scan: " + ex.Message);
            }

            // 2) Optional external Rules\ folder next to the exe (extra user rules).
            try
            {
                string folder = Path.Combine(AppContext.BaseDirectory, "Rules");
                if (Directory.Exists(folder))
                {
                    var files = new List<string>();
                    files.AddRange(Directory.GetFiles(folder, "*.yar", SearchOption.AllDirectories));
                    files.AddRange(Directory.GetFiles(folder, "*.yara", SearchOption.AllDirectories));
                    foreach (var file in files)
                    {
                        try { LoadRulesFromString(File.ReadAllText(file)); }
                        catch (Exception ex) { _ruleErrors.Add($"{Path.GetFileName(file)}: {ex.Message}"); }
                    }
                }
            }
            catch (Exception ex)
            {
                _ruleErrors.Add("external scan: " + ex.Message);
            }
        }

        private static IEnumerable<CompiledRule> ParseFile(string text)
        {
            text = Regex.Replace(text, @"/\*.*?\*/", "", RegexOptions.Singleline);
            text = Regex.Replace(text, @"//.*", "");

            var ruleRegex = new Regex(
                @"rule\s+(\w+)(?:\s*:\s*([\w\s]+?))?\s*\{(.*?)\}",
                RegexOptions.Singleline);

            foreach (Match m in ruleRegex.Matches(text))
            {
                var rule = new CompiledRule
                {
                    Name = m.Groups[1].Value,
                    Tags = m.Groups[2].Success
                        ? new List<string>(m.Groups[2].Value.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                        : new List<string>()
                };

                string body = m.Groups[3].Value;

                var stringsMatch = Regex.Match(body, @"strings\s*:(.*?)(?=condition\s*:|$)", RegexOptions.Singleline);
                if (stringsMatch.Success)
                {
                    foreach (Match s in Regex.Matches(stringsMatch.Groups[1].Value,
                                                       @"(\$\w+)\s*=\s*""((?:[^""\\]|\\.)*)""\s*([\w\s]*)"))
                    {
                        string id = s.Groups[1].Value;
                        string val = Regex.Unescape(s.Groups[2].Value);
                        string mods = s.Groups[3].Value.ToLowerInvariant();
                        bool nocase = mods.Contains("nocase");
                        if (nocase) rule.NoCase = true;
                        rule.Strings[id] = Encoding.UTF8.GetBytes(val);
                    }
                }

                var condMatch = Regex.Match(body, @"condition\s*:\s*(.*)", RegexOptions.Singleline);
                if (condMatch.Success)
                {
                    rule.Condition = condMatch.Groups[1].Value.Trim();
                    var lower = rule.Condition.ToLowerInvariant();
                    if (lower.Contains("all of them")) rule.MinHits = rule.Strings.Count;
                    else if (lower.Contains("any of them")) rule.MinHits = 1;
                    else
                    {
                        var num = Regex.Match(lower, @"(\d+)\s+of\s+them");
                        rule.MinHits = num.Success ? int.Parse(num.Groups[1].Value) : 1;
                    }
                }
                else
                {
                    rule.MinHits = 1;
                }

                if (rule.Strings.Count > 0)
                    yield return rule;
            }
        }

        public class ScanResult
        {
            public List<string> Matches { get; set; } = new();
            public bool IsCheat { get; set; }
        }

        public ScanResult Scan(string filePath)
        {
            var result = new ScanResult();
            if (!File.Exists(filePath)) return result;

            byte[] fileBytes;
            try
            {
                var fi = new FileInfo(filePath);
                if (fi.Length > 100 * 1024 * 1024) return result;
                fileBytes = File.ReadAllBytes(filePath);
            }
            catch { return result; }

            foreach (var rule in _rules)
            {
                int hits = 0;
                foreach (var kv in rule.Strings)
                {
                    if (ContainsBytes(fileBytes, kv.Value, rule.NoCase))
                        hits++;
                }
                if (hits >= rule.MinHits && rule.Strings.Count > 0)
                {
                    result.Matches.Add(rule.Name);
                    bool taggedCheat = rule.Tags.Exists(t =>
                        t.Equals("cheat", StringComparison.OrdinalIgnoreCase) ||
                        t.Equals("cheating", StringComparison.OrdinalIgnoreCase));
                    if (taggedCheat || rule.Name.IndexOf("cheat", StringComparison.OrdinalIgnoreCase) >= 0)
                        result.IsCheat = true;
                }
            }

            return result;
        }

        private static bool ContainsBytes(byte[] haystack, byte[] needle, bool ignoreCase)
        {
            if (needle.Length == 0 || haystack.Length < needle.Length) return false;

            if (!ignoreCase)
                return IndexOf(haystack, needle, 0) >= 0;

            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    byte a = haystack[i + j];
                    byte b = needle[j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int start)
        {
            for (int i = start; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                if (match) return i;
            }
            return -1;
        }

        public void Dispose() { }
    }
}
