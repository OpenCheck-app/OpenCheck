using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PCCheck.Engine
{
    /// <summary>Compares file and program names against the cheat list. Only names are compared, never file contents.</summary>
    public sealed class Matcher
    {
        static readonly string[] StripExtensions = { ".exe", ".dll", ".lnk", ".zip", ".rar", ".7z", ".bat", ".cmd", ".msi", ".sys", ".tmp", ".bak", ".old", ".lua", ".luau", ".ahk", ".json" };

        /// <summary>File types the file scan looks at. Everything else is skipped without being recorded.</summary>
        public static readonly HashSet<string> ScannedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".lnk", ".zip", ".rar", ".7z", ".bat", ".cmd", ".msi", ".sys", ".lua", ".luau", ".ahk" };

        readonly SignatureSet set;

        public Matcher(SignatureSet set) { this.set = set; }

        public SignatureSet Set { get { return set; } }

        /// <summary>"C:\x\Solara V3 (1).exe" -> "solarav31". Prefetch names lose their "-1A2B3C4D.pf" tail.</summary>
        public static string Normalize(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return "";
            string n = fileName.Trim().ToLowerInvariant();
            int slash = Math.Max(n.LastIndexOf('\\'), n.LastIndexOf('/'));
            if (slash >= 0) n = n.Substring(slash + 1);

            if (n.EndsWith(".pf"))
            {
                n = n.Substring(0, n.Length - 3);
                int dash = n.LastIndexOf('-');
                if (dash > 0) n = n.Substring(0, dash);
            }

            bool stripped = true;
            while (stripped)
            {
                stripped = false;
                foreach (var ext in StripExtensions)
                {
                    if (n.Length > ext.Length && n.EndsWith(ext))
                    {
                        n = n.Substring(0, n.Length - ext.Length);
                        stripped = true;
                        break;
                    }
                }
            }

            var sb = new StringBuilder(n.Length);
            foreach (char c in n) if (char.IsLetterOrDigit(c)) sb.Append(c);
            return sb.ToString();
        }

        /// <summary>Returns the first signature whose tokens match this file or program name, or null.</summary>
        public Signature MatchName(string fileName)
        {
            string norm = Normalize(fileName);
            if (norm.Length < 3) return null;
            string noDigits = norm.TrimEnd('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');

            foreach (var sig in set.Items)
            {
                foreach (var token in sig.Tokens)
                {
                    if (sig.Strict)
                    {
                        if (StrictEquals(norm, token) || StrictEquals(noDigits, token)) return sig;
                    }
                    else if (norm.Contains(token))
                    {
                        return sig;
                    }
                }
            }
            return null;
        }

        /// <summary>Folder names only match non-strict tokens, so a folder called "Wave" or "Zenith" is not flagged.</summary>
        public Signature MatchFolderName(string folderName)
        {
            string norm = Normalize(folderName);
            if (norm.Length < 4) return null;
            foreach (var sig in set.Items)
            {
                if (sig.Strict || sig.Severity == Severity.Info) continue;
                foreach (var token in sig.Tokens)
                    if (token.Length >= 5 && norm.Contains(token)) return sig;
            }
            return null;
        }

        bool StrictEquals(string norm, string token)
        {
            if (norm == token) return true;
            if (!norm.StartsWith(token, StringComparison.Ordinal)) return false;
            string rest = norm.Substring(token.Length);
            return set.Suffixes.Contains(rest);
        }

        /// <summary>Returns the layout that matches a folder's child folder names, or null.</summary>
        public string[] MatchLayout(ICollection<string> childFolderNamesLower)
        {
            foreach (var layout in set.FolderLayouts)
                if (layout.All(childFolderNamesLower.Contains)) return layout;
            return null;
        }

        static readonly Regex UserProfilePrefix = new Regex(@"^(\\\\\?\\)?[A-Za-z]:\\Users\\[^\\]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>Hides the Windows user name in a path: C:\Users\alex\Downloads -> ~\Downloads.</summary>
        public static string MaskUser(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            return UserProfilePrefix.Replace(path, "~");
        }
    }
}
