using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;

namespace PCCheck.Engine
{
    public sealed class Signature
    {
        public string Name;
        public string Category;
        public string Note;
        public Severity Severity;
        public bool Strict;
        public List<string> Tokens = new List<string>();
        public List<string> Folders = new List<string>();
    }

    /// <summary>The cheat list. It is compiled into the .exe (signatures.json) so the person being checked can't edit it.</summary>
    public sealed class SignatureSet
    {
        public string Version = "";
        public List<Signature> Items = new List<Signature>();
        public HashSet<string> Suffixes = new HashSet<string>(StringComparer.Ordinal);
        public List<string[]> FolderLayouts = new List<string[]>();
        public List<string> FlagWords = new List<string>();
        public List<string> LooseFlagFileWords = new List<string>();
        public Dictionary<string, string> DmaVendors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> VmMacPrefixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> KnownBadSha256 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static SignatureSet LoadEmbedded()
        {
            return Parse(ReadResource("signatures.json"));
        }

        public static string ReadResource(string name)
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream(name))
            {
                if (s == null) throw new InvalidOperationException("Missing built-in resource: " + name);
                using (var r = new StreamReader(s, Encoding.UTF8)) return r.ReadToEnd();
            }
        }

        public static SignatureSet Parse(string json)
        {
            var root = Json.Object(Json.Parse(json));
            var set = new SignatureSet();
            set.Version = Json.Str(root, "version") ?? "";

            foreach (var o in Json.Array(Json.Get(root, "nameSuffixes")))
                set.Suffixes.Add(Clean(Convert.ToString(o)));

            foreach (var o in Json.Array(Json.Get(root, "signatures")))
            {
                var d = Json.Object(o);
                var sig = new Signature
                {
                    Name = Json.Str(d, "name") ?? "Unknown",
                    Category = Json.Str(d, "category") ?? "",
                    Note = Json.Str(d, "note"),
                    Strict = Json.Bool(d, "strict"),
                    Severity = ParseSeverity(Json.Str(d, "severity"))
                };
                foreach (var t in Json.Array(Json.Get(d, "match")))
                {
                    var tok = Clean(Convert.ToString(t));
                    if (tok.Length >= 3) sig.Tokens.Add(tok);
                }
                foreach (var f in Json.Array(Json.Get(d, "folders"))) sig.Folders.Add(Convert.ToString(f));
                if (sig.Tokens.Count > 0 || sig.Folders.Count > 0) set.Items.Add(sig);
            }

            foreach (var o in Json.Array(Json.Get(root, "executorFolderLayouts")))
            {
                var parts = Json.Array(o).Select(x => Convert.ToString(x).ToLowerInvariant()).Where(x => x.Length > 0).ToArray();
                if (parts.Length >= 2) set.FolderLayouts.Add(parts);
            }

            var ff = Json.Object(Json.Get(root, "fastFlags"));
            foreach (var w in Json.Array(Json.Get(ff, "suspiciousWords"))) set.FlagWords.Add(Convert.ToString(w));

            foreach (var w in Json.Array(Json.Get(Json.Object(Json.Get(root, "looseFastFlagFiles")), "nameWords")))
                set.LooseFlagFileWords.Add(Clean(Convert.ToString(w)));

            var dma = Json.Object(Json.Get(root, "dma"));
            foreach (var kv in Json.Object(Json.Get(dma, "suspiciousVendorIds"))) set.DmaVendors[kv.Key] = Convert.ToString(kv.Value);

            foreach (var kv in Json.Object(Json.Get(root, "vmMacPrefixes"))) set.VmMacPrefixes[kv.Key] = Convert.ToString(kv.Value);

            foreach (var kv in Json.Object(Json.Get(root, "knownBadSha256")))
                if (!kv.Key.StartsWith("_")) set.KnownBadSha256[kv.Key] = Convert.ToString(kv.Value);

            return set;
        }

        static Severity ParseSeverity(string s)
        {
            switch ((s ?? "").ToLowerInvariant())
            {
                case "high": return Severity.High;
                case "medium": return Severity.Medium;
                default: return Severity.Info;
            }
        }

        /// <summary>Lowercase letters and digits only.</summary>
        public static string Clean(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s.ToLowerInvariant()) if (char.IsLetterOrDigit(c)) sb.Append(c);
            return sb.ToString();
        }
    }

    /// <summary>Small helpers over the built-in .NET JSON reader.</summary>
    public static class Json
    {
        public static object Parse(string json)
        {
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 64 };
            return ser.DeserializeObject(json);
        }

        public static string Serialize(object value)
        {
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 64 };
            return ser.Serialize(value);
        }

        public static Dictionary<string, object> Object(object o)
        {
            var d = o as Dictionary<string, object>;
            return d ?? new Dictionary<string, object>();
        }

        public static object[] Array(object o)
        {
            var arr = o as object[];
            if (arr != null) return arr;
            var list = o as ArrayList;
            if (list != null) return list.ToArray();
            return new object[0];
        }

        public static object Get(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v : null;
        }

        public static string Str(Dictionary<string, object> d, string key)
        {
            var v = Get(d, key);
            return v == null ? null : Convert.ToString(v);
        }

        public static bool Bool(Dictionary<string, object> d, string key)
        {
            var v = Get(d, key);
            return v is bool && (bool)v;
        }
    }
}
