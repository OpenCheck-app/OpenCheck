using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace PCCheck.Tests
{
    /// <summary>
    /// These tests read the app's own source code and fail the build if anything that could
    /// delete, change, upload or run other programs is ever added. They back up the promises on the first screen.
    /// </summary>
    public class SafetyTests
    {
        static string[] SourceFiles()
        {
            return Directory.GetFiles(Path.Combine(Repo.Root, "src", "PCCheck"), "*.cs", SearchOption.AllDirectories)
                .Where(p => p.IndexOf(@"\obj\", StringComparison.OrdinalIgnoreCase) < 0 && p.IndexOf(@"\bin\", StringComparison.OrdinalIgnoreCase) < 0)
                .ToArray();
        }

        static void AssertNotUsed(string pattern, string why, params string[] allowedFiles)
        {
            var rx = new Regex(pattern);
            foreach (var file in SourceFiles())
            {
                if (allowedFiles.Contains(Path.GetFileName(file))) continue;
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (line.StartsWith("//") || line.StartsWith("///")) continue;
                    Assert.False(rx.IsMatch(line), Path.GetFileName(file) + " line " + (i + 1) + ": " + why + "\n" + line);
                }
            }
        }

        [Fact] public void Never_deletes_or_moves_files() { AssertNotUsed(@"\b(File|Directory)\.(Delete|Move|Copy|Replace|SetAttributes|SetLastWriteTime|SetCreationTime)\b|\.Delete\(\)|\.MoveTo\(", "deleting or changing files is not allowed"); }

        [Fact] public void Never_changes_the_registry() { AssertNotUsed(@"\.SetValue\(|CreateSubKey|DeleteSubKey|DeleteValue|OpenSubKey\([^)]*,\s*true", "registry writes are not allowed"); }

        [Fact] public void Never_uses_the_network() { AssertNotUsed(@"HttpClient|WebClient|WebRequest|TcpClient|UdpClient|\bSocket\b|Dns\.|Ping\(|SmtpClient|HttpListener|ClientWebSocket", "network access is not allowed"); }

        [Fact] public void Never_starts_other_programs() { AssertNotUsed(@"Process\.Start|ProcessStartInfo|ShellExecute|WinExec|CreateProcess", "starting programs is not allowed"); }

        [Fact] public void Never_loads_hidden_code() { AssertNotUsed(@"Assembly\.Load|Activator\.CreateInstance|FromBase64String|CSharpCodeProvider|CompileAssembly|ExecuteScriptAsync|AddHostObjectToScript|powershell|cmd\.exe", "loading or running hidden code is not allowed"); }

        [Fact] public void Never_opens_handles_for_writing() { AssertNotUsed(@"GENERIC_WRITE|GENERIC_ALL|WriteFile\(|FSCTL_DELETE|FSCTL_CREATE|FileAccess\.(Write|ReadWrite)|FileMode\.(Create|Append|Truncate|OpenOrCreate)", "write access is not allowed"); }

        [Fact] public void Only_the_report_is_written() { AssertNotUsed(@"File\.(WriteAll|AppendAll)|new StreamWriter|new BinaryWriter|Directory\.CreateDirectory", "only ReportWriter may write (the saved report)", "ReportWriter.cs"); }

        [Fact]
        public void Ui_cannot_reach_the_internet()
        {
            string html = File.ReadAllText(Path.Combine(Repo.Root, "src", "PCCheck", "ui", "index.html"));
            Assert.Contains("connect-src 'none'", html);
            Assert.DoesNotMatch(@"https?://", html);
            Assert.DoesNotMatch(@"\bfetch\(|XMLHttpRequest|WebSocket|\beval\(|new Function\(|\.innerHTML\s*=\s*[a-z]", html);
        }

        [Fact]
        public void Signature_list_is_built_into_the_exe()
        {
            string csproj = File.ReadAllText(Path.Combine(Repo.Root, "src", "PCCheck", "PCCheck.csproj"));
            Assert.Contains("EmbeddedResource Include=\"signatures.json\"", csproj);
            Assert.Contains("EmbeddedResource Include=\"ui\\index.html\"", csproj);
        }
    }
}
