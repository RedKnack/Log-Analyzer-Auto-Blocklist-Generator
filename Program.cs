/*
 * RedKnack Interactive - Log Analyzer & Auto Blocklist Generator
 * --------------------------------------------------------------
 * This tool scans server log files (.log) and identifies IP addresses
 * that cause multiple consecutive errors (HTTP 4xx/5xx or Apache error logs).
 *
 * Features:
 *  - Detects IPs that exceed a configurable consecutive error threshold.
 *  - Outputs results as CSV (stdout).
 *  - Optionally writes:
 *      * a plain IP list (--iplist) for firewall bans
 *      * an .htaccess blocklist (--htaccess) for Apache 2.2 / 2.4+
 *
 * Example usage:
 *   dotnet run -- "C:\\logs" --min 4 --iplist "C:\\temp\\banlist.txt" --htaccess "C:\\web\\.htaccess"
 *
 * Author: RedKnack Interactive
 * License: MIT
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

class Program
{
    private static readonly Regex IpRegex = new Regex(@"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", RegexOptions.Compiled);
    private const int DefaultThreshold = 4;

    static void Main(string[] args)
    {
        string logDir = Directory.GetCurrentDirectory();
        string ipListPath = null;
        int threshold = DefaultThreshold;
        string htaccessPath = null;

        // Argument parsing
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (string.Equals(a, "--iplist", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                ipListPath = args[++i];
            }
            else if (string.Equals(a, "--min", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                if (!int.TryParse(args[++i], out threshold) || threshold < 1)
                {
                    Console.Error.WriteLine("--min requires a positive integer value.");
                    return;
                }
            }
            else if (string.Equals(a, "--htaccess", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                htaccessPath = args[++i];
            }
            else if (a.StartsWith("--"))
            {
                Console.Error.WriteLine($"Unknown option: {a}");
                PrintUsage();
                return;
            }
            else
            {
                logDir = a;
            }
        }

        if (!Directory.Exists(logDir))
        {
            Console.Error.WriteLine("Log directory not found: " + logDir);
            return;
        }

        var files = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories);
        if (files.Length == 0)
        {
            Console.WriteLine("No .log files found in the given directory.");
            return;
        }

        var consecutiveErrors = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var offenders = new Dictionary<string, Offender>(StringComparer.OrdinalIgnoreCase);

        // Process log files
        foreach (var file in files)
        {
            foreach (var line in File.ReadLines(file))
            {
                var ipMatch = IpRegex.Match(line);
                if (!ipMatch.Success)
                    continue;

                string ip = ipMatch.Value;
                bool isError = IsErrorLine(line);
                DateTime? dt = ExtractDate(line);

                if (isError)
                {
                    if (!consecutiveErrors.TryGetValue(ip, out int current))
                        current = 0;

                    current++;
                    consecutiveErrors[ip] = current;

                    if (current > threshold)
                    {
                        if (!offenders.TryGetValue(ip, out var off))
                        {
                            off = new Offender
                            {
                                Ip = ip,
                                MaxConsecutiveErrors = current,
                                LastSeen = dt,
                                LastFile = Path.GetFileName(file)
                            };
                            offenders[ip] = off;
                        }
                        else
                        {
                            if (current > off.MaxConsecutiveErrors)
                                off.MaxConsecutiveErrors = current;
                            if (dt.HasValue)
                                off.LastSeen = dt;
                            off.LastFile = Path.GetFileName(file);
                        }
                    }
                }
                else
                {
                    // reset the error streak for this IP
                    consecutiveErrors[ip] = 0;
                }
            }
        }

        // Output results as CSV
        if (offenders.Count == 0)
        {
            Console.WriteLine("No IP exceeded the defined error threshold.");
        }
        else
        {
            Console.WriteLine("ip,max_consecutive_errors,last_seen,file");
            foreach (var off in offenders.Values.OrderByDescending(o => o.MaxConsecutiveErrors).ThenBy(o => o.Ip))
            {
                string dt = off.LastSeen.HasValue ? off.LastSeen.Value.ToString("yyyy-MM-dd HH:mm:ss") : "";
                Console.WriteLine($"{off.Ip},{off.MaxConsecutiveErrors},{dt},{off.LastFile}");
            }
        }

        // Optional: write plain IP list
        if (!string.IsNullOrWhiteSpace(ipListPath))
        {
            try
            {
                var ipLines = offenders.Values
                    .OrderByDescending(o => o.MaxConsecutiveErrors)
                    .ThenBy(o => o.Ip)
                    .Select(o => o.Ip)
                    .Distinct()
                    .ToArray();

                using (var sw = new StreamWriter(ipListPath, false))
                {
                    sw.WriteLine($"# Ban list generated by LogTool at {DateTime.UtcNow:s}Z");
                    sw.WriteLine($"# Threshold (consecutive errors) > {threshold}");
                    foreach (var ip in ipLines)
                        sw.WriteLine(ip);
                }

                Console.Error.WriteLine($"IP list written: {ipListPath} ({ipLines.Length} IPs)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error writing IP list: " + ex.Message);
            }
        }

        // Optional: write .htaccess blocklist
        if (!string.IsNullOrWhiteSpace(htaccessPath))
        {
            try
            {
                var ips = offenders.Values
                    .OrderByDescending(o => o.MaxConsecutiveErrors)
                    .ThenBy(o => o.Ip)
                    .Select(o => o.Ip)
                    .Distinct()
                    .ToArray();

                using (var sw = new StreamWriter(htaccessPath, false))
                {
                    sw.WriteLine($"# .htaccess blocklist generated by LogTool at {DateTime.UtcNow:s}Z");
                    sw.WriteLine($"# Threshold (consecutive errors) > {threshold}");
                    sw.WriteLine();

                    // Apache 2.4+ block (mod_authz_core)
                    sw.WriteLine("# Apache 2.4+ style (Require not ip)");
                    sw.WriteLine("<IfModule mod_authz_core.c>");
                    sw.WriteLine("  <RequireAll>");
                    sw.WriteLine("    Require all granted");
                    foreach (var ip in ips)
                        sw.WriteLine($"    Require not ip {ip}");
                    sw.WriteLine("  </RequireAll>");
                    sw.WriteLine("</IfModule>");
                    sw.WriteLine();

                    // Fallback for Apache 2.2 (Order/Deny)
                    sw.WriteLine("# Fallback for older Apache (Order/Deny)");
                    sw.WriteLine("<IfModule !mod_authz_core.c>");
                    sw.WriteLine("  Order Allow,Deny");
                    sw.WriteLine("  Allow from all");
                    foreach (var ip in ips)
                        sw.WriteLine($"  Deny from {ip}");
                    sw.WriteLine("</IfModule>");
                    sw.WriteLine();
                    sw.WriteLine("# End of blocklist");
                }

                Console.Error.WriteLine($".htaccess written: {htaccessPath} ({ips.Length} IPs)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error writing .htaccess: " + ex.Message);
            }
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: dotnet run -- [<logDir>] [--min <n>] [--iplist <path>] [--htaccess <path>]");
        Console.WriteLine("  <logDir>          Directory containing .log files (default: current directory)");
        Console.WriteLine("  --min <n>         Threshold (default: 4) -> lists IPs with more than <n> consecutive errors");
        Console.WriteLine("  --iplist <path>   Optional: write plain ban list (one IP per line)");
        Console.WriteLine("  --htaccess <path> Optional: write Apache .htaccess with Require not ip / Deny from rules");
    }

    private static bool IsErrorLine(string line)
    {
        if (line.Contains(" 404 ") || line.Contains(" 403 ") || line.Contains(" 401 ") ||
            line.Contains(" 400 ") || line.Contains(" 500 ") || line.Contains(" 502 ") ||
            line.Contains(" 503 ") || line.Contains(" 504 "))
        {
            return true;
        }
        if (line.IndexOf("] [error]", StringComparison.OrdinalIgnoreCase) >= 0 ||
            line.IndexOf("] [crit]", StringComparison.OrdinalIgnoreCase) >= 0 ||
            line.IndexOf("] [alert]", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return true;
        }
        return false;
    }

    private static DateTime? ExtractDate(string line)
    {
        int s = line.IndexOf('[');
        int e = line.IndexOf(']');
        if (s != -1 && e != -1 && e > s)
        {
            string inner = line.Substring(s + 1, e - s - 1);
            string core = inner.Split(' ')[0];
            if (DateTime.TryParseExact(core, "dd/MMM/yyyy:HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var dt1))
            {
                return dt1.ToUniversalTime();
            }
            if (DateTime.TryParse(inner, out var dt2))
                return dt2;
        }
        return null;
    }

    private class Offender
    {
        public string Ip { get; set; }
        public int MaxConsecutiveErrors { get; set; }
        public DateTime? LastSeen { get; set; }
        public string LastFile { get; set; }
    }
}
