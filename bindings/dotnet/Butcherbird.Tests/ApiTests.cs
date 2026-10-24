using System.Runtime.CompilerServices;
using Xunit;

namespace Butcherbird.Tests;

internal static class NativePath
{
    [ModuleInitializer]
    internal static void Init()
    {
        var file = OperatingSystem.IsWindows()
            ? "butcherbird_ffi.dll"
            : OperatingSystem.IsMacOS()
                ? "libbutcherbird_ffi.dylib"
                : "libbutcherbird_ffi.so";
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "crates", "ffi", "Cargo.toml")))
            {
                Environment.SetEnvironmentVariable(
                    "BUTCHERBIRD_NATIVE",
                    Path.Combine(dir.FullName, "target", "debug", file));
                return;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException("butcherbird repo root was not found");
    }
}

public class ApiTests
{
    private static readonly string[] Providers =
    [
        "abuseipdb",
        "urlhaus",
        "virustotal",
        "otx",
        "greynoise",
        "shodan",
        "urlscan",
        "threatfox",
        "malwarebazaar",
        "safebrowsing",
        "openphish",
        "spamhaus-zen",
        "spamhaus-dbl",
        "rdap",
        "whois",
    ];

    private static string QuietToml(string cache)
    {
        var cachePath = cache.Replace("\\", "/");
        var lines = new List<string>
        {
            "[profiles.default.cache]",
            "enabled = false",
            $"path = \"{cachePath}\"",
            "",
        };
        foreach (var provider in Providers)
        {
            lines.Add($"[profiles.default.providers.{provider}]");
            lines.Add("enabled = false");
            lines.Add("");
        }
        return string.Join("\n", lines);
    }

    [Fact]
    public void Parse_defanged_url()
    {
        var ioc = Indicators.Parse("hxxps://evil[.]example/a");
        Assert.NotNull(ioc);
        Assert.Equal("url", ioc.Type);
        Assert.Equal("https://evil.example/a", ioc.Value);
    }

    [Fact]
    public void Load_dedupes()
    {
        var iocs = Indicators.Load("192.0.2.1\n192.0.2.1\n");
        Assert.Single(iocs);
        Assert.Equal("ipv4", iocs[0].Type);
        Assert.Equal("192.0.2.1", iocs[0].Value);
    }

    [Fact]
    public void Check_with_providers_disabled()
    {
        var dir = Directory.CreateTempSubdirectory("butcherbird-");
        try
        {
            using var engine = CheckEngine.FromToml(QuietToml(Path.Combine(dir.FullName, "cache.sqlite")));
            var rows = engine.Check(Indicators.Load("192.0.2.1\n"));
            Assert.Single(rows);
            Assert.Equal("unknown", rows[0].Verdict);
            Assert.Equal(3, ExitCodes.Check(rows));
            Assert.NotEmpty(engine.Notices);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task Async_check_matches()
    {
        var dir = Directory.CreateTempSubdirectory("butcherbird-");
        try
        {
            using var engine = CheckEngine.FromToml(QuietToml(Path.Combine(dir.FullName, "cache.sqlite")));
            var rows = await engine.CheckAsync(Indicators.Load("evil.example\n"));
            Assert.Equal("evil.example", rows[0].Ioc.Value);
            Assert.Equal(3, ExitCodes.Check(rows));
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task Report_dry_run_sends_nothing()
    {
        var dir = Directory.CreateTempSubdirectory("butcherbird-");
        try
        {
            using var engine = ReportEngine.FromToml(QuietToml(Path.Combine(dir.FullName, "cache.sqlite")));
            Assert.False(engine.HasReporters());
            var rows = await engine.RunAsync(Indicators.Load("https://phish.example/login\n"));
            Assert.Empty(rows);
            Assert.Equal(0, ExitCodes.Report(rows));
            Assert.Contains(engine.Notices, notice => notice.Contains("skipped", StringComparison.Ordinal));
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public void Evidence_pack_is_local()
    {
        var dir = Directory.CreateTempSubdirectory("butcherbird-");
        try
        {
            Evidence.Write(dir.FullName, Indicators.Load("evil.example\n"));
            var pdf = File.ReadAllBytes(Path.Combine(dir.FullName, "evidence.pdf"));
            var markdown = File.ReadAllText(Path.Combine(dir.FullName, "evidence.md"));
            Assert.True(pdf.Length >= 4 && pdf[0] == (byte)'%' && pdf[1] == (byte)'P');
            Assert.Contains("evil.example", System.Text.Encoding.ASCII.GetString(pdf), StringComparison.Ordinal);
            Assert.Contains("did not submit", markdown, StringComparison.Ordinal);
            Assert.Contains("ic3.gov", markdown, StringComparison.Ordinal);
        }
        finally
        {
            dir.Delete(true);
        }
    }
}
