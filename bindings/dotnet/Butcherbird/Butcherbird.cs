using System.Text.Json;
using System.Text.Json.Serialization;

namespace Butcherbird;

/// <summary>Failure from the Rust core. API keys are already masked.</summary>
public sealed class ButcherbirdException : Exception
{
    public ButcherbirdException(string message) : base(message) { }
}

public sealed record Ioc(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("value")] string Value,
    [property: JsonPropertyName("raw")] string Raw);

public sealed record SourceRow(
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("verdict")] string? Verdict,
    [property: JsonPropertyName("confidence")] int? Confidence,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("cached")] bool Cached);

public sealed record CheckReport(
    [property: JsonPropertyName("ioc")] Ioc Ioc,
    [property: JsonPropertyName("verdict")] string Verdict,
    [property: JsonPropertyName("confidence")] int Confidence,
    [property: JsonPropertyName("sources")] IReadOnlyList<SourceRow> Sources);

public sealed record ReportRow(
    [property: JsonPropertyName("destination")] string Destination,
    [property: JsonPropertyName("ioc_type")] string IocType,
    [property: JsonPropertyName("ioc_value")] string IocValue,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("payload")] string Payload,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary>Parsing and bulk load. Both call the Rust core.</summary>
public static class Indicators
{
    public static Ioc? Parse(string text)
    {
        var json = Native.Call(Native.bb_parse_ioc(text, out var error), error);
        return json == "null" ? null : JsonSerializer.Deserialize<Ioc>(json, Json.Options);
    }

    public static IReadOnlyList<Ioc> Load(string text, string format = "auto")
    {
        var json = Native.Call(Native.bb_load_iocs(text, format, out var error), error);
        return JsonSerializer.Deserialize<List<Ioc>>(json, Json.Options) ?? [];
    }
}

/// <summary>
/// Lookups. <see cref="CheckAsync"/> runs the blocking core call on the thread pool.
/// Cancellation stops the call from starting. It does not abort a call that has started.
/// </summary>
public sealed class CheckEngine : IDisposable
{
    private IntPtr _handle;

    private CheckEngine(IntPtr handle, IReadOnlyList<string> notices)
    {
        _handle = handle;
        Notices = notices;
    }

    public IReadOnlyList<string> Notices { get; }

    public static CheckEngine FromToml(
        string toml,
        string? profile = null,
        IReadOnlyDictionary<string, string>? env = null)
    {
        var envJson = env is null ? null : JsonSerializer.Serialize(env, Json.Options);
        var handle = Native.CallHandle(
            Native.bb_check_engine_new(toml, profile, envJson, out var error),
            error);
        var noticesJson = Native.Call(Native.bb_check_engine_notices(handle, out var noticeError), noticeError);
        var notices = JsonSerializer.Deserialize<List<string>>(noticesJson, Json.Options) ?? [];
        return new CheckEngine(handle, notices);
    }

    public CheckReport[] Check(IReadOnlyList<Ioc> iocs)
    {
        ObjectDisposedException.ThrowIf(_handle == IntPtr.Zero, this);
        var json = JsonSerializer.Serialize(iocs, Json.Options);
        var body = Native.Call(Native.bb_check_engine_check(_handle, json, out var error), error);
        return JsonSerializer.Deserialize<CheckReport[]>(body, Json.Options) ?? [];
    }

    public Task<CheckReport[]> CheckAsync(
        IReadOnlyList<Ioc> iocs,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Check(iocs), cancellationToken);
    }

    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (handle != IntPtr.Zero)
            Native.bb_check_engine_free(handle);
        GC.SuppressFinalize(this);
    }

    ~CheckEngine() => Dispose();
}

/// <summary>
/// Reports. <paramref name="submit"/> on <see cref="RunAsync"/> sends with no prompt.
/// The default is a dry run.
/// </summary>
public sealed class ReportEngine : IDisposable
{
    private IntPtr _handle;

    private ReportEngine(IntPtr handle, IReadOnlyList<string> notices)
    {
        _handle = handle;
        Notices = notices;
    }

    public IReadOnlyList<string> Notices { get; }

    public static ReportEngine FromToml(
        string toml,
        string? profile = null,
        IReadOnlyDictionary<string, string>? env = null)
    {
        var envJson = env is null ? null : JsonSerializer.Serialize(env, Json.Options);
        var handle = Native.CallHandle(
            Native.bb_report_engine_new(toml, profile, envJson, out var error),
            error);
        var noticesJson = Native.Call(Native.bb_report_engine_notices(handle, out var noticeError), noticeError);
        var notices = JsonSerializer.Deserialize<List<string>>(noticesJson, Json.Options) ?? [];
        return new ReportEngine(handle, notices);
    }

    public bool HasReporters()
    {
        ObjectDisposedException.ThrowIf(_handle == IntPtr.Zero, this);
        return Native.CallCode(Native.bb_report_engine_has_reporters(_handle, out var error), error) == 1;
    }

    public ReportRow[] Run(IReadOnlyList<Ioc> iocs, bool submit = false)
    {
        ObjectDisposedException.ThrowIf(_handle == IntPtr.Zero, this);
        var json = JsonSerializer.Serialize(iocs, Json.Options);
        var body = Native.Call(
            Native.bb_report_engine_run(_handle, json, submit ? 1 : 0, out var error),
            error);
        return JsonSerializer.Deserialize<ReportRow[]>(body, Json.Options) ?? [];
    }

    public Task<ReportRow[]> RunAsync(
        IReadOnlyList<Ioc> iocs,
        bool submit = false,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Run(iocs, submit), cancellationToken);
    }

    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (handle != IntPtr.Zero)
            Native.bb_report_engine_free(handle);
        GC.SuppressFinalize(this);
    }

    ~ReportEngine() => Dispose();
}

public static class ExitCodes
{
    public static int Check(IReadOnlyList<CheckReport> reports)
    {
        var json = JsonSerializer.Serialize(reports, Json.Options);
        return Native.CallCode(Native.bb_check_exit_code(json, out var error), error);
    }

    public static int Report(IReadOnlyList<ReportRow> rows)
    {
        var json = JsonSerializer.Serialize(rows, Json.Options);
        return Native.CallCode(Native.bb_report_exit_code(json, out var error), error);
    }
}

public static class Evidence
{
    public static void Write(string directory, IReadOnlyList<Ioc> iocs, string? templatesDir = null)
    {
        var json = JsonSerializer.Serialize(iocs, Json.Options);
        Native.CallCode(Native.bb_write_evidence_pack(directory, json, templatesDir, out var error), error);
    }
}

internal static class Json
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
    };
}
