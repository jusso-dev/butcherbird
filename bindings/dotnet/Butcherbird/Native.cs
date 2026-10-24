using System.Reflection;
using System.Runtime.InteropServices;

namespace Butcherbird;

/// <summary>
/// Calls into butcherbird-ffi. The caller frees returned strings inside <see cref="Take"/>.
/// </summary>
internal static partial class Native
{
    private const string Lib = "butcherbird_ffi";

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!libraryName.Contains(Lib, StringComparison.Ordinal))
            return IntPtr.Zero;
        var configured = Environment.GetEnvironmentVariable("BUTCHERBIRD_NATIVE");
        if (!string.IsNullOrEmpty(configured))
            return NativeLibrary.Load(configured);
        return IntPtr.Zero;
    }

    internal static string Take(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            throw new ButcherbirdException("empty native result");
        try
        {
            return Marshal.PtrToStringUTF8(ptr) ?? "";
        }
        finally
        {
            bb_free(ptr);
        }
    }

    internal static string Call(IntPtr result, IntPtr error)
    {
        if (error != IntPtr.Zero)
        {
            var message = Take(error);
            if (result != IntPtr.Zero)
                bb_free(result);
            throw new ButcherbirdException(message);
        }
        return Take(result);
    }

    internal static IntPtr CallHandle(IntPtr result, IntPtr error)
    {
        if (error != IntPtr.Zero)
            throw new ButcherbirdException(Take(error));
        if (result == IntPtr.Zero)
            throw new ButcherbirdException("empty native result");
        return result;
    }

    internal static int CallCode(int code, IntPtr error)
    {
        if (error != IntPtr.Zero)
            throw new ButcherbirdException(Take(error));
        return code;
    }

    [LibraryImport(Lib)]
    internal static partial void bb_free(IntPtr ptr);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_parse_ioc(string text, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_load_iocs(string text, string inputFormat, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_check_engine_new(string toml, string? profile, string? envJson, out IntPtr error);

    [LibraryImport(Lib)]
    internal static partial void bb_check_engine_free(IntPtr engine);

    [LibraryImport(Lib)]
    internal static partial IntPtr bb_check_engine_notices(IntPtr engine, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_check_engine_check(IntPtr engine, string iocsJson, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_report_engine_new(string toml, string? profile, string? envJson, out IntPtr error);

    [LibraryImport(Lib)]
    internal static partial void bb_report_engine_free(IntPtr engine);

    [LibraryImport(Lib)]
    internal static partial IntPtr bb_report_engine_notices(IntPtr engine, out IntPtr error);

    [LibraryImport(Lib)]
    internal static partial int bb_report_engine_has_reporters(IntPtr engine, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr bb_report_engine_run(IntPtr engine, string iocsJson, int submit, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int bb_check_exit_code(string reportsJson, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int bb_report_exit_code(string rowsJson, out IntPtr error);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int bb_write_evidence_pack(
        string directory,
        string iocsJson,
        string? templatesDir,
        out IntPtr error);
}
