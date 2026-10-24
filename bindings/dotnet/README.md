# Butcherbird for C#

The package calls the Rust core through the C ABI in `crates/ffi`. Parsing, scoring, reporting and evidence packs are not reimplemented here. The generated header is `crates/ffi/include/butcherbird.h`.

## Install from a checkout

.NET 8 SDK, and Rust 1.85 or newer.

```sh
cargo build -p butcherbird-ffi
export BUTCHERBIRD_NATIVE="$PWD/target/debug/libbutcherbird_ffi.dylib"
```

On Linux the file is `libbutcherbird_ffi.so`. On Windows it is `butcherbird_ffi.dll`. `BUTCHERBIRD_NATIVE` is the full path the P/Invoke resolver loads.

## Quick start

```csharp
using Butcherbird;

var toml = File.ReadAllText("butcherbird.toml");
using var engine = CheckEngine.FromToml(toml);
var iocs = Indicators.Load(File.ReadAllText("indicators.txt"));
var rows = await engine.CheckAsync(iocs);
Console.WriteLine($"{rows[0].Verdict} {ExitCodes.Check(rows)}");
```

`Check` is the blocking call. `CheckAsync` runs that call on the thread pool. A cancellation token stops the call from starting. It does not abort a call that has started.

`FromToml` takes the file text, an optional profile name, and an optional env dictionary. The dictionary is the only environment the core reads, so a missing key is a missing key even if your shell has one set.

## Reports

```csharp
using var reports = ReportEngine.FromToml(toml);
var rows = await reports.RunAsync(iocs); // dry run
```

`RunAsync(iocs, submit: true)` sends the report. The library does not prompt. Confirm before you pass it. A dry run still queries RDAP when the email reporter is configured, and it does not open SMTP.

`Evidence.Write(directory, iocs)` writes `evidence.md`, `evidence.csv` and `evidence.pdf`. Nothing in that pack is submitted.

Lookups and live reports send indicators to other services. Read `docs/responsible-use.md` before using real data.
