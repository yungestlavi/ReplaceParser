# Replace Parser

Replace Parser is a forensic helper for Minecraft screen shares. It reconstructs the file replacements and renames that happened on a machine since the last boot, then tells you, for each one, whether the file looks like a known cheat, whether its extension has been faked, and whether its digital signature actually checks out.

It was built around one idea: a screen sharer shouldn't have to trust the suspect's word about what a file is. The journal that NTFS keeps doesn't lie, and neither does an Authenticode signature, so the tool leans on those instead of on file names or timestamps that anyone can edit.

Made by yungestlavi.

## Download

Grab the latest build from the [Releases](https://github.com/yungestlavi/ReplaceParser/releases) page. Each release is a single `SSForensic.exe`. The .NET runtime and the detection rules are baked into that one file, so there is nothing to install and no extra folder to keep next to it. Download it, right click, run as administrator. The manifest already requests elevation, so Windows will prompt for it on its own. The elevation is needed to read the NTFS change journal; without it the scan comes back empty.

## What it actually looks at

The tool does not scan the whole disk. It reads the NTFS USN journal, which records every create, rename and overwrite on the volume, and works backwards from there. Everything else hangs off that list.

- **USN journal.** This is the spine of the analysis. The journal gives an ordered record of what changed and when, going back to the last boot, so a file that was swapped in mid-session shows up with the rename and overwrite reasons attached.
- **Magic bytes versus extension.** For every flagged file the first bytes are checked against the claimed extension. A `.jar` that is really a PE executable, or a `.png` that starts with `MZ`, gets marked as spoofed.
- **YARA rules.** Flagged files are matched against a built-in rule set covering the common client families (Vape, LiquidBounce, Wurst, Impact, Aristois, Meteor and others) along with generic injection and native-agent markers.
- **Digital signatures.** This goes further than reading the certificate subject. The tool pulls the Authenticode certificate, builds and validates the X509 chain, checks the validity dates, and then calls the Windows trust API (WinVerifyTrust) for the authoritative verdict. The result lands in one of a few buckets: valid, unsigned, expired, self-signed, untrusted, or invalid. Catalog-signed Windows binaries, which have no embedded certificate, are recognised correctly instead of being thrown in with the unsigned files.
- **Forensic services.** A separate page reports the live state of ten Windows services that produce execution artefacts, including the time their host process started. If one of them is stopped, that is worth a second look, because turning a service off is a way to stop it from recording what ran. SysMain gets an extra host-process health check, described below.
- **Java running at the time.** Replacements that happened while `java.exe` or `javaw.exe` was alive are flagged separately, since that usually means Minecraft was open when the swap took place.

## Cutting down false positives

A naive version of this tool would flag half of Windows. Several filters keep that from happening: system extensions like `.tmp`, `.log` and `.etl` are ignored, files signed by Microsoft, Mojang and other known vendors are trusted, and the Windows, WinSxS, Installer, WindowsApps and servicing directories are skipped. Batches of files written with identical timestamps by a system process are treated as automated rather than manual, and the known-good Minecraft client files are recognised on sight. None of this is perfect, so if something legitimate still gets flagged, the details panel will usually make it obvious why.

## Using it

1. Run `SSForensic.exe` as administrator.
2. Leave the drive set to `C` unless Minecraft or the suspect file live on another disk.
3. Pick the extensions to scan. `.exe`, `.jar`, `.dll`, `.py` and `.bat` are on by default. The rest (`.ps1`, `.vbs`, `.js`, `.class`, `.pyc`, `.cmd`, `.lua`, `.sys`) are optional. The "Modified extensions" checkbox turns on a more aggressive check against non-standard extensions; it catches more but it is noisier.
4. Press Run Analysis. A loading indicator with a percentage appears in the middle of the window while the scan runs. It starts from the last boot.
5. Read the results. Each row is one detected replacement. The Trust column is colour coded: green for a file that is signed and valid, orange for unsigned, blue for a YARA cheat match, purple for a spoofed extension.
6. Use the filter chips under the extension bar to narrow things down: all, renames, cheats, spoofed, unsigned, legit.
7. Click a row to open the detail panel at the bottom. It shows the original file, the replacement, the SHA-256 hash, the full signature verdict, any YARA matches, and the USN timeline with the exact reasons (rename old name, rename new name, data overwrite, file create, and so on).

The two buttons in the top right are Services, which opens the service status page, and Check Updates, which is covered below.

## The services page

The Services button opens a window listing the ten monitored services with a coloured dot each: green when running, orange when paused or in a transitional state, red when stopped or missing. Every entry also shows its start type and the time its host process started, which is useful for spotting a service that was restarted in the middle of a session.

SysMain is treated specially. Because it builds the prefetch and SuperFetch trail of everything that runs, a SysMain that has been frozen or suspended is a real blind spot. There is a limit to what any program can see here from user mode, and the tool is honest about that: it cannot inspect the service's kernel threads or reach inside `sechost.dll`. What it does instead is probe the svchost process that hosts SysMain and report what is genuinely observable, namely that the host process exists, how many threads it has, whether any of them are in a suspended wait state, whether the process reports as responding, and whether the standard service host module is mapped. If every thread in the host is suspended, the tool says so and downgrades the service to orange even when the service manager still calls it "running", because in that state it is not updating the trail.

## Updating

Check Updates queries this repository's releases. If a newer version is published it offers to download it, and on confirmation it pulls the new build, closes the app, replaces the executable and starts it again. The check is deliberately manual rather than automatic on launch, so the tool never reaches out on its own without being asked.

## Building from source

You need Windows 10 or 11 on x64 and the .NET 8 SDK.

```
git clone https://github.com/yungestlavi/ReplaceParser.git
cd ReplaceParser
dotnet publish SSForensic/SSForensic.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The single-file executable ends up in `SSForensic/bin/Release/net8.0-windows/win-x64/publish/`.

## Troubleshooting

If the app says it needs .NET, you are not running the release build. The release executable is self-contained and needs nothing installed; download it from the Releases page.

If the scan finds nothing, that is usually correct. The journal only goes back to the last boot, so on a freshly booted machine with little activity there may be nothing to report. Run something, even just Minecraft, and scan again.

If the journal cannot be read at all, the app is almost certainly not elevated. Run it as administrator.

If a system file is flagged that you believe is legitimate, open an issue and attach a screenshot of the detail panel so the filter can be improved.

## Project layout

```
SSForensic/
  App.xaml, App.xaml.cs          WPF bootstrap and global crash logging
  Forensics/
    UsnJournalReader.cs          Native NTFS journal reads via DeviceIoControl
    EventLogReader.cs
  Models/ForensicModels.cs       Replace records, evidence, trust types
  Services/
    ForensicAnalyzer.cs          Main engine and false-positive filtering
    SignatureVerifier.cs         Authenticode, X509 chain and WinVerifyTrust
    UpdateChecker.cs             Self-update through the GitHub releases API
    YaraEngine.cs                Managed YARA-subset scanner
    FileHasher.cs                SHA-256
  Rules/cheats.yar               Built-in YARA rules (embedded into the exe)
  ViewModels/
    MainViewModel.cs
    ServicesViewModel.cs
  Views/
    MainWindow.xaml
    ServicesWindow.xaml
```

## License

For personal, non-commercial use. See individual releases for per-version notes.
