# Replace Parser v1.2 — made by yungestlavi

Tool C# / WPF per individuare **replace di file** su Windows usando ESCLUSIVAMENTE l'USN journal NTFS + fsutil. Modalità rapida, focused, search-friendly.

## Cosa fa

1. Apre il volume in raw (`\\.\C:`) e legge l'intera USN journal via `DeviceIoControl(FSCTL_READ_USN_JOURNAL)`.
2. Filtra sui reason che indicano replace: FILE_CREATE, DATA_OVERWRITE, DATA_TRUNCATION, NAMED_DATA_OVERWRITE/TRUNCATION, RENAME_OLD/NEW_NAME, STREAM_CHANGE.
3. Salta i file di sistema Windows (path-based + signature-based) per ridurre rumore e velocizzare.
4. Estensioni filtrate: `.exe`, `.jar`, `.dll`, `.py`, `.bat`.
5. Per ogni file: SHA-256, signer Authenticode, YARA scan, timestamp Created/Modified/Accessed, evidence USN completa.

## UI v1.2

- **Titolo**: Replace Parser — made by yungestlavi
- **Filter chips cliccabili** in alto: All / Renames / Cheat hits / Spoofed / Unsigned. Click → filtra. Testo bianco su sfondo colorato semi-trasparente.
- **Barra di ricerca** in tempo reale per filename o path.
- **Pannello dettagli in basso** (non a destra): layout orizzontale a 3 colonne (File info | Timestamps + YARA | Timeline USN evidence). Resizable.
- **Filtro giorni** funzionante (range 1-3650).

## Skip Windows files

- Path roots ignorati: WinSxS, System32, SysWOW64, Microsoft.NET, servicing, assembly, Installer, SystemApps, ImmersiveControlPanel, WindowsApps, Windows Defender, Microsoft\Edge.
- Filename prefix ignorati: api-ms-win-*, ext-ms-win-*, Microsoft.*, System.*, vcruntime*, msvcp*, mscor*, ucrtbase*, ntdll*, kernel32*, Windows.*, Microsoft-Windows-*.
- Signature check: se firmato da Microsoft/Windows → skip dal risultato finale.

## YARA Rules (built-in)

`Rules/cheats.yar`: Vape, LiquidBounce, Wurst, Impact, Aristois, Meteor, Pyro/Slinky + pattern generici + JVM native agents + DLL injection markers. Engine managed, niente dipendenze native.

## Requisiti

- Windows 10/11 x64
- .NET 8 SDK
- Esecuzione come Amministratore

## Compilazione

```powershell
cd Replace Parser
dotnet restore
dotnet publish -c Release -r win-x64 --self-contained false
```

Eseguibile in `bin\Release\net8.0-windows\win-x64\publish\SSForensic.exe` (il nome interno è ancora SSForensic.exe).

## Note operative

- Se l'USN è disabilitato: `fsutil usn createjournal m=33554432 a=4194304 C:`
- Tutti i timestamp sono UTC.
- Crash logger attivo: `crash.log` nella cartella dell'exe.

## Changelog

### v1.2
- Rebrand: Replace Parser made by yungestlavi
- Barra di ricerca per filename/path
- Filter chips cliccabili (testo bianco acceso)
- Pulsante All per resettare il filtro
- Pannello dettagli in basso (layout orizzontale 3 colonne)
- Filtro giorni con clamp 1-3650 e applicazione corretta
- Skip Windows system files (path + filename prefix + signer Microsoft)
- Signature verification rapida (cert subject)
- Velocità migliorata grazie agli skip preventivi

### v1.1
- Rimossa dnYara, YARA scanner managed
- Solo USN journal + fsutil
- 23 reason flag USN
- Crash logger

### v1.0
- Versione iniziale con event log, prefetch, signature, format detection (rimossi in v1.1)
