# Replace Parser

> **Tool forensic per Screen Sharer Minecraft** — rileva sostituzioni di file e cheat usando esclusivamente il journal NTFS USN e altri artefatti nativi di Windows.
>
> *Made by yungestlavi*

---

## 📥 Download

Scarica l'ultima versione dalla pagina [**Releases**](https://github.com/yungestlavi/ReplaceParser/releases).

È **un singolo file `SSForensic.exe`** self-contained: include già il runtime .NET e le regole di rilevamento, **non devi installare nulla**. Scaricalo e fai doppio click (richiede di essere eseguito come amministratore — il manifest lo richiede automaticamente).

---

## 🔍 Cosa fa

Replace Parser ricostruisce, dal momento dell'**ultimo boot del PC**, ogni operazione di sostituzione/rinomina di file rilevante ai fini di uno Screen Share su Minecraft, e per ciascuna ti dice se il file *originale* era pulito, se il *rimpiazzo* è una cheat conosciuta, se l'estensione è camuffata e se la firma digitale è valida.

### Cosa controlla

| Controllo | Dove guarda | Cosa rileva |
|---|---|---|
| **USN Journal** | NTFS Change Journal del drive scelto | Ogni creazione / rinomina / sovrascrittura di file dall'ultimo boot |
| **Magic bytes vs estensione** | I primi byte di ogni file flaggato | `.jar` che in realtà sono `.exe`, `.png` che sono PE, ecc. (extension spoofing) |
| **Regole YARA** | I file flaggati | Pattern noti di cheat client (Vape, LiquidBounce, Wurst, Impact, Aristois, Meteor, Pyro/Slinky, ecc.) e marker di injection/native agent |
| **Firma digitale approfondita** | Authenticode + catena X509 + WinTrust | Distingue VALID / UNSIGNED / EXPIRED / SELF-SIGNED / UNTRUSTED / INVALID — supporta anche i file catalog-signed di Windows |
| **Servizi forensi** | Service Control Manager | Stato di 10 servizi (SysMain, PcaSvc, DPS, DcomLaunch, PlugPlay, Schedule, BAM, DiagTrack, Appinfo, EventLog) — se uno è fermo è un possibile tentativo di anti-forensics |
| **Java attivo al momento** | Heuristica processi | Marca le sostituzioni avvenute mentre `java.exe` / `javaw.exe` era in esecuzione (= Minecraft aperto) |

### Falsi positivi

Replace Parser ha più livelli di filtro per ridurre i falsi positivi:
- blacklist di estensioni di sistema (.tmp, .log, .etl, …);
- whitelist dei signer Microsoft / vendor noti (Mojang, Microsoft, ecc.);
- esclusione delle cartelle Windows / WinSxS / Installer / WindowsApps / servicing;
- esclusione dei batch di file con identico timestamp generati da processi di sistema;
- riconoscimento dei file legit del client Minecraft.

---

## ▶️ Come usarlo

1. **Avvia** `SSForensic.exe` (accetta l'elevazione UAC — serve per leggere il journal NTFS).
2. **Drive**: per default `C`. Cambialo solo se Minecraft / il cheat girano su un altro disco.
3. **Estensioni**: scegli le estensioni da scansionare. Sono attive di default `.exe .jar .dll .py .bat`. Le altre (`.ps1 .vbs .js .class .pyc .cmd .lua .sys`) sono opzionali. La casella *"Modified extensions (may false flag)"* attiva un controllo aggressivo sulle estensioni non standard — utile ma rumoroso.
4. **RUN ANALYSIS**. Al centro della finestra appare il cerchio di caricamento con la percentuale. La scansione parte dall'ultimo boot.
5. **Risultati**: ogni riga è una sostituzione rilevata. Colori in colonna `Trust`:
   - 🟢 **Legit** — file firmato e valido
   - 🟠 **Unsigned** — non firmato
   - 🔵 **Cheat** — match con regola YARA cheat
   - 🟣 **ExtSpoofed** — estensione camuffata
6. **Filtri** sotto la barra estensioni: All / Renames / Cheats / Spoofed / Unsigned / Legit.
7. Clicca una riga → in basso vedi i dettagli: file originale, file rimpiazzo, hash SHA-256, **verdetto firma** completo, YARA matches, e la timeline USN con le ragioni esatte (RENAME_OLD_NAME, RENAME_NEW_NAME, DATA_OVERWRITE, FILE_CREATE…).

### Bottoni in alto a destra

- **SERVICES** — apre la pagina di stato dei 10 servizi forensi (verde = ok, arancione = pausa/transizione, rosso = fermo o non installato).
- **CHECK UPDATES** — interroga questa stessa pagina GitHub: se è uscita una versione più nuova, ti chiede se vuoi installarla, scarica il pacchetto, chiude l'app, sostituisce i file e riavvia il tool.

---

## 🧰 Compilare dai sorgenti

Servono **Windows 10/11 x64** e il **.NET 8 SDK**.

```powershell
git clone https://github.com/yungestlavi/ReplaceParser.git
cd ReplaceParser
dotnet publish SSForensic/SSForensic.csproj -c Release -r win-x64 --self-contained true
```

L'output è in `SSForensic/bin/Release/net8.0-windows/win-x64/publish/`.

---

## 🛠️ Troubleshooting

| Problema | Soluzione |
|---|---|
| "Devi installare .NET" all'avvio | Scarica `SSForensic.exe` dalle Releases (è self-contained, non richiede .NET). |
| L'app non vede il journal USN | Avvia come amministratore (il manifest lo richiede di default). |
| Nessun risultato | È normale se da ultimo boot non c'è stata nessuna scrittura sul drive. Apri qualcosa (anche solo Minecraft) e rilancia. |
| Falso positivo su un file di sistema | Aprime un issue allegando lo screenshot del pannello dettagli. |

---

## 📂 Struttura del progetto

```
SSForensic/
├── App.xaml / App.xaml.cs        # Bootstrap WPF + crash logger globale
├── Forensics/
│   ├── UsnJournalReader.cs       # Lettura nativa del journal NTFS via DeviceIoControl
│   └── EventLogReader.cs
├── Models/ForensicModels.cs      # Record di replace, evidenze, trust
├── Services/
│   ├── ForensicAnalyzer.cs       # Motore principale, multi-filtro anti falsi-positivi
│   ├── SignatureVerifier.cs      # Authenticode + X509 chain + WinTrust
│   ├── UpdateChecker.cs          # Self-update via GitHub Releases API
│   ├── YaraEngine.cs             # Scanner YARA managed
│   └── FileHasher.cs             # SHA-256
├── Rules/cheats.yar              # Regole YARA built-in
├── ViewModels/
│   ├── MainViewModel.cs
│   └── ServicesViewModel.cs
└── Views/
    ├── MainWindow.xaml
    └── ServicesWindow.xaml
```

---

## 📜 Licenza

Uso personale e non commerciale. Vedi le release per i dettagli di ogni versione.
