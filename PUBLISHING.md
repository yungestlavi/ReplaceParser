# Come pubblicare questo repo e fare la prima release

> Tutto è già configurato. Devi solo fare i passaggi qui sotto.

## 1) Crea il repo vuoto su GitHub

Vai su https://github.com/new e crea un repo chiamato esattamente:

    ReplaceParser

con owner **yungestlavi**. **Non** inizializzarlo con README/license/gitignore (li abbiamo già).

## 2) Pusha il codice

Apri PowerShell dentro questa cartella (quella che contiene `SSForensic/`, `README.md`, `.github/`) ed esegui:

```powershell
git init -b main
git add .
git commit -m "Initial commit: Replace Parser v1.2.0"
git remote add origin https://github.com/yungestlavi/ReplaceParser.git
git push -u origin main
```

Se è la prima volta che usi git su questo PC ti chiederà di autenticarti — segui il prompt (browser / token).

## 3) Crea la prima release

Sempre dalla stessa cartella:

```powershell
git tag v1.2.0
git push origin v1.2.0
```

Ora vai su https://github.com/yungestlavi/ReplaceParser/actions: vedrai partire il workflow **Build & Release**.

Quando finisce (~3-5 min):
- nella tab **Releases** del tuo repo apparirà **Replace Parser v1.2.0**;
- in allegato troverai `ReplaceParser-v1.2.0-win-x64.zip` (l'exe self-contained pronto, ~70-100 MB);
- chiunque scarica quel zip, lo estrae, fa doppio click su `SSForensic.exe` e parte.

## 4) Release successive

Quando vorrai pubblicare una nuova versione:

1. modifica il codice;
2. aggiorna la riga `<Version>1.2.0</Version>` in `SSForensic/SSForensic.csproj` (es. `1.3.0`);
3. commit + push;
4. crea un nuovo tag:
   ```powershell
   git tag v1.3.0
   git push origin v1.3.0
   ```
5. Actions builda e pubblica da solo.

Da quel momento il bottone **CHECK UPDATES** dentro l'app, su qualsiasi PC, vedrà la v1.3.0, la scaricherà e installerà al volo.

## Note

- Il numero del tag (`v1.3.0`) **deve combaciare** con `<Version>` nel csproj, altrimenti l'auto-update si comporta in modo strano (l'app pensa di avere già la versione nuova o sempre quella vecchia).
- Il workflow è in `.github/workflows/release.yml`. Se vuoi cambiare il formato dello zip o la piattaforma, modifichi lì.
- Lo stato dell'auto-update si vede nella status bar in basso a destra dell'app.
