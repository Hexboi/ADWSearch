# ADWSearch

ADWSearch è un programma da riga di comando per consultare **Active Directory tramite ADWS** (Active Directory Web Services), normalmente sulla porta TCP **9389**, invece di usare il protocollo LDAP.

Serve a raccogliere informazioni sul dominio, individuare configurazioni da approfondire durante un assessment ed esportare dati per successive analisi. Puoi scegliere un controllo già pronto oppure eseguire una ricerca personalizzata.

Il programma opera **in sola lettura**: non modifica oggetti, permessi o configurazioni del dominio. I risultati dipendono dai diritti dell'account utilizzato. Usalo esclusivamente in ambienti per i quali hai un'autorizzazione.

## Quali controlli esegue

Scegli un controllo con `--preset NOME`:

| Preset | Cosa mostra |
| --- | --- |
| `forest-level` | Il livello funzionale del dominio indicato come base. |
| `maq` | La quota che regola l'aggiunta di computer al dominio. |
| `asrep` | Gli account utente senza preautenticazione Kerberos, da approfondire per il rischio AS-REP roasting. |
| `kerberoastable` | Gli account utente abilitati con SPN, da approfondire per il rischio Kerberoasting. |
| `spn` | Gli oggetti con servizi registrati tramite SPN, inclusi utenti e computer. |
| `writable` | I diritti effettivi esposti per l'account su attributi, permessi e creazione di oggetti figli, senza tentare modifiche. |
| `dns-dump` | I record DNS presenti nelle partizioni di Active Directory accessibili all'account. |

Sono controlli di configurazione: **non estraggono password, non eseguono roasting e non provano automaticamente la sfruttabilità delle condizioni rilevate**.

Con `--dump` puoi inoltre:

- `buildcache`: creare una cache JSON degli identificativi degli oggetti.
- `showstats`: leggere le statistiche della cache, senza collegarti al dominio.
- `bhdump`: esportare oggetti e relazioni in JSON per analisi con BloodHound; non raccoglie sessioni o informazioni locali dagli host.
- `certdump`: raccogliere CA, template e certificati attendibili di AD CS e segnalare possibili configurazioni rischiose. Non richiede certificati e non verifica endpoint HTTP/RPC o impostazioni locali delle CA.

## Installazione

Servono **Python 3.10 o successivo**, ADWS raggiungibile sul controller e credenziali di dominio valide oppure una cache Kerberos valida.

Apri PowerShell nella cartella di ADWSearch, dove si trova `pyproject.toml`, ed esegui:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\Activate.ps1
```

Le dipendenze sono installate automaticamente; l'intervallo supportato di impacket è `>=0.13.1,<0.14`. Se non puoi attivare l'ambiente, sostituisci `adwsearch` negli esempi con `.\.venv\Scripts\python.exe -m adwsearch`.

Su Linux/macOS usa `python3 -m venv .venv`, attiva l'ambiente con `source .venv/bin/activate` e installa con `python -m pip install .`.

## Come eseguirlo

Gli esempi seguenti sono per PowerShell. Sostituisci controller, account e base di ricerca con i valori del tuo ambiente. `-W` chiede la password senza inserirla nella riga di comando.

Anche gli esempi di `adwsearch --help` usano `-W` per le password. Nell'aiuto CLI i comandi sono spezzati su più righe con la sintassi POSIX: in PowerShell riportali su una sola riga oppure usa gli esempi di questo README.

### Ricerca personalizzata

Per leggere gli utenti e gli attributi indicati:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" "(sAMAccountType=805306368)" sAMAccountName memberOf
```

- `-H`: nome del domain controller.
- `-u`: account; puoi anche usare `-u alice -d corp.local`.
- `-b`: base di ricerca, obbligatoria per le operazioni online.
- Il filtro tra virgolette sceglie gli oggetti; i nomi successivi scelgono gli attributi.

Senza filtro e attributi vengono cercati tutti gli oggetti sotto la base indicata e letti gli attributi disponibili. L'output predefinito è LDIF, un formato testuale per dati di directory.

Se il nome del controller non viene risolto, aggiungi `--dc-ip 10.10.1.10`, mantenendo il nome corretto in `-H`.

### Controlli pronti e salvataggio dei risultati

Per cercare account senza preautenticazione Kerberos:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --preset asrep
```

Sostituisci `asrep` con un altro preset della tabella. Non aggiungere filtri o attributi personalizzati a un preset: la ricerca è già definita.

Il preset `kerberoastable` elenca account utente abilitati con SPN e i relativi metadati: **non richiede ticket per il roasting e non raccoglie hash da decifrare**. `msDS-SupportedEncryptionTypes` descrive la configurazione dell'account, non l'algoritmo di un ticket effettivo. Anche scegliendo `-o json`, il risultato non è un input per Hashcat o John the Ripper.

Per salvare gli SPN in JSON:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --preset spn -o json --outfile spns.json
```

### Autenticazione Kerberos

Occorre una cache già valida e coerente con l'account e il dominio. ADWSearch non acquisisce automaticamente un TGT dalla password.

```powershell
$env:KRB5CCNAME = "C:\Percorso\alice.ccache"
adwsearch -H dc01.corp.local -u alice@corp.local -k -b "DC=corp,DC=local" --preset spn
```

Con `-k`, l'opzione `--kerberos-enctype` seleziona la policy:

- `aes`: predefinita; usa AES senza fallback a RC4.
- `rc4`: richiede esplicitamente RC4 per compatibilità legacy.
- `auto`: prova AES e ripiega su RC4 solo se il KDC segnala algoritmi non supportati, non per errori di autenticazione, timeout o integrità.

Preferisci AES: RC4 conserva limiti di sicurezza propri del protocollo legacy. Nessuna policy del controller viene modificata. Per NTLM è disponibile anche `--hashes ":HASH_NT"` al posto di `-W`: sostituisci `HASH_NT` con un hash NT di 32 caratteri esadecimali e trattalo come una credenziale.

### Esportazione del dominio e di AD CS

Prima crea la cache:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump buildcache --cachefile corp-cache.json
```

Poi scegli l'esportazione desiderata, usando la stessa cache del dominio:

```powershell
# Oggetti e relazioni per BloodHound
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump bhdump --cachefile corp-cache.json --outdir bh-out

# Configurazione di AD CS e possibili criticità
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump certdump --cachefile corp-cache.json --outdir adcs-out

# Statistiche locali, senza connessione al dominio
adwsearch --dump showstats --cachefile corp-cache.json
```

Non combinare `--dump` con preset, filtri o attributi personalizzati. Proteggi cache ed esportazioni: possono contenere informazioni sensibili sul dominio.

## Opzioni utili e limiti

- `--dry-run`: mostra la ricerca prevista senza contattare il controller; restano necessari i prerequisiti della modalità scelta.
- `-s base|one|sub`: cerca sull'oggetto base, nei figli diretti o nel sottoalbero; il valore predefinito è `sub`.
- `--page-size N` e `-z N`: impostano la dimensione delle pagine e il limite totale dei risultati.
- `--timeout 30`, `-v` e `-vv`: regolano il timeout del socket e i dettagli diagnostici.
- `--sleep 1 --jitter 2`: aggiunge una pausa tra richieste consecutive.
- `--socks 127.0.0.1:1080`: instrada ADWS tramite SOCKS5, non automaticamente il traffico verso il KDC.

Preferisci `-W` a `-w PASSWORD`: password e hash passati come argomenti possono essere visibili nell'elenco dei processi e restare nella cronologia della shell. `-w` rimane disponibile per compatibilità, ma non è usato negli esempi di autenticazione con password. Prima di usare un'esportazione controlla il codice di uscita: `0` indica successo, `1` un errore operativo gestito e `2` argomenti o prerequisiti non validi. Un risultato vuoto non dimostra l'assenza di criticità.

AES, RC4 esplicito e `auto` con AES sono stati collaudati su un domain controller Windows Server 2019, comprese letture Resource/Get e ricerche successive. Il fallback automatico a RC4 è verificato nei test offline, non forzato sul KDC. SOCKS5, importazione effettiva in BloodHound e compatibilità con altre versioni di Windows Server non sono stati collaudati.

Per tutte le opzioni esegui `adwsearch --help`.

## Sviluppo e test

Dalla cartella del progetto, con l'ambiente virtuale attivo:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -m "not lab"
python -m ruff check adwsearch tests
```

I test offline usano dati sintetici, incluse password e chiavi fittizie: non sono credenziali operative. I test di integrazione sono facoltativi e richiedono un ambiente autorizzato configurato esplicitamente; consulta [tests/lab/README.md](tests/lab/README.md). La cartella non include credenziali, ticket, dump, ambienti virtuali o report del laboratorio di sviluppo.

## Licenza e crediti

ADWSearch è sviluppato da [Hexboi](https://github.com/Hexboi) e il codice originale è distribuito sotto [MPL-2.0](LICENSE), anche per uso professionale e commerciale.
Crediti e licenze delle parti di terze parti sono raccolti in [NOTICE](NOTICE).
