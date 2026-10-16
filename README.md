# ADWSearch

ADWSearch è uno strumento per consultare **Active Directory tramite ADWS** (Active Directory Web Services), normalmente sulla porta TCP **9389**, invece di usare il protocollo LDAP.

Serve a raccogliere informazioni sul dominio, individuare configurazioni da approfondire durante un assessment ed esportare dati per successive analisi. 

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

Supportato a partire da **Python 3.10**.

```powershell
python -m pip install .
```

## Come eseguirlo

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

Per salvare in JSON:

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

Preferisci AES: RC4 conserva limiti di sicurezza propri del protocollo legacy. Nessuna policy del controller viene modificata. Per NTLM è disponibile anche `--hashes ":HASH_NT"` al posto di `-W`.

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

## Sviluppo e test

Dalla cartella del progetto, con l'ambiente virtuale attivo:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -m "not lab"
python -m ruff check adwsearch tests
```

I test offline usano dati fittizi, incluse password e chiavi fittizie: non sono credenziali operative. I test di integrazione sono facoltativi e richiedono un ambiente autorizzato configurato esplicitamente; consulta [tests/lab/README.md](tests/lab/README.md).

## Licenza e crediti

ADWSearch è sviluppato da [Hexboi](https://github.com/Hexboi) e il codice originale è distribuito sotto [MPL-2.0](LICENSE), anche per uso professionale e commerciale.
Crediti e licenze delle parti di terze parti sono raccolti in [NOTICE](NOTICE).
