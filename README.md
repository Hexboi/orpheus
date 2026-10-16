# Orpheus

Orpheus è un wrapper CLI e interattivo per Kerberoasting e AS-REP Roasting,
basato su Impacket. Consente di scegliere le KDC options e l'etype richiesto
(AES256 o RC4), mantenendolo distinto dalla credenziale usata per ottenere il
TGT. Usarlo esclusivamente in ambienti autorizzati.

## Modifiche rispetto all’originale

Questa versione deriva da [TrustedSec/Orpheus](https://github.com/trustedsec/orpheus)
e ne conserva le attribuzioni. Le principali modifiche sono:

- **Funzionalità:** AS-REP Roasting, CLI non interattiva con `--dry-run` e
  opzioni per proxychains, oltre alla REPL originale.
- **Compatibilità:** integrazione con Impacket 0.13.x e sostituzione del fork
  completo `kerberosv5.py` con un modulo locale per le estensioni necessarie.
- **Correzioni:** separazione fra credenziali TGT ed etype TGS richiesto,
  validazione degli input, opzioni KDC decimali/hex coerenti e pacing anche
  dopo i tentativi falliti.
- **Affidabilità:** trasporto Kerberos TCP con timeout e letture complete,
  output atomico, controllo delle sovrascritture e codici di uscita espliciti.
- **Test e documentazione:** suite di regressione, test di laboratorio opt-in,
  workflow CI e documentazione aggiornata.

## Installazione

Richiede Python 3.10+. Il file unico include le dipendenze di esecuzione e test.
Installare preferibilmente in un ambiente virtuale:

```text
python -m pip install .
```

Con l'ambiente attivo, il comando `orpheus` è disponibile da qualsiasi cartella:

```text
orpheus --help
```

Per lavorare sui sorgenti senza reinstallare dopo ogni modifica:
`python -m pip install -e .`.


## Avvio rapido

Gli esempi seguenti usano valori fittizi. Kerberoasting con TGS AES256:

```text
orpheus --cred 'lab.local/user:password' --dcip 10.1.1.1 --file spns.txt --enc 18
```

AS-REP Roasting senza autenticazione, da una lista utenti:

```text
orpheus --cred 'lab.local/' --dcip 10.1.1.1 --mode asrep --usersfile users.txt --file asrep.txt --enc 23
```

Una lista utenti contiene un nome per riga. Gli script ignorano righe vuote e
duplicati, preservando l'ordine della prima occorrenza.

## CLI del wrapper

```text
orpheus --help
```

| Flag | Scopo e default |
| --- | --- |
| `--cred` | Obbligatorio: `domain/user[:password]`; `domain/` per una lista AS-REP senza autenticazione. |
| `--dcip` | Obbligatorio: indirizzo del domain controller. |
| `--mode` | `kerb` (default) oppure `asrep`. |
| `--file` | File hash, default `spns.txt` anche in modalità AS-REP. |
| `--usersfile` | Lista utenti per `asrep`; aggiunge `-no-pass` al comando figlio. |
| `--options` | Maschera unsigned a 32 bit, default `0x40810000`. |
| `--enc` | Etype richiesto: `18` AES256 (default) oppure `23` RC4. |
| `--sleep` | Secondi fra tentativi consecutivi, default `0`. |
| `--jitter` | Variazione casuale intera di `±N` secondi, default `0`. |
| `--overwrite` | Consente la sostituzione dell'output esistente. |
| `--proxychains` | Anteposta esecuzione tramite `proxychains`, solo Linux; ignorata su Windows. |
| `--pcconf` | Configurazione passata a `proxychains -f`. |
| `-n`, `--dry-run` | Mostra il comando senza eseguirlo. |

## Modalità interattiva

Avviare senza argomenti:

```text
orpheus
```

| Comando REPL | Effetto |
| --- | --- |
| `cred <valore>`, `dcip <valore>`, `file <percorso>` | Impostano credenziali, DC e output. |
| `0` … `31` | Invertono il bit KDC indicato, numerato da sinistra. |
| `hex <valore>` | Imposta la maschera KDC; accetta anche un intero decimale. |
| `enc` | Alterna AES256 e RC4. |
| `mode` | Alterna Kerberoasting e AS-REP Roasting. |
| `usersfile <percorso>` | Imposta la lista utenti per AS-REP. |
| `sleep <secondi>`, `jitter <secondi>` | Impostano il pacing. |
| `overwrite` | Attiva/disattiva la sostituzione dell'output. |
| `proxychains`, `pcconf <percorso>` | Attivano il prefisso Linux e ne impostano la configurazione. |
| `command` | Mostra il comando costruito, incluse le credenziali. |
| `run` | Esegue il comando corrente. |
| `clear`, `help`, `exit` | Ridisegna lo schermo, mostra i comandi o termina. |


## Codici di uscita

| Codice | Significato |
| ---: | --- |
| `0` | Tutti i target richiesti sono riusciti, oppure enumerazione completata anche senza corrispondenze. |
| `1` | Almeno un risultato e almeno un target fallito o saltato. |
| `2` | Input, file locale o combinazione di opzioni non validi. |
| `3` | Errore Kerberos/LDAP di autenticazione o autorizzazione prima del ciclo sui target. |
| `4` | Errore di rete, protocollo o runtime prima del ciclo sui target. |
| `5` | Richiesta senza risultati riusciti, inclusi tutti i target falliti o saltati. |

## Sviluppo e test

```text
python -m pytest -m "not lab" -q
python -m pip check
```

I test `lab` sono opzionali. Configurare `ORPHEUS_LAB_DC`, `ORPHEUS_LAB_DOMAIN`,
`ORPHEUS_LAB_USERNAME` e `ORPHEUS_LAB_PASSWORD`; per gli scenari dedicati anche
`ORPHEUS_LAB_ASREP_USER` e `ORPHEUS_LAB_SPN_USER`. Eseguirli con
`python -m pytest -m lab -q`. Non salvare credenziali o risultati nel progetto.

| File | Responsabilità |
| --- | --- |
| `pyproject.toml` | Installazione, comando `orpheus` e configurazione dei test. |
| `orpheus.py` | CLI, REPL e avvio dello script figlio. |
| `GetUserSPNs.py` | Enumerazione LDAP SPN, acquisizione TGT e richieste TGS. |
| `GetNPUsers.py` | Enumerazione degli account senza preautenticazione e richieste AS-REP. |
| `orpheus_kerberos.py` | Estensioni Kerberos e trasporto TCP locale con timeout di 10 secondi. |
| `orpheus_runtime.py` | Validazioni, conteggi, codici di uscita e output atomico. |
| `tests/` | Test offline e integrazione di laboratorio. |

## Licenza

I testi GPLv3 di Orpheus e delle licenze Impacket sono conservati in [LICENSE](LICENSE).
Le attribuzioni originali restano nei sorgenti.

This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/) and Fortra (https://www.fortra.com).
