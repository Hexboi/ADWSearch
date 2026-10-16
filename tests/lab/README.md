# Optional integration tests

These are reusable test sources, not development-lab results or configuration.
All usernames, passwords, keys and hashes in the offline test fixtures are
synthetic. Never replace them with real credentials.

The normal offline suite does not contact a domain controller:

```powershell
python -m pytest -m "not lab"
```

Live tests require explicit opt-in with `ADWSEARCH_LAB=1`. Only run them against
a domain you are authorized to assess. They perform directory enumeration and
may create local exports in pytest's temporary directory. They do not modify
domain configuration. The LDAP comparison requires Windows PowerShell with
System.DirectoryServices.Protocols and network access to LDAP as well as ADWS.

Configure these environment variables in the current session:

| Variable | Value |
| --- | --- |
| `ADWSEARCH_LAB_HOST` | Actual domain-controller FQDN |
| `ADWSEARCH_LAB_IP` | Actual domain-controller IP address |
| `ADWSEARCH_LAB_BASE` | Domain distinguished name |
| `ADWSEARCH_LAB_DOMAIN` | Account domain |
| `ADWSEARCH_LAB_USER` | Authorized account name |
| `ADWSEARCH_LAB_PASSWORD` | Password supplied through a secure session mechanism |
| `ADWSEARCH_LAB` | `1`, only when ready to run live tests |

Do not put a real password in a command, script, source file, or shared shell
history. Environment variables are not a secret vault: clear them when finished.
The built-in `corp.example` / `192.0.2.10` defaults are documentation placeholders,
not a working domain; configure every connection variable above.

Optional variables:

- `KRB5CCNAME`: valid AES Kerberos cache for the configured account. Kerberos
  cases are skipped if it is absent. Do not commit the cache.
- `ADWSEARCH_LAB_SPN`: explicit SPN, otherwise `host/<controller FQDN>`.
- `ADWSEARCH_LAB_TIMEOUT`: socket timeout in seconds, default `10`.
- `ADWSEARCH_LAB_SOCKS`: optional SOCKS5 proxy; its test is skipped if absent.

After configuring the session:

```powershell
python -m pytest -m lab
```

The Kerberos suite includes an explicit RC4 case: this needs controller/account
support and does not enable RC4 on the domain. AD CS checks need a suitable
Enterprise CA; absent prerequisites produce skips. The suite does not force
automatic AES-to-RC4 fallback on a KDC or perform an actual BloodHound import.

Keep generated caches, exports, tickets and test logs outside the source tree.
The ignore rules are a safeguard, not a guarantee that arbitrary output paths
will be excluded from a future commit.
