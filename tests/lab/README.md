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
- `ADWSEARCH_LAB_SOCKS`: optional `[socks4://|socks5://]HOST:PORT` proxy
  (default SOCKS5); its test is skipped if absent.

After configuring the session:

```powershell
python -m pytest -m lab
```

To verify full NTLM authentication and `forest-level` through an existing SOCKS4
proxy, also set `ADWSEARCH_LAB_SOCKS=socks4://127.0.0.1:8443` and run:

```powershell
python -m pytest tests/lab/test_adws_lab.py::test_socks_route_and_forest_level_when_configured -q
```

This test performs a base query through the proxy, then runs the real CLI with
automatic base discovery and `forest-level`, comparing normal and `--raw` JSON
against direct ADWS. The raw value is also checked against independent signed/sealed
LDAP. Only password entry is supplied by the fixture; authentication and network
transports are real. On 10 November 2026 it passed against VirtualBox GOAD through
a temporary local SOCKS4 relay (seven proxied connections, no relay errors).
This did not exercise the Zaiux HTTPS tunnel or Kerberos through SOCKS.

The `password-policy` checks compare all nine raw domain policy attributes (including `forceLogoff`) with
the independent signed/sealed LDAP reference, then exercise LDIF/JSON and `--raw`
through the CLI with automatic base discovery. Edge cases and special interval
values use synthetic offline fixtures; these tests do not change the domain policy.

The AD CS CLI checks use page sizes 1, 7, and 256 and inspect actual Pull
requests. They compare template flags and publication with independent signed
LDAP, and include real `--sleep 5 --jitter 2` pauses in the 256-object case.
The synthetic ESC1 AllExtendedRights regression does not modify lab templates.
The same checks compare issuance-policy/group joins and ESC13/ESC17 prerequisites
with LDAP. A TCP connection guard permits the ADWSearch collection to connect
only to the configured DC on port 9389; LDAP references run separately.

The Kerberos suite includes an explicit RC4 case: this needs controller/account
support and does not enable RC4 on the domain. AD CS checks need a suitable
Enterprise CA; absent prerequisites produce skips. The suite does not force
automatic AES-to-RC4 fallback on a KDC or perform an actual BloodHound import.

Keep generated caches, exports, tickets and test logs outside the source tree.
The ignore rules are a safeguard, not a guarantee that arbitrary output paths
will be excluded from a future commit.
