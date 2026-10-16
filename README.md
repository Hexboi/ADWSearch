# ADWSearch

ADWSearch is a tool for querying **Active Directory through ADWS** (Active Directory Web Services), usually on TCP port **9389**, rather than using the LDAP protocol.

Use it to collect domain information, identify configurations that need further assessment, and export data for later analysis.

The tool is **read-only**: it does not modify domain objects, permissions, or configuration. Results depend on the permissions of the account you use. Only run it in environments you are authorized to assess.

## Available checks

Select a check with `--preset NAME`:

| Preset | What it shows |
| --- | --- |
| `forest-level` | The functional level of the domain specified as the search base. |
| `maq` | The quota that controls how many computers an account can add to the domain. |
| `asrep` | User accounts without Kerberos preauthentication, for further assessment of AS-REP roasting exposure. |
| `kerberoastable` | Enabled user accounts with SPNs, for further assessment of Kerberoasting exposure. |
| `spn` | Objects with registered service principal names, including users and computers. |
| `writable` | Effective rights exposed for the current account on attributes, permissions, and child-object creation, without attempting changes. |
| `dns-dump` | DNS records in Active Directory partitions accessible to the account. |

These are configuration checks: **they do not extract passwords, perform roasting, or automatically prove that a finding is exploitable**.

The `--dump` modes also let you:

- `buildcache`: create a JSON cache of object identifiers.
- `showstats`: read cache statistics without connecting to the domain.
- `bhdump`: export objects and relationships as JSON for BloodHound analysis; it does not collect sessions or local host information.
- `certdump`: collect AD CS CAs, templates, and trusted certificates, and flag potentially risky configurations. It does not request certificates or check HTTP/RPC endpoints or local CA settings.

## Installation

Requires **Python 3.10 or later**.

```powershell
python -m pip install .
```

## How to run

### Custom query

To list users and the selected attributes:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" "(sAMAccountType=805306368)" sAMAccountName memberOf
```

- `-H`: domain-controller hostname.
- `-u`: account; you can also use `-u alice -d corp.local`.
- `-b`: search base, required for online operations.
- The quoted filter selects objects; the following names select attributes.

Without a filter or attributes, the tool searches for all objects below the specified base and reads the available attributes. The default output is LDIF, a text format for directory data.

If the controller hostname does not resolve, add `--dc-ip 10.10.1.10` while keeping the correct hostname in `-H`.

### Built-in checks and saving results

To find accounts without Kerberos preauthentication:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --preset asrep
```

To save results as JSON:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --preset spn -o json --outfile spns.json
```

### Kerberos authentication

You need an existing valid cache matching the account and domain. ADWSearch does not automatically obtain a TGT from a password.

```powershell
$env:KRB5CCNAME = "C:\Path\alice.ccache"
adwsearch -H dc01.corp.local -u alice@corp.local -k -b "DC=corp,DC=local" --preset spn
```

With `-k`, `--kerberos-enctype` selects the policy:

- `aes`: the default; uses AES without falling back to RC4.
- `rc4`: explicitly requests RC4 for legacy compatibility.
- `auto`: tries AES and falls back to RC4 only when the KDC reports unsupported encryption types, not on authentication, timeout, or integrity errors.

Prefer AES: RC4 retains the security limitations of the legacy protocol. No controller policy is changed. For NTLM, you can also use `--hashes ":NT_HASH"` instead of `-W`.

### Domain and AD CS exports

First, build the cache:

```powershell
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump buildcache --cachefile corp-cache.json
```

Then choose the export you need, using the cache for the same domain:

```powershell
# Objects and relationships for BloodHound
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump bhdump --cachefile corp-cache.json --outdir bh-out

# AD CS configuration and potential findings
adwsearch -H dc01.corp.local -u alice@corp.local -W -b "DC=corp,DC=local" --dump certdump --cachefile corp-cache.json --outdir adcs-out

# Local statistics, without a domain connection
adwsearch --dump showstats --cachefile corp-cache.json
```

## Development and tests

From the project directory, with the virtual environment active:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -m "not lab"
python -m ruff check adwsearch tests
```

Offline tests use fake data, including fake passwords and keys; these are not operational credentials. Integration tests are optional and require an explicitly configured, authorized environment; see [tests/lab/README.md](tests/lab/README.md).

## License and credits

ADWSearch is developed by [Hexboi](https://github.com/Hexboi), and its original code is available under [MPL-2.0](LICENSE), including for professional and commercial use.
Third-party credits and license texts are collected in [NOTICE](NOTICE).
