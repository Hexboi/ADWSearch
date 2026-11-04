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
| `password-policy` | The default domain password, account lockout and forced-logoff policy, including readable intervals and property flags. |
| `asrep` | User accounts without Kerberos preauthentication, for further assessment of AS-REP roasting exposure. |
| `kerberoastable` | Enabled user accounts with SPNs, for further assessment of Kerberoasting exposure. |
| `spn` | Objects with registered service principal names, including users and computers. |
| `users-description` | All user accounts and their descriptions, displayed as a table by default. |
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
- `-b`: optional search base. If omitted, the tool reads the contacted DC's
  `defaultNamingContext` through authenticated ADWS RootDSE. An explicit base
  overrides discovery, for example to restrict the search to an OU.
- The quoted filter selects objects; the following names select attributes.

Without a filter or attributes, the tool searches for all objects below the specified base and reads the available attributes. The default output is LDIF, a text format for directory data.

If the controller hostname does not resolve, add `--dc-ip 10.10.1.10` while keeping the correct hostname in `-H`.

The account domain (`-d`) is independent of the search base and remains available.
Base discovery uses the controller's domain, never a DN guessed from `-d` or the
username. If RootDSE discovery is unavailable, the tool asks for an explicit `-b`.
For `writable` without `-b`, Configuration and Schema paths also come from RootDSE,
including when the DC belongs to a child domain. A dry-run never connects: omitted
bases appear as `(auto: defaultNamingContext)` and equivalent partition placeholders.

### Built-in checks and saving results

To read the default domain password and account lockout policy:

```powershell
adwsearch -H dc01.corp.local -u alice -d corp.local -W --preset password-policy
```

This returns `minPwdLength`, `pwdHistoryLength`, `minPwdAge`, `maxPwdAge`,
`pwdProperties`, `lockoutThreshold`, `lockoutDuration`,
`lockOutObservationWindow` and `forceLogoff`. Intervals are shown in seconds, alongside the original
100-nanosecond values; password-property flags include complexity and reversible
encryption. Special values distinguish no expiration, no minimum age, disabled
lockout and administrator-only unlock. The last setting matters only when the
lockout threshold is enabled. Unknown flags and malformed values retain their
original numeric/text representation.

`forceLogoff` concerns expiration of allowed logon hours, not password expiration:
zero means immediate forced logoff at that point, while `-9223372036854775808`
means forced logoff is disabled. Other negative intervals use the same exact
seconds conversion. With `--raw`, the original value is returned unchanged.

Use `--raw` to keep the original values without annotations, or `-o json` for
JSON output. The preset reads the domain root, discovered automatically when
`-b` is omitted. An explicit base must identify a domain root: an OU produces
no results. Missing attributes remain absent rather than being treated as zero.
This is the domain default policy; fine-grained policies (FGPP/PSO) and the
resulting policy for a specific user are not collected.

To list users and their descriptions as one table row per account:

```powershell
adwsearch -H dc01.corp.local -u alice -d corp.local -W --preset users-description
```

This includes enabled and disabled users, including accounts without a returned
description (`[not returned]`); computers and groups are excluded. Multiple returned
descriptions share the same cell, separated by ` ; `. Control characters and table
delimiters are escaped, and descriptions are never truncated. The table streams in
the controller's order; a narrow terminal may visually wrap long lines.

Use `-o json --outfile users.json` or `-o ldif` for structured exports with the DN
and original attribute values. `-o table` is supported only with this preset;
other searches keep LDIF as their default output. `--outfile users.txt` saves the
table instead of printing it. A missing description can also mean the attribute
was not readable; it does not necessarily mean no description exists.

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
