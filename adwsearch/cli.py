# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Command-line interface for ADWSearch.

Wires argparse → :class:`Credentials` → NTLM/Kerberos SecurityContext → ``connect_adws``
→ :class:`AdwsClient.search` → LDIF/JSON writer. SOCKS5 is enabled with ``--socks
HOST:PORT`` (uses PySocks); ``--dry-run`` prints the summary of what would be sent without
opening a socket.
"""

from contextlib import contextmanager
from textwrap import fill

import argparse
import getpass
import math
import os
import sys

from adwsearch import __version__
from adwsearch.adws.client import AdwsClient
from adwsearch.adws.factory import connect_adws
from adwsearch.auth.credentials import Credentials, parse_hashes
from adwsearch.auth.kerberos import KerberosAuthenticationError, KerberosSecurityContext
from adwsearch.auth.ntlm import NtlmSecurityContext
from adwsearch.auth.kerberos_ticket import ccache_path, resolve_spn, validate_ccache
from adwsearch.logging_config import configure_logging
from adwsearch.enum import PRESETS
from adwsearch.output.writers import write_json, write_ldif

DEFAULT_PORT = 9389
DEFAULT_FILTER = "(objectClass=*)"
DEFAULT_PAGE_SIZE = 256
DEFAULT_TIMEOUT = 30


_EPILOG = f"""\
examples:
  # Examples below use POSIX shell continuations; in PowerShell use one line.
  # Names and values are placeholders. -W prompts without exposing a password in argv.
  # Basic search (LDIF output) - default filter (objectClass=*) if none given.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName memberOf

  # Pass-the-hash + JSON output to a file.
  adwsearch -H dc01.corp.local -u alice \\
      --hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \\
      -b 'DC=corp,DC=local' -o json --outfile users.json '(objectClass=user)'

  # Kerberos from an existing ccache (KRB5CCNAME must point at a valid TGT).
  KRB5CCNAME=alice.ccache adwsearch -H dc01.corp.local -u alice -k \\
      -b 'DC=corp,DC=local' '(sAMAccountName=krbtgt)'

  # SOCKS5 pivot through a beacon on 127.0.0.1:1080 (IPv6 literals supported).
  adwsearch -H dc01.corp.local --dc-ip 10.10.1.10 -u alice@corp.local -W \\
      --socks 127.0.0.1:1080 -b 'DC=corp,DC=local' '(objectClass=computer)'

  # Enum preset: forest / domain functional level.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset forest-level

  # Enum preset: Machine Account Quota (RBCD precondition).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset maq

  # Enum preset: AS-REP-roastable accounts (DONT_REQ_PREAUTH bit).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset asrep

  # Enum preset: writable objects, only users, scanning every NC partition.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset writable \\
      --writable-otype user --writable-partition all

  # Enum preset: full DNS dump including AD-internal glue records.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset dns-dump --dns-include-glue -o json

  # Enum preset: every SPN-bearing object (users, computers, gMSA, trusts).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset spn -o json --outfile spns.json

  # Enum preset: find every registered SQL Server instance in the domain.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset spn --spn-class MSSQLSvc

{fill(PRESETS['kerberoastable'].description, width=96, initial_indent='  # ', subsequent_indent='  # ')}
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset kerberoastable -o json

  # Dump: build SID/GUID <-> DN cache (foundation for BH dump).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --dump buildcache --cachefile corp-cache.json

  # Dump: read a previously-built cache and print stats (offline, no DC required).
  adwsearch --dump showstats --cachefile corp-cache.json

  # Dump: full BloodHound v5 collection (requires cache built first).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --dump bhdump \\
      --cachefile corp-cache.json --outdir bh-out

  # OPSEC: rate-limit a massive dump (base 1s + up to 2s of jitter per request).
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --sleep 1 --jitter 2 \\
      --dump bhdump --cachefile corp-cache.json --outdir bh-out

  # Dry-run - see the resolved SOAP query without connecting to the DC.
  adwsearch -H dc01.corp.local -u alice@corp.local -W \\
      -b 'DC=corp,DC=local' --preset kerberoastable --dry-run
"""


def _formatter(prog):
    """RawDescription + wider help column so no argument's description wraps.

    max_help_position=32 fits every option (longest: --writable-partition PART)
    on a single line, uniform across all argument groups.
    """
    return argparse.RawDescriptionHelpFormatter(prog, max_help_position=32, width=100)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adwsearch",
        description="Query Active Directory over ADWS (SOAP, TCP 9389).",
        formatter_class=_formatter,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    conn = parser.add_argument_group("connection")
    conn.add_argument("-H", "--host", metavar="FQDN",
                      help="Domain Controller FQDN (required for the Kerberos SPN)")
    conn.add_argument("--dc-ip", metavar="IP",
                      help="DC IP address, if DNS does not resolve the host")
    conn.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                      help=f"ADWS port (default: {DEFAULT_PORT})")
    conn.add_argument("--socks", metavar="HOST:PORT",
                      help="route the connection through a SOCKS5 proxy")
    conn.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
                      help=f"socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    conn.add_argument("--sleep", type=float, default=0.0, metavar="SEC",
                      help="OPSEC: base delay (seconds) between consecutive "
                           "SOAP requests (0 = disabled)")
    conn.add_argument("--jitter", type=float, default=0.0, metavar="SEC",
                      help="OPSEC: max random additive delay in seconds, "
                           "uniform 0..jitter on top of --sleep")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--user", metavar="USER",
                      help="username (user, DOMAIN\\user, or user@domain)")
    auth.add_argument("-d", "--domain", metavar="DOMAIN",
                      help="domain, if not embedded in --user")
    auth.add_argument("-w", "--password", metavar="PW",
                      help="password argument (may appear in process listings and shell history; prefer -W)")
    auth.add_argument("-W", "--prompt-password", action="store_true",
                      help="prompt for the password interactively")
    auth.add_argument("--hashes", metavar="[LM]:NT",
                      help="NT (optionally LM) hash for pass-the-hash; sensitive argument, "
                           "may appear in process listings and shell history")
    auth.add_argument("--kerberos-enctype", choices=("aes", "rc4", "auto"),
                      help="Kerberos session policy (default: aes; rc4/auto explicitly permit legacy RC4)")
    auth.add_argument("-k", "--kerberos", action="store_true",
                      help="use Kerberos from an existing ccache (KRB5CCNAME)")
    auth.add_argument("--spn", metavar="SPN",
                      help="override the Kerberos SPN of the DC")

    search = parser.add_argument_group("search")
    search.add_argument("-b", "--base", metavar="DN",
                        help="search base DN (required for online operations)")
    search.add_argument("-s", "--scope", choices=("base", "one", "sub"), default="sub",
                        metavar="SCOPE",
                        help="search scope: base|one|sub (default: sub)")
    search.add_argument("-z", "--sizelimit", type=int, default=0, metavar="N",
                        help="maximum entries to return (0 = unlimited)")
    search.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, metavar="N",
                        help=f"WS-Enumeration Pull batch size (default: {DEFAULT_PAGE_SIZE})")
    search.add_argument("filter", nargs="?", default=DEFAULT_FILTER,
                        help=f"LDAP filter, RFC 4515 (default: {DEFAULT_FILTER})")
    search.add_argument("attributes", nargs="*",
                        help="attributes to return (default: all)")

    enum = parser.add_argument_group(
        "enum",
        "Preset enumeration recipes. Each --preset overrides the positional "
        "filter/attrs with a fixed ADWS query.",
    )
    enum.add_argument("--preset", choices=sorted(PRESETS), metavar="NAME",
                      help="run a preset enumeration: forest-level | maq | "
                           "asrep | kerberoastable | writable | dns-dump | "
                           "spn")
    enum.add_argument("--writable-otype", choices=("user", "group", "ou", "gpo", "any"),
                      default="any", metavar="TYPE",
                      help="--preset writable object type: user|group|ou|gpo|any "
                           "(default: any)")
    enum.add_argument("--writable-partition",
                      choices=("domain", "config", "schema", "all"), default="domain",
                      metavar="PART",
                      help="--preset writable partition: domain|config|schema|all "
                           "(default: domain)")
    enum.add_argument("--dns-include-glue", action="store_true",
                      help="include AD-internal glue records in --preset dns-dump "
                           "(_kerberos.*, _ldap.*, DomainDnsZones, ...)")
    enum.add_argument("--spn-class", metavar="CLASS", default=None,
                      help="--preset spn: filter by SPN service class "
                           "(e.g. MSSQLSvc, HTTP, HOST, CIFS). For "
                           "kerberoastable targets use the dedicated "
                           "'--preset kerberoastable'. Default: all SPN "
                           "service classes.")

    dump = parser.add_argument_group(
        "dump",
        "Massive dump modes (SOAPHound-style). Mutually exclusive with --preset "
        "and positional filter/attributes.",
    )
    dump.add_argument("--dump",
                      choices=("buildcache", "showstats", "bhdump", "certdump"),
                      metavar="MODE", default=None,
                      help="dump mode: buildcache | showstats | bhdump | certdump")
    dump.add_argument("--cachefile", metavar="PATH", default="adwsearch-cache.json",
                      help="path of the cache JSON file "
                           "(default: adwsearch-cache.json)")
    dump.add_argument("--outdir", metavar="PATH", default="bhdump-output",
                      help="--dump bhdump: output directory for BH v5 JSON files "
                           "(default: bhdump-output)")
    dump.add_argument("--autosplit", action="store_true",
                      help="--dump bhdump: split the single (!soaphound=*) query "
                           "into 36 per-leading-CN-letter queries plus a nonchars "
                           "catch-all (mitigates DC paging limits on large domains)")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", choices=("ldif", "json"), default="ldif",
                     metavar="FMT",
                     help="output format: ldif|json (default: ldif)")
    out.add_argument("--outfile", metavar="PATH",
                     help="write output to a file instead of stdout")
    out.add_argument("--raw", action="store_true",
                     help="do not decode binary attributes (SID/GUID/...): emit base64")
    out.add_argument("--dry-run", action="store_true",
                     help="build and print the SOAP requests without sending them")
    out.add_argument("-v", "--verbose", action="count", default=0,
                     help="increase verbosity (repeatable)")

    return parser


def _split_user(user_arg: str | None, domain_arg: str | None) -> tuple[str, str]:
    """Accept ``user``, ``user@domain``, or ``DOMAIN\\user``. Returns (user, domain)."""
    if not user_arg:
        return "", domain_arg or ""
    if "@" in user_arg:
        u, d = user_arg.rsplit("@", 1)
        return u, d
    if "\\" in user_arg:
        d, u = user_arg.split("\\", 1)
        return u, d
    return user_arg, domain_arg or ""


def _parse_host_port(spec: str) -> tuple[str, int]:
    """Parse ``HOST:PORT``. Accepts IPv6 literals in ``[::1]:1080`` form.

    Raises ``ValueError`` with a user-oriented message if ``spec`` is malformed
    (no colon separator, or non-integer port). Call sites in :func:`main` catch
    this and route it through ``parser.error`` so the user sees a clean message
    instead of a traceback.
    """
    if spec.startswith("[") and "]:" in spec:
        host, port_str = spec[1:].split("]:", 1)
    elif ":" in spec:
        host, port_str = spec.rsplit(":", 1)
    else:
        raise ValueError(f"expected HOST:PORT, got {spec!r}")
    try:
        port = int(port_str)
        if not host or not 1 <= port <= 65535:
            raise ValueError("invalid host or port")
        return host, port
    except ValueError:
        raise ValueError(
            f"invalid port {port_str!r} in {spec!r} (expected an integer)"
        ) from None


def _build_socks5_factory(socks_arg: str, timeout: int):
    """Return a socket_factory(host, port) that dials through a SOCKS5 proxy."""
    proxy_host, proxy_port = _parse_host_port(socks_arg)

    def factory(host, port):
        import socks  # imported lazily so PySocks is optional at install time
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        s.settimeout(timeout)
        s.connect((host, port))
        return s

    return factory


def _dry_run(args, connect_host: str, credentials: Credentials) -> None:
    auth_kind = (
        f"Kerberos (ccache, {args.kerberos_enctype or 'aes'})" if args.kerberos
        else "NTLM pass-the-hash" if args.hashes
        else "NTLM (password)"
    )
    principal = f"{credentials.username}@{credentials.domain}" if credentials.domain else credentials.username

    lines = [
        f"[dry-run] target:  {args.host or args.dc_ip}:{args.port} "
        f"(connect to {connect_host})",
        f"[dry-run] socks:   {args.socks or '(none)'}",
        f"[dry-run] auth:    {auth_kind} as {principal or '(anonymous)'}",
        *([f"[dry-run] SPN:     {resolve_spn(args.host or args.dc_ip, args.spn)}"]
          if args.kerberos else []),
        f"[dry-run] rate-limit: sleep={args.sleep}s jitter={args.jitter}s",
    ]

    if args.preset:
        preset = PRESETS[args.preset]
        lines.append(f"[dry-run] preset:  {preset.name} - {preset.description}")
        if preset.resolve is not None:
            resolved = preset.resolve(args)
            if "bases" in resolved:
                for base in resolved["bases"]:
                    lines.append(f"[dry-run]   base:  {base}")
            else:
                lines.append(f"[dry-run]   base:  {resolved['base']}")
            lines.append(f"[dry-run]   scope: {resolved['scope']}")
            lines.append(f"[dry-run]   filter: {resolved['filter']}")
            lines.append(f"[dry-run]   attrs: {' '.join(resolved['attributes'])}")
    else:
        attrs = " ".join(args.attributes) if args.attributes else "(all default)"
        lines.extend([
            f"[dry-run] base:    {args.base}",
            f"[dry-run] scope:   {args.scope}",
            f"[dry-run] filter:  {args.filter}",
            f"[dry-run] attrs:   {attrs}",
        ])
    lines.append(
        f"[dry-run] page:    {args.page_size}   sizelimit: {args.sizelimit or 'unlimited'}")
    lines.append(
        f"[dry-run] output:  {args.output}"
        + (f" -> {args.outfile}" if args.outfile else " -> stdout"))
    for line in lines:
        print(line)


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    if args.dump and (args.preset or args.filter != DEFAULT_FILTER or args.attributes):
        parser.error("--dump is mutually exclusive with --preset and positional filter/attributes")
    for name, valid in (
        ("port", 1 <= args.port <= 65535),
        ("timeout", args.timeout > 0), ("page-size", args.page_size > 0),
        ("sizelimit", args.sizelimit >= 0),
        ("sleep", math.isfinite(args.sleep) and args.sleep >= 0),
        ("jitter", math.isfinite(args.jitter) and args.jitter >= 0),
    ):
        if not valid:
            parser.error(f"invalid --{name} value (finite >= 0; timeout/page-size > 0; ports 1..65535)")
    if args.kerberos_enctype is not None and not args.kerberos:
        parser.error("--kerberos-enctype requires --kerberos")
    if args.spn and not args.kerberos:
        parser.error("--spn requires --kerberos")
    lmhash, nthash = (b"", b"")
    if args.hashes:
        try:
            lmhash, nthash = parse_hashes(args.hashes)
        except ValueError:
            parser.error("--hashes requires [LM]:NT with 32 hexadecimal characters per nonempty hash")
    if args.socks:
        try:
            _parse_host_port(args.socks)
        except ValueError as exc:
            parser.error(f"--socks: {exc}")
    username, domain = _split_user(args.user, args.domain)
    identity = Credentials(username, domain)
    if args.kerberos:
        try:
            ccache_path()
            if not (args.host or args.dc_ip):
                raise ValueError("--kerberos requires a target hostname")
            validate_ccache(identity, resolve_spn(args.host or args.dc_ip, args.spn),
                            args.kerberos_enctype or 'aes')
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    cache = None
    if args.dump in ("showstats", "bhdump", "certdump"):
        from adwsearch.dump.cache import Cache
        try:
            cache = Cache.deserialize(args.cachefile)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(f"--dump {args.dump} requires a valid cache; run --dump buildcache first ({type(exc).__name__})")

    # --- offline dump modes: no network / auth required ---------------------
    if args.dump == "showstats":
        from adwsearch.dump import Cache, showstats
        showstats(cache)
        return 0

    # --- validate -----------------------------------------------------------
    if not args.host and not args.dc_ip:
        parser.error("either -H/--host or --dc-ip is required")
    if not args.base:
        parser.error("-b/--base is required")
    if not (args.kerberos or args.password or args.prompt_password or args.hashes):
        parser.error(
            "authentication required: -w PASSWORD | -W | --hashes LM:NT | -k")
    if args.preset and (args.filter != DEFAULT_FILTER or args.attributes):
        parser.error(
            f"--preset {args.preset} conflicts with positional filter/attributes; "
            "the preset defines its own query")
    # The old alias ``--spn-class kerberoastable`` was promoted to a
    # first-class preset. Catch the legacy invocation and redirect, rather
    # than silently search for a service class literally named "kerberoastable".
    if args.spn_class == "kerberoastable":
        parser.error(
            "--spn-class kerberoastable was removed; use "
            "'--preset kerberoastable' instead")
    if args.dump and (args.preset or args.filter != DEFAULT_FILTER or args.attributes):
        parser.error(
            "--dump is mutually exclusive with --preset and positional filter/attributes")
    if args.sleep < 0:
        parser.error("--sleep must be >= 0")
    if args.jitter < 0:
        parser.error("--jitter must be >= 0")
    if args.socks:
        try:
            _parse_host_port(args.socks)
        except ValueError as exc:
            parser.error(f"--socks: {exc}")

    # --- credentials --------------------------------------------------------
    password = args.password
    if args.prompt_password and not password:
        password = getpass.getpass("Password: ")

    credentials = Credentials(
        username=identity.username, domain=identity.domain,
        password=password or "",
        lmhash=lmhash, nthash=nthash,
    )

    # --- routing decisions --------------------------------------------------
    # For DNS-less environments, prefer the raw IP on the TCP dial, but keep the
    # FQDN as the SPN target (Kerberos) and as the wsa:To hostname (AdwsClient).
    target_host = args.host or args.dc_ip
    connect_host = args.dc_ip or args.host

    def make_security():
        if args.kerberos:
            return KerberosSecurityContext(credentials, target_host=target_host,
                                           kdc_host=connect_host, spn=args.spn,
                                           policy=args.kerberos_enctype or 'aes', timeout=args.timeout)
        return NtlmSecurityContext(credentials)

    # --- dry run short-circuit ---------------------------------------------
    if args.dry_run:
        _dry_run(args, connect_host, credentials)
        return 0

    # --- socket factory (SOCKS5 or direct) ---------------------------------
    socket_factory = _build_socks5_factory(args.socks, args.timeout) if args.socks else None

    # --- connect + search + write ------------------------------------------
    conn = connect_adws(connect_host, args.port, make_security(),
                        socket_factory=socket_factory, timeout=args.timeout)
    from adwsearch.adws.rate_limit import RateLimitedTransport, RequestPacer
    pacer = RequestPacer(args.sleep, args.jitter)
    if args.sleep > 0 or args.jitter > 0:
        conn = RateLimitedTransport(conn, pacer=pacer)

    @contextmanager
    def resource_transport():
        resource = connect_adws(connect_host, args.port, make_security(),
                                endpoint="Windows/Resource", socket_factory=socket_factory,
                                timeout=args.timeout)
        try:
            yield RateLimitedTransport(resource, pacer=pacer) if args.sleep > 0 or args.jitter > 0 else resource
        finally:
            resource.close()
    try:
        client = AdwsClient(conn, target_host, args.port,
                            resource_transport_factory=resource_transport)
        if args.dump == "buildcache":
            from adwsearch.dump import build_cache
            cache = build_cache(client, args.base)
            cache.serialize(args.cachefile)
            print(f"cache written: {args.cachefile} "
                  f"({len(cache.value_to_id)} objects)")
            return 0
        if args.dump == "bhdump":
            from adwsearch.dump import Cache, bhdump
            if not os.path.isfile(args.cachefile):
                parser.error(
                    f"--dump bhdump requires an existing cache at {args.cachefile}; "
                    "run --dump buildcache first")
            counts = bhdump(client, args.base, args.outdir, cache,
                            autosplit=args.autosplit)
            total = sum(counts.values())
            print(f"bhdump written to {args.outdir}: {total} nodes")
            for kind, n in counts.items():
                print(f"  {kind}: {n}")
            return 0
        if args.dump == "certdump":
            from adwsearch.dump import Cache, certdump
            if not os.path.isfile(args.cachefile):
                parser.error(
                    f"--dump certdump requires an existing cache at {args.cachefile}; "
                    "run --dump buildcache first")
            counts = certdump(client, args.base, args.outdir, cache)
            print(f"certdump written to {args.outdir}: "
                  f"{counts['cas']} CAs, {counts['templates']} templates")
            return 0
        if args.preset:
            entries = PRESETS[args.preset].run(client, args)
        else:
            entries = client.search(
                base=args.base, scope=args.scope, ldap_filter=args.filter,
                attributes=list(args.attributes) if args.attributes else None,
                size_limit=args.sizelimit, page_size=args.page_size,
            )

        writer = write_json if args.output == "json" else write_ldif
        if args.outfile:
            from adwsearch.output.atomic import atomic_text_file
            with atomic_text_file(args.outfile) as stream:
                writer(entries, stream, raw=args.raw)
        else:
            writer(entries, sys.stdout, raw=args.raw)
    finally:
        conn.close()

    return 0


def main(argv: list[str] | None = None) -> int:
    from impacket.krb5.kerberosv5 import KerberosError
    from adwsearch.soap.parser import AdwsSoapFault
    from adwsearch.transport.nns import NnsHandshakeError
    try:
        return _main(argv)
    except (OSError, EOFError, AdwsSoapFault, NnsHandshakeError, KerberosError,
            KerberosAuthenticationError) as exc:
        print(f"error: operation failed ({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
