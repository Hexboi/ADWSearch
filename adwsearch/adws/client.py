# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADWS client: WS-Enumeration search orchestration + WS-Transfer Get.

The client is transport-agnostic. A ``transport`` collaborator exposes a single method
``request(events) -> events`` (send one SOAP message as NBF records, return the decoded
response records). The real transport (socket + NMF + NNS + NBFSE) is the connection layer
(Phase 3); tests inject a fake.

Single-object reads can use either ``get`` (one SOAP round-trip, WS-Transfer) or
``search(scope="base")`` (the ldapsearch model, which costs Enumerate+Pull+Release).
``get`` auto-detects the resource endpoint and silently falls back to the search
path if the DC does not accept WS-Transfer on either endpoint.
"""

import logging

from adwsearch.soap import parser, templates
from adwsearch.soap.parser import AdwsSoapFault

_log = logging.getLogger(__name__)

# Sentinel: WS-Transfer attempted and known-bad on this host (fall back to search).
_GET_UNSUPPORTED = object()

# SOAP fault subcodes that mean "this endpoint does not accept this action
# at all" -- the only cases where silently retrying on the other resource
# endpoint and ultimately falling back to search(scope=base) is correct.
# Matched by local-part only: the namespace prefix is server-chosen (WCF
# emits ``a:DestinationUnreachable``, the W3C WS-Addressing spec example
# uses ``wsa:``) and both refer to the same WS-Addressing fault code.
# Any other fault (MustUnderstand, Sender, InvalidPropertyFault, ...) is
# a bug in our request and MUST propagate instead of being masked as "DC
# does not support WS-Transfer".
_UNSUPPORTED_SUBCODE_LOCALS = frozenset({
    "ActionNotSupported",
    "DestinationUnreachable",
    "EndpointUnavailable",
})


def _is_unsupported_subcode(subcode: str | None) -> bool:
    if not subcode:
        return False
    local = subcode.split(":", 1)[1] if ":" in subcode else subcode
    return local in _UNSUPPORTED_SUBCODE_LOCALS

# LDAP attribute names that ADWS exposes as synthetic (ad:) rather than data (addata:).
_SYNTHETIC = {
    "distinguishedName",
    "relativeDistinguishedName",
    "objectReferenceProperty",
    "canonicalName",
    "container-hierarchy-parent",
}


def selection_property(name: str) -> str:
    """Map an LDAP attribute name to an ad:Selection SelectionProperty string."""
    if ":" in name:
        return name  # already qualified (e.g. "ad:objectSid")
    if name in _SYNTHETIC:
        return "ad:" + name
    return "addata:" + name


class AdwsClient:
    def __init__(self, transport, host, port: int = 9389, *, resource_transport_factory=None):
        self.transport = transport
        self.host = host
        self.port = port
        # Lazily set on first ``get`` call: either one of _RESOURCE_ENDPOINTS
        # (sticky winner) or _GET_UNSUPPORTED (fall back to search).
        self._resource_endpoint = None
        self._resource_transport_factory = resource_transport_factory

    def get(self, dn: str):
        """Read through a dedicated Resource connection; never reroute Enumeration."""
        if self._resource_transport_factory is None or self._resource_endpoint is _GET_UNSUPPORTED:
            return self._get_via_search(dn)
        try:
            with self._resource_transport_factory() as resource:
                return parser.parse_get_response(resource.request(
                    templates.get_request(self.host, dn, port=self.port)))
        except AdwsSoapFault as fault:
            if not _is_unsupported_subcode(fault.subcode):
                raise
            self._resource_endpoint = _GET_UNSUPPORTED
            _log.info("WS-Transfer Get on %s/Windows/Resource rejected (%s); "
                      "using search(scope=base)", self.host, fault)
        return self._get_via_search(dn)

    def _get_via_search(self, dn: str):
        """Fallback used by :meth:`get` when WS-Transfer is unavailable."""
        return next(iter(self.search(
            base=dn, scope="base", ldap_filter="(objectClass=*)",
            size_limit=0, page_size=1)), None)

    def search(self, base, scope="sub", ldap_filter="(objectClass=*)",
               attributes=None, size_limit=0, page_size=256, ldap_controls=None):
        """Yield AdObject items matching the query (Enumerate -> Pull* -> Release).

        ``ldap_controls`` is a list of ``(oid, base64_value)`` tuples forwarded to
        the DC as MS-ADDM ``<Controls>``. Used by bhdump/certdump for SD_FLAGS.
        """
        adws_scope = templates.SCOPE.get(scope)
        if adws_scope is None:
            raise ValueError(f"invalid scope {scope!r}; expected one of {sorted(templates.SCOPE)}")
        selection = [selection_property(a) for a in attributes] if attributes else None

        enumerate_req = templates.enumerate_request(
            self.host, base, adws_scope, ldap_filter, selection, port=self.port)
        context = parser.parse_enumerate_response(self.transport.request(enumerate_req))

        count = 0
        ended = False
        try:
            while context is not None:
                if size_limit:
                    remaining = size_limit - count
                    if remaining <= 0:
                        return
                    batch = min(page_size, remaining)
                else:
                    batch = page_size

                pull_req = templates.pull_request(self.host, context, batch,
                                                  port=self.port, controls=ldap_controls)
                result = parser.parse_pull_response(self.transport.request(pull_req))
                context = result.context  # the context valid for the next Pull / Release

                for adobject in result.items:
                    yield adobject
                    count += 1
                    if size_limit and count >= size_limit:
                        return

                if result.end_of_sequence:
                    ended = True
                    break
        finally:
            # Per MS-ADOD: no Release is needed once EndOfSequence has been observed.
            if not ended and context is not None:
                try:
                    self.transport.request(
                        templates.release_request(self.host, context, port=self.port))
                except Exception:
                    _log.debug(
                        "Release request failed for context %r (best-effort cleanup)",
                        context, exc_info=True)
