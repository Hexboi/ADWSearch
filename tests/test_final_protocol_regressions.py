# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import datetime
import struct

import pytest
from impacket.krb5.asn1 import KRB_ERROR
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.asn1 import seq_set
from impacket.krb5.crypto import _AES128CTS
from pyasn1.codec.der import encoder

from adwsearch.auth import kerberos_tgs, kerberos_ticket
from adwsearch.auth.credentials import Credentials
from adwsearch.soap import parser
from adwsearch.transport.nbf.records import Xmlns
from tests.test_adws_resource import direct_response
from tests.test_adws_client import item
from tests.test_kerberos_mutual import context, reply, SUBKEY
from tests.test_kerberos_security import _simulate_server_wrap


def test_modified_clear_sequence_cannot_replay_authenticated_aes_frame():
    ctx = context()
    ctx.step(reply(7))
    token = _simulate_server_wrap(SUBKEY, _AES128CTS, b"answer", 7)
    assert ctx.unwrap(token) == b"answer"
    forged = token[:8] + struct.pack(">Q", 8) + token[16:]
    with pytest.raises(ValueError):
        ctx.unwrap(forged)
    assert ctx._recv_seq == 8


@pytest.mark.parametrize(
    "offset,value", [(2, 1), (2, 2), (2, 4), (3, 1), (4, 1), (6, 1)]
)
def test_aes_rejects_altered_header_fields(offset, value):
    ctx = context()
    ctx.step(reply(7))
    token = bytearray(_simulate_server_wrap(SUBKEY, _AES128CTS, b"answer", 7))
    token[offset] ^= value
    with pytest.raises(ValueError):
        ctx.unwrap(bytes(token))
    assert ctx._recv_seq == 7


def test_old_aprep_from_same_ticket_key_does_not_restore_old_state():
    ctx = context()
    ctx._initiator_timestamp = ("20000101000000Z", 123)
    with pytest.raises(RuntimeError):
        ctx.step(reply(7))
    assert not ctx.complete and ctx._recv_seq == 0


def test_malformed_error14_does_not_enable_auto_fallback(monkeypatch):
    error = KRB_ERROR()
    error["pvno"], error["msg-type"], error["error-code"] = 5, 30, 14
    error["stime"] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
    error["susec"], error["realm"] = 0, "REALM"
    seq_set(error, "sname", Principal("krbtgt/REALM", type=2).components_to_asn1)
    from tests.test_kerberos_tgs import tgt

    calls = []

    def exchange(*args):
        calls.append(True)
        return encoder.encode(error) + b"JUNK"

    monkeypatch.setattr(kerberos_tgs, "_exchange", exchange)

    class Tgt:
        def toTGT(self):
            return tgt()

    monkeypatch.setattr(
        kerberos_ticket,
        "_cache_material",
        lambda *args: ("host/dc", "REALM", None, Tgt()),
    )
    with pytest.raises(ValueError):
        kerberos_ticket.load_service_ticket(
            Credentials("alice"), "host/dc", None, policy="auto"
        )
    assert len(calls) == 1


@pytest.mark.parametrize("prefix", ["d", None])
def test_get_representation_uses_expanded_name_not_literal_prefix(prefix):
    from adwsearch.transport.nbf.records import StartElement

    events = direct_response([item("domainDNS", {"cn": ["x"]})])
    events = [
        StartElement(prefix, e.name)
        if isinstance(e, StartElement) and e.prefix == "addata"
        else e
        for e in events
    ]
    events.insert(
        1, Xmlns(prefix, "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data")
    )
    assert parser.parse_get_response(events).object_class == "domainDNS"


def test_get_rejects_wrong_namespace_despite_literal_addata_prefix():
    events = direct_response([item("domainDNS", {})])
    events = [
        Xmlns("addata", "urn:wrong")
        if isinstance(e, Xmlns) and e.prefix == "addata"
        else e
        for e in events
    ]
    with pytest.raises(ValueError):
        parser.parse_get_response(events)


def test_coordinated_ec_rrc_edit_cannot_shorten_authenticated_plaintext():
    ctx = context()
    ctx.step(reply(7))
    token = bytearray(_simulate_server_wrap(SUBKEY, _AES128CTS, b"answer", 7))
    token[4:8] = struct.pack(
        ">HH", 1, 27
    )  # Same rotation; previously truncated one byte.
    with pytest.raises(ValueError):
        ctx.unwrap(bytes(token))
    assert ctx._recv_seq == 7


def test_get_rejects_nested_soap_lookalikes():
    from tests.test_adws_client import el

    events = el(
        "s",
        "Envelope",
        [
            el(
                "addata",
                "wrapper",
                [
                    el(
                        "s",
                        "Header",
                        [
                            el(
                                "wsa",
                                "Action",
                                text="http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
                            )
                        ],
                    ),
                    el("s", "Body", [item("domainDNS", {})]),
                ],
            )
        ],
    )
    with pytest.raises(ValueError):
        parser.parse_get_response(events)


def test_get_namespace_rebinding_is_scoped_to_representation():
    from adwsearch.transport.nbf.records import StartElement

    events = direct_response([item("domainDNS", {})])
    index = next(
        i
        for i, event in enumerate(events)
        if isinstance(event, StartElement) and event.name == "domainDNS"
    )
    events.insert(index + 1, Xmlns("addata", "urn:wrong"))
    with pytest.raises(ValueError):
        parser.parse_get_response(events)
