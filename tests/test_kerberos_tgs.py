# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import importlib.util
import pytest
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import AS_REP, TGS_REQ, seq_set
from impacket.krb5.types import Principal
from impacket.krb5.crypto import Key, _AES256CTS


def tgt():
    reply = AS_REP()
    reply["pvno"] = 5
    reply["msg-type"] = 11
    reply["crealm"] = "REALM"
    seq_set(reply, "cname", Principal("alice", type=1).components_to_asn1)
    ticket = reply["ticket"]
    ticket["tkt-vno"] = 5
    ticket["realm"] = "REALM"
    seq_set(ticket, "sname", Principal("krbtgt/REALM", type=2).components_to_asn1)
    ticket["enc-part"]["etype"] = 18
    ticket["enc-part"]["cipher"] = b"opaque"
    reply["enc-part"]["etype"] = 18
    reply["enc-part"]["cipher"] = b"opaque"
    return {
        "KDC_REP": encoder.encode(reply),
        "cipher": _AES256CTS(),
        "sessionKey": Key(18, b"\x22" * 32),
    }


@pytest.mark.parametrize("etypes", [(18, 17), (23,)])
def test_request_wire_enctypes_and_exact_spn(monkeypatch, etypes):
    assert importlib.util.find_spec("adwsearch.auth.kerberos_tgs") is not None
    from adwsearch.auth import kerberos_tgs

    seen = []

    class ProbeComplete(Exception):
        pass

    def exchange(data, realm, host, timeout):
        request = decoder.decode(data, asn1Spec=TGS_REQ())[0]
        body = request["req-body"]
        seen.append(
            (
                [int(n) for n in body["etype"]],
                str(body["realm"]),
                [str(x) for x in body["sname"]["name-string"]],
            )
        )
        raise ProbeComplete()

    monkeypatch.setattr(kerberos_tgs, "_exchange", exchange)
    with pytest.raises(ProbeComplete):
        kerberos_tgs.request_service_ticket(
            tgt(), "ldap/alias", "REALM", "192.0.2.1", enctypes=etypes
        )
    assert seen == [(list(etypes), "REALM", ["ldap", "alias"])]


@pytest.mark.parametrize(
    "change", [None, "nonce", "server", "client", "enctype", "integrity", "tail", "encrypted-tail", "metadata"]
)
def test_authenticated_tgs_reply_contract(monkeypatch, change):
    import datetime
    from impacket.krb5.asn1 import TGS_REP, EncTGSRepPart
    from impacket.krb5.types import KerberosTime
    from impacket.krb5 import constants
    from adwsearch.auth import kerberos_tgs

    source = tgt()

    def exchange(data, *args):
        request = decoder.decode(data, asn1Spec=TGS_REQ())[0]
        response = TGS_REP()
        response["pvno"], response["msg-type"], response["crealm"] = 5, 13, "REALM"
        seq_set(
            response,
            "cname",
            Principal(
                "bob" if change == "client" else "alice", type=1
            ).components_to_asn1,
        )
        ticket = response["ticket"]
        ticket["tkt-vno"], ticket["realm"] = 5, "REALM"
        seq_set(
            ticket,
            "sname",
            Principal(
                "ldap/wrong" if change == "server" else "ldap/alias", type=2
            ).components_to_asn1,
        )
        # Outer ticket encryption is unrelated to its negotiated session key.
        ticket["enc-part"]["etype"], ticket["enc-part"]["cipher"] = 23, b"opaque"
        part = EncTGSRepPart()
        part["key"]["keytype"] = 23 if change == "enctype" else 18
        part["key"]["keyvalue"] = b"\x33" * (16 if change == "enctype" else 32)
        part["last-req"][0]["lr-type"] = 0
        now = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
        part["last-req"][0]["lr-value"] = now
        part["nonce"] = int(request["req-body"]["nonce"]) + (change == "nonce")
        part["flags"] = constants.encodeFlags([])
        part["authtime"], part["endtime"], part["srealm"] = now, now, "REALM"
        seq_set(part, "sname", Principal("ldap/alias", type=2).components_to_asn1)
        encrypted = source["cipher"].encrypt(
            source["sessionKey"], 8, encoder.encode(part) + (b'junk' if change == 'encrypted-tail' else b''), None
        )
        if change == "integrity":
            encrypted = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        response["enc-part"]["etype"], response["enc-part"]["cipher"] = 18, encrypted
        if change == 'metadata':
            response['enc-part']['etype'] = 17
        return encoder.encode(response) + (b"junk" if change == "tail" else b"")

    monkeypatch.setattr(kerberos_tgs, "_exchange", exchange)
    if change is not None:
        with pytest.raises(ValueError):
            kerberos_tgs.request_service_ticket(
                source, "ldap/alias", "REALM", None, enctypes=(18, 17)
            )
    else:
        result = kerberos_tgs.request_service_ticket(
            source, "ldap/alias", "REALM", None, enctypes=(18, 17)
        )
        assert result["cipher"].enctype == 18
        assert result["sessionKey"].contents == b"\x33" * 32


@pytest.mark.parametrize(
    "reply", [b"", b"\x00\x00\x00\x00", b"\x01\x00\x00\x01", b"\x00\x00\x00\x02x"]
)
def test_kdc_exchange_rejects_eof_and_unbounded_reply(monkeypatch, reply):
    from adwsearch.auth import kerberos_tgs

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendall(self, data):
            pass

        def recv(self, count):
            nonlocal reply
            result, reply = reply[:1], reply[1:]
            return result

    monkeypatch.setattr(
        kerberos_tgs.socket, "create_connection", lambda *a, **kw: Socket()
    )
    with pytest.raises((ValueError, ConnectionError)):
        kerberos_tgs._exchange(b"request", "REALM", "192.0.2.1", 1)
