# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""ADWS connection layer: wires socket + NMF + NNS + NBFSE into a request/response transport.

Client handshake:
  1. send NMF Preamble (Version, Mode=Duplex, Via, KnownEncoding=binary-session)
  2. send NMF UpgradeRequest("application/negotiate"); read UpgradeResponse (raw)
  3. run the NNS (Negotiate) handshake on the raw socket
  4. through the now-secured NNS stream: send PreambleEnd, read PreambleAck
Then each request() sends one NBFSE message inside an NMF Sized Envelope over the NNS stream
and reads one back. This ``request(records) -> records`` is exactly what AdwsClient expects.

The NNS security context (impacket-backed NTLM / pass-the-hash / Kerberos) is injected; see the
auth layer. The exact placement of PreambleEnd/Ack relative to the security upgrade follows the
net.tcp behavior and is confirmed by live testing (Phase 6).
"""

from adwsearch.transport import nbf, nmf, nns
from adwsearch.transport.streams import FramingReader


class AdwsConnection:
    def __init__(self, stream, security, via, mode=nmf.MODE_DUPLEX,
                 encoding=nmf.ENCODING_BINARY_SESSION):
        self.stream = stream          # RawStream: sendall(bytes) + recv_exact(n)
        self.security = security      # NNS SecurityContext: complete/step/wrap/unwrap
        self.via = via
        self.mode = mode
        self.encoding = encoding
        self.nns = None
        self._reader = None           # NMF reader over the secured NNS stream
        self._decoder = nbf.NbfseSessionDecoder()

    def connect(self):
        self.stream.sendall(
            nmf.build_preamble(self.via, self.mode, self.encoding)
            + nmf.upgrade_request_record())

        raw_reader = FramingReader(self.stream.recv_exact)
        record_type, _ = nmf.read_record(raw_reader)
        if record_type != nmf.RT_UPGRADE_RESPONSE:
            raise ConnectionError(
                f"expected NMF UpgradeResponse, got 0x{record_type:02X}")

        self.nns = nns.NegotiateStream(self.stream, self.security)
        self.nns.handshake()
        self._reader = FramingReader(self.nns.read_exact)

        self.nns.write(nmf.preamble_end_record())
        record_type, _ = nmf.read_record(self._reader)
        if record_type != nmf.RT_PREAMBLE_ACK:
            raise ConnectionError(
                f"expected NMF PreambleAck, got 0x{record_type:02X}")
        return self

    def request(self, records):
        self.nns.write(nmf.sized_envelope_record(nbf.encode_message(records)))
        payload = nmf.read_sized_envelope(self._reader)
        return self._decoder.decode_message(payload)

    def close(self) -> None:
        """Release the underlying stream (best-effort)."""
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
