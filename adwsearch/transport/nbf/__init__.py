# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""NBF codec: .NET Binary Format for XML/SOAP.

Implements MC-NBFX (XML data structure), MC-NBFS (static SOAP dictionary) and
MC-NBFSE (in-band dynamic dictionary), used by ADWS over the net.tcp binding.

Public API:
    encode(events) / decode(bytes)            -- raw NBFX body
    encode_message(events) / decode_message(bytes) -- NBFSE StringTable + NBFX body
"""

from .decoder import decode
from .encoder import encode
from .nbfse import (
    NbfseSessionDecoder,
    build_stringtable,
    decode_message,
    encode_message,
    parse_stringtable,
)

__all__ = [
    "NbfseSessionDecoder",
    "decode",
    "encode",
    "decode_message",
    "encode_message",
    "build_stringtable",
    "parse_stringtable",
]
