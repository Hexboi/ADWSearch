# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Logical records produced by the NBF decoder / consumed by the encoder.

The decoder turns a byte stream into a flat list of these events; the encoder does
the reverse. Keeping them explicit (rather than going straight to XML) makes the
codec easy to test against the byte vectors in the Microsoft specifications.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class StartElement:
    prefix: Optional[str]
    name: str


@dataclass
class Attribute:
    prefix: Optional[str]
    name: str
    value: object


@dataclass
class Xmlns:
    prefix: Optional[str]  # None means the default namespace (xmlns="...")
    value: str


@dataclass
class Text:
    value: object


@dataclass
class Comment:
    text: str


@dataclass
class EndElement:
    pass
