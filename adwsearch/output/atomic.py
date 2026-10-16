# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Publish complete UTF-8 files while preserving previous output on failure."""

import os
import tempfile
from contextlib import contextmanager
from typing import Iterator, TextIO


@contextmanager
def atomic_text_file(path: str) -> Iterator[TextIO]:
    target = os.path.abspath(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".adwsearch-", suffix=".tmp",
                                           dir=os.path.dirname(target))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            yield stream
            stream.flush()
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
