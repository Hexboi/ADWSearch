# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""CLI-only logging configuration; never log authentication structures."""

import logging
import sys


class _StderrHandler(logging.StreamHandler):
    def emit(self, record):
        self.stream = sys.stderr
        super().emit(record)


def configure_logging(verbosity: int) -> None:
    logger = logging.getLogger("adwsearch")
    for handler in list(logger.handlers):
        if isinstance(handler, _StderrHandler):
            logger.removeHandler(handler)
            handler.close()
    handler = _StderrHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING if verbosity == 0 else
                    logging.INFO if verbosity == 1 else logging.DEBUG)
    logger.propagate = False
    for name in ("impacket", "Cryptodome", "cryptography"):
        logging.getLogger(name).setLevel(logging.WARNING)
