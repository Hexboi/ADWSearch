# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Keep process-global CLI logging changes local to each unit test."""

import logging

import pytest


@pytest.fixture(autouse=True)
def restore_cli_logging():
    logger = logging.getLogger("adwsearch")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    for handler in list(logger.handlers):
        if handler not in handlers:
            logger.removeHandler(handler)
            handler.close()
    logger.handlers = handlers
    logger.setLevel(level)
    logger.propagate = propagate
