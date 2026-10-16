# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Explicit opt-in only: no socket or credential lookup during offline tests."""

import os
from contextlib import contextmanager
from dataclasses import dataclass, field

import pytest

from adwsearch.adws.client import AdwsClient
from adwsearch.adws.factory import connect_adws
from adwsearch.auth.credentials import Credentials
from adwsearch.auth.ntlm import NtlmSecurityContext


@dataclass
class LabSettings:
    host: str
    ip: str
    base: str
    domain: str
    user: str
    password: str = field(repr=False)
    timeout: int = 10

    def credentials(self):
        return Credentials(self.user, self.domain, self.password)


@pytest.fixture(scope="session")
def lab_settings():
    if os.environ.get("ADWSEARCH_LAB") != "1":
        pytest.skip("live ADWS tests require ADWSEARCH_LAB=1")
    user, password = os.environ.get("ADWSEARCH_LAB_USER"), os.environ.get("ADWSEARCH_LAB_PASSWORD")
    if not user or not password:
        pytest.fail("set ADWSEARCH_LAB_USER and ADWSEARCH_LAB_PASSWORD", pytrace=False)
    # Reserved documentation addresses, not a configured development lab.
    return LabSettings(os.environ.get("ADWSEARCH_LAB_HOST", "dc01.corp.example"),
                       os.environ.get("ADWSEARCH_LAB_IP", "192.0.2.10"),
                       os.environ.get("ADWSEARCH_LAB_BASE", "DC=corp,DC=example"),
                       os.environ.get("ADWSEARCH_LAB_DOMAIN", "corp.example"), user, password,
                       int(os.environ.get("ADWSEARCH_LAB_TIMEOUT", "10")))


@pytest.fixture(scope="function")
def lab_client(lab_settings):
    settings = lab_settings
    try:
        conn = connect_adws(settings.ip, 9389, NtlmSecurityContext(settings.credentials()),
                            timeout=settings.timeout)
    except Exception as exc:
        pytest.fail(f"ADWS connection failed ({type(exc).__name__})", pytrace=False)
    try:
        @contextmanager
        def resource():
            with connect_adws(settings.ip, 9389, NtlmSecurityContext(settings.credentials()),
                              endpoint="Windows/Resource", timeout=settings.timeout) as resource_conn:
                yield resource_conn
        yield AdwsClient(conn, settings.host, resource_transport_factory=resource)
    finally:
        conn.close()
