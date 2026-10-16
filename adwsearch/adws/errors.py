# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Structured error classification shared by optional directory collectors."""

from adwsearch.soap.parser import AdwsSoapFault


def is_missing_object_fault(fault: AdwsSoapFault) -> bool:
    return fault.ldap_result_code == 32 or fault.win32_error_code == 8240
