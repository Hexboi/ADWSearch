# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Independent signed/sealed LDAP oracle. Never pass credentials on argv."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from adwsearch.soap.parser import AdObject


def ldap_query(base, ldap_filter='(objectClass=*)', scope='sub', attributes=None, page_size=256):
    shell = shutil.which('pwsh') or shutil.which('powershell')
    if shell is None or os.name != 'nt':
        pytest.skip('signed LDAP reference needs Windows PowerShell')
    command = [shell, '-NoProfile', '-NonInteractive', '-File',
               str(Path(__file__).with_name('ldap_reference.ps1')),
               '-Base', base, '-Filter', ldap_filter, '-Scope', scope,
               '-Attributes', ','.join(attributes or ['distinguishedName']), '-PageSize', str(page_size)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, 'independent signed LDAP query failed: ' + result.stderr
    rows = json.loads(result.stdout)
    assert isinstance(rows, list)
    objects = []
    for row in rows:
        names = {v.casefold(): v for v in (attributes or []) + [
            'objectClass', 'dnsRecord', 'name', 'msDS-Behavior-Version', 'ms-DS-MachineAccountQuota']}
        attrs = {names.get(key.casefold(), key): [base64.b64decode(v['base64']) if isinstance(v, dict) else v for v in values]
                 for key, values in row['attributes'].items()}
        attrs['distinguishedName'] = [row['dn']]
        for name in ('msDS-Behavior-Version', 'ms-DS-MachineAccountQuota', 'sDRightsEffective'):
            for key in list(attrs):
                if key.casefold() == name.casefold():
                    attrs[name] = [int(v) for v in attrs.pop(key)]
        classes = attrs.get('objectClass', ['object'])
        objects.append(AdObject(classes[-1], attrs))
    return objects


def assert_same_dns(actual, expected):
    def dns(entries):
        return [str(e.attributes['distinguishedName'][0]).casefold() for e in entries]
    left, right = dns(actual), dns(expected)
    assert len(left) == len(set(left)), 'duplicate ADWS DN'
    assert len(right) == len(set(right)), 'duplicate LDAP DN'
    assert set(left) == set(right), ('ADWS/LDAP DN sets differ (missing page or inconsistent results): '
                                    f'ADWS-only={set(left)-set(right)}, LDAP-only={set(right)-set(left)}')


class LdapReference:
    def search(self, base, ldap_filter='(objectClass=*)', scope='sub', attributes=None,
               size_limit=0, page_size=256, **kwargs):
        entries = ldap_query(base, ldap_filter, scope, attributes, page_size)
        return iter(entries[:size_limit] if size_limit else entries)

    def get(self, dn):
        entries = ldap_query(dn, scope='base', attributes=['*', '+'])
        return entries[0] if entries else None
