# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

param(
    [string]$Base = $env:ADWSEARCH_LAB_BASE,
    [string]$Filter = '(objectClass=*)',
    [ValidateSet('base','one','sub')][string]$Scope = 'base',
    [string]$Attributes = 'distinguishedName',
    [ValidateRange(1,1000)][int]$PageSize = 256
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices.Protocols
$labIp = if ($env:ADWSEARCH_LAB_IP) { $env:ADWSEARCH_LAB_IP } else { '192.0.2.10' }
if (-not $Base) { $Base = 'DC=corp,DC=example' }
$labDomain = if ($env:ADWSEARCH_LAB_DOMAIN) { $env:ADWSEARCH_LAB_DOMAIN } else { 'corp.example' }
$labIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($labIp,389,$false,$false)
$labLdap = [System.DirectoryServices.Protocols.LdapConnection]::new($labIdentifier)
try {
    $labLdap.Timeout = [TimeSpan]::FromSeconds(15)
    $labLdap.SessionOptions.ProtocolVersion = 3
    $labLdap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $labLdap.SessionOptions.Signing = $true
    $labLdap.SessionOptions.Sealing = $true
    $labLdap.Credential = [System.Net.NetworkCredential]::new($env:ADWSEARCH_LAB_USER,$env:ADWSEARCH_LAB_PASSWORD,$labDomain)
    $labLdap.Bind()
    $labScope = @{base='Base';one='OneLevel';sub='Subtree'}[$Scope]
    $labRequest = [System.DirectoryServices.Protocols.SearchRequest]::new($Base,$Filter,[System.DirectoryServices.Protocols.SearchScope]::$labScope,[string[]]($Attributes -split ','))
    $labPaging = [System.DirectoryServices.Protocols.PageResultRequestControl]::new($PageSize)
    [void]$labRequest.Controls.Add($labPaging)
    $labRows = [System.Collections.Generic.List[object]]::new()
    do {
        try { $labResponse = $labLdap.SendRequest($labRequest) }
        catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
            if ($_.Exception.Response.ResultCode -eq 'NoSuchObject') { break }
            throw
        }
        foreach ($labEntry in $labResponse.Entries) {
            $labAttrs = [ordered]@{}
            foreach ($labName in $labEntry.Attributes.AttributeNames) {
                $labBinary = $labName -match '^(objectSid|objectGUID|nTSecurityDescriptor|dnsRecord|cACertificate|userCertificate|msDS-AllowedToActOnBehalfOfOtherIdentity)$'
                $labType = if ($labBinary) { [byte[]] } else { [string] }
                $labValues = @($labEntry.Attributes[$labName].GetValues($labType) | ForEach-Object {
                    if ($labBinary) { @{base64=[Convert]::ToBase64String($_)} } else { $_ }
                })
                $labAttrs[$labName] = $labValues
            }
            $labRows.Add(@{dn=$labEntry.DistinguishedName;attributes=$labAttrs})
        }
        $labPageResponse = @($labResponse.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] })
        if ($labPageResponse.Count -ne 1) { throw 'LDAP pagination response control missing' }
        $labPaging.Cookie = $labPageResponse[0].Cookie
    } while ($labPaging.Cookie.Length -gt 0)
    ConvertTo-Json -InputObject @($labRows.ToArray()) -Depth 8 -Compress
} finally { $labLdap.Dispose() }
