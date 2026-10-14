# mxcheck.ps1 - check a list of domains for MX, SPF, DKIM and DMARC.
#
# Usage:   .\mxcheck.ps1 domains.csv [results.csv]
# Input:   domain in the first column (header row is fine, it gets skipped)
# Output:  one row per MX server (a domain without MX gets one row)
# Needs:   Windows (uses Resolve-DnsName). On Linux/macOS use mxcheck.sh.

param(
    [Parameter(Mandatory)] [string]$InputFile,
    [string]$OutputFile = "results.csv"
)

# DKIM selectors are chosen by the sender, so we can only guess.
# 1) try the selectors of the provider we detect (from MX hosts / SPF)
# 2) if nothing is found, try the generic list
$GenericSelectors = 'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'smtp'

$ProviderSelectors = @{
    'google.com'  = 'google'
    'outlook.com' = 'selector1', 'selector2'
    'zoho.'       = 'zoho', 'zmail'
    'protonmail'  = 'protonmail', 'protonmail2', 'protonmail3'
    'fastmail'    = 'fm1', 'fm2', 'fm3'
    'yandex.'     = 'mail'
    'sendgrid'    = 's1', 's2'
    'mailgun'     = 'k1', 'smtp', 'mx'
    'mailchimp'   = 'k1', 'k2', 'k3'
    'mcsv.net'    = 'k1', 'k2', 'k3'
    'mandrill'    = 'mandrill'
    'mailjet'     = 'mailjet'
}

# ---------- small helpers ----------
function Get-Dns($name, $type) {
    try   { Resolve-DnsName -Name $name -Type $type -DnsOnly -ErrorAction Stop | Where-Object Type -eq $type }
    catch { }                                   # no record / lookup failed -> nothing
}

function Get-Txt($name) {
    Get-Dns $name TXT | ForEach-Object { $_.Strings -join '' }    # join split TXT strings
}

function YesNo($value) {
    if ($value) { 'yes' } else { 'no' }
}

# All values of one SPF mechanism, joined by ";"
# e.g. type 'include' for "include:_spf.google.com", type 'ip4' for "ip4:1.2.3.0/24"
function Get-SpfValue($spf, $type) {
    ("$spf" -split '\s+' |
        ForEach-Object { $_.TrimStart('+', '-', '~', '?') } |
        Where-Object { $_ -like "${type}:*" } |
        ForEach-Object { $_.Substring($type.Length + 1) }) -join ';'
}

# ---------- main loop ----------
Remove-Item $OutputFile -ErrorAction SilentlyContinue

foreach ($line in Get-Content $InputFile) {
    $domain = ($line -split ',')[0].Trim('" ').TrimEnd('.').ToLower()
    if ($domain -notlike '*.*') { continue }    # skips blank lines and the header row

    Write-Host "Checking $domain"

    # MX records, lowest preference first (fetched first: the hosts hint at the provider)
    $mxRecords = @(Get-Dns $domain MX | Sort-Object Preference)

    # SPF: a TXT record on the domain starting with v=spf1
    $spf = Get-Txt $domain | Where-Object { $_ -like 'v=spf1*' } | Select-Object -First 1
    $spfInclude = Get-SpfValue $spf 'include'
    $spfIpv4    = Get-SpfValue $spf 'ip4'
    $spfIpv6    = Get-SpfValue $spf 'ip6'

    # DKIM: look for <selector>._domainkey.<domain>
    $hint = ((($mxRecords | ForEach-Object { $_.NameExchange }) -join ' ') + " $spf").ToLower()
    $providerList = foreach ($key in $ProviderSelectors.Keys) {
        if ($hint -like "*$key*") { $ProviderSelectors[$key] }
    }

    $found = @()
    foreach ($list in @($providerList), $GenericSelectors) {
        foreach ($sel in $list | Select-Object -Unique) {
            if (Get-Txt "$sel._domainkey.$domain" | Where-Object { $_ -match 'v=DKIM1|p=' }) {
                $found += $sel
            }
        }
        if ($found) { break }
    }

    # DMARC: a TXT record on _dmarc.<domain>
    $dmarc = Get-Txt "_dmarc.$domain" | Where-Object { $_ -like 'v=DMARC1*' } | Select-Object -First 1
    $policy = ''
    if ($dmarc -match '(^|;)\s*p=(\w+)') { $policy = $Matches[2] }

    # One row per MX server, with the A record (IP) of that server.
    # A row looks the same everywhere, only the three MX fields change.
    function New-Row($mxHost, $mxIp, $mxPreference) {
        [pscustomobject][ordered]@{
            domain         = $domain
            has_mx         = YesNo $mxHost
            mx_host        = $mxHost
            mx_ip          = $mxIp
            mx_preference  = $mxPreference
            has_spf        = YesNo $spf
            has_dkim       = YesNo $found
            has_dmarc      = YesNo $dmarc
            spf_include    = $spfInclude
            spf_ipv4       = $spfIpv4
            spf_ipv6       = $spfIpv6
            spf_record     = $spf
            dkim_selectors = $found -join ';'
            dmarc_policy   = $policy
            dmarc_record   = $dmarc
        }
    }

    $rows = @()
    foreach ($mx in $mxRecords) {
        $mxHost = $mx.NameExchange.TrimEnd('.')
        if (-not $mxHost) { continue }          # "0 ." means: this domain accepts no mail
        $ips = @(Get-Dns $mxHost A | ForEach-Object { $_.IPAddress })
        $rows += New-Row $mxHost ($ips -join ';') $mx.Preference
    }

    # no MX at all: still write one row so the domain is not lost
    if (-not $rows) { $rows += New-Row '' '' '' }

    $rows | Export-Csv $OutputFile -Append -NoTypeInformation -Encoding UTF8
}

Write-Host "Done. Results saved to $OutputFile"
