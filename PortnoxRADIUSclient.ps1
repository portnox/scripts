#Requires -Version 5.1
<#
.SYNOPSIS
    Tests RADIUS authentication using either RADSEC (RADIUS over TLS) or standard RADIUS (UDP) with PAP, MAB, PEAP/MSCHAPv2, EAP-TLS, or EAP-TTLS/PAP.
.DESCRIPTION
    This script performs RADIUS authentication tests against a specified server using either standard RADIUS or RADSEC transport. It supports PAP, MAB, EAP-TLS, EAP-TTLS/PAP, and PEAP/MSCHAPv2 authentication methods with flexible configuration options for EAP identities, certificates, and RADIUS attributes. The script can be used for functional testing, performance measurement, and interoperability validation of RADIUS/RADSEC deployments.
    Parameters:
        -Server
            Target RADIUS or RADSEC server hostname or IP address.
        -Port
            Server port. Defaults to 1812 for RADIUS or 2083 for RADSEC when not specified.
        -Transport
            Transport mode: RADIUS for UDP RADIUS or RADSEC for RADIUS over TLS.
        -UseRadSec
            Backward-compatible switch that forces RADSEC transport.
        -AuthType
            Authentication method: PAP, MAB, EAP-TLS, EAP-TTLS, or EAP-PEAP.
        -Username
            Username used for PAP, MAB, or outer/inner EAP identity defaults.
        -Password
            Password used for PAP, MAB, TTLS tunneled PAP, or PEAP inner EAP-MSCHAPv2.
        -PeapOuterIdentity
            Optional explicit PEAP outer identity. Defaults to Username unless anonymous outer identity is requested.
        -PeapInnerIdentity
            Optional explicit PEAP inner identity. Defaults to Username.
        -SharedSecret
            Shared RADIUS secret used for packet signing and PAP password protection.
        -NasIdentifier
            NAS-Identifier attribute sent in Access-Request packets.
        -NasPortId
            Optional NAS-Port-Id attribute (RADIUS Attribute 87), for example a switch port or SSID name.
        -NasPortType
            Optional NAS-Port-Type attribute (RADIUS Attribute 61).
            Accepted values:
              0  = Asynchronous
              1  = Synchronous
              15 = Ethernet
              18 = Other Wireless
              19 = Wireless 802.11 (Wi-Fi)
              20 = Token Ring
        -NasIpAddress
            NAS-IP-Address attribute sent in Access-Request packets.
        -CallingStationId
            Calling-Station-Id attribute, typically representing the client MAC or caller ID.
        -CalledStationId
            Optional Called-Station-Id attribute.
        -RootCACertPath
            Root CA certificate path used to validate the outer RADSEC server certificate.
        -ClientCertPath
            Client certificate path used for outer RADSEC mutual TLS when required.
        -ClientCertPassword
            Password for the outer client certificate.
        -EapClientCertPath
            Client certificate path used for inner EAP-TLS authentication.
        -EapClientCertPassword
            Password for the inner EAP-TLS client certificate.
        -EapRootCACertPath
            Root CA certificate path used to validate the inner EAP-TLS, EAP-TTLS, or PEAP server certificate.
        -EapServerName
            Expected DNS name for inner EAP-TLS, EAP-TTLS, or PEAP server certificate validation.
        -SkipEapServerCertCheck
            Disables inner EAP server certificate validation for lab or troubleshooting use.
            [string]-typed flag - pass 1/true/yes/on to enable, e.g. -SkipEapServerCertCheck 1 or,
            in Orion Script Arguments, SkipEapServerCertCheck=1.
        -SkipCertificateCheck
            Disables outer RADSEC server certificate validation for lab or troubleshooting use.
            [string]-typed flag - pass 1/true/yes/on to enable, e.g. -SkipCertificateCheck 1 or,
            in Orion Script Arguments, SkipCertificateCheck=1.
        -SkipRevocationCheck
            Disables certificate revocation checking (OCSP/CRL lookups) for outer RADSEC
            validation and for the inner EAP-TLS/EAP-TTLS/PEAP server certificate validation.
            [string]-typed flag - pass 1/true/yes/on to enable, e.g. -SkipRevocationCheck 1 or,
            in Orion Script Arguments, SkipRevocationCheck=1.
        -TimeoutSeconds
            Per-request timeout in seconds for network and EAP round processing. For UDP RADIUS
            (Transport RADIUS), each round automatically retransmits the same request up to 2
            additional times on timeout before failing, so a worst-case timed-out round can take
            up to 3x this value. For RADSEC (Transport RADSEC), the initial TCP connect + TLS
            handshake similarly retries up to 2 additional times (with a fresh connection each
            attempt) before failing, to absorb transient connection blips or brief certificate
            revocation-check (OCSP/CRL) lookup timeouts.
        -MaxEapRounds
            Maximum number of EAP rounds before aborting.
        -DesiredEapTypes
            EAP types suggested in EAP-NAK responses when the server offers an unsupported method.
        -ReuseRadiusIdentifier
            Reuses the same RADIUS packet Identifier after the EAP engine is initialized.
        -MaxEapTlsFragmentSize
            Maximum TLS payload size per outbound EAP-TLS, EAP-TTLS, or PEAP fragment.
        -PeapPhase2VersionMode
            How PEAP phase-2 version bits are set: CopyServer, Zero, or One.
        -PeapRadiusUserNameMode
            Chooses whether the RADIUS User-Name attribute follows the PEAP outer or inner identity.
        -UseAnonymousPeapOuterIdentity
            Uses anonymous or anonymous@realm as the default PEAP outer identity.
        -PeapPhase2SetLengthBit
            Enables the PEAP phase-2 L-bit and length field on tunneled payloads.
        -PeapPhase2AckBeforeData
            Sends a PEAP ACK round before selected phase-2 payloads for interoperability.
        -continuous
            Runs the script continuously with the same startup parameters and renders a rolling ASCII chart of the Time metric (ms).
        -DebugOutput
            Enables detailed diagnostic logging, packet parsing, and TLS fragment dumps.
        -CaptureDebugOnFailure
            Forces full diagnostic verbosity (as if -DebugOutput were set) into a PowerShell
            transcript for this run. The transcript is discarded automatically when the run
            ends in Access-Accept, and kept only when it ends in reject/failure/error - safe to
            leave enabled permanently on Orion/SAM monitors without generating noise on
            successful runs. Combine with -DebugLogDirectory to control where failure logs land,
            e.g. in the Orion Script Arguments: ...,CaptureDebugOnFailure=1,DebugLogDirectory=C:\ProgramData\PortnoxRadiusDebug
        -DebugLogDirectory
            Directory where failure transcripts are written when -CaptureDebugOnFailure is used.
            Defaults to a "PortnoxRadiusDebugLogs" folder under the system temp directory.
                -Orion
                    When running under SolarWinds SAM, place Orion as the first Script
                    Arguments token (for example: Orion,${IP},1812,RADIUS,PAP,...).
                    The script will treat that sentinel as Orion mode and read the
                    remaining comma-separated values into the in-script fallback settings
                    block instead of relying on named PowerShell switch parameters.
                    Command-line parameters still override those fallback values.
                        Emits SolarWinds SAM PowerShell Script Monitor output keys:
                            Statistic: <elapsed milliseconds>
                            Message: <final response or error message>
                        Exit code mapping in Orion mode:
                            0 = Access-Accept
                            3 = Access-Reject
                            1 = Any other failure

    Example invocations:
        1. PAP Authentication with regular RADIUS (no RADSEC)
               .\PortnoxRADIUSclient.ps1 -Server {IP/FQDN} -Port {RADIUS-Port} -Transport RADIUS -SharedSecret {RADIUS secret} -AuthType PAP -Username {username} -Password {password} -NasPortId GigabitEthernet1/0/9 -NasPortType 15

         1a. MAB Authentication with regular RADIUS (no RADSEC)
             .\PortnoxRADIUSclient.ps1 -Server {IP/FQDN} -Port {RADIUS-Port} -Transport RADIUS -SharedSecret {RADIUS secret} -AuthType MAB -CallingStationId 00-11-22-33-44-55 -NasPortId GigabitEthernet1/0/9 -NasPortType 15

        2. PAP Authentication over RADSEC
               .\PortnoxRADIUSclient.ps1 -Server clear-rad.portnox.com -Port {RADIUS-Port} -Transport RADSEC -SharedSecret radsec -AuthType PAP -Username {username} -Password {password} -RootCACertPath .\rootCertificate.cer -NasPortId MyWiFiSSID -NasPortType 19

         2a. MAB Authentication over RADSEC
             .\PortnoxRADIUSclient.ps1 -Server clear-rad.portnox.com -Port {RADIUS-Port} -Transport RADSEC -SharedSecret radsec -AuthType MAB -CallingStationId 00-11-22-33-44-55 -RootCACertPath .\rootCertificate.cer -NasPortId MyWiFiSSID -NasPortType 19

        3. PEAP/MSCHAPv2 authentication with regular RADIUS (no RADSEC)
               .\PortnoxRADIUSclient.ps1 -Server {IP/FQDN} -Port {RADIUS-Port} -Transport RADIUS -SharedSecret {RADIUS secret} -AuthType EAP-PEAP -Username {username} -Password {password} -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer -NasPortId GigabitEthernet1/0/9 -NasPortType 18

        4. PEAP/MSCHAPv2 over RADSEC
               .\PortnoxRADIUSclient.ps1 -Server clear-rad.portnox.com -Port {RADIUS-Port} -Transport RADSEC -SharedSecret radsec -AuthType EAP-PEAP -Username {username} -Password {password} -RootCACertPath .\rootCertificate.cer -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer -NasPortId MyWiFiSSID -NasPortType 1

        5. EAP-TLS Authentication with regular RADIUS (no RADSEC)
               .\PortnoxRADIUSclient.ps1 -Server {IP/FQDN} -Port {RADIUS-Port} -Transport RADIUS -SharedSecret {RADIUS secret} -AuthType EAP-TLS -Username {username} -EapClientCertPath .\client.p12 -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer -NasPortId GigabitEthernet1/0/9 -NasPortType 0

        6. EAP-TLS Authentication over RADSEC
               .\PortnoxRADIUSclient.ps1 -Server clear-rad.portnox.com -Port {RADIUS-Port} -Transport RADSEC -SharedSecret radsec -AuthType EAP-TLS -RootCACertPath .\rootCertificate.cer -EapClientCertPath .\client.p12 -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer

         7. EAP-TTLS/PAP Authentication with regular RADIUS (no RADSEC)
             .\PortnoxRADIUSclient.ps1 -Server {IP/FQDN} -Port {RADIUS-Port} -Transport RADIUS -SharedSecret {RADIUS secret} -AuthType EAP-TTLS -Username {username} -Password {password} -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer

         8. EAP-TTLS/PAP Authentication over RADSEC
             .\PortnoxRADIUSclient.ps1 -Server clear-rad.portnox.com -Port {RADIUS-Port} -Transport RADSEC -SharedSecret radsec -AuthType EAP-TTLS -Username {username} -Password {password} -RootCACertPath .\rootCertificate.cer -EapServerName clear-rad.portnox.com -EapRootCACertPath .\rootCertificate.cer

    
#>

[CmdletBinding(PositionalBinding=$false)]
param(
    [string] $Server,
    [int] $Port = 0,

    [ValidateSet("RADSEC","RADIUS")]
    [string] $Transport = "RADIUS",

    [switch] $UseRadSec,

    [ValidateSet("PAP","MAB","EAP-TLS","EAP-PEAP","EAP-TTLS")]
    [string] $AuthType = "PAP",

    [string] $Username,
    [string] $Password,

    [string] $PeapOuterIdentity,
    [string] $PeapInnerIdentity,

    [string] $SharedSecret = "radsec",
    [string] $NasIdentifier = "Test-RadSec-Script",
    [string] $NasPortId,
    [ValidateSet("0","1","15","18","19","20")]
    [string] $NasPortType,

    [string] $NasIpAddress = "127.0.0.1",
    [string] $CallingStationId = "00-00-00-00-00-00",
    [string] $CalledStationId,

    [string] $RootCACertPath,
    [string] $ClientCertPath,
    [SecureString] $ClientCertPassword,

    # EAP-TLS inner TLS parameters
    [string] $EapClientCertPath,
    [SecureString] $EapClientCertPassword,
    [string] $EapRootCACertPath,
    [string] $EapServerName,

    # Intentionally [string] rather than [switch]/[bool]: SolarWinds SAM decomposes
    # comma-separated "Name=Value" Script Arguments into individually PSRP-bound named
    # parameters, passing an explicit System.String value (e.g. "1") for SkipRevocationCheck=1.
    # That binding fails hard for [switch]/[bool] params - PowerShell's ArgumentTypeConverterAttribute
    # (auto-applied to those types) rejects any System.String value, even "1". [string] has no
    # such converter, so PSRP binding always succeeds; truthiness is evaluated manually via
    # Test-TruthyToken.
    [string] $SkipEapServerCertCheck = "",

    [string] $SkipCertificateCheck = "",
    [string] $SkipRevocationCheck = "",

    [int] $TimeoutSeconds = 15,
    [int] $MaxEapRounds = 60,

    [byte[]] $DesiredEapTypes,

    [switch] $ReuseRadiusIdentifier,

    [int] $MaxEapTlsFragmentSize = 900,

    [ValidateSet("CopyServer","Zero","One")]
    [string] $PeapPhase2VersionMode = "CopyServer",

    [ValidateSet("Outer","Inner")]
    [string] $PeapRadiusUserNameMode = "Inner",

    [switch] $UseAnonymousPeapOuterIdentity,

    [switch] $PeapPhase2SetLengthBit,

    [switch] $PeapPhase2AckBeforeData,

    [switch] $continuous,

    [Alias("?","help")]
    [switch] $ShowHelp,

    [switch] $EmitResultObject,

    [switch] $Orion,

    [switch] $DebugOutput,

    # Intentionally [string] rather than [switch]/[bool]: SolarWinds SAM decomposes
    # comma-separated "Name=Value" Script Arguments into individually PSRP-bound named
    # parameters, passing an explicit System.String value (e.g. "1") for
    # CaptureDebugOnFailure=1. PowerShell's ArgumentTypeConverterAttribute (auto-applied to
    # [switch] AND [bool] parameters) explicitly rejects any System.String value in that
    # binding path - even "1" - accepting only real Boolean/SwitchParameter/numeric CLR types
    # ("Cannot convert value "System.String" to type ... Boolean/SwitchParameter"). [string]
    # has no such converter, so PSRP binding always succeeds; truthiness is evaluated manually
    # via Test-TruthyToken below.
    [string] $CaptureDebugOnFailure = "",
    [string] $DebugLogDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "PortnoxRadiusDebugLogs"),

    # Catches any stray unnamed/positional argument - most notably the bare "Orion" sentinel
    # token in comma-separated SAM Script Arguments - that isn't consumed by any named
    # parameter above. With PositionalBinding=$false, PowerShell has no other eligible
    # parameter to place an unnamed value into; advanced functions/scripts ([CmdletBinding()])
    # have no implicit $args catch-all, so without this the binder hard-fails with
    # "A positional parameter cannot be found that accepts argument 'Orion'." instead of
    # either silently corrupting some other parameter (the original bug) or accepting it
    # harmlessly. Must remain the last declared parameter (ValueFromRemainingArguments
    # requirement).
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArguments
)

# Populate these values only if SolarWinds SAM will invoke the script with -Orion
# and without passing the normal script arguments. Any values passed on the command
# line still take precedence over these in-script fallbacks.
$script:OrionFallbackSettings = [ordered]@{
    Server = ""
    Port = 0
    Transport = ""
    UseRadSec = $false
    AuthType = ""
    Username = ""
    Password = ""
    PeapOuterIdentity = ""
    PeapInnerIdentity = ""
    SharedSecret = ""
    NasIdentifier = ""
    NasPortId = ""
    NasPortType = ""
    NasIpAddress = ""
    CallingStationId = ""
    CalledStationId = ""
    RootCACertPath = ""
    ClientCertPath = ""
    ClientCertPasswordPlainText = ""
    EapClientCertPath = ""
    EapClientCertPasswordPlainText = ""
    EapRootCACertPath = ""
    EapServerName = ""
    SkipEapServerCertCheck = $false
    SkipCertificateCheck = $false
    SkipRevocationCheck = $false
    TimeoutSeconds = 0
    MaxEapRounds = 0
    ReuseRadiusIdentifier = $false
    MaxEapTlsFragmentSize = 0
    PeapPhase2VersionMode = ""
    PeapRadiusUserNameMode = ""
    UseAnonymousPeapOuterIdentity = $false
    PeapPhase2SetLengthBit = $false
    PeapPhase2AckBeforeData = $false
    DebugOutput = $false
    CaptureDebugOnFailure = $false
    DebugLogDirectory = ""
}

$script:IsOrionMode = $Orion.IsPresent

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Manually interprets a raw string value (from -CaptureDebugOnFailure, -SkipEapServerCertCheck,
# -SkipCertificateCheck, -SkipRevocationCheck, or similar string-typed flag parameters) as a
# boolean, since these parameters are intentionally NOT [switch]/[bool] typed - see the
# corresponding param block comments for why.
function Test-TruthyToken {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value.Trim() -notmatch '(?i)^(0|false|no|off)$')
}

function Split-NormalizedInvocationToken {
    param([string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }
    $tokens = New-Object 'System.Collections.Generic.List[string]'
    foreach ($commaPart in ($Text -split ',')) {
        $part = $commaPart.Trim()
        if ($part.Length -eq 0) {
            continue
        }

        foreach ($spacePart in ($part -split '\s+(?=[A-Za-z][A-Za-z0-9]*=)')) {
            $token = $spacePart.Trim()
            if ($token.Length -gt 0) {
                [void]$tokens.Add($token)
            }
        }
    }

    return ,$tokens.ToArray()
}

function Get-NormalizedInvocationArguments {
    $tokens = New-Object 'System.Collections.Generic.List[string]'

    # With PositionalBinding=$false, any stray unnamed argument (e.g. the bare "Orion" sentinel
    # token) is captured by the -RemainingArguments catch-all parameter rather than surfacing in
    # $args or $MyInvocation.UnboundArguments, so check it first.
    $sourceArgs = @()
    if ($RemainingArguments -and $RemainingArguments.Count -gt 0) {
        $sourceArgs = @($RemainingArguments)
    } else {
        $argsVariable = Get-Variable -Name args -Scope Local -ErrorAction SilentlyContinue
        if ($argsVariable -and $null -ne $argsVariable.Value) {
            $sourceArgs = @($argsVariable.Value)
        } elseif ($MyInvocation -and $MyInvocation.UnboundArguments) {
            $sourceArgs = @($MyInvocation.UnboundArguments)
        }
    }

    foreach ($item in $sourceArgs) {
        if ($null -eq $item) { continue }
        foreach ($token in (Split-NormalizedInvocationToken -Text ([string]$item))) {
            [void]$tokens.Add($token)
        }
    }

    return ,$tokens.ToArray()
}

function Test-IsOrionArgumentInvocation {
    param([string[]] $InvocationArguments)

    if (-not $InvocationArguments -or $InvocationArguments.Count -eq 0) {
        return $false
    }

    if ($InvocationArguments[0] -eq 'Orion') {
        return $true
    }

    foreach ($argument in $InvocationArguments) {
        if ([string]::IsNullOrWhiteSpace($argument)) {
            continue
        }

        if ($argument -match '^[A-Za-z][A-Za-z0-9]*=') {
            return $true
        }
    }

    return $false
}

function Test-IsOrionInvocationLine {
    param([string] $InvocationLine)

    if ([string]::IsNullOrWhiteSpace($InvocationLine)) {
        return $false
    }

    if ($InvocationLine -match '(^|[\s,])Orion([\s,]|$)') {
        return $true
    }

    if ($InvocationLine -match '\b(Server|Port|Transport|AuthType|Username|Password|SharedSecret|NasPortId|NasPortType|CaptureDebugOnFailure|DebugLogDirectory)=') {
        return $true
    }

    return $false
}

function Convert-OrionArgumentValue {
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $trimmed = $Value.Trim()
    switch -Regex ($trimmed) {
        '^(?i:true|false)$' { return [bool]::Parse($trimmed) }
        '^(?i:1|0|yes|no|on|off)$' {
            switch -Regex ($trimmed) {
                '^(?i:1|yes|on)$' { return $true }
                default { return $false }
            }
        }
        '^(?i:null|none)$' { return $null }
        '^[+-]?\d+$' {
            try { return [int]$trimmed } catch { return $trimmed }
        }
        default { return $trimmed }
    }
}

function Initialize-OrionFallbackSettingsFromArguments {
    param([string[]] $InvocationArguments)

    if (-not $InvocationArguments -or $InvocationArguments.Count -eq 0) {
        return $false
    }

    if ($InvocationArguments[0] -ne 'Orion') {
        return $false
    }

    $script:IsOrionMode = $true

    $orionArgumentNames = @(
        'Server',
        'Port',
        'Transport',
        'UseRadSec',
        'AuthType',
        'Username',
        'Password',
        'PeapOuterIdentity',
        'PeapInnerIdentity',
        'SharedSecret',
        'NasIdentifier',
        'NasPortId',
        'NasPortType',
        'NasIpAddress',
        'CallingStationId',
        'CalledStationId',
        'RootCACertPath',
        'ClientCertPath',
        'ClientCertPasswordPlainText',
        'EapClientCertPath',
        'EapClientCertPasswordPlainText',
        'EapRootCACertPath',
        'EapServerName',
        'SkipEapServerCertCheck',
        'SkipCertificateCheck',
        'SkipRevocationCheck',
        'TimeoutSeconds',
        'MaxEapRounds',
        'ReuseRadiusIdentifier',
        'MaxEapTlsFragmentSize',
        'PeapPhase2VersionMode',
        'PeapRadiusUserNameMode',
        'UseAnonymousPeapOuterIdentity',
        'PeapPhase2SetLengthBit',
        'PeapPhase2AckBeforeData',
        'DebugOutput',
        'CaptureDebugOnFailure',
        'DebugLogDirectory'
    )

    $positionalIndex = 0
    for ($i = 1; $i -lt $InvocationArguments.Count; $i++) {
        $argument = $InvocationArguments[$i]
        if ([string]::IsNullOrWhiteSpace($argument)) {
            continue
        }

        $name = $null
        $valueText = $argument
        if ($argument -match '^([^=]+)=(.*)$') {
            $candidateName = $matches[1].Trim()
            if ($candidateName) {
                $name = $candidateName
                $valueText = $matches[2]
            }
        }

        if (-not $name) {
            if ($positionalIndex -ge $orionArgumentNames.Count) {
                continue
            }
            $name = $orionArgumentNames[$positionalIndex]
            $positionalIndex++
        }

        $value = Convert-OrionArgumentValue -Value $valueText
        if ($null -eq $value) {
            continue
        }

        switch ($name) {
            'UseRadSec' { $script:OrionFallbackSettings.UseRadSec = [bool]$value; continue }
            'SkipEapServerCertCheck' { $script:OrionFallbackSettings.SkipEapServerCertCheck = [bool]$value; continue }
            'SkipCertificateCheck' { $script:OrionFallbackSettings.SkipCertificateCheck = [bool]$value; continue }
            'SkipRevocationCheck' { $script:OrionFallbackSettings.SkipRevocationCheck = [bool]$value; continue }
            'ReuseRadiusIdentifier' { $script:OrionFallbackSettings.ReuseRadiusIdentifier = [bool]$value; continue }
            'UseAnonymousPeapOuterIdentity' { $script:OrionFallbackSettings.UseAnonymousPeapOuterIdentity = [bool]$value; continue }
            'PeapPhase2SetLengthBit' { $script:OrionFallbackSettings.PeapPhase2SetLengthBit = [bool]$value; continue }
            'PeapPhase2AckBeforeData' { $script:OrionFallbackSettings.PeapPhase2AckBeforeData = [bool]$value; continue }
            'DebugOutput' { $script:OrionFallbackSettings.DebugOutput = [bool]$value; continue }
            'CaptureDebugOnFailure' { $script:OrionFallbackSettings.CaptureDebugOnFailure = [bool]$value; continue }
            'Port' { $script:OrionFallbackSettings.Port = [int]$value; continue }
            'TimeoutSeconds' { $script:OrionFallbackSettings.TimeoutSeconds = [int]$value; continue }
            'MaxEapRounds' { $script:OrionFallbackSettings.MaxEapRounds = [int]$value; continue }
            'MaxEapTlsFragmentSize' { $script:OrionFallbackSettings.MaxEapTlsFragmentSize = [int]$value; continue }
            'ClientCertPasswordPlainText' { $script:OrionFallbackSettings.ClientCertPasswordPlainText = [string]$value; continue }
            'EapClientCertPasswordPlainText' { $script:OrionFallbackSettings.EapClientCertPasswordPlainText = [string]$value; continue }
            default { $script:OrionFallbackSettings[$name] = [string]$value }
        }
    }

    return $true
}

function Apply-OrionFallbackSettings {
    param([System.Collections.IDictionary] $BoundParameters)

    if (-not $script:IsOrionMode) {
        return
    }

    foreach ($entry in $script:OrionFallbackSettings.GetEnumerator()) {
        $name = [string]$entry.Key
        $value = $entry.Value

        if ($name -in @("ClientCertPasswordPlainText", "EapClientCertPasswordPlainText")) {
            continue
        }

        if ($BoundParameters.ContainsKey($name) -and -not ($script:IsOrionMode -and $name -eq "Server" -and $Server -match '(^|[\s,])Orion([\s,]|$)')) {
            continue
        }

        if ($value -is [string]) {
            if ([string]::IsNullOrWhiteSpace($value)) {
                continue
            }
            Set-Variable -Name $name -Value $value -Scope Script
            continue
        }

        if ($value -is [int]) {
            if ($value -le 0) {
                continue
            }
            Set-Variable -Name $name -Value $value -Scope Script
            continue
        }

        if ($value -is [bool]) {
            if (-not $value) {
                continue
            }
            if ($name -in @("CaptureDebugOnFailure", "SkipEapServerCertCheck", "SkipCertificateCheck", "SkipRevocationCheck")) {
                # These are [string], not [switch]/[bool] - see param block comments.
                Set-Variable -Name $name -Value "1" -Scope Script
            } else {
                Set-Variable -Name $name -Value ([System.Management.Automation.SwitchParameter]::Present) -Scope Script
            }
            continue
        }

        if ($null -ne $value) {
            Set-Variable -Name $name -Value $value -Scope Script
        }
    }

    if (-not $BoundParameters.ContainsKey("ClientCertPassword") -and -not [string]::IsNullOrWhiteSpace($script:OrionFallbackSettings.ClientCertPasswordPlainText)) {
        $ClientCertPassword = ConvertTo-SecureString -String $script:OrionFallbackSettings.ClientCertPasswordPlainText -AsPlainText -Force
    }

    if (-not $BoundParameters.ContainsKey("EapClientCertPassword") -and -not [string]::IsNullOrWhiteSpace($script:OrionFallbackSettings.EapClientCertPasswordPlainText)) {
        $EapClientCertPassword = ConvertTo-SecureString -String $script:OrionFallbackSettings.EapClientCertPasswordPlainText -AsPlainText -Force
    }
}

# Reads the top <# ... #> block from this script and prints it as runtime help.
# This keeps CLI help aligned with the maintained header documentation.
function Write-ScriptHeaderHelp {
    param([string] $Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        Write-Host "Usage help is unavailable because the script path could not be resolved."
        return
    }

    $helpLines = [System.Collections.Generic.List[string]]::new()
    $inBlock = $false

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $inBlock) {
            if ($trimmed -eq "<#") {
                $inBlock = $true
            }
            continue
        }

        if ($trimmed -eq "#>") {
            break
        }

        [void]$helpLines.Add($line)
    }

    if ($helpLines.Count -gt 0) {
        Write-Host ($helpLines -join [Environment]::NewLine)
        return
    }

    Write-Host "No script header help block was found."
}

$rawArgs = Get-NormalizedInvocationArguments
if ($Server -and $Server -match '(^|[\s,])Orion([\s,]|$)') {
    $serverArgTokens = Split-NormalizedInvocationToken -Text $Server
    if ($serverArgTokens -and $serverArgTokens.Count -gt 0) {
        $rawArgs = @($serverArgTokens) + @($rawArgs)
    } elseif (-not $rawArgs -or $rawArgs.Count -eq 0 -or $rawArgs[0] -ne "Orion") {
        $rawArgs = @("Orion") + @($rawArgs)
    }
}
$script:IsOrionMode = $script:IsOrionMode -or (Test-IsOrionArgumentInvocation -InvocationArguments $rawArgs)
$script:IsOrionMode = $script:IsOrionMode -or (Test-IsOrionInvocationLine -InvocationLine $MyInvocation.Line)
$null = Initialize-OrionFallbackSettingsFromArguments -InvocationArguments $rawArgs
$helpTokenRequested = $rawArgs -contains "/?" -or $rawArgs -contains "-?" -or $rawArgs -contains "-help" -or $rawArgs -contains "--help"
$noArgumentsProvided = ($PSBoundParameters.Count -eq 0 -and $rawArgs.Count -eq 0)

# Handle documentation-only invocations before any auth validation or network setup.
if ($ShowHelp.IsPresent -or $helpTokenRequested -or $noArgumentsProvided) {
    Write-ScriptHeaderHelp -Path $PSCommandPath
    return
}

Apply-OrionFallbackSettings -BoundParameters $PSBoundParameters

if ([string]::IsNullOrWhiteSpace($Server)) {
    throw "Parameter -Server is required. Run the script with -help to view parameters and examples."
}

function Get-PrimaryLocalIPv4 {
    try {
        $hostName = [System.Net.Dns]::GetHostName()
        $addresses = [System.Net.Dns]::GetHostAddresses($hostName) | Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
            -not $_.IPAddressToString.StartsWith("127.") -and
            -not $_.IPAddressToString.StartsWith("169.254.")
        }
        if ($addresses -and $addresses.Count -gt 0) {
            return $addresses[0].IPAddressToString
        }
    } catch {
        return $null
    }
    return $null
}

$script:StartupBoundParameters = @{}
foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    $script:StartupBoundParameters[$entry.Key] = $entry.Value
}

# IMPORTANT: This script compiles C# types on first run. If you modify the C# code and re-run
# in the same PowerShell session, the old cached version will be used. Use a fresh PowerShell
# session after any code changes (especially changes to EapTlsPipeStream class).
Write-Verbose "NOTE: Using fresh PowerShell session ensures latest compiled types are loaded"

#region --- Validation / defaults
if ($Port -le 0) {
    $Port = if ($Transport -eq "RADSEC") { 2083 } else { 1812 }
}

if ($UseRadSec.IsPresent) {
    if ($PSBoundParameters.ContainsKey("Transport") -and $Transport -ne "RADSEC") {
        throw "Conflicting transport options: -UseRadSec cannot be combined with -Transport RADIUS."
    }
    $Transport = "RADSEC"
    if (-not $PSBoundParameters.ContainsKey("Port")) {
        $Port = 2083
    }
}

if (-not $PSBoundParameters.ContainsKey("NasIpAddress") -and ([string]::IsNullOrWhiteSpace($NasIpAddress) -or $NasIpAddress -eq "127.0.0.1")) {
    # Auto-detect a real NAS-IP-Address whenever the caller relies on the loopback default,
    # regardless of Orion-mode detection, since Portnox's backend rejects 127.0.0.1.
    $detectedNasIp = Get-PrimaryLocalIPv4
    if (-not [string]::IsNullOrWhiteSpace($detectedNasIp)) {
        $NasIpAddress = $detectedNasIp
    }
}

if ($AuthType -eq "PAP") {
    if (-not $Username) { throw "Parameter -Username is required for PAP." }
    if (-not $Password) { throw "Parameter -Password is required for PAP." }
} elseif ($AuthType -eq "MAB") {
    # MAB identity is always the Calling-Station-Id (the MAC being authenticated). This is
    # unconditional - not gated on $PSBoundParameters - because argument-binding behavior for
    # the Orion sentinel invocation can differ across PowerShell hosts/versions, and any stray
    # or sentinel value (e.g. "Orion") reaching User-Name causes Portnox's backend to reject
    # the request with an HTTP 400. MAB has no legitimate use case for a distinct -Username.
    if (-not $CallingStationId) {
        throw "Parameter -CallingStationId is required for MAB."
    }
    $Username = $CallingStationId
    if (-not $Password) { $Password = $Username }
} else {
    if (-not $Username) { $Username = "eapuser" }
    if ($Username -eq "Orion") {
        # Same class of issue as the MAB Orion-sentinel fix above: "Orion" reaching Username here
        # is never a legitimate credential. Unlike MAB, this can't be silently substituted with a
        # sane default (there's no equivalent of Calling-Station-Id to fall back to), so surface it
        # as an explicit, actionable error rather than letting it silently reach the wire and fail
        # opaquely downstream (e.g. as a confusing Portnox auth rejection).
        throw "Username resolved to the literal value 'Orion' (the Orion-mode sentinel token), not a real credential. This usually means the SolarWinds SAM Script Arguments 'Username=' field is missing, blank, or was accidentally left as a leftover template/sentinel value. Check that monitor's Script Arguments configuration."
    }
    if ($AuthType -eq "EAP-PEAP" -and -not $Password) { throw "Parameter -Password is required for EAP-PEAP (MSCHAPv2 inner auth)." }
    if ($AuthType -eq "EAP-TTLS" -and -not $Password) { throw "Parameter -Password is required for EAP-TTLS (tunneled PAP auth)." }
    if (-not $EapClientCertPath) { $EapClientCertPath = $ClientCertPath }
    if (-not $EapClientCertPassword) { $EapClientCertPassword = $ClientCertPassword }
    if (-not $EapRootCACertPath) { $EapRootCACertPath = $RootCACertPath }
    if (-not $EapServerName) { $EapServerName = $Server }

    if ($AuthType -eq "EAP-PEAP") {
        if (-not $PeapInnerIdentity) {
            $PeapInnerIdentity = $Username
        }
        if (-not $PeapOuterIdentity) {
            if ($UseAnonymousPeapOuterIdentity.IsPresent) {
                if ($PeapInnerIdentity -and $PeapInnerIdentity.Contains("@")) {
                    $realm = $PeapInnerIdentity.Split("@", 2)[1]
                    $PeapOuterIdentity = "anonymous@$realm"
                } else {
                    $PeapOuterIdentity = "anonymous"
                }
            } else {
                # Backward-compatible default: outer identity matches Username unless explicitly overridden.
                $PeapOuterIdentity = $Username
            }
        }
    }
}

if ($AuthType -eq "EAP-PEAP" -and -not $PSBoundParameters.ContainsKey("PeapRadiusUserNameMode")) {
    # Keep outer EAP identity and RADIUS User-Name aligned by default when using an
    # anonymous outer identity; otherwise preserve the historical inner-user default.
    if ($UseAnonymousPeapOuterIdentity.IsPresent -or ($PeapOuterIdentity -and $PeapOuterIdentity -ne $PeapInnerIdentity)) {
        $PeapRadiusUserNameMode = "Outer"
    } else {
        $PeapRadiusUserNameMode = "Inner"
    }
}

if ($AuthType -eq "EAP-PEAP" -and -not $PSBoundParameters.ContainsKey("PeapPhase2SetLengthBit")) {
    # Interop default: include L-bit/length on tunneled phase-2 EAP payloads unless explicitly overridden.
    $PeapPhase2SetLengthBit = $true
}

if ($AuthType -eq "EAP-PEAP" -and -not $PSBoundParameters.ContainsKey("PeapPhase2AckBeforeData")) {
    # Interop default: after generating tunneled phase-2 data, send one PEAP ACK first and
    # send the tunneled payload on the next PEAP round.
    $PeapPhase2AckBeforeData = $true
}

if (-not $PSBoundParameters.ContainsKey("DesiredEapTypes") -or -not $DesiredEapTypes -or $DesiredEapTypes.Length -eq 0) {
    # Default NAK suggestions should align with the selected auth method.
    $DesiredEapTypes = switch ($AuthType) {
        "EAP-TTLS" { @([byte]21) }
        "EAP-PEAP" { @([byte]25) }
        default { @([byte]13) }
    }
}
#endregion

#region --- Byte utils
# Simple byte array helpers used by both RADIUS and EAP packet builders/parsers.
function Concat-Bytes {
    param([byte[]]$A, [byte[]]$B)
    if (-not $A) { return [byte[]]$B }
    if (-not $B) { return [byte[]]$A }
    $out = [byte[]]::new($A.Length + $B.Length)
    [Array]::Copy($A,0,$out,0,$A.Length)
    [Array]::Copy($B,0,$out,$A.Length,$B.Length)
    return $out
}
function Bytes-ToHex {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return "" }
    return ($Bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}
function Dump-Hex {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "   (empty payload)" }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Bytes.Length; $i += 16) {
        $count = [Math]::Min(16, $Bytes.Length - $i)
        $hex = ""
        $ascii = ""
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -lt $count) {
                $b = $Bytes[$i + $j]
                $hex += $b.ToString("X2") + " "
                $ascii += if ($b -ge 32 -and $b -le 126) { [char]$b } else { "." }
            } else {
                $hex += "   "
            }
        }
        $sb.AppendLine(("{0:X4}  {1} |{2}|" -f $i, $hex, $ascii)) | Out-Null
    }
    return $sb.ToString()
}
#endregion

#region --- EAP type names
# Friendly EAP type labels used only for diagnostics and human-readable output.
$EapTypeName = @{
    1  = "Identity"
    2  = "Notification"
    3  = "NAK"
    13 = "EAP-TLS"
    21 = "EAP-TTLS"
    25 = "PEAP"
    26 = "EAP-MSCHAPv2"
}
function Get-EapTypeName {
    param($Type)
    if ($null -eq $Type) { return "None" }
    $k = [int][byte]$Type
    if ($EapTypeName.ContainsKey($k)) { return $EapTypeName[$k] }
    return "Unknown"
}
#endregion

#region --- C# Pipe Stream
# In-memory duplex stream used to bridge EAP fragment I/O and SslStream semantics.
# Try to add type; if it already exists from a previous run, catch the error
try {
    Add-Type -Language CSharp @"
using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;

public sealed class EapTlsPipeStream : Stream
{
    private readonly object _lockObj = new object();
    private readonly Queue<byte> _inQ = new Queue<byte>();
    private readonly MemoryStream _outMs = new MemoryStream();
    private bool _closed = false;

    public void AddIncoming(byte[] data)
    {
        if (data == null || data.Length == 0) return;
        lock (_lockObj)
        {
            for (int i = 0; i < data.Length; i++) _inQ.Enqueue(data[i]);
            Monitor.PulseAll(_lockObj);
        }
    }

    public byte[] TakeOutgoing()
    {
        lock (_lockObj)
        {
            if (_outMs.Length == 0) return new byte[0];
            byte[] b = _outMs.ToArray();
            _outMs.SetLength(0);
            return b;
        }
    }

    public byte[] TakeOutgoingWait(int timeoutMs)
    {
        lock (_lockObj)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (_outMs.Length == 0 && !_closed && DateTime.UtcNow < deadline)
            {
                int remainMs = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (remainMs > 0)
                {
                    Monitor.Wait(_lockObj, remainMs);
                }
            }
            if (_outMs.Length == 0) return new byte[0];
            byte[] b = _outMs.ToArray();
            _outMs.SetLength(0);
            return b;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        lock (_lockObj)
        {
            while (!_closed && _inQ.Count == 0)
            {
                Monitor.Wait(_lockObj);
            }
            if (_closed) return 0;
            int n = Math.Min(count, _inQ.Count);
            for (int i = 0; i < n; i++) buffer[offset + i] = _inQ.Dequeue();
            return n;
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        lock (_lockObj)
        {
            _outMs.Write(buffer, offset, count);
            Monitor.PulseAll(_lockObj);
        }
    }

    public override void Close()
    {
        lock (_lockObj)
        {
            _closed = true;
            Monitor.PulseAll(_lockObj);
        }
        base.Close();
    }

    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return true; } }

    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
}
"@
} catch {
    # Type already exists from a previous run - this is OK if it has the new method
    # If running in same session after code update, you may need a fresh PowerShell session
    Write-Verbose "Type EapTlsPipeStream already loaded (likely from previous script run)"
}
#endregion

#region --- MSCHAPv2 crypto helper
# Inline crypto implementation so PEAP/MSCHAPv2 works without external modules.
try {
    Add-Type -Language CSharp @"
using System;
using System.Text;
using System.Security.Cryptography;

public static class MschapV2Crypto {
    public static byte[] GenerateNtResponse(string password, byte[] authChallenge, byte[] peerChallenge, string userName) {
        if (password == null) password = string.Empty;
        if (authChallenge == null || authChallenge.Length < 16) throw new ArgumentException("authChallenge must be >= 16 bytes");
        if (peerChallenge == null || peerChallenge.Length < 16) throw new ArgumentException("peerChallenge must be >= 16 bytes");
        if (userName == null) userName = string.Empty;

        byte[] challenge8 = ChallengeHash(peerChallenge, authChallenge, userName);
        byte[] pwHash = NtPasswordHash(password);
        return ChallengeResponse(challenge8, pwHash);
    }

    private static byte[] NtPasswordHash(string password) {
        byte[] pw = Encoding.Unicode.GetBytes(password);
        return MD4Hash(pw);
    }

    private static byte[] ChallengeHash(byte[] peerChallenge, byte[] authChallenge, string userName) {
        byte[] user = Encoding.UTF8.GetBytes(userName);
        byte[] buf = new byte[16 + 16 + user.Length];
        Buffer.BlockCopy(peerChallenge, 0, buf, 0, 16);
        Buffer.BlockCopy(authChallenge, 0, buf, 16, 16);
        if (user.Length > 0) Buffer.BlockCopy(user, 0, buf, 32, user.Length);
        using (SHA1 sha1 = SHA1.Create()) {
            byte[] h = sha1.ComputeHash(buf);
            byte[] out8 = new byte[8];
            Buffer.BlockCopy(h, 0, out8, 0, 8);
            return out8;
        }
    }

    private static byte[] ChallengeResponse(byte[] challenge8, byte[] pwHash16) {
        byte[] zpw = new byte[21];
        Buffer.BlockCopy(pwHash16, 0, zpw, 0, 16);
        byte[] resp = new byte[24];
        byte[] key7 = new byte[7];

        Buffer.BlockCopy(zpw, 0, key7, 0, 7);
        Buffer.BlockCopy(DesEncrypt(key7, challenge8), 0, resp, 0, 8);
        Buffer.BlockCopy(zpw, 7, key7, 0, 7);
        Buffer.BlockCopy(DesEncrypt(key7, challenge8), 0, resp, 8, 8);
        Buffer.BlockCopy(zpw, 14, key7, 0, 7);
        Buffer.BlockCopy(DesEncrypt(key7, challenge8), 0, resp, 16, 8);

        return resp;
    }

    private static byte[] DesEncrypt(byte[] key7, byte[] data8) {
        byte[] key8 = CreateDesKey(key7);
        using (DES des = DES.Create()) {
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = key8;
            using (ICryptoTransform enc = des.CreateEncryptor()) {
                return enc.TransformFinalBlock(data8, 0, 8);
            }
        }
    }

    private static byte[] CreateDesKey(byte[] key7) {
        byte[] key8 = new byte[8];
        key8[0] = (byte)(key7[0] & 0xFE);
        key8[1] = (byte)(((key7[0] << 7) | (key7[1] >> 1)) & 0xFE);
        key8[2] = (byte)(((key7[1] << 6) | (key7[2] >> 2)) & 0xFE);
        key8[3] = (byte)(((key7[2] << 5) | (key7[3] >> 3)) & 0xFE);
        key8[4] = (byte)(((key7[3] << 4) | (key7[4] >> 4)) & 0xFE);
        key8[5] = (byte)(((key7[4] << 3) | (key7[5] >> 5)) & 0xFE);
        key8[6] = (byte)(((key7[5] << 2) | (key7[6] >> 6)) & 0xFE);
        key8[7] = (byte)((key7[6] << 1) & 0xFE);
        for (int i = 0; i < 8; i++) key8[i] = SetOddParity(key8[i]);
        return key8;
    }

    private static byte SetOddParity(byte b) {
        int ones = 0;
        for (int i = 1; i < 8; i++) if (((b >> i) & 0x01) != 0) ones++;
        if ((ones % 2) == 0) return (byte)(b | 0x01);
        return (byte)(b & 0xFE);
    }

    private static byte[] MD4Hash(byte[] input) {
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        int origLen = input.Length;
        int padLen = (56 - ((origLen + 1) % 64) + 64) % 64;
        byte[] msg = new byte[origLen + 1 + padLen + 8];
        Buffer.BlockCopy(input, 0, msg, 0, origLen);
        msg[origLen] = 0x80;
        ulong bitLen = (ulong)origLen * 8UL;
        for (int i = 0; i < 8; i++) msg[msg.Length - 8 + i] = (byte)((bitLen >> (8 * i)) & 0xff);

        uint[] x = new uint[16];
        for (int i = 0; i < msg.Length; i += 64) {
            for (int j = 0; j < 16; j++) {
                int k = i + j * 4;
                x[j] = (uint)(msg[k] | (msg[k + 1] << 8) | (msg[k + 2] << 16) | (msg[k + 3] << 24));
            }
            uint aa = a, bb = b, cc = c, dd = d;

            FF(ref a,b,c,d,x[0],3);   FF(ref d,a,b,c,x[1],7);   FF(ref c,d,a,b,x[2],11);  FF(ref b,c,d,a,x[3],19);
            FF(ref a,b,c,d,x[4],3);   FF(ref d,a,b,c,x[5],7);   FF(ref c,d,a,b,x[6],11);  FF(ref b,c,d,a,x[7],19);
            FF(ref a,b,c,d,x[8],3);   FF(ref d,a,b,c,x[9],7);   FF(ref c,d,a,b,x[10],11); FF(ref b,c,d,a,x[11],19);
            FF(ref a,b,c,d,x[12],3);  FF(ref d,a,b,c,x[13],7);  FF(ref c,d,a,b,x[14],11); FF(ref b,c,d,a,x[15],19);

            GG(ref a,b,c,d,x[0],3);   GG(ref d,a,b,c,x[4],5);   GG(ref c,d,a,b,x[8],9);   GG(ref b,c,d,a,x[12],13);
            GG(ref a,b,c,d,x[1],3);   GG(ref d,a,b,c,x[5],5);   GG(ref c,d,a,b,x[9],9);   GG(ref b,c,d,a,x[13],13);
            GG(ref a,b,c,d,x[2],3);   GG(ref d,a,b,c,x[6],5);   GG(ref c,d,a,b,x[10],9);  GG(ref b,c,d,a,x[14],13);
            GG(ref a,b,c,d,x[3],3);   GG(ref d,a,b,c,x[7],5);   GG(ref c,d,a,b,x[11],9);  GG(ref b,c,d,a,x[15],13);

            HH(ref a,b,c,d,x[0],3);   HH(ref d,a,b,c,x[8],9);   HH(ref c,d,a,b,x[4],11);  HH(ref b,c,d,a,x[12],15);
            HH(ref a,b,c,d,x[2],3);   HH(ref d,a,b,c,x[10],9);  HH(ref c,d,a,b,x[6],11);  HH(ref b,c,d,a,x[14],15);
            HH(ref a,b,c,d,x[1],3);   HH(ref d,a,b,c,x[9],9);   HH(ref c,d,a,b,x[5],11);  HH(ref b,c,d,a,x[13],15);
            HH(ref a,b,c,d,x[3],3);   HH(ref d,a,b,c,x[11],9);  HH(ref c,d,a,b,x[7],11);  HH(ref b,c,d,a,x[15],15);

            a += aa; b += bb; c += cc; d += dd;
        }

        byte[] out16 = new byte[16];
        WriteLe(out16, 0, a); WriteLe(out16, 4, b); WriteLe(out16, 8, c); WriteLe(out16, 12, d);
        return out16;
    }

    private static void FF(ref uint a, uint b, uint c, uint d, uint x, int s) { a = Rol(a + F(b,c,d) + x, s); }
    private static void GG(ref uint a, uint b, uint c, uint d, uint x, int s) { a = Rol(a + G(b,c,d) + x + 0x5a827999, s); }
    private static void HH(ref uint a, uint b, uint c, uint d, uint x, int s) { a = Rol(a + H(b,c,d) + x + 0x6ed9eba1, s); }
    private static uint F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
    private static uint G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
    private static uint H(uint x, uint y, uint z) { return x ^ y ^ z; }
    private static uint Rol(uint x, int s) { return (x << s) | (x >> (32 - s)); }
    private static void WriteLe(byte[] b, int o, uint v) {
        b[o] = (byte)(v & 0xff);
        b[o+1] = (byte)((v >> 8) & 0xff);
        b[o+2] = (byte)((v >> 16) & 0xff);
        b[o+3] = (byte)((v >> 24) & 0xff);
    }
}
"@
} catch {
    Write-Verbose "Type MschapV2Crypto already loaded (likely from previous script run)"
}
#endregion

#region --- EAP helpers
# Packet-level EAP encode/decode helpers for Identity, NAK, TLS/PEAP framing, and phase-2 payload handling.
function Parse-EapPacket {
    param([byte[]] $Eap)
    if (-not $Eap -or $Eap.Length -lt 4) { return $null }
    $code = $Eap[0]
    $id   = $Eap[1]
    $len  = (([int]$Eap[2]) -shl 8) -bor ([int]$Eap[3])
    if ($len -gt $Eap.Length) { $len = $Eap.Length }
    $type = $null
    $data = [byte[]]::new(0)
    if ($len -ge 5) {
        $type = [byte]$Eap[4]
        $dataLen = $len - 5
        if ($dataLen -gt 0) {
            $data = [byte[]]::new($dataLen)
            [Array]::Copy($Eap, 5, $data, 0, $dataLen)
        }
    }
    [pscustomobject]@{ Code=$code; Id=$id; Length=$len; Type=$type; Data=$data; Raw=[byte[]]$Eap }
}

# Creates an outer/inner EAP Response/Identity packet.
function New-EapIdentityResponse {
    param([byte] $Id, [string] $Username)
    $identityBytes = [System.Text.Encoding]::UTF8.GetBytes($Username)
    $length = 5 + $identityBytes.Length
    $pkt = [byte[]]::new($length)
    $pkt[0]=2; $pkt[1]=$Id; $pkt[2]=[byte](($length -shr 8) -band 0xFF); $pkt[3]=[byte]($length -band 0xFF); $pkt[4]=1
    [Array]::Copy($identityBytes,0,$pkt,5,$identityBytes.Length)
    return $pkt
}

# Creates EAP NAK with suggested fallback types for method negotiation.
function New-EapNakResponse {
    param([byte] $Id, [byte[]] $DesiredTypes)
    if (-not $DesiredTypes -or $DesiredTypes.Length -eq 0) { $DesiredTypes = @([byte]13) }
    $length = 5 + $DesiredTypes.Length
    $pkt = [byte[]]::new($length)
    $pkt[0]=2; $pkt[1]=$Id; $pkt[2]=[byte](($length -shr 8) -band 0xFF); $pkt[3]=[byte]($length -band 0xFF); $pkt[4]=3
    [Array]::Copy($DesiredTypes,0,$pkt,5,$DesiredTypes.Length)
    return $pkt
}

# Parses EAP-TLS/PEAP Type-Data flags, optional 4-byte length, and TLS fragment bytes.
function Parse-EapTlsTypeData {
    param([byte[]] $TypeData)
    if (-not $TypeData -or $TypeData.Length -lt 1) {
        return [pscustomobject]@{ Flags=0; HasLen=$false; TotalLen=$null; TlsData=[byte[]]::new(0) }
    }
    $flags = $TypeData[0]
    $hasLen = (($flags -band 0x80) -ne 0)
    $idx = 1
    $totalLen = $null
    if ($hasLen) {
        if ($TypeData.Length -lt 5) { throw "EAP-TLS length flag set but Type-Data < 5 bytes." }
        $totalLen = (([int]$TypeData[1]) -shl 24) -bor (([int]$TypeData[2]) -shl 16) -bor (([int]$TypeData[3]) -shl 8) -bor ([int]$TypeData[4])
        $idx = 5
    }
    $tlsLen = $TypeData.Length - $idx
    if ($tlsLen -le 0) { return [pscustomobject]@{ Flags=$flags; HasLen=$hasLen; TotalLen=$totalLen; TlsData=[byte[]]::new(0) } }
    $tls = [byte[]]::new($tlsLen)
    [Array]::Copy($TypeData,$idx,$tls,0,$tlsLen)
    return [pscustomobject]@{ Flags=$flags; HasLen=$hasLen; TotalLen=$totalLen; TlsData=$tls }
}

# Builds a generic EAP-TLS/PEAP response packet with caller-supplied flags and payload.
function New-EapTlsResponse {
    param(
        [byte] $Id,
        [byte] $Flags,
        [byte[]] $TlsPayload,
        [Nullable[uint32]] $TotalLen,
        [byte] $OuterType = 13
    )
    if (-not $TlsPayload) { $TlsPayload = [byte[]]::new(0) }
    $hasLen = (($Flags -band 0x80) -ne 0)

    $ms = New-Object System.IO.MemoryStream
    try {
        $ms.WriteByte($Flags)
        if ($hasLen) {
            $actualTotal = if ($null -ne $TotalLen) { $TotalLen } else { [uint32]$TlsPayload.Length }
            $lenBytes = [byte[]]@(
                ([byte]($actualTotal -shr 24 -band 0xFF)),
                ([byte]($actualTotal -shr 16 -band 0xFF)),
                ([byte]($actualTotal -shr 8  -band 0xFF)),
                ([byte]($actualTotal -band 0xFF))
            )
            $ms.Write($lenBytes, 0, $lenBytes.Length)
        }
        if ($TlsPayload.Length -gt 0) { $ms.Write($TlsPayload, 0, $TlsPayload.Length) }
        $typeData = $ms.ToArray()
    } finally { $ms.Dispose() }

    $length = 5 + $typeData.Length
    $pkt = [byte[]]::new($length)
    $pkt[0] = 2
    $pkt[1] = $Id
    $pkt[2] = [byte](($length -shr 8) -band 0xFF)
    $pkt[3] = [byte]($length -band 0xFF)
    $pkt[4] = $OuterType
    if ($typeData.Length -gt 0) { [Array]::Copy($typeData, 0, $pkt, 5, $typeData.Length) }
    return $pkt
}

# Builds an ACK-only EAP-TLS/PEAP response (Type field + zero flag byte).
function New-EapTlsAckResponse {
    param(
        [byte] $Id,
        [byte] $OuterType = 13
    )
    $pkt = [byte[]]::new(6)
    $pkt[0] = 2
    $pkt[1] = $Id
    $pkt[2] = 0
    $pkt[3] = 6
    $pkt[4] = $OuterType
    $pkt[5] = 0
    return $pkt
}

# Builds a typed EAP response wrapper used by PEAP inner methods (MSCHAPv2, Type 33, etc.).
function New-EapTypedResponse {
    param([byte] $Id, [byte] $Type, [byte[]] $TypeData)
    if (-not $TypeData) { $TypeData = [byte[]]::new(0) }
    $length = 5 + $TypeData.Length
    $pkt = [byte[]]::new($length)
    $pkt[0] = 2
    $pkt[1] = $Id
    $pkt[2] = [byte](($length -shr 8) -band 0xFF)
    $pkt[3] = [byte]($length -band 0xFF)
    $pkt[4] = $Type
    if ($TypeData.Length -gt 0) { [Array]::Copy($TypeData, 0, $pkt, 5, $TypeData.Length) }
    return $pkt
}

# Converts full inner EAP packets into PEAP phase-2 tunnel payload format.
# Type 33 remains fully framed due to interop requirements.
function ConvertTo-PeapPhase2Payload {
    param([byte[]] $InnerEapPacket)
    if (-not $InnerEapPacket -or $InnerEapPacket.Length -lt 5) {
        throw "PEAP inner EAP packet too short to convert into phase-2 payload."
    }

    # PEAP Extensions / Result TLV (Type 33) uses full inner EAP framing in-tunnel.
    if ($InnerEapPacket[4] -eq 33) {
        return [byte[]]$InnerEapPacket
    }

    $payloadLen = $InnerEapPacket.Length - 4
    $payload = [byte[]]::new($payloadLen)
    [Array]::Copy($InnerEapPacket, 4, $payload, 0, $payloadLen)
    return $payload
}

# Parses PEAP inner traffic that may arrive as full EAP or PEAPv0 headerless payload.
function Parse-PeapInnerPacket {
    param([byte[]] $Bytes)

    if (-not $Bytes -or $Bytes.Length -eq 0) { return $null }

    $maybeFullEap = $false
    if ($Bytes.Length -ge 4) {
        $declaredLen = (([int]$Bytes[2]) -shl 8) -bor ([int]$Bytes[3])
        $maybeFullEap = ($Bytes[0] -ge 1 -and $Bytes[0] -le 4 -and $declaredLen -ge 4 -and $declaredLen -le $Bytes.Length)
    }

    if ($maybeFullEap) {
        $parsed = Parse-EapPacket -Eap $Bytes
        if ($parsed) {
            return [pscustomobject]@{
                Code = $parsed.Code
                Id = $parsed.Id
                Length = $parsed.Length
                Type = $parsed.Type
                Data = $parsed.Data
                Raw = [byte[]]$parsed.Raw
                IsHeaderless = $false
            }
        }
    }

    $type = [byte]$Bytes[0]
    $dataLen = $Bytes.Length - 1
    $data = [byte[]]::new($dataLen)
    if ($dataLen -gt 0) {
        [Array]::Copy($Bytes, 1, $data, 0, $dataLen)
    }

    return [pscustomobject]@{
        Code = [byte]1
        Id = $null
        Length = $Bytes.Length
        Type = $type
        Data = $data
        Raw = [byte[]]$Bytes
        IsHeaderless = $true
    }
}

# Normalizes username format for MSCHAPv2 ChallengeHash input.
# DOMAIN\user is reduced to user; user@realm is preserved for server compatibility.
function Get-MschapUserForChallengeHash {
    param([string] $User)
    if (-not $User) { return "" }
    $u = $User
    if ($u.Contains("\\")) { $u = $u.Split('\\')[-1] }
    # Interop: some PEAP/MSCHAPv2 servers expect the full user@realm form in ChallengeHash.
    # Keep realm for UPN-style identities; still strip DOMAIN\ prefix above.
    return $u
}

# Reads tunneled PEAP inner bytes from SslStream without overlapping ReadAsync calls.
function Read-PeapInnerEap {
    param($SslStream, [int] $TimeoutMs = 1000)
    if ($null -eq $script:PeapInnerReadBuffer) {
        $script:PeapInnerReadBuffer = [byte[]]::new(8192)
    }
    try {
        if ($null -eq $script:PeapInnerReadTask) {
            $script:PeapInnerReadTask = $SslStream.ReadAsync($script:PeapInnerReadBuffer, 0, $script:PeapInnerReadBuffer.Length)
        }

        if (-not $script:PeapInnerReadTask.Wait($TimeoutMs)) {
            return ,([byte[]]::new(0))
        }

        $n = [int]$script:PeapInnerReadTask.Result
        $script:PeapInnerReadTask = $null

        if ($n -le 0) { return ,([byte[]]::new(0)) }
        $out = [byte[]]::new($n)
        [Array]::Copy($script:PeapInnerReadBuffer, 0, $out, 0, $n)
        return ,$out
    } catch [System.IO.IOException] {
        $script:PeapInnerReadTask = $null
        return ,([byte[]]::new(0))
    } catch [System.AggregateException] {
        $script:PeapInnerReadTask = $null
        if ($_.Exception.InnerException -is [System.IO.IOException]) {
            return ,([byte[]]::new(0))
        }
        throw
    }
}

# Pulls an initial TLS burst plus short follow-on chunks to reduce split-packet churn.
function Take-PipeOutgoingBurst {
    param(
        $Pipe,
        [int] $FirstWaitMs = 2000,
        [int] $NextWaitMs = 50,
        [int] $MaxExtraReads = 20
    )

    $all = $Pipe.TakeOutgoingWait($FirstWaitMs)
    if (-not $all -or $all.Length -eq 0) {
        return [byte[]]::new(0)
    }

    for ($i = 0; $i -lt $MaxExtraReads; $i++) {
        $chunk = $Pipe.TakeOutgoingWait($NextWaitMs)
        if (-not $chunk -or $chunk.Length -eq 0) { break }
        $all = Concat-Bytes $all $chunk
    }

    return $all
}

# Creates TTLS AVPs carrying tunneled PAP credentials.
function New-TtlsPhase2PapPayload {
    param(
        [string] $Username,
        [string] $Password
    )

    function New-TtlsAvp {
        param([uint32] $Code, [byte[]] $Data)

        if (-not $Data) { $Data = [byte[]]::new(0) }
        $headerLen = 8
        $totalLen = $headerLen + $Data.Length
        $paddedLen = [int]([Math]::Ceiling($totalLen / 4.0) * 4)
        $avp = [byte[]]::new($paddedLen)

        $avp[0] = [byte](($Code -shr 24) -band 0xFF)
        $avp[1] = [byte](($Code -shr 16) -band 0xFF)
        $avp[2] = [byte](($Code -shr 8) -band 0xFF)
        $avp[3] = [byte]($Code -band 0xFF)
        $avp[4] = 0x40 # Mandatory bit
        $avp[5] = [byte](($totalLen -shr 16) -band 0xFF)
        $avp[6] = [byte](($totalLen -shr 8) -band 0xFF)
        $avp[7] = [byte]($totalLen -band 0xFF)

        if ($Data.Length -gt 0) {
            [Array]::Copy($Data, 0, $avp, $headerLen, $Data.Length)
        }

        return $avp
    }

    $userBytes = [System.Text.Encoding]::UTF8.GetBytes($Username)
    $passBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)

    $userAvp = New-TtlsAvp -Code 1 -Data $userBytes
    $passAvp = New-TtlsAvp -Code 2 -Data $passBytes

    return Concat-Bytes $userAvp $passAvp
}

# Implements PEAP inner state machine responses (Identity, MSCHAPv2 challenge/success, Type 33).
function New-PeapInnerResponse {
    param(
        [object] $InnerEap,
        [string] $Username,
        [string] $Password,
        [bool] $Diag
    )

    if (-not $InnerEap) { return $null }

    if ($InnerEap.Code -eq 1 -and $InnerEap.Type -eq 1) {
        if ($Diag) { Write-Host " [DBG] PEAP inner request: EAP-Identity" -ForegroundColor DarkGray }
        return New-EapIdentityResponse -Id ([byte]$InnerEap.Id) -Username $Username
    }

    if ($InnerEap.Code -eq 1 -and $InnerEap.Type -eq 26) {
        $td = [byte[]]$InnerEap.Data
        if ($td.Length -lt 4) { throw "PEAP inner MSCHAPv2 payload too short." }
        $op = $td[0]
        $msId = $td[1]

        if ($op -eq 1) {
            if ($td.Length -lt 5) { throw "PEAP inner MSCHAPv2 challenge missing Value-Size." }
            $valueSize = [int]$td[4]
            if ($valueSize -lt 16 -or $td.Length -lt (5 + $valueSize)) {
                throw "PEAP inner MSCHAPv2 challenge malformed (invalid Value-Size)."
            }

            $authChallenge = [byte[]]::new(16)
            [Array]::Copy($td, 5, $authChallenge, 0, 16)

            $peerChallenge = [byte[]]::new(16)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($peerChallenge)

            $userHash = Get-MschapUserForChallengeHash -User $Username
            $ntResponse = [MschapV2Crypto]::GenerateNtResponse($Password, $authChallenge, $peerChallenge, $userHash)

            $value = [byte[]]::new(49)
            [Array]::Copy($peerChallenge, 0, $value, 0, 16)
            [Array]::Copy($ntResponse, 0, $value, 24, 24)
            $value[48] = 0

            $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Username)
            $msLen = 5 + $value.Length + $nameBytes.Length
            $respTd = [byte[]]::new($msLen)
            $respTd[0] = 2
            $respTd[1] = $msId
            $respTd[2] = [byte](($msLen -shr 8) -band 0xFF)
            $respTd[3] = [byte]($msLen -band 0xFF)
            $respTd[4] = 49
            [Array]::Copy($value, 0, $respTd, 5, $value.Length)
            if ($nameBytes.Length -gt 0) { [Array]::Copy($nameBytes, 0, $respTd, 5 + $value.Length, $nameBytes.Length) }

            if ($Diag) { Write-Host " [DBG] PEAP inner request: MSCHAPv2 Challenge. Sending Response." -ForegroundColor DarkGray }
            return New-EapTypedResponse -Id ([byte]$InnerEap.Id) -Type 26 -TypeData $respTd
        }

        if ($op -eq 3) {
            $respTd = [byte[]]@(3, $msId, 0, 4)
            if ($Diag) { Write-Host " [DBG] PEAP inner request: MSCHAPv2 Success. Sending success ACK." -ForegroundColor DarkGray }
            return New-EapTypedResponse -Id ([byte]$InnerEap.Id) -Type 26 -TypeData $respTd
        }

        if ($op -eq 4) {
            throw "PEAP inner MSCHAPv2 Failure received from server."
        }

        throw "PEAP inner MSCHAPv2 unsupported OpCode=$op"
    }

    if ($InnerEap.Code -eq 1 -and $InnerEap.Type -eq 33) {
        # PEAP Extensions / Result TLV request. Reply with matching Type 33 payload.
        if ($null -eq $InnerEap.Id) {
            throw "PEAP Extensions request is missing inner EAP Id."
        }
        if ($Diag) { Write-Host " [DBG] PEAP inner request: Extensions (Type 33). Sending Result TLV response." -ForegroundColor DarkGray }
        return New-EapTypedResponse -Id ([byte]$InnerEap.Id) -Type 33 -TypeData ([byte[]]$InnerEap.Data)
    }

    if ($InnerEap.Code -eq 3) {
        if ($Diag) { Write-Host " [DBG] PEAP inner EAP-Success received." -ForegroundColor DarkGray }
        return $null
    }

    if ($InnerEap.Code -eq 4) {
        throw "PEAP inner EAP-Failure received from server."
    }

    throw "Unsupported PEAP inner EAP type $($InnerEap.Type) code $($InnerEap.Code)."
}
#endregion

#region --- RADIUS helpers
# RADIUS packet construction/parsing, attribute utilities, and Message-Authenticator signing.
function New-RadiusAuthenticator {
    $b = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return $b
}

# Encodes a single RADIUS TLV attribute.
function New-RadiusAttribute {
    param([byte] $Type,[byte[]] $Value)
    $len = $Value.Length + 2
    if ($len -gt 255) { throw "Attribute $Type too long: $len" }
    $attr = [byte[]]::new($len)
    $attr[0]=$Type; $attr[1]=[byte]$len
    if ($Value.Length -gt 0) { [Array]::Copy($Value,0,$attr,2,$Value.Length) }
    return $attr
}

function New-RadiusIntegerAttribute {
    param([byte] $Type, [uint32] $Value)

    $bytes = [byte[]]@(
        ([byte](($Value -shr 24) -band 0xFF)),
        ([byte](($Value -shr 16) -band 0xFF)),
        ([byte](($Value -shr 8) -band 0xFF)),
        ([byte]($Value -band 0xFF))
    )

    return New-RadiusAttribute -Type $Type -Value $bytes
}

# Splits oversized attribute values into multiple TLVs of the same type.
function New-RadiusAttributeChunks {
    param([byte] $Type,[byte[]] $Value,[int] $MaxValueLen = 253)
    $ms = New-Object System.IO.MemoryStream
    try {
        $offset=0
        while ($offset -lt $Value.Length) {
            $take = [Math]::Min($MaxValueLen, $Value.Length-$offset)
            $chunk = [byte[]]::new($take)
            [Array]::Copy($Value,$offset,$chunk,0,$take)
            $attr = New-RadiusAttribute -Type $Type -Value $chunk
            $ms.Write($attr,0,$attr.Length)
            $offset += $take
        }
        return $ms.ToArray()
    } finally { $ms.Dispose() }
}

# Parses all TLVs in a RADIUS packet body into a structured array.
function Parse-RadiusAttributes {
    param([byte[]] $Packet, [bool]$Diag)
    $attrs = @()
    if ($Packet.Length -lt 20) { return $attrs }
    
    $pos = 20
    $attrIdx = 0
    
    while ($pos -lt $Packet.Length) {
        if ($pos + 2 -gt $Packet.Length) { 
            break 
        }
        $type = $Packet[$pos]
        $len  = $Packet[$pos+1]
        
        if ($len -lt 2 -or ($pos + $len -gt $Packet.Length)) { 
            if ($Diag) { Write-Host " [DIAG-WARN] Corrupted attribute map or boundary fault detected at offset $pos." -ForegroundColor Red }
            break
        }
        
        $vlen = $len - 2
        $value = [byte[]]::new($vlen)
        if ($vlen -gt 0) { [Array]::Copy($Packet, $pos + 2, $value, 0, $vlen) }
        $attrs += [pscustomobject]@{ Type=$type; Length=$len; Value=$value }
        
        if ($Diag) {
            Write-Host " [DIAG-ATTR] #$attrIdx - Type: $type, TotalLen: $len, ValueLen: $vlen" -ForegroundColor DarkGray
        }
        $pos += $len
        $attrIdx++
    }
    return $attrs
}

# Reassembles fragmented attributes by type (for EAP-Message and State retrieval).
function Get-AttributeConcat {
    param([object[]] $Attributes,[byte] $Type)
    $ms = New-Object System.IO.MemoryStream
    try {
        foreach ($a in $Attributes) {
            if ([byte]$a.Type -eq $Type) {
                $v = [byte[]]$a.Value
                if ($v.Length -gt 0) { $ms.Write($v,0,$v.Length) }
            }
        }
        $b = $ms.ToArray()
        if ($b.Length -eq 0) { return $null }
        return $b
    } finally { $ms.Dispose() }
}

# Appends a zeroed Message-Authenticator (Type 80) placeholder and returns its offset.
function Add-MessageAuthenticator {
    param([byte[]] $AttrsBytes)
    $maVal = [byte[]]::new(16)
    $maAttr = New-RadiusAttribute -Type 80 -Value $maVal
    [pscustomobject]@{ AttrsBytes = (Concat-Bytes $AttrsBytes $maAttr); MaOffset = $AttrsBytes.Length }
}

# Computes and injects HMAC-MD5 Message-Authenticator over the full RADIUS packet.
function Sign-MessageAuthenticator {
    param([byte[]] $Packet,[int] $MaOffsetInAttrs,[string] $SharedSecret)
    $key = [System.Text.Encoding]::UTF8.GetBytes($SharedSecret)
    $hmac = [System.Security.Cryptography.HMACMD5]::new($key)
    try { $digest = $hmac.ComputeHash($Packet) } finally { $hmac.Dispose() }
    $start = 20 + $MaOffsetInAttrs + 2
    [Array]::Copy($digest,0,$Packet,$start,16)
    return $Packet
}

# Implements PAP User-Password hiding per RFC 2865 using MD5 block chaining.
function Protect-UserPassword {
    param([string] $PlainPassword,[string] $Secret,[byte[]] $RequestAuthenticator)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainPassword)

    $padLen = [Math]::Ceiling($pwBytes.Length / 16) * 16
    if ($padLen -eq 0) { $padLen = 16 }
    if ($padLen -gt 128) { throw "Password too long." }

    $padded = [byte[]]::new($padLen)
    [Array]::Copy($pwBytes,0,$padded,0,$pwBytes.Length)

    $cipher = [byte[]]::new($padLen)
    $prev = $RequestAuthenticator

    for ($i=0; $i -lt ($padLen/16); $i++) {
        $hash = $md5.ComputeHash((Concat-Bytes $secretBytes $prev))
        for ($j=0; $j -lt 16; $j++) { $cipher[$i*16+$j] = $padded[$i*16+$j] -bxor $hash[$j] }
        $prev = $cipher[($i*16)..($i*16+15)]
    }
    return $cipher
}

# Builds a complete Access-Request for PAP, MAB, or EAP, including optional NAS port attributes.
function Build-AccessRequest {
    param(
        [string] $Username,[string] $Password,[string] $SharedSecret,
        [string] $NasIdentifier,[string] $NasPortId,[string] $NasPortType,[string] $NasIpAddress,[string] $CallingStationId,[string] $CalledStationId,
        [byte] $Identifier,[ValidateSet("PAP","MAB","EAP-TLS","EAP-PEAP","EAP-TTLS")] [string] $AuthType,
        [byte[]] $EapMessage,[byte[]] $State
    )

    $auth = New-RadiusAuthenticator
    $attrs = [byte[]]@()

    $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 1 -Value ([System.Text.Encoding]::UTF8.GetBytes($Username)))
    $ip = [System.Net.IPAddress]::Parse($NasIpAddress).GetAddressBytes()
    $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 4 -Value $ip)
    $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 32 -Value ([System.Text.Encoding]::UTF8.GetBytes($NasIdentifier)))
    if ($NasPortId) {
        $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 87 -Value ([System.Text.Encoding]::UTF8.GetBytes($NasPortId)))
    }
    if ($NasPortType) {
        $attrs = Concat-Bytes $attrs (New-RadiusIntegerAttribute -Type 61 -Value ([uint32][int]$NasPortType))
    }
    $attrs = Concat-Bytes $attrs ([byte[]]@(5,6,0,0,0,1))

    if ($CallingStationId) { $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 31 -Value ([System.Text.Encoding]::UTF8.GetBytes($CallingStationId))) }
    if ($CalledStationId)  { $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 30 -Value ([System.Text.Encoding]::UTF8.GetBytes($CalledStationId))) }

    if ($AuthType -eq "PAP" -or $AuthType -eq "MAB") {
        $cipher = Protect-UserPassword -PlainPassword $Password -Secret $SharedSecret -RequestAuthenticator $auth
        $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 2 -Value $cipher)
        $maOffset = $null
    } else {
        if ($State) { $attrs = Concat-Bytes $attrs (New-RadiusAttribute -Type 24 -Value $State) }
        $attrs = Concat-Bytes $attrs (New-RadiusAttributeChunks -Type 79 -Value $EapMessage)
        $ma = Add-MessageAuthenticator -AttrsBytes $attrs
        $attrs = $ma.AttrsBytes
        $maOffset = $ma.MaOffset
    }

    $totalLen = 20 + $attrs.Length
    $header = [byte[]]::new(20)
    $header[0]=1; $header[1]=$Identifier
    $header[2]=[byte](($totalLen -shr 8) -band 0xFF); $header[3]=[byte]($totalLen -band 0xFF)
    [Array]::Copy($auth,0,$header,4,16)

    $packet = Concat-Bytes $header $attrs
    if ($AuthType -ne "PAP" -and $AuthType -ne "MAB") {
        $packet = Sign-MessageAuthenticator -Packet $packet -MaOffsetInAttrs $maOffset -SharedSecret $SharedSecret
    }
    return $packet
}

# Parses response header and attributes into a normalized object for main-loop handling.
function Parse-RadiusResponse {
    param([byte[]] $Data, [bool]$Diag)
    if ($Data.Length -lt 20) { throw "Response too short." }
    $code = $Data[0]
    $identifier = $Data[1]
    $len = (([int]$Data[2]) -shl 8) -bor ([int]$Data[3])
    $codeName = switch ($code) { 2{"Access-Accept"} 3{"Access-Reject"} 11{"Access-Challenge"} default{"Unknown"} }
    
    if ($Diag) {
        Write-Host " [DIAG-PARSE] Header Code: $code ($codeName), ID: $identifier, Claimed Length: $len, Actual Size: $($Data.Length)" -ForegroundColor Magenta
    }
    
    $attrs = Parse-RadiusAttributes -Packet $Data -Diag $Diag
    [pscustomobject]@{ Code=$code; CodeName=$codeName; Identifier=$identifier; Length=$len; Raw=$Data; Attributes=$attrs }
}
#endregion

#region --- RadSec TLS connection + reader
# Transport abstraction helpers: RADSEC TLS stream and UDP RADIUS datagram handling.
function New-TlsStream {
    param(
        [string] $Server,[int] $Port,[string] $RootCACertPath,[string] $ClientCertPath,[SecureString]$ClientCertPassword,
        [bool] $SkipCertCheck,[bool] $SkipRevocation,[int] $TimeoutMs,
        [bool] $Diag = $false,
        [int] $MaxRetries = 2
    )

    $certs = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
    if ($ClientCertPath) {
        $ClientCertPath = (Resolve-Path $ClientCertPath).Path
        if ($ClientCertPassword) {
            $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientCertPassword)
            $plain=[Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $cc=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertPath,$plain)
        } else {
            $cc=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertPath)
        }
        $certs.Add($cc) | Out-Null
    }

    # NOTE: SolarWinds SAM/PSRP hosts long-lived, persistent PowerShell processes across monitor
    # runs. Add-Type cannot redefine an existing type within the same process/AppDomain, so if a
    # process already loaded an OLDER version of this class (missing a field/member this version
    # relies on), setting that member below throws "property ... cannot be found on this object".
    # In practice this self-resolves: expect up to two Orion polling cycles of failures after
    # changing this class's members before every worker process has cycled to a fresh one running
    # the current definition - no action needed beyond waiting it out.
    if (-not ([System.Management.Automation.PSTypeName]"RadSecStreamFactory").Type) {
        Add-Type -Language CSharp @"
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class RadSecStreamFactory {
  public static X509Certificate2 TrustedRoot = null;
  public static bool SkipRevocation = false;
  public static bool SkipAll = false;
  public static string LastValidationDetail = "";
  private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
    LastValidationDetail = "";
    if (SkipAll) return true;
    if (TrustedRoot != null) {
      chain.ChainPolicy.ExtraStore.Add(TrustedRoot);
      chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
      if (SkipRevocation) chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
      bool built = chain.Build(new X509Certificate2(cert));
      X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
      bool rootMatches = root.Thumbprint == TrustedRoot.Thumbprint;
      var sb = new System.Text.StringBuilder();
      sb.Append("SslPolicyErrors=").Append(errors).Append("; Built=").Append(built).Append("; RootMatches=").Append(rootMatches);
      foreach (var s in chain.ChainStatus) {
        sb.Append("; ").Append(s.Status).Append(": ").Append(s.StatusInformation.Trim());
      }
      LastValidationDetail = sb.ToString();
      return built && rootMatches;
    }
    var sb2 = new System.Text.StringBuilder();
    sb2.Append("SslPolicyErrors=").Append(errors);
    if (chain != null && chain.ChainStatus != null) {
      foreach (var s in chain.ChainStatus) {
        sb2.Append("; ").Append(s.Status).Append(": ").Append(s.StatusInformation.Trim());
      }
    }
    LastValidationDetail = sb2.ToString();
    return errors == SslPolicyErrors.None;
  }
  public static SslStream CreateSslStream(System.Net.Sockets.NetworkStream ns) {
    return new SslStream(ns, false, new RemoteCertificateValidationCallback(Validate));
  }
}
"@
    }

    [RadSecStreamFactory]::SkipAll = $SkipCertCheck
    [RadSecStreamFactory]::SkipRevocation = $SkipRevocation
    [RadSecStreamFactory]::TrustedRoot = $null

    if (-not $SkipCertCheck -and $RootCACertPath) {
        $RootCACertPath = (Resolve-Path $RootCACertPath).Path
        [RadSecStreamFactory]::TrustedRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCACertPath)
    }

    $checkRevocation = -not $SkipRevocation

    # Bounded retry for the initial TCP connect + TLS handshake: intermittent RADSEC connection
    # failures are commonly caused by transient network blips during the TCP handshake, or by
    # certificate revocation checking (OCSP/CRL lookups, enabled by default unless
    # -SkipRevocationCheck is passed) briefly timing out against a slow/unreachable responder -
    # neither indicates a real, persistent problem with the server or certificate, so a fresh
    # retry attempt (new TCP connection + new TLS handshake) will very often just succeed.
    $attempt = 0
    while ($true) {
        $tcp = $null
        $ssl = $null
        $stage = "connect"
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $t = $tcp.ConnectAsync($Server,$Port)
                if (-not $t.Wait($TimeoutMs)) { throw "TCP connect timeout." }
            } catch {
                throw "Failed to connect to $Server on port $Port : $($_.Exception.Message)"
            }

            $stage = "tls"
            $ssl = [RadSecStreamFactory]::CreateSslStream($tcp.GetStream())
            $a = $ssl.AuthenticateAsClientAsync(
                $Server, $certs,
                [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13,
                $checkRevocation
            )
            if (-not $a.Wait($TimeoutMs)) { throw "RadSec TLS handshake timeout." }

            return @{ Tcp=$tcp; Ssl=$ssl }
        } catch {
            try { if ($ssl) { $ssl.Dispose() } } catch {}
            try { if ($tcp) { $tcp.Close() } } catch {}

            # $_.Exception is typically a System.Management.Automation.MethodInvocationException wrapping
            # an AggregateException from Task.Wait(); its top-level .Message is the unhelpful generic
            # "One or more errors occurred." Unwrap down to the real TLS negotiation failure reason
            # (e.g. certificate validation failure, protocol/cipher mismatch, connection reset) so
            # failures are actionable instead of opaque.
            $msg = $_.Exception
            while ($msg -is [System.Management.Automation.MethodInvocationException] -and $msg.InnerException) {
                $msg = $msg.InnerException
            }
            if ($msg -is [System.AggregateException]) {
                $inner = $msg.Flatten().InnerExceptions
                if ($inner -and $inner.Count -gt 0) {
                    $msg = $inner[0]
                }
            }

            if ($attempt -lt $MaxRetries) {
                $attempt++
                if ($Diag) {
                    Write-Host (" [DBG] RadSec {0} failed ({1}); retrying with a fresh connection (retry {2}/{3})..." -f $stage, $msg.Message, $attempt, $MaxRetries) -ForegroundColor Yellow
                }
                continue
            }

            $hint = ""
            if ($msg.Message -match "certificate is invalid" -or $msg.Message -match "authentication failed" -or $msg.Message -match "TrustFailure") {
                $hint = " Hint: provide -RootCACertPath, or use -SkipCertificateCheck for lab testing, if the RADSEC server certificate isn't trusted. If this failure is intermittent rather than persistent, also consider -SkipRevocationCheck to rule out transient OCSP/CRL lookup timeouts."
            }
            $detail = ""
            if ([RadSecStreamFactory]::LastValidationDetail) { $detail = " ValidationDetail: $([RadSecStreamFactory]::LastValidationDetail)" }
            if ($stage -eq "connect") {
                throw $msg.Message
            }
            throw "RadSec TLS Authentication layer failed: $($msg.Message)$hint$detail"
        }
    }
}

# Reads one full RADSEC framed RADIUS packet (4-byte framing + remaining bytes).
function Read-RadiusPacket {
    param($SslStream,[int] $TimeoutMs, [bool]$Diag)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)

    # 1. Acquire the exact 4-byte framing envelope header
    $hdr = [byte[]]::new(4)
    $read = 0
    while ($read -lt 4) {
        if ([DateTime]::UtcNow -ge $deadline) { throw "Timeout reading RADIUS framing header." }
        $n = $SslStream.Read($hdr, $read, 4 - $read)
        if ($n -eq 0) { throw "Socket terminated while acquiring framework parameters." }
        $read += $n
    }

    # 2. Extract the absolute declared length using native .NET System.BitConverter
    $lenBytes = @($hdr[2], $hdr[3])
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
    $totalLen = [BitConverter]::ToUInt16($lenBytes, 0)
    
    if ($Diag) {
        Write-Host (" [DIAG-STREAM] Inbound Frame Header Catch. Code: {0}, Declared Envelope Length: {1} bytes" -f $hdr[0], $totalLen) -ForegroundColor DarkCyan
    }

    if ($totalLen -lt 20) {
        if ($hdr[0] -ge 32 -and $hdr[0] -le 126) {
            $leakString = [System.Text.Encoding]::ASCII.GetString($hdr)
            throw "Protocol synchronization desync caught. Expected RADIUS binary envelope, found raw text stream chunk: '$leakString'"
        }
        $hex = ($hdr | ForEach-Object { $_.ToString('X2') }) -join ' '
        throw "Invalid RadSec framed payload size context ($totalLen): $hex"
    }

    # 3. FORCE complete drainage of remaining bytes matching the declared payload structure
    $remaining = $totalLen - 4
    $body = [byte[]]::new($remaining)
    $bodyRead = 0
    
    while ($bodyRead -lt $remaining) {
        if ([DateTime]::UtcNow -ge $deadline) { throw "Timeout gathering multi-segment fragments. Got ($bodyRead/$remaining) bytes." }
        $n = $SslStream.Read($body, $bodyRead, $remaining - $bodyRead)
        if ($n -eq 0) { throw "Connection truncated during body context assembly." }
        $bodyRead += $n
    }
    
    $fullPacket = Concat-Bytes $hdr $body
    
    if ($Diag) {
        Write-Host " [DIAG-HEXDUMP] --- RAW INBOUND RADSEC PACKET MATRIX ---" -ForegroundColor Gray
        Write-Host (Dump-Hex -Bytes $fullPacket) -ForegroundColor Gray
    }

    return $fullPacket
}

# Creates UDP client for classic RADIUS transport.
function New-RadiusUdpConnection {
    param([string] $Server,[int] $Port,[int] $TimeoutMs)
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        $udp.Connect($Server, $Port)
    } catch {
        try { $udp.Close() } catch {}
        throw "Failed to open UDP RADIUS connection to $Server on port $Port : $($_.Exception.Message)"
    }
    return @{ Udp = $udp }
}

# Sends a packet through the selected transport without changing packet bytes.
function Send-RadiusRequestPacket {
    param($Connection, [byte[]] $Packet, [ValidateSet("RADSEC","RADIUS")] [string] $TransportMode)
    if ($TransportMode -eq "RADSEC") {
        $Connection.Ssl.Write($Packet, 0, $Packet.Length)
        $Connection.Ssl.Flush()
        return
    }
    [void]$Connection.Udp.Send($Packet, $Packet.Length)
}

# Receives one response packet from selected transport and optionally emits diagnostics.
function Read-RadiusResponsePacket {
    param($Connection, [int] $TimeoutMs, [bool] $Diag, [ValidateSet("RADSEC","RADIUS")] [string] $TransportMode)
    if ($TransportMode -eq "RADSEC") {
        return Read-RadiusPacket -SslStream $Connection.Ssl -TimeoutMs $TimeoutMs -Diag $Diag
    }

    try {
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $packet = $Connection.Udp.Receive([ref]$remote)
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            throw "Timeout waiting for RADIUS UDP response."
        }
        throw
    }

    if ($Diag) {
        Write-Host (" [DIAG-STREAM] Inbound UDP RADIUS datagram from {0}:{1}, Size: {2} bytes" -f $remote.Address, $remote.Port, $packet.Length) -ForegroundColor DarkCyan
        Write-Host " [DIAG-HEXDUMP] --- RAW INBOUND RADIUS PACKET MATRIX ---" -ForegroundColor Gray
        Write-Host (Dump-Hex -Bytes $packet) -ForegroundColor Gray
    }

    return $packet
}

# Sends a request and reads its response, automatically retransmitting the exact same
# packet bytes (same Identifier/Request Authenticator, per RFC 2865 client retransmission
# guidance) on a UDP RADIUS timeout before giving up. RADSEC (TCP/TLS) is never retried here:
# TCP already guarantees delivery/ordering at the transport layer, so a stalled TLS stream
# read indicates a different class of failure that retransmission would not fix.
function Send-AndReceiveRadiusPacket {
    param(
        $Connection,
        [byte[]] $Packet,
        [ValidateSet("RADSEC","RADIUS")] [string] $TransportMode,
        [int] $TimeoutMs,
        [bool] $Diag,
        [int] $MaxRetries = 2
    )

    $attempt = 0
    while ($true) {
        Send-RadiusRequestPacket -Connection $Connection -Packet $Packet -TransportMode $TransportMode
        try {
            return Read-RadiusResponsePacket -Connection $Connection -TimeoutMs $TimeoutMs -Diag $Diag -TransportMode $TransportMode
        } catch {
            $isUdpTimeout = ($TransportMode -eq "RADIUS") -and ($_.Exception.Message -match "Timeout waiting for RADIUS UDP response")
            if (-not $isUdpTimeout -or $attempt -ge $MaxRetries) {
                throw
            }
            $attempt++
            if ($Diag) {
                Write-Host (" [DBG] UDP RADIUS response timeout; retransmitting same request (retry {0}/{1})..." -f $attempt, $MaxRetries) -ForegroundColor Yellow
            }
        }
    }
}
#endregion

#region --- Inner EAP-TLS engine using SslStream over pipe
# Builds the hint text appended to inner EAP-TLS failures. Special-cases a hostname/SAN
# mismatch (proven via [EapTlsStreamFactory]::LastValidationDetail) with specific guidance,
# since that failure mode looks identical to a chain/revocation failure otherwise and was
# previously misdiagnosed as one.
function Get-EapTlsCertValidationHint {
    $detail = [EapTlsStreamFactory]::LastValidationDetail
    if ($detail -match "NameMatches=False" -or $detail -match "RemoteCertificateNameMismatch") {
        $hint = " Hint: the server certificate's DNS name does not match -EapServerName. Set -EapServerName to the exact CN/SAN the server presents (see CertName= in ValidationDetail below), not a tenant-specific or vanity hostname that may only be valid for -Server connectivity."
    } else {
        $hint = " Hint: provide -EapRootCACertPath (or -RootCACertPath for fallback), set -EapServerName to the cert DNS name when connecting to an IP, use -SkipEapServerCertCheck for lab testing, or if this failure is intermittent rather than persistent, use -SkipRevocationCheck to rule out transient OCSP/CRL lookup timeouts."
    }
    if ($detail) {
        $hint += " ValidationDetail: $detail"
    }
    return $hint
}

# Creates the inner TLS engine used by EAP-TLS, EAP-TTLS, and PEAP outer methods.
function New-EapTlsEngine {
    param(
        [string] $ServerName,
        [string] $ClientCertPath,
        [SecureString] $ClientCertPassword,
        [string] $RootCaPath,
        [switch] $SkipServerCertCheck,
        [switch] $ForceTls12,
        [switch] $SkipRevocationCheck
    )

    $pipe = New-Object EapTlsPipeStream
    $certs = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
    if ($ClientCertPath) {
        $ClientCertPath = (Resolve-Path $ClientCertPath).Path
        if ($ClientCertPassword) {
            $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientCertPassword)
            $plain=[Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $cc=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertPath,$plain)
        } else {
            $cc=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertPath)
        }
        $certs.Add($cc) | Out-Null
    }

    $trustedRoot = $null
    if ($RootCaPath) {
        $RootCaPath = (Resolve-Path $RootCaPath).Path
        $trustedRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCaPath)
    }

        # NOTE: SolarWinds SAM/PSRP hosts long-lived, persistent PowerShell processes across
        # monitor runs. Add-Type cannot redefine an existing type within the same process/AppDomain,
        # so if a process already loaded an OLDER version of this class (missing a field/member this
        # version relies on), setting that member below throws "property ... cannot be found on this
        # object" (e.g. this bit ExpectedServerName the first time it was added). In practice this
        # self-resolves: expect up to two Orion polling cycles of failures after changing this
        # class's members before every worker process has cycled to a fresh one running the current
        # definition - no action needed beyond waiting it out.
        if (-not ([System.Management.Automation.PSTypeName]"EapTlsStreamFactory").Type) {
                Add-Type -Language CSharp @"
using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class EapTlsStreamFactory {
    public static X509Certificate2 TrustedRoot = null;
    public static bool SkipAll = false;
    public static bool SkipRevocation = false;
    public static string ExpectedServerName = null;
    public static string LastValidationDetail = "";

    private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        LastValidationDetail = "";
        if (SkipAll) return true;
        if (TrustedRoot != null) {
            if (chain == null || cert == null) { LastValidationDetail = "chain or cert was null"; return false; }
            chain.ChainPolicy.ExtraStore.Add(TrustedRoot);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            if (SkipRevocation) chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            X509Certificate2 leaf = new X509Certificate2(cert);
            bool built = chain.Build(leaf);
            var sb = new System.Text.StringBuilder();
            sb.Append("SslPolicyErrors=").Append(errors).Append("; Built=").Append(built);
            foreach (var s in chain.ChainStatus) {
                sb.Append("; ").Append(s.Status).Append(": ").Append(s.StatusInformation.Trim());
            }
            if (chain.ChainElements == null || chain.ChainElements.Count == 0) {
                sb.Append("; ChainElements=0");
                LastValidationDetail = sb.ToString();
                return false;
            }
            X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            bool rootMatches = string.Equals(root.Thumbprint, TrustedRoot.Thumbprint, StringComparison.OrdinalIgnoreCase);
            bool nameOk = true;
            string certName = leaf.GetNameInfo(X509NameType.DnsName, false);
            if (!string.IsNullOrEmpty(ExpectedServerName)) {
                nameOk = string.Equals(certName, ExpectedServerName, StringComparison.OrdinalIgnoreCase);
            }
            sb.Append("; RootMatches=").Append(rootMatches).Append("; CertName=").Append(certName).Append("; ExpectedServerName=").Append(ExpectedServerName).Append("; NameMatches=").Append(nameOk);
            LastValidationDetail = sb.ToString();
            return built && rootMatches && nameOk;
        }
        var sb2 = new System.Text.StringBuilder();
        sb2.Append("SslPolicyErrors=").Append(errors);
        if (chain != null && chain.ChainStatus != null) {
            foreach (var s in chain.ChainStatus) {
                sb2.Append("; ").Append(s.Status).Append(": ").Append(s.StatusInformation.Trim());
            }
        }
        LastValidationDetail = sb2.ToString();
        return errors == SslPolicyErrors.None;
    }

    public static SslStream CreateSslStream(Stream s) {
        return new SslStream(s, false, new RemoteCertificateValidationCallback(Validate));
    }
}
"@
        }

        [EapTlsStreamFactory]::SkipAll = $SkipServerCertCheck.IsPresent
        [EapTlsStreamFactory]::TrustedRoot = $trustedRoot
        [EapTlsStreamFactory]::SkipRevocation = $SkipRevocationCheck.IsPresent
        [EapTlsStreamFactory]::ExpectedServerName = $ServerName
        $ssl = [EapTlsStreamFactory]::CreateSslStream($pipe)
    $sslProtocols = if ($ForceTls12.IsPresent) {
        [System.Security.Authentication.SslProtocols]::Tls12
    } else {
        [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
    }
    # NOTE: EapTlsStreamFactory.Validate has TWO independent code paths depending on whether a
    # trusted root cert was supplied (-EapRootCACertPath, or its -RootCACertPath fallback):
    #  - TrustedRoot != null: our own callback rebuilds the chain and gates revocation checking
    #    on the [EapTlsStreamFactory]::SkipRevocation static field (set below).
    #  - TrustedRoot == null: validation falls back to whatever SslPolicyErrors .NET/SChannel
    #    computed itself, which is driven by this checkCertificateRevocation argument.
    # Both paths are wired to -SkipRevocationCheck so a transient OCSP/CRL lookup timeout against
    # the server cert's revocation responder (third-party CA infrastructure, outside our control)
    # doesn't surface as a hard, indistinguishable-from-a-bad-certificate failure either way.
    $checkRevocation = -not (Test-TruthyToken $SkipRevocationCheck)
    $task = $ssl.AuthenticateAsClientAsync(
        $ServerName, $certs,
        $sslProtocols,
        $checkRevocation
    )
    return [pscustomobject]@{ Pipe=$pipe; Ssl=$ssl; AuthTask=$task }
}
#endregion

#region --- Main
$timeoutMs = $TimeoutSeconds * 1000

# Maps internal auth values to user-facing labels in summaries/charts.
function Get-AuthTypeSummaryLabel {
    param([string]$Type)
    switch ($Type) {
        "MAB" { return "MAB" }
        "EAP-PEAP" { return "PEAP/MSCHAPv2" }
        "EAP-TTLS" { return "EAP-TTLS/PAP" }
        default { return $Type }
    }
}

function Get-OrionExitCode {
    param([string] $FinalResponse)

    switch ($FinalResponse) {
        "Access-Accept" { return 0 }
        "Access-Reject" { return 3 }
        default { return 1 }
    }
}

# Writes concise final run summary and optionally emits structured metrics for loop mode.
function Write-AuthenticationSummary {
    param(
        [string] $Server,
        [int] $Port,
        [string] $Transport,
        [string] $AuthType,
        [string] $Username,
        [string] $NasIdentifier,
        [string] $SharedSecret,
        [string] $FinalResponse,
        [long] $ElapsedMilliseconds
    )

    $orionStatistic = [long]$ElapsedMilliseconds
    if ($FinalResponse -ne "Access-Accept") {
        # In Orion mode, use 0 on auth failure so threshold-based monitors can mark the component down.
        $orionStatistic = 0
    }

    if ($script:IsOrionMode -and -not $EmitResultObject.IsPresent) {
        echo ("Statistic: {0}" -f $orionStatistic)
        echo ("Message: {0} (elapsed={1}ms)" -f $FinalResponse, [long]$ElapsedMilliseconds)
        $script:OrionExitCode = Get-OrionExitCode -FinalResponse $FinalResponse
        [Environment]::ExitCode = [int]$script:OrionExitCode
    } elseif (-not $EmitResultObject.IsPresent) {
        Write-Host ""
        Write-Host "---------------------------------------------------" -ForegroundColor Cyan
        Write-Host " Authentication Summary" -ForegroundColor Cyan
        Write-Host "---------------------------------------------------" -ForegroundColor Cyan
        Write-Host " Server    : $Server`:$Port"
        Write-Host " Transport : $Transport"
        Write-Host " AuthType  : $(Get-AuthTypeSummaryLabel -Type $AuthType)"
        Write-Host " Username  : $Username"
        Write-Host " NAS-ID    : $NasIdentifier"
        Write-Host " Secret    : $('*' * 8)"
        Write-Host " Response  : $FinalResponse"
        Write-Host " Time      : $ElapsedMilliseconds ms"
        echo ("Statistic: {0}" -f [long]$ElapsedMilliseconds)
        echo ("Message: {0}" -f $FinalResponse)
        $script:OrionExitCode = Get-OrionExitCode -FinalResponse $FinalResponse
        [Environment]::ExitCode = [int]$script:OrionExitCode
    }

    if ($EmitResultObject.IsPresent) {
        [pscustomobject]@{
            FinalResponse = $FinalResponse
            ElapsedMilliseconds = [long]$ElapsedMilliseconds
        }
    }
}

# Renders a compact ASCII time-series graph for continuous timing visualization.
function Write-TimeSeriesAsciiChart {
    param(
        [System.Collections.Generic.List[long]] $Values,
        [int] $Iteration = 0,
        [string] $LastResponse = "",
        [switch] $InPlace,
        [int] $Width = 60,
        [int] $Height = 10
    )

    if (-not $Values -or $Values.Count -eq 0) { return }

    $points = @($Values)
    if ($points.Count -gt $Width) {
        $start = $points.Count - $Width
        $points = $points[$start..($points.Count - 1)]
    }

    $count = $points.Count
    $min = [double](($points | Measure-Object -Minimum).Minimum)
    $max = [double](($points | Measure-Object -Maximum).Maximum)
    $avg = [double](($points | Measure-Object -Average).Average)
    $last = [long]$points[$count - 1]

    if ($max -le $min) {
        $max = $min + 1
    }

    $canvas = @()
    for ($r = 0; $r -lt $Height; $r++) {
        $canvas += ,([char[]](' ' * $count))
    }

    for ($x = 0; $x -lt $count; $x++) {
        $value = [double]$points[$x]
        $norm = ($value - $min) / ($max - $min)
        $row = ($Height - 1) - [int][Math]::Round($norm * ($Height - 1))
        if ($row -lt 0) { $row = 0 }
        if ($row -ge $Height) { $row = $Height - 1 }
        $canvas[$row][$x] = '*'
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add((" Time Series (ms)  iter={0}  response={1}  last={2}  min={3}  max={4}  avg={5:N1}  samples={6}" -f $Iteration, $LastResponse, $last, [long]$min, [long]$max, $avg, $Values.Count))
    for ($r = 0; $r -lt $Height; $r++) {
        $y = [long][Math]::Round($max - (($max - $min) * $r / [Math]::Max(1, ($Height - 1))))
        $label = $y.ToString().PadLeft(5)
        $lines.Add($label + " |" + (-join $canvas[$r]))
    }
    $lines.Add("      +" + ('-' * $count))
    $lines.Add("       oldest" + (' ' * [Math]::Max(1, $count - 12)) + "newest")

    if ($InPlace.IsPresent -and $script:ContinuousChartLineCount -gt 0) {
        try {
            $esc = [char]27
            for ($i = 0; $i -lt $script:ContinuousChartLineCount; $i++) {
                [Console]::Write("$esc[1F$esc[2K")
            }
        }
        catch {
            # If terminal cursor control is unavailable, fall back to normal append mode.
        }
    }

    if (-not $InPlace.IsPresent -or -not $script:ContinuousChartHasDrawn) {
        Write-Host ""
    }

    if ($lines.Count -gt 0) {
        Write-Host $lines[0] -ForegroundColor Cyan
        for ($i = 1; $i -lt $lines.Count; $i++) {
            Write-Host $lines[$i]
        }
    }

    $script:ContinuousChartLineCount = $lines.Count
    $script:ContinuousChartHasDrawn = $true
}

# Replays the same startup parameters repeatedly and refreshes the timing chart in-place.
function Start-ContinuousMode {
    param([string] $ScriptPath)

    if (-not $ScriptPath -or -not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Continuous mode cannot start because the script path could not be resolved."
    }

    $childParams = @{}
    foreach ($entry in $script:StartupBoundParameters.GetEnumerator()) {
        if ($entry.Key -in @("continuous","ShowHelp","EmitResultObject","RemainingArguments")) { continue }
        $childParams[$entry.Key] = $entry.Value
    }
    $childParams["EmitResultObject"] = $true

    $history = [System.Collections.Generic.List[long]]::new()
    $iteration = 0
    $script:ContinuousChartLineCount = 0
    $script:ContinuousChartHasDrawn = $false

    Write-Host "Continuous mode enabled. Press Ctrl+C to stop." -ForegroundColor Yellow

    while ($true) {
        $iteration++

        $attempt = $null
        try {
            $childOutput = & $ScriptPath @childParams
            foreach ($item in @($childOutput)) {
                if ($item -and $item.PSObject -and $item.PSObject.Properties["ElapsedMilliseconds"]) {
                    $attempt = $item
                }
            }
        }
        catch {
            Write-Host " [ERROR] Continuous iteration failed: $_" -ForegroundColor Red
            continue
        }

        if ($attempt) {
            $history.Add([long]$attempt.ElapsedMilliseconds)
            $response = "Unknown"
            if ($attempt.PSObject.Properties["FinalResponse"] -and $attempt.FinalResponse) {
                $response = [string]$attempt.FinalResponse
            }
            Write-TimeSeriesAsciiChart -Values $history -Iteration $iteration -LastResponse $response -InPlace
        } else {
            Write-Host " [WARN] Iteration did not return a timing metric to chart." -ForegroundColor Yellow
        }
    }
}

if ($continuous.IsPresent) {
    # Continuous mode wraps this script as a child process and renders a live timing chart.
    Start-ContinuousMode -ScriptPath $PSCommandPath
    return
}

$script:OrionExitCode = $null

# Optional failure-only debug capture: force full diagnostic verbosity into a transcript file
# for this run, then keep the file only if the run did not end in Access-Accept. This lets
# Orion/SAM monitors stay quiet on success while still auto-producing a full DBG transcript
# whenever a monitor fails or errors.
$script:DebugTranscriptStarted = $false
$script:DebugTranscriptPath = $null
if ((Test-TruthyToken -Value $CaptureDebugOnFailure) -and -not $EmitResultObject.IsPresent) {
    $DebugOutput = [System.Management.Automation.SwitchParameter]::Present
    try {
        if (-not (Test-Path -LiteralPath $DebugLogDirectory)) {
            New-Item -ItemType Directory -Path $DebugLogDirectory -Force | Out-Null
        }
        $script:DebugTranscriptPath = Join-Path ([System.IO.Path]::GetTempPath()) ("PortnoxRadiusDebug_{0}.tmp.log" -f ([Guid]::NewGuid().ToString("N")))
        Start-Transcript -Path $script:DebugTranscriptPath -Force | Out-Null
        $script:DebugTranscriptStarted = $true
    } catch {
        $script:DebugTranscriptStarted = $false
    }
}

if ($DebugOutput.IsPresent) {
    # Debug banner prints only when verbose tracing is explicitly requested.
    Write-Host ""
    Write-Host "---------------------------------------------------" -ForegroundColor Cyan
    Write-Host " RADIUS/RADSEC Authentication Test"   -ForegroundColor Cyan
    Write-Host "---------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Server    : $Server`:$Port"
    Write-Host " Transport : $Transport"
    Write-Host " AuthType  : $(Get-AuthTypeSummaryLabel -Type $AuthType)"
    Write-Host " Username  : $Username"
    if ($AuthType -eq "EAP-PEAP") {
        Write-Host " PEAP Out  : $PeapOuterIdentity"
        Write-Host " PEAP In   : $PeapInnerIdentity"
        Write-Host " PEAP R-U  : $PeapRadiusUserNameMode"
    }
    if ($DesiredEapTypes -and $DesiredEapTypes.Length -gt 0) {
        $desiredTypeLabels = @($DesiredEapTypes | ForEach-Object {
            $t = [int][byte]$_
            "{0}({1})" -f $t, (Get-EapTypeName $t)
        }) -join ", "
        Write-Host " NAK Types : $desiredTypeLabels"
    }
    Write-Host " NAS-ID    : $NasIdentifier"
    Write-Host " Secret    : $('*' * 8)"
    Write-Host ""
}

$connection = $null
# Start timer before connection setup so the reported metric reflects end-to-end runtime.
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    # Create transport connection once per script run, then reuse for all EAP rounds.
    if ($Transport -eq "RADSEC") {
        $connection = New-TlsStream -Server $Server -Port $Port -RootCACertPath $RootCACertPath `
            -ClientCertPath $ClientCertPath -ClientCertPassword $ClientCertPassword `
            -SkipCertCheck (Test-TruthyToken $SkipCertificateCheck) -SkipRevocation (Test-TruthyToken $SkipRevocationCheck) -TimeoutMs $timeoutMs `
            -Diag $DebugOutput.IsPresent -MaxRetries 2
    } else {
        $connection = New-RadiusUdpConnection -Server $Server -Port $Port -TimeoutMs $timeoutMs
    }

    # PAP and MAB are single request/response exchanges and return immediately after summary output.
    if ($AuthType -eq "PAP" -or $AuthType -eq "MAB") {
        $rid = [byte](Get-Random -Minimum 0 -Maximum 255)
        $req = Build-AccessRequest -Username $Username -Password $Password -SharedSecret $SharedSecret `
            -NasIdentifier $NasIdentifier -NasPortId $NasPortId -NasPortType $NasPortType -NasIpAddress $NasIpAddress -CallingStationId $CallingStationId -CalledStationId $CalledStationId `
            -Identifier $rid -AuthType $AuthType
        $respData = Send-AndReceiveRadiusPacket -Connection $connection -Packet $req -TransportMode $Transport -TimeoutMs $timeoutMs -Diag $DebugOutput.IsPresent -MaxRetries 2
        $resp = Parse-RadiusResponse -Data $respData -Diag $DebugOutput.IsPresent
        $stopwatch.Stop()
        Write-AuthenticationSummary -Server $Server -Port $Port -Transport $Transport -AuthType $AuthType -Username $Username `
            -NasIdentifier $NasIdentifier -SharedSecret $SharedSecret -FinalResponse $resp.CodeName -ElapsedMilliseconds $stopwatch.ElapsedMilliseconds
        if ($EmitResultObject.IsPresent) {
            return
        }
        # Always enforce a correct process exit code here (0 only for Access-Accept), regardless
        # of whether Orion-mode auto-detection classified this invocation as Orion or not.
        if ($null -eq $script:OrionExitCode) { $script:OrionExitCode = 1 }
        exit ([int]$script:OrionExitCode)
    }

    $engine = $null
    $pipe = $null
    $tlsTask = $null
    $outerEapType = switch ($AuthType) {
        "EAP-PEAP" { [byte]25 }
        "EAP-TTLS" { [byte]21 }
        default { [byte]13 }
    }
    $outerEapName = Get-EapTypeName $outerEapType
    if ($AuthType -eq "EAP-PEAP" -and $DebugOutput.IsPresent) {
        Write-Host " [INFO] EAP-PEAP outer tunnel enabled with Phase 2 inner EAP-MSCHAPv2 support." -ForegroundColor Yellow
        Write-Host (" [INFO] PEAP Phase2 compat: VersionMode={0}, LengthBit={1}, AckBeforeData={2}" -f $PeapPhase2VersionMode, $PeapPhase2SetLengthBit.IsPresent, $PeapPhase2AckBeforeData.IsPresent) -ForegroundColor Yellow
    }
    if ($AuthType -eq "EAP-TTLS" -and $DebugOutput.IsPresent) {
        Write-Host " [INFO] EAP-TTLS outer tunnel enabled with Phase 2 tunneled PAP support." -ForegroundColor Yellow
    }
    $peapInnerComplete = $false
    $peapInnerWaitRounds = 0
    $peapLastServerVersionBits = [byte]0
    $peapDeferredOuterPacket = $null
    $ttlsPhase2Complete = $false
    $script:PeapInnerReadTask = $null
    $script:PeapInnerReadBuffer = $null

    $state = $null
    $round = 0
    $radiusId = [byte](Get-Random -Minimum 0 -Maximum 255)
    $isEngineInitialized = $false
    $outerEapIdentity = if ($AuthType -eq "EAP-PEAP") { $PeapOuterIdentity } else { $Username }
    $innerEapIdentity = if ($AuthType -eq "EAP-PEAP") { $PeapInnerIdentity } else { $Username }
    $radiusUserName = if ($AuthType -eq "EAP-PEAP") {
        if ($PeapRadiusUserNameMode -eq "Outer") { $outerEapIdentity } else { $innerEapIdentity }
    } else { $Username }

    if ($AuthType -eq "EAP-PEAP" -and $DebugOutput.IsPresent) {
        Write-Host " RADIUS U  : $radiusUserName"
    }

    $eapId = [byte]0
    $nextEap = New-EapIdentityResponse -Id $eapId -Username $outerEapIdentity

    $clientOut = [byte[]]::new(0)
    $clientOutTotal = $null
    $lenFieldSent = $false
    $incomingTlsData = [byte[]]::new(0)  # Accumulate fragmented server TLS data
    $serverTlsExpectedLen = $null        # Expected TLS bytes for current inbound message (from EAP-TLS L bit)

    # Multi-round EAP state machine: send next request, parse challenge, produce next EAP payload.
    while ($round -lt $MaxEapRounds) {
        $round++
        
        $rid = if ($ReuseRadiusIdentifier -and $isEngineInitialized) { 
            $radiusId 
        } else { 
            [byte](Get-Random -Minimum 0 -Maximum 255) 
        }

        if ($DebugOutput.IsPresent) {
            Write-Host (" [DBG] Using State = {0}" -f ($(if($state){"0x"+(Bytes-ToHex $state)} else {"<none>"}))) -ForegroundColor DarkGray
        }

        $req = Build-AccessRequest -Username $radiusUserName -SharedSecret $SharedSecret `
            -NasIdentifier $NasIdentifier -NasPortId $NasPortId -NasPortType $NasPortType -NasIpAddress $NasIpAddress -CallingStationId $CallingStationId -CalledStationId $CalledStationId `
            -Identifier $rid -AuthType $AuthType -EapMessage $nextEap -State $state

        if ($DebugOutput.IsPresent) {
            Write-Host " >> Access-Request(EAP) sent (round=$round, id=$rid, eapId=$eapId)" -ForegroundColor Yellow
        }

        $respData = Send-AndReceiveRadiusPacket -Connection $connection -Packet $req -TransportMode $Transport -TimeoutMs $timeoutMs -Diag $DebugOutput.IsPresent -MaxRetries 2
        $resp = Parse-RadiusResponse -Data $respData -Diag $DebugOutput.IsPresent
        if ($DebugOutput.IsPresent) {
            Write-Host " << Response: $($resp.CodeName) (round=$round)" -ForegroundColor Cyan
        }

        if ($resp.Code -eq 2 -or $resp.Code -eq 3) {
            if ($resp.Code -eq 3 -and $DebugOutput.IsPresent) {
                $rejEap = Get-AttributeConcat -Attributes $resp.Attributes -Type 79
                if ($rejEap) {
                    Write-Host (" [DBG] Reject EAP raw hex: {0}" -f (Bytes-ToHex $rejEap)) -ForegroundColor DarkGray
                    $rejParsed = Parse-EapPacket -Eap $rejEap
                    if ($rejParsed) {
                        Write-Host (" [DBG] Reject EAP parsed: Code={0} Id={1} Len={2} Type={3} ({4})" -f $rejParsed.Code, $rejParsed.Id, $rejParsed.Length, $(if($null -ne $rejParsed.Type){$rejParsed.Type}else{"<none>"}), $(if($null -ne $rejParsed.Type){Get-EapTypeName $rejParsed.Type}else{"None"})) -ForegroundColor DarkGray
                    }
                }
            }
            $stopwatch.Stop()
            Write-AuthenticationSummary -Server $Server -Port $Port -Transport $Transport -AuthType $AuthType -Username $Username `
                -NasIdentifier $NasIdentifier -SharedSecret $SharedSecret -FinalResponse $resp.CodeName -ElapsedMilliseconds $stopwatch.ElapsedMilliseconds
            break
        }
        if ($resp.Code -ne 11) { throw "Unexpected response code $($resp.Code)" }

        $state = Get-AttributeConcat -Attributes $resp.Attributes -Type 24
        if ($DebugOutput.IsPresent) {
            Write-Host (" [DBG] Received State (len={0}) = {1}" -f ($(if($state){$state.Length}else{0})), ($(if($state){"0x"+(Bytes-ToHex $state)} else {"<none>"}))) -ForegroundColor DarkGray
        }

        $eapMsg = Get-AttributeConcat -Attributes $resp.Attributes -Type 79
        if (-not $eapMsg) { throw "No EAP-Message (79) found in Access-Challenge." }

        $eapParsed = Parse-EapPacket -Eap $eapMsg
        if (-not $eapParsed) { throw "EAP-Message present but not parsable." }

        $eapId = [byte]$eapParsed.Id
        $typeName = Get-EapTypeName $eapParsed.Type
        if ($DebugOutput.IsPresent) {
            Write-Host (" [INFO] Server EAP: Code={0} Id={1} Type={2} ({3}) DataLen={4}" -f $eapParsed.Code, $eapId, $eapParsed.Type, $typeName, $eapParsed.Data.Length) -ForegroundColor DarkCyan
        }

        if ($eapParsed.Code -eq 4) {
            $stopwatch.Stop()
            if ($DebugOutput.IsPresent) {
                Write-Host " [INFO] Server returned an explicit standalone EAP-Failure code." -ForegroundColor DarkRed
            }
            Write-AuthenticationSummary -Server $Server -Port $Port -Transport $Transport -AuthType $AuthType -Username $Username `
                -NasIdentifier $NasIdentifier -SharedSecret $SharedSecret -FinalResponse "EAP-Failure" -ElapsedMilliseconds $stopwatch.ElapsedMilliseconds
            break
        }
        if ($eapParsed.Code -eq 3) {
            $stopwatch.Stop()
            if ($DebugOutput.IsPresent) {
                Write-Host " [INFO] Server returned an explicit standalone EAP-Success code." -ForegroundColor DarkGreen
            }
            Write-AuthenticationSummary -Server $Server -Port $Port -Transport $Transport -AuthType $AuthType -Username $Username `
                -NasIdentifier $NasIdentifier -SharedSecret $SharedSecret -FinalResponse "EAP-Success" -ElapsedMilliseconds $stopwatch.ElapsedMilliseconds
            break
        }

        if ($eapParsed.Type -eq 1) {
            $nextEap = New-EapIdentityResponse -Id $eapId -Username $outerEapIdentity
            continue
        }

        if ($eapParsed.Type -eq $outerEapType) {
            # Outer EAP-TLS/TTLS/PEAP handling drives fragment ACK logic and inner TLS engine progression.
            $td = Parse-EapTlsTypeData -TypeData $eapParsed.Data
            if ($outerEapType -eq 25) {
                $peapLastServerVersionBits = [byte]($td.Flags -band 0x07)
            }
            if ($DebugOutput.IsPresent) {
                Write-Host (" [DBG] EAP-TLS in: Flags=0x{0} HasLen={1} TotalLen={2} FragLen={3} InAccum={4} Exp={5}" -f $td.Flags.ToString("X2"), $td.HasLen, $(if($null -ne $td.TotalLen){$td.TotalLen}else{"<none>"}), $td.TlsData.Length, $incomingTlsData.Length, $(if($null -ne $serverTlsExpectedLen){$serverTlsExpectedLen}else{"<none>"})) -ForegroundColor DarkGray
            }
            if ($DebugOutput.IsPresent -and $td.TlsData.Length -gt 0) {
                Write-Host (" [DBG] EAP-TLS in fragment hex: {0}" -f (Bytes-ToHex $td.TlsData)) -ForegroundColor DarkGray
            }

            if ($AuthType -eq "EAP-PEAP" -and $peapDeferredOuterPacket -and -not $td.HasLen -and $td.TlsData.Length -eq 0) {
                if ($DebugOutput.IsPresent) {
                    Write-Host " [DBG] PEAP deferred phase-2 payload ready; rebuilding with current EAP Id and sending now after server ACK/empty PEAP frame." -ForegroundColor DarkGray
                }
                $deferred = $peapDeferredOuterPacket
                $peapDeferredOuterPacket = $null
                $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$deferred.Flags) -TlsPayload ([byte[]]$deferred.TlsPayload) -TotalLen $deferred.TotalLen -OuterType $outerEapType
                continue
            }

            if ($null -eq $engine) {
                if ($DebugOutput.IsPresent) {
                    Write-Host " [DBG] Initializing EAP-TLS inner engine..." -ForegroundColor DarkGray
                }
                $engine = New-EapTlsEngine -ServerName $EapServerName -ClientCertPath $EapClientCertPath -ClientCertPassword $EapClientCertPassword `
                    -RootCaPath $EapRootCACertPath -SkipServerCertCheck:(Test-TruthyToken $SkipEapServerCertCheck) -ForceTls12:($AuthType -eq "EAP-PEAP") `
                    -SkipRevocationCheck:(Test-TruthyToken $SkipRevocationCheck)
                $pipe = $engine.Pipe
                $tlsTask = $engine.AuthTask

                # Wait up to 1 second for SslStream to produce initial ClientHello data
                $newOut = $pipe.TakeOutgoingWait(1000)

                if ($tlsTask.IsCompleted -and $tlsTask.IsFaulted) {
                    $msg = $tlsTask.Exception
                    if ($msg.InnerException) { $msg = $msg.InnerException }
                    throw "Inner EAP-TLS handshake thread initialization failed completely: $($msg.Message)"
                }
                
                $isEngineInitialized = $true
                
                # Create initial EAP-TLS response with ClientHello
                if ($newOut.Length -gt 0) {
                    $clientOut = Concat-Bytes $clientOut $newOut
                    $clientOutTotal = [uint32]$clientOut.Length
                    
                    $take = [Math]::Min($MaxEapTlsFragmentSize, $clientOut.Length)
                    $frag = [byte[]]::new($take)
                    [Array]::Copy($clientOut, 0, $frag, 0, $take)
                    
                    $remain = $clientOut.Length - $take
                    $rest = [byte[]]::new($remain)
                    if ($remain -gt 0) { [Array]::Copy($clientOut, $take, $rest, 0, $remain) }
                    $clientOut = $rest
                    
                    $flags = 0x80  # Length field present for initial message
                    if ($clientOut.Length -gt 0) { $flags = $flags -bor 0x40 }  # More fragments flag
                    
                    $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$flags) -TlsPayload $frag -TotalLen $clientOutTotal -OuterType $outerEapType
                    $lenFieldSent = $true
                    continue
                }
            } else {
                # Accumulate fragmented server TLS data
                if ($td.TlsData.Length -gt 0) { 
                    $incomingTlsData = Concat-Bytes $incomingTlsData $td.TlsData
                }

                # Track expected inbound TLS length when server provides it.
                if ($td.HasLen -and $null -ne $td.TotalLen -and $td.TotalLen -gt 0) {
                    if ($null -eq $serverTlsExpectedLen -or $incomingTlsData.Length -eq $td.TlsData.Length) {
                        $serverTlsExpectedLen = [int]$td.TotalLen
                    }
                }
                
                # Check if server has more fragments coming
                $serverHasMoreFragments = (($td.Flags -band 0x40) -ne 0)

                # Be robust against servers that signal fragmentation inconsistently:
                # if we know expected total length and have not reached it yet, ACK and continue collecting.
                $haveCompleteServerTls = $false
                if ($null -ne $serverTlsExpectedLen) {
                    $haveCompleteServerTls = ($incomingTlsData.Length -ge $serverTlsExpectedLen)
                } else {
                    $haveCompleteServerTls = (-not $serverHasMoreFragments)
                }
                
                if (-not $haveCompleteServerTls) {
                    # More fragments coming - just send ACK and wait
                    if ($DebugOutput.IsPresent) {
                        Write-Host (" [DBG] Server TLS payload incomplete ({0}/{1} bytes). Sending EAP-TLS ACK..." -f $incomingTlsData.Length, $(if($null -ne $serverTlsExpectedLen){$serverTlsExpectedLen}else{"?"})) -ForegroundColor DarkGray
                    }
                    $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                    continue
                }

                # Server sent ACK-only EAP-TLS (no TLS payload). If we still have queued
                # client bytes from a previous fragment burst, send the next chunk now.
                $serverAckOnly = (-not $td.HasLen) -and ($td.TlsData.Length -eq 0) -and (($td.Flags -band 0x40) -eq 0)
                if ($serverAckOnly -and $clientOut.Length -gt 0) {
                    $take = [Math]::Min($MaxEapTlsFragmentSize, $clientOut.Length)
                    $frag = [byte[]]::new($take)
                    [Array]::Copy($clientOut, 0, $frag, 0, $take)

                    $remain = $clientOut.Length - $take
                    $rest = [byte[]]::new($remain)
                    if ($remain -gt 0) { [Array]::Copy($clientOut, $take, $rest, 0, $remain) }
                    $clientOut = $rest

                    $flags = 0
                    if (-not $lenFieldSent) {
                        $flags = $flags -bor 0x80
                        $lenFieldSent = $true
                    }
                    if ($clientOut.Length -gt 0) { $flags = $flags -bor 0x40 }

                    if ($DebugOutput.IsPresent) {
                        Write-Host (" [DBG] ACK-only from server; sending queued client TLS fragment: send={0} remain={1} flags=0x{2}" -f $frag.Length, $clientOut.Length, ([byte]$flags).ToString("X2")) -ForegroundColor DarkGray
                    }
                    $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$flags) -TlsPayload $frag -TotalLen $clientOutTotal -OuterType $outerEapType
                    continue
                }
                
                # No more fragments - feed accumulated data to SslStream and wait for response
                if ($incomingTlsData.Length -gt 0) {
                    if ($DebugOutput.IsPresent) {
                        Write-Host " [DBG] Received final TLS fragment. Feeding $($incomingTlsData.Length) bytes to SslStream..." -ForegroundColor DarkGray
                    }
                    $pipe.AddIncoming($incomingTlsData)
                    $incomingTlsData = [byte[]]::new(0)  # Reset for next round
                    $serverTlsExpectedLen = $null
                }
                
                # Wait for SslStream to process and produce response
                if ($DebugOutput.IsPresent) {
                    Write-Host " [DBG] Waiting for inner TLS engine to produce client response data (max 60000ms)..." -ForegroundColor DarkGray
                }
                $pollCount = 0
                $maxPolls = 60  # Poll up to 60 times (60 seconds / 1000ms per poll)
                
                while ($pollCount -lt $maxPolls) {
                    $newOut = $pipe.TakeOutgoingWait(1000)
                    $pollCount++
                    
                    if ($newOut.Length -gt 0) {
                        if ($DebugOutput.IsPresent) {
                            Write-Host " [DBG] TLS engine produced $($newOut.Length) bytes after $(($pollCount * 1000))ms." -ForegroundColor DarkGray
                        }
                        break
                    }
                    
                    if ($tlsTask.IsFaulted) {
                        $msg = $tlsTask.Exception
                        if ($msg.InnerException) { $msg = $msg.InnerException }
                        $hint = ""
                        if ($msg.Message -match "certificate is invalid" -or $msg.Message -match "authentication failed") {
                            $hint = Get-EapTlsCertValidationHint
                        }
                        throw "Inner EAP-TLS engine failed during processing: $($msg.Message)$hint"
                    }
                    
                    if ($tlsTask.IsCompleted) {
                        if ($DebugOutput.IsPresent) {
                            Write-Host " [DBG] TLS task completed after $(($pollCount * 1000))ms with no output." -ForegroundColor DarkGray
                        }
                        break
                    }
                }

                # Guard against a race where the inner TLS engine writes a final fatal Alert
                # record (e.g. bad_record_mac, certificate_unknown, decrypt_error) to the pipe
                # in the same instant it faults the auth task. TakeOutgoingWait can return that
                # alert's bytes a moment before $tlsTask.IsFaulted flips to true, which previously
                # caused the alert to be forwarded to the RADIUS server as if it were legitimate
                # handshake data - masking the real .NET/SChannel error and producing a confusing
                # Access-Reject instead of a clear exception. Give the task a brief grace period
                # to settle, then prefer surfacing the real fault over forwarding the alert.
                if ($newOut.Length -gt 0 -and -not $tlsTask.IsCompleted) {
                    Start-Sleep -Milliseconds 75
                }
                if ($tlsTask.IsFaulted) {
                    $msg = $tlsTask.Exception
                    if ($msg.InnerException) { $msg = $msg.InnerException }
                    $hint = ""
                    if ($msg.Message -match "certificate is invalid" -or $msg.Message -match "authentication failed") {
                        $hint = Get-EapTlsCertValidationHint
                    }
                    if ($DebugOutput.IsPresent -and $newOut.Length -gt 0) {
                        Write-Host (" [DBG] Discarding {0} byte(s) of engine output - task faulted instead of completing normally (likely a fatal TLS alert): {1}" -f $newOut.Length, (Bytes-ToHex $newOut)) -ForegroundColor Yellow
                    }
                    throw "Inner EAP-TLS engine failed during processing: $($msg.Message)$hint"
                }

                if ($newOut.Length -gt 0) {
                    if ($clientOut.Length -eq 0) {
                        $clientOutTotal = [uint32]$newOut.Length
                        $lenFieldSent = $false
                    } elseif ($null -eq $clientOutTotal) {
                        $clientOutTotal = [uint32]($clientOut.Length + $newOut.Length)
                    }
                    $clientOut = Concat-Bytes $clientOut $newOut

                    $take = [Math]::Min($MaxEapTlsFragmentSize, $clientOut.Length)
                    $frag = [byte[]]::new($take)
                    [Array]::Copy($clientOut, 0, $frag, 0, $take)

                    $remain = $clientOut.Length - $take
                    $rest = [byte[]]::new($remain)
                    if ($remain -gt 0) { [Array]::Copy($clientOut, $take, $rest, 0, $remain) }
                    $clientOut = $rest

                    $flags = 0
                    if (-not $lenFieldSent) {
                        $flags = $flags -bor 0x80
                        $lenFieldSent = $true
                    }
                    if ($clientOut.Length -gt 0) { $flags = $flags -bor 0x40 }

                    if ($DebugOutput.IsPresent) {
                        Write-Host (" [DBG] EAP-TLS out: send={0} remain={1} flags=0x{2} total={3}" -f $frag.Length, $clientOut.Length, ([byte]$flags).ToString("X2"), $(if($null -ne $clientOutTotal){$clientOutTotal}else{"<none>"})) -ForegroundColor DarkGray
                    }
                    $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$flags) -TlsPayload $frag -TotalLen $clientOutTotal -OuterType $outerEapType
                    continue
                } else {
                    # No response data. Check if TLS handshake is complete.
                    if ($tlsTask.IsCompleted) {
                        if ($tlsTask.IsFaulted) {
                            $msg = $tlsTask.Exception
                            if ($msg.InnerException) { $msg = $msg.InnerException }
                            $hint = ""
                            if ($msg.Message -match "certificate is invalid" -or $msg.Message -match "authentication failed") {
                                $hint = Get-EapTlsCertValidationHint
                            }
                            throw "Inner EAP-TLS handshake failed: $($msg.Message)$hint"
                        }
                        if ($AuthType -eq "EAP-PEAP") {
                            if (-not $peapInnerComplete) {
                                $innerRaw = Read-PeapInnerEap -SslStream $engine.Ssl -TimeoutMs 1500
                                if ($null -eq $innerRaw) {
                                    $innerRaw = [byte[]]::new(0)
                                } elseif ($innerRaw -isnot [byte[]]) {
                                    $innerRaw = [byte[]]$innerRaw
                                }
                                if ($innerRaw.Length -eq 0) {
                                    $peapInnerWaitRounds++
                                    if ($DebugOutput.IsPresent) {
                                        Write-Host (" [DBG] PEAP outer TLS completed; inner EAP not available yet (wait round {0}). Sending PEAP ACK to continue..." -f $peapInnerWaitRounds) -ForegroundColor DarkGray
                                    }
                                    if ($peapInnerWaitRounds -ge 10) {
                                        throw "PEAP outer TLS completed, but no inner EAP message arrived after multiple rounds."
                                    }
                                    $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                                    continue
                                }

                                $peapInnerWaitRounds = 0

                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP inner in: {0} bytes" -f $innerRaw.Length) -ForegroundColor DarkGray
                                }
                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP inner in hex: {0}" -f (Bytes-ToHex $innerRaw)) -ForegroundColor DarkGray
                                }

                                $innerParsed = Parse-PeapInnerPacket -Bytes $innerRaw
                                $innerTypeName = Get-EapTypeName $innerParsed.Type
                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP inner parsed: Code={0} Id={1} Type={2} ({3}) Headerless={4}" -f $innerParsed.Code, $(if($null -ne $innerParsed.Id){$innerParsed.Id}else{"<none>"}), $innerParsed.Type, $innerTypeName, $innerParsed.IsHeaderless) -ForegroundColor DarkGray
                                }

                                $innerResp = New-PeapInnerResponse -InnerEap $innerParsed -Username $innerEapIdentity -Password $Password -Diag:$DebugOutput.IsPresent
                                if ($null -eq $innerResp) {
                                    $peapInnerComplete = $true
                                    if ($DebugOutput.IsPresent) {
                                        Write-Host " [DBG] PEAP inner auth complete; awaiting outer EAP-Success." -ForegroundColor DarkGray
                                    }
                                    $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                                    continue
                                }

                                $innerRespType = if ($innerResp.Length -ge 5) { [byte]$innerResp[4] } else { [byte]0 }
                                $shouldDeferPhase2 = ($PeapPhase2AckBeforeData.IsPresent -and ($innerRespType -eq 1 -or $innerRespType -eq 33))

                                $peapPhase2Payload = ConvertTo-PeapPhase2Payload -InnerEapPacket $innerResp

                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP inner out hex: {0}" -f (Bytes-ToHex $innerResp)) -ForegroundColor DarkGray
                                    Write-Host (" [DBG] PEAP phase2 payload hex: {0}" -f (Bytes-ToHex $peapPhase2Payload)) -ForegroundColor DarkGray
                                }

                                $engine.Ssl.Write($peapPhase2Payload, 0, $peapPhase2Payload.Length)
                                $engine.Ssl.Flush()

                                $peapOut = Take-PipeOutgoingBurst -Pipe $pipe -FirstWaitMs 2000 -NextWaitMs 60 -MaxExtraReads 30
                                if ($peapOut.Length -eq 0) {
                                    throw "PEAP inner response was generated, but no outer TLS data became available to send."
                                }
                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP wrapped TLS out hex: {0}" -f (Bytes-ToHex $peapOut)) -ForegroundColor DarkGray
                                }

                                $clientOut = Concat-Bytes $clientOut $peapOut
                                if ($clientOut.Length -eq $peapOut.Length) {
                                    $clientOutTotal = [uint32]$peapOut.Length
                                    $lenFieldSent = $false
                                } elseif ($null -eq $clientOutTotal) {
                                    $clientOutTotal = [uint32]$clientOut.Length
                                }

                                $take = [Math]::Min($MaxEapTlsFragmentSize, $clientOut.Length)
                                $frag = [byte[]]::new($take)
                                [Array]::Copy($clientOut, 0, $frag, 0, $take)

                                $remain = $clientOut.Length - $take
                                $rest = [byte[]]::new($remain)
                                if ($remain -gt 0) { [Array]::Copy($clientOut, $take, $rest, 0, $remain) }
                                $clientOut = $rest

                                # PEAP Phase 2 interop: send tunneled data without L-bit/length field.
                                # Keep only M-bit for fragmentation continuation.
                                $flags = 0
                                if ($clientOut.Length -gt 0) { $flags = $flags -bor 0x40 }

                                $phase2VersionBits = switch ($PeapPhase2VersionMode) {
                                    "One"  { [byte]1 }
                                    "Zero" { [byte]0 }
                                    default { [byte]($peapLastServerVersionBits -band 0x07) }
                                }

                                if ($DebugOutput.IsPresent -and $PeapPhase2VersionMode -ne "CopyServer" -and $phase2VersionBits -ne ($peapLastServerVersionBits -band 0x07)) {
                                    Write-Host (" [DBG] PEAP phase2 version override active: serverBits=0x{0}, clientBits=0x{1}" -f ([byte]($peapLastServerVersionBits -band 0x07)).ToString("X2"), $phase2VersionBits.ToString("X2")) -ForegroundColor DarkGray
                                }

                                $phase2TotalLen = $null
                                $usePhase2LengthBit = $PeapPhase2SetLengthBit.IsPresent
                                if ($shouldDeferPhase2) {
                                    # Portnox accepts the deferred ACK round; for the first deferred
                                    # phase-2 payload it appears to prefer no L-bit/length field.
                                    $usePhase2LengthBit = $false
                                }
                                if ($usePhase2LengthBit) {
                                    $flags = $flags -bor 0x80
                                    $phase2TotalLen = [uint32]($frag.Length + $clientOut.Length)
                                }

                                $flags = [byte]($flags -bor $phase2VersionBits)

                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] PEAP outer out: send={0} remain={1} flags=0x{2} verBits=0x{3} lenBit={4}" -f $frag.Length, $clientOut.Length, ([byte]$flags).ToString("X2"), $phase2VersionBits.ToString("X2"), $usePhase2LengthBit) -ForegroundColor DarkGray
                                }
                                if ($shouldDeferPhase2) {
                                    $peapDeferredOuterPacket = [pscustomobject]@{
                                        Flags = [byte]$flags
                                        TlsPayload = [byte[]]$frag
                                        TotalLen = $phase2TotalLen
                                    }
                                    if ($DebugOutput.IsPresent) {
                                        Write-Host (" [DBG] Deferring PEAP phase-2 payload by one round; sending ACK first for interop (Type={0})." -f $innerRespType) -ForegroundColor DarkGray
                                    }
                                    $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                                } else {
                                    if ($PeapPhase2AckBeforeData.IsPresent -and $DebugOutput.IsPresent) {
                                        Write-Host (" [DBG] Sending PEAP phase-2 payload immediately (Type={0}) to preserve inner EAP request/response sequencing." -f $innerRespType) -ForegroundColor DarkGray
                                    }
                                    $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$flags) -TlsPayload $frag -TotalLen $phase2TotalLen -OuterType $outerEapType
                                }
                                continue
                            }

                            $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                            continue
                        }
                        if ($AuthType -eq "EAP-TTLS") {
                            if (-not $ttlsPhase2Complete) {
                                $ttlsPayload = New-TtlsPhase2PapPayload -Username $innerEapIdentity -Password $Password
                                if ($DebugOutput.IsPresent) {
                                    $ttlsUserLen = [System.Text.Encoding]::UTF8.GetByteCount($innerEapIdentity)
                                    $ttlsPassLen = [System.Text.Encoding]::UTF8.GetByteCount($Password)
                                    Write-Host (" [DBG] TTLS phase2 AVPs: User-Name({0} bytes), User-Password({1} bytes), TotalPayload={2} bytes" -f $ttlsUserLen, $ttlsPassLen, $ttlsPayload.Length) -ForegroundColor DarkGray
                                    Write-Host (" [DBG] TTLS phase2 payload hex: {0}" -f (Bytes-ToHex $ttlsPayload)) -ForegroundColor DarkGray
                                }

                                $engine.Ssl.Write($ttlsPayload, 0, $ttlsPayload.Length)
                                $engine.Ssl.Flush()

                                $ttlsOut = Take-PipeOutgoingBurst -Pipe $pipe -FirstWaitMs 2000 -NextWaitMs 60 -MaxExtraReads 30
                                if ($ttlsOut.Length -eq 0) {
                                    throw "EAP-TTLS phase2 PAP payload was written, but no outer TLS data became available to send."
                                }

                                $clientOut = Concat-Bytes $clientOut $ttlsOut
                                if ($clientOut.Length -eq $ttlsOut.Length) {
                                    $clientOutTotal = [uint32]$ttlsOut.Length
                                    $lenFieldSent = $false
                                } elseif ($null -eq $clientOutTotal) {
                                    $clientOutTotal = [uint32]$clientOut.Length
                                }

                                $take = [Math]::Min($MaxEapTlsFragmentSize, $clientOut.Length)
                                $frag = [byte[]]::new($take)
                                [Array]::Copy($clientOut, 0, $frag, 0, $take)

                                $remain = $clientOut.Length - $take
                                $rest = [byte[]]::new($remain)
                                if ($remain -gt 0) { [Array]::Copy($clientOut, $take, $rest, 0, $remain) }
                                $clientOut = $rest

                                # TTLS phase 2 payloads are sent without L-bit/length by default.
                                $flags = 0
                                if ($clientOut.Length -gt 0) { $flags = $flags -bor 0x40 }

                                if ($DebugOutput.IsPresent) {
                                    Write-Host (" [DBG] EAP-TTLS out: send={0} remain={1} flags=0x{2}" -f $frag.Length, $clientOut.Length, ([byte]$flags).ToString("X2")) -ForegroundColor DarkGray
                                }

                                $ttlsPhase2Complete = $true
                                $nextEap = New-EapTlsResponse -Id $eapId -Flags ([byte]$flags) -TlsPayload $frag -TotalLen $null -OuterType $outerEapType
                                continue
                            }

                            if ($DebugOutput.IsPresent) {
                                Write-Host " [DBG] TTLS phase2 payload sent; replying with ACK while waiting for outer Access-Accept/Reject." -ForegroundColor DarkGray
                            }
                            $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                            continue
                        }
                        # Handshake complete - send empty ACK to finalize
                        if ($DebugOutput.IsPresent) {
                            Write-Host (" [DBG] {0} handshake complete. Sending empty ACK..." -f $outerEapName) -ForegroundColor DarkGray
                        }
                        $nextEap = New-EapTlsAckResponse -Id $eapId -OuterType $outerEapType
                        continue
                    }
                    
                    throw "TLS engine did not produce response data and handshake is still pending after 60000ms."
                }
            }
        }

        $nakTypes = if ($DesiredEapTypes -and $DesiredEapTypes.Length -gt 0) { $DesiredEapTypes } else { @([byte]$outerEapType) }
        Write-Host (" [WARN] Unsupported EAP type {0} ({1}). Sending EAP-NAK suggesting: {2}" -f $eapParsed.Type, $typeName, ($nakTypes -join ",")) -ForegroundColor Yellow
        $nextEap = New-EapNakResponse -Id $eapId -DesiredTypes $nakTypes
    }
}
catch {
    if ($EmitResultObject.IsPresent) {
        throw
    }
    if ($script:IsOrionMode) {
        echo "Statistic: 0"
        echo ("Message: {0}" -f $_.Exception.Message)
        $script:OrionExitCode = 1
        [Environment]::ExitCode = 1
    } else {
        Write-Host ""
        Write-Host " [ERROR] $_" -ForegroundColor Red
        echo "Statistic: 0"
        echo ("Message: {0}" -f $_.Exception.Message)
        exit 1
    }
}
finally {
    if ($connection) {
        try { if ($connection.Ssl) { $connection.Ssl.Close() } } catch {}
        try { if ($connection.Tcp) { $connection.Tcp.Close() } } catch {}
        try { if ($connection.Udp) { $connection.Udp.Close() } } catch {}
    }
    if ($script:DebugTranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
        $isFailureRun = ($null -eq $script:OrionExitCode) -or ([int]$script:OrionExitCode -ne 0)
        if ($isFailureRun) {
            $resultLabel = if ($null -ne $script:OrionExitCode -and [int]$script:OrionExitCode -eq 3) { "Reject" } else { "Failure" }
            $safeServer = ($Server -replace '[^A-Za-z0-9\.\-]', '_')
            # Include Port, Transport (RADSEC/RADIUS), and AuthType in the filename itself so
            # failures can be triaged/filtered from a directory listing alone, without opening
            # every file - e.g. to isolate periodic RADSEC-only failures.
            $finalLogName = "PortnoxRadiusDebug_{0}_{1}_{2}_{3}_{4}_{5}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"), $safeServer, $Port, $Transport, $AuthType, $resultLabel
            $finalLogPath = Join-Path $DebugLogDirectory $finalLogName
            try {
                Move-Item -LiteralPath $script:DebugTranscriptPath -Destination $finalLogPath -Force
            } catch {
                # Best-effort: leave the temp transcript file in place if the move fails.
            }
        } else {
            try { Remove-Item -LiteralPath $script:DebugTranscriptPath -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    if (-not $EmitResultObject.IsPresent -and -not $script:IsOrionMode) {
        Write-Host "---------------------------------------------------" -ForegroundColor Cyan
        Write-Host ""
    }
}

if (-not $EmitResultObject.IsPresent) {
    # Enforce exit code unconditionally (not just in Orion mode) so any caller can rely on
    # 0 = Access-Accept, non-zero = failure/reject.
    if ($null -eq $script:OrionExitCode) {
        $script:OrionExitCode = 1
    }
    exit ([int]$script:OrionExitCode)
}
#endregion
