<#
.DESCRIPTION
    Updates Chrome and Edge policies for Portnox certificate auto-selection.
    
    Author: Portnox
    Version: 1.0.0
#>

# Your OrgId
$CertificateIssuer = '<YOUR_ORGID>'

# Auto-selection URL patterns
$AutoSelectionPatterns = @(
    '[*.]appaccess.portnox.com'
    '[*.]pa.portnox.com'
    # Put here your custom URLs for Hosted applications
)

# Where is OrgId stored in the certificate issuer
# Possible values: O, CN (old organizations)
$CertificateIssuerField = 'O'

# Update or remove
$IsUpdate = $true

####### Internal script logic - modifies browser registry (configuration) #######
$PoliciesRegPath = 'HKLM:\SOFTWARE\Policies'

$ChromiumBrowserPaths = @(
    'Google\Chrome'
    'Microsoft\Edge'
)

function Update-CertificateAutoSelect {
    $updateGroupPolicy = $false
    
    # Currently we only support Chromium based browsers
    foreach ($policyPath in $ChromiumBrowserPaths) {
        try {
            $needUpdate = Update-ChromiumAutoSelect -PolicyPath $policyPath
            $updateGroupPolicy = $updateGroupPolicy -or $needUpdate
        } catch {
            # Continue execution for other browser
            Write-Host "Failed update for $policyPath"
        }
    }

    # Tell everyone there are some policy changes they should reflect
    if ($updateGroupPolicy) {
        Update-GroupPolicy
    }
}

function Update-ChromiumAutoSelect {
    param (
        $PolicyPath
    )

    $autoSelectPath = "$PoliciesRegPath\$PolicyPath\AutoSelectCertificateForUrls"
    if (-not (Test-Path $autoSelectPath)) {
        try {
            New-Item -Path $autoSelectPath -Force | Out-Null
        } catch {
            Write-Host "Error creating policy registry key $autoSelectPath"
            Write-Error $_
            return $false
        }
    }

    $updateGroupPolicy = $false
    foreach ($pattern in $AutoSelectionPatterns) {
        $policyJsonPattern = "{`"pattern`":`"$pattern`",`"filter`":{`"ISSUER`":{`"$CertificateIssuerField`":`"$CertificateIssuer`"}}}"
        $policyJson = if ($isUpdate) {$policyJsonPattern} else {""}
        $needUpdate = Update-ChromiumAutoSelectPolicy -PolicyPath $autoSelectPath -Pattern $pattern -PolicyJson $policyJson
        $updateGroupPolicy = $updateGroupPolicy -or $needUpdate
    }

    return $updateGroupPolicy
}

function Update-ChromiumAutoSelectPolicy {
    param (
        $PolicyPath,
        $Pattern,
        $PolicyJson
    )

    $valueNames = (Get-Item -Path $PolicyPath).GetValueNames()
    foreach ($valueName in $valueNames) {
        $policy = Get-ItemProperty -Path $PolicyPath -Name $valueName
        $policyValue = $policy.$valueName
        
        # No update necessary
        if ($isUpdate -and ($policyValue -eq $PolicyJson)) {
            return $false
        }

        # Update existing auto-select policy
        if ($policyValue.Contains($Pattern)) {
            if ($isUpdate) {
                Set-ItemProperty -Path $PolicyPath -Name $valueName -Value $PolicyJson -Type String
                Write-Host "Updated certificate auto-select policy for '$PolicyPath' and pattern '$Pattern'."
            } else {
                Remove-ItemProperty -Path $PolicyPath -Name $valueName
                Write-Host "Deleted certificate auto-select policy for '$PolicyPath' and pattern '$Pattern'."
            }
            return $true
        }
    }

    # Create new auto-select policy
    if ($isUpdate) {
        $numericKeys = $valueNames | Where-Object { $_ -as [int] } | ForEach-Object { [int]$_ }

        if ($numericKeys.Count -gt 0) {
            $max = $numericKeys | Measure-Object -Maximum
            $maxIndex = $max.Maximum
        } else {
            $maxIndex = 0
        }
        Set-ItemProperty -Path $PolicyPath -Name "$($maxIndex + 1)" -Value $PolicyJson -Type String
        Write-Host "Created certificate auto-select policy for '$PolicyPath' and pattern '$Pattern'."
        return $true
    }
    return $false
}

function Update-GroupPolicy {
    try {
        Start-Process "gpupdate" -ArgumentList "/force" -Wait -NoNewWindow
    } catch {
        Write-Host "Error updating group policy"
        Write-Error $_
    }
}

Update-CertificateAutoSelect
