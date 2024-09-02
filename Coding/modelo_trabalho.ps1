# Para Git
# Define the registry paths for the different zones
$zones = @{
    "Internet Zone" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
    "Intranet Zone" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
    "Local Machine Zone" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"
    "Restricted Sites Zone" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
    "Trusted Sites Zone" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
}

# Policies to manage
$policies = @(
    "1802", "1809", "1201", "1200", "1405", "1208", "1804", "1601", "1406", "1806", 
    "1400", "1402", "1607", "1606", "1604", "1807", "1803", "1001", "1004", "1800",
    "1802", "1809", "1601", "1401", "1200", "1405", "1208", "1606", "1607", "1604",
    "1001", "1803", "1004", "1201", "1209", "1001", "1806", "1802"
)

# Step 1: Backup current policy settings
function Backup-CurrentPolicies {
    $backupFile = "IE_Policy_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    foreach ($zone in $zones.Keys) {
        $zonePath = $zones[$zone]
        foreach ($policy in $policies) {
            $value = Get-ItemProperty -Path $zonePath -Name $policy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $policy
            Add-Content -Path $backupFile -Value "$zone - $policy: $value"
        }
    }
    Write-Host "Backup completed. File saved as $backupFile"
}

# Step 2: Display current policies
function Display-CurrentPolicies {
    foreach ($zone in $zones.Keys) {
        Write-Host "`n$zone"
        $zonePath = $zones[$zone]
        foreach ($policy in $policies) {
            $value = Get-ItemProperty -Path $zonePath -Name $policy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $policy
            Write-Host "$policy: $value"
        }
    }
}

# Step 3: Apply new policy settings
function Apply-NewPolicies {
    $newPolicies = @{
        # Add here the new policies from the New Policy Configuration section
        "Internet Zone" = @{
            "1802" = 3; "1809" = 3; "1201" = 3; "1200" = 3; "1405" = 3; "1208" = 3; 
            "1804" = 3; "1601" = 3; "1406" = 3; "1806" = 3; "1400" = 1; "1402" = 3; 
            "1607" = 3; "1606" = 3; "1604" = 3; "1807" = 3
        },
        "Intranet Zone" = @{
            "1803" = 3; "1001" = 0
        },
        "Local Machine Zone" = @{
            "1803" = 3; "1004" = 3
        },
        "Restricted Sites Zone" = @{
            "1201" = 3; "1802" = 3; "1809" = 3; "1601" = 1; "1401" = 3; "1200" = 3; 
            "1405" = 3; "1208" = 3; "1606" = 3; "1607" = 3; "1604" = 3; "1001" = 0
        },
        "Trusted Sites Zone" = @{
            "1803" = 3; "1004" = 3; "1201" = 1; "1209" = 1
        }
    }

    foreach ($zone in $newPolicies.Keys) {
        $zonePath = $zones[$zone]
        foreach ($policy in $newPolicies[$zone].Keys) {
            $value = $newPolicies[$zone][$policy]
            Set-ItemProperty -Path $zonePath -Name $policy -Value $value
        }
    }
    Write-Host "New policy settings applied."
}

# Step 4: Rollback to previous settings
function Rollback-Policies {
    $rollbackFile = Read-Host "Enter the filename of the backup to use for rollback"
    if (-Not (Test-Path $rollbackFile)) {
        Write-Host "Rollback file not found."
        return
    }

    $rollbackData = Get-Content -Path $rollbackFile
    foreach ($line in $rollbackData) {
        $lineData = $line -split " - "
        $zone = $lineData[0]
        $policyData = $lineData[1] -split ": "
        $policy = $policyData[0]
        $value = $policyData[1]

        if ($zones.ContainsKey($zone)) {
            $zonePath = $zones[$zone]
            Set-ItemProperty -Path $zonePath -Name $policy -Value $value
        }
    }
    Write-Host "Rollback completed using $rollbackFile."
}

# Main menu
function Show-Menu {
    while ($true) {
        Write-Host "`n1. Display current policy settings"
        Write-Host "2. Apply new policy settings"
        Write-Host "3. Rollback to previous settings"
        Write-Host "4. Exit"
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" { Display-CurrentPolicies }
            "2" { Apply-NewPolicies }
            "3" { Rollback-Policies }
            "4" { Exit }
            default { Write-Host "Invalid selection, please choose again." }
        }
    }
}

# Start the script
Backup-CurrentPolicies
Show-Menu