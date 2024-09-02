# Define the path where the output file will be saved
$outputFilePath = "$PSScriptRoot\IE_Original_Policy_Status_v2.txt"

# Define a list of policy names and their corresponding registry paths
$policies = @(
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "120b"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "120c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1804"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1607"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "2004"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "2001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "1606"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "2101"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" },
    @{ Name = "270c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" },
    @{ Name = "1407"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "120b"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "120c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" },
    @{ Name = "1201"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" },
    @{ Name = "Isolation64Bit"; Path = "HKCU:\Software\Microsoft\Internet Explorer\Main" }
)

# Step 1: Check the current status of each policy and save the results to a file
$policyStatuses = @()
foreach ($policy in $policies) {
    $value = Get-ItemPropertyValue -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
    $status = if ($null -eq $value) { "Not Configured" } else { "Current Conf: $value" }
    $policyStatuses += "$($policy.Name): $status - From Path: $($policy.Path)"
}
$policyStatuses | Out-File -FilePath $outputFilePath

# Step 2: Display a menu to the user
function Show-Menu {
    Clear-Host
    Write-Host "Select an option:"
    Write-Host "1: Display the content of the policy status file"
    Write-Host "2: Terminate the script"
    $choice = Read-Host "Enter your choice (1 or 2)"

    switch ($choice) {
        1 {
            Clear-Host
            Get-Content -Path $outputFilePath | Write-Host
            Pause
            Show-Menu
        }
        2 {
            Clear-Host
            Write-Host "Terminating script..."
            Exit
        }
        default {
            Write-Host "Invalid choice. Please select 1 or 2."
            Pause
            Show-Menu
        }
    }
}

Show-Menu