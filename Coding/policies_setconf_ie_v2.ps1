# Para GIT
# Inicializando variaveis globais
$Global:checkPoliFile = "Initialized"
$Global:backupFileName = "Initialized"
$Global:newPolicyApplied = "Initialized"

# Define uma lista com as propriedades dos policies settings dos atributos de seguranca do IE sob trabalho
$policies = @(
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow drag and drop or copy and paste files"; ZName = "Internet Zone" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow loading of XAML files"; ZName = "Internet Zone" },
    @{ Name = "120b"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow only approved domains to use ActiveX controls without prompt"; ZName = "Internet Zone" },
    @{ Name = "120c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow only approved domains to use the TDC ActiveX control"; ZName = "Internet Zone" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow scripting of Internet Explorer WebBrowser controls"; ZName = "Internet Zone" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Allow scriptlets"; ZName = "Internet Zone" },
    @{ Name = "1001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Download signed ActiveX controls"; ZName = "Internet Zone" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Include local path when user is uploading files to a server"; ZName = "Internet Zone" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Java permissions"; ZName = "Internet Zone" },
    @{ Name = "1804"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Launching applications and files in an IFRAME"; ZName = "Internet Zone" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Logon options"; ZName = "Internet Zone" },
    @{ Name = "1607"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Navigate windows and frames across different domains"; ZName = "Internet Zone" },
    @{ Name = "2004"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Run .NET Framework-reliant components not signed with Authenticode"; ZName = "Internet Zone" },
    @{ Name = "2001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Run .NET Framework-reliant components signed with Authenticode"; ZName = "Internet Zone" },
    @{ Name = "1606"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Userdata persistence"; ZName = "Internet Zone" },
    @{ Name = "2101"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; LName = "Web sites in less privileged Web content zones can navigate into this zone"; ZName = "Internet Zone" },
    @{ Name = "270c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"; LName = "Don't run antimalware programs against ActiveX controls"; ZName = "Intranet Zone" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"; LName = "Java permissions"; ZName = "Intranet Zone" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"; LName = "Don't run antimalware programs against ActiveX controls"; ZName = "Local Machine Zone" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"; LName = "Java permissions"; ZName = "Local Machine Zone" },
    @{ Name = "1407"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow cut, copy or paste operations from the clipboard via script"; ZName = "Restricted Sites Zone" },
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow drag and drop or copy and paste files"; ZName = "Restricted Sites Zone" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow loading of XAML files"; ZName = "Restricted Sites Zone" },
    @{ Name = "120b"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow only approved domains to use ActiveX controls without prompt"; ZName = "Restricted Sites Zone" },
    @{ Name = "120c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow only approved domains to use the TDC ActiveX control"; ZName = "Restricted Sites Zone" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow scripting of Internet Explorer WebBrowser controls"; ZName = "Restricted Sites Zone" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Allow scriptlets"; ZName = "Restricted Sites Zone" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Include local path when users is uploading files to a server"; ZName = "Restricted Sites Zone" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; LName = "Logon options"; ZName = "Restricted Sites Zone" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; LName = "Don't run antimalware programs against ActiveX controls"; ZName = "Trusted Sites Zone" },
    @{ Name = "1201"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; LName = "Initialize and script ActiveX controls not market as safe"; ZName = "Trusted Sites Zone" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; LName = "Java permissions"; ZName = "Trusted Sites Zone" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"; LName = "Internet Explorer Processes Restrict ActiveX Install"; ZName = "Restrict ActiveX Install" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"; LName = "Internet Explorer Processes Restrict Download"; ZName = "Restrict File Download" },
    @{ Name = "Isolation64Bit"; Path = "HKCU:\Software\Microsoft\Internet Explorer\Main"; LName = "IE 64-bit Processes"; ZName = "Internet Explorer Administrative Template" }
)

# Define uma lista com os valores sugeridos pelo BitDefender GavityZone para os atributos de seguranca do IE
$NewPolicies = @(
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Allow drag and drop or copy and paste files"; ZName = "Internet Zone" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Allow loading of XAML files"; ZName = "Internet Zone" },
    @{ Name = "120b"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "0"; NameAction = "Enable Allow only approved domains to use ActiveX controls without prompt"; ZName = "Internet Zone" },
    @{ Name = "120c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "0"; NameAction = "Enable Allow only approved domains to use the TDC ActiveX control"; ZName = "Internet Zone" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Allow scripting of Internet Explorer WebBrowser controls"; ZName = "Internet Zone" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Allow scriptlets"; ZName = "Internet Zone" },
    @{ Name = "1001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Download signed ActiveX controls"; ZName = "Internet Zone" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Include local path when user is uploading files to a server"; ZName = "Internet Zone" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "0"; NameAction = "Disable Java permissions"; ZName = "Internet Zone" },
    @{ Name = "1804"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Launching applications and files in an IFRAME"; ZName = "Internet Zone" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "1"; NameAction = "Prompt for username and password for Logon options"; ZName = "Internet Zone" },
    @{ Name = "1607"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Navigate windows and frames across different domains"; ZName = "Internet Zone" },
    @{ Name = "2004"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Run .NET Framework-reliant components not signed with Authenticode"; ZName = "Internet Zone" },
    @{ Name = "2001"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Run .NET Framework-reliant components signed with Authenticode"; ZName = "Internet Zone" },
    @{ Name = "1606"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Userdata persistence"; ZName = "Internet Zone" },
    @{ Name = "2101"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"; NValue = "3"; NameAction = "Disable Web sites in less privileged Web content zones can navigate into this zone"; ZName = "Internet Zone" },
    @{ Name = "270c"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"; NValue = "3"; NameAction = "Disable Don't run antimalware programs against ActiveX controls"; ZName = "Intranet Zone" },
    @{ Name = "1c00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"; NValue = "65536"; NameAction = "High Safety for Java permissions"; ZName = "Intranet Zone" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"; NValue = "3"; NameAction = "Disable Don't run antimalware programs against ActiveX controls"; ZName = "Local Machine Zone" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"; NValue = "0"; NameAction = "Disable Java permissions"; ZName = "Local Machine Zone" },
    @{ Name = "1407"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Allow cut, copy or paste operations from the clipboard via script"; ZName = "Restricted Sites Zone" },
    @{ Name = "1802"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Allow drag and drop or copy and paste files"; ZName = "Restricted Sites Zone" },
    @{ Name = "2402"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Allow loading of XAML files"; ZName = "Restricted Sites Zone" },
    @{ Name = "120b"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "0"; NameAction = "Enable Allow only approved domains to use ActiveX controls without prompt"; ZName = "Restricted Sites Zone" },
    @{ Name = "120c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "0"; NameAction = "Enable Allow only approved domains to use the TDC ActiveX control"; ZName = "Restricted Sites Zone" },
    @{ Name = "1206"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Allow scripting of Internet Explorer WebBrowser controls"; ZName = "Restricted Sites Zone" },
    @{ Name = "1209"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Allow scriptlets"; ZName = "Restricted Sites Zone" },
    @{ Name = "160a"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "3"; NameAction = "Disable Include local path when users is uploading files to a server"; ZName = "Restricted Sites Zone" },
    @{ Name = "1a00"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"; NValue = "0"; NameAction = "Anonymous for Logon options"; ZName = "Restricted Sites Zone" },
    @{ Name = "270c"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; NValue = "3"; NameAction = "Disable Don't run antimalware programs against ActiveX controls"; ZName = "Trusted Sites Zone" },
    @{ Name = "1201"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; NValue = "3"; NameAction = "Disable Initialize and script ActiveX controls not market as safe"; ZName = "Trusted Sites Zone" },
    @{ Name = "1c00"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"; NValue = "65536"; NameAction = "High Safety for Java permissions"; ZName = "Trusted Sites Zone" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"; NValue = "1"; NameAction = "Enable Restriction for Internet Explorer Processes Restrict ActiveX Install"; ZName = "Restrict ActiveX Install" },
    @{ Name = "VSTOInstaller.exe"; Path = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"; NValue = "1"; NameAction = "Enable Restriction for Internet Explorer Processes Restrict Download"; ZName = "Restrict File Download" },
    @{ Name = "Isolation64Bit"; Path = "HKCU:\Software\Microsoft\Internet Explorer\Main"; NValue = "0"; NameAction = "Enable IE 64-bit Processes"; ZName = "Internet Explorer Administrative Template" }
)

# Step 1: Verifica o status atual de cada policy e salva os resultados em um arquivo.
function checkPolicyStatus {
    $outputFilePath = "$PSScriptRoot\IE_Original-Policy-Status_$(Get-Date -Format 'ddMMyyyy_HHmmss').txt"
    $policyStatuses = @()
    foreach ($policy in $policies) {
        $value = Get-ItemPropertyValue -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
        $status = if ($null -eq $value) { "Not Configured" } else { "Current Conf: $value" }
        $policyStatuses += "$($policy.Name): $status - From Path: $($policy.Path) - Zone: $($policy.ZName)"
    }
    $policyStatuses | Out-File -FilePath $outputFilePath
    $Global:checkPoliFile = $outputFilePath
}

# Step 2: Realiza o backup do status atual das policies settings
function backupCurrentPolicies {
    $backupFile = "$PSScriptRoot\IE_Policy-Backup_$(Get-Date -Format 'ddMMyyyy_HHmmss').txt"
    foreach ($policyVal in $policies) {
        $bkpValue = Get-ItemProperty -Path $policyVal.Path -Name $policyVal.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $policyVal.Name
        #$bkpValue = Get-ItemPropertyValue -Path $policyVal.Path -Name $policyVal.Name -ErrorAction SilentlyContinue
        #Write-Host "Conteudo da variavel bkpValue: $bkpValue"
        Add-Content -Path $backupFile -Value "$($policyVal.Path)::$($policyVal.Name)::$bkpValue"
    }
    Write-Host "Backup completado. Arquivo savo como: $backupFile"
    $Global:backupFileName = $backupFile
}

function applyNewPolicies {
    $npsAppliedFile = "$PSScriptRoot\IE_NewPoliciesSetApplied_$(Get-Date -Format 'ddMMyyyy_HHmmss').txt"
    foreach ($npolicy in $NewPolicies) {
        #Set-ItemProperty -Path $npolicy.Path -Name $npolicy.Name -Value $npolicy.NValue
        Add-Content -Path $npsAppliedFile -Value "Nova policy setting: $($npolicy.NValue) - $($npolicy.NameAction) Aplicada"
    }
    Write-Host "Novos valores de policies settings aplicados. Arquivo gerado: $npsAppliedFile"
    $Global:newPolicyApplied = $npsAppliedFile
}

function rollbackPolicies {
    $rollBackFile = $backupFileName
    if (-Not (Test-Path $rollBackFile)) {
        Write-Host "Arquivo de backup $($rollBackFile) nao encontrado."
        return
    }

    $rollbackData = Get-Content -Path $rollBackFile
    foreach ($line in $rollbackData) {
        $charArray = $line.Split("::")
        $bpathVal = $charArray[0]
        $bpolicyVal = $charArray[1]
        $bvalueVal = $charArray[2]
        #Set-ItemProperty -Path $bpathVal -Name $bpolicyVal -Value $bvalueVal
        Write-Host "Comando executado: Set-ItemProperty -Path $($bpathVal) -Name $($bpolicyVal) -Value $($bvalueVal)"
        #Write-Host "Conteudo das variaveis bpathVal: $($bpathVal) - bpolicyVal: $($bpolicyVal) - bvalueVal: $($bvalueVal)"
    }
    Write-Host "Processo de Rollback realizado - Arquivo $($rollBackFile) utilizado"
    #Write-Host "Conteudo do arquivo: $($backupFileName)"
    #$rollbackData
}

# Step 2: Exibe um menu para o usuario
function Show-Menu {
    Clear-Host
    Write-Host "Selecione uma das opcoes:"
    Write-Host "1: Exibe o conteudo do arquivo contendo o status das policies settings"
    Write-Host "2: Exibe o conteudo do arquivo contendo o backup do status atual das policies settings do IE"
    Write-Host "3: Aplica as novas policies settings para o IE"
    Write-Host "4: Realiza o rollback dos policies settings para seus valores originais"
    Write-Host "5: Finaliza a execucao do script"
    $choice = Read-Host "Entre com sua escolha (1, 2, 3, 4 ou 5) "

    switch ($choice) {
        1 {
            Clear-Host
            checkPolicyStatus
            Get-Content -Path $checkPoliFile | Write-Host
            Pause
            Show-Menu
        }
        2 {
            Clear-Host
            backupCurrentPolicies
            Get-Content -Path $backupFileName | Write-Host
            Pause
            Show-Menu
        }
        3 {
            Clear-Host
            applyNewPolicies
            Get-Content -Path $newPolicyApplied | Write-Host
            Pause
            Show-Menu
        }
        4 {
            Clear-Host
            rollbackPolicies
            #Get-Content -Path $newPolicyApplied | Write-Host
            Pause
            Show-Menu
        }
        5 {
            Clear-Host
            Write-Host "Finalizando script..."
            Exit
        }
        default {
            Write-Host "Escolha invalida. Por favor, selecione 1, 2, 3 ou 4."
            Pause
            Show-Menu
        }
    }
}

#Backup manual das policies settings atuais
#backupCurrentPolicies

#Para efeito de Debug
#Write-Host "Saida de Debug - Backup completado. Arquivo savo como: $backupFileName"

#rollbackPolicies

#Para commit

Show-Menu