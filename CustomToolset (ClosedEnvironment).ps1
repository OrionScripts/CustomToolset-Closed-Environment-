##  ITMSC Toolset Version 2
##  Maintained by Ryan Amos

Param (
    [Parameter(ValueFromPipeline)]
    [switch]$NoUpdate = $true
)

##  Set the Default Service-Desk Computer Name
    $DefaultComputer = 'APGRWKECG-H0441'

##  Set the Toolset Window
    $Host.UI.RawUI.WindowTitle = 'ITMSC Toolset Version 2'
    $Host.UI.RawUI.ForegroundColor = "Gray"
    $Host.UI.RawUI.BackgroundColor = "DarkGray"
    $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(72,35)
    $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(72,800)

##  Define the Target Computer Variable
    $TargetComputer =$false

##  Define the Target User Variable
    $TargetUser = $false

##  Define the Toolset Menu Variable
    $ToolsetMenu = 'Main'

#region Toolset Functions

    Function Backup-ECBCUserProfile {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Backup User Profile' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $UserProfile = Get-ChildItem -Path "\\$ComputerName\c$\Users" -Directory -Exclude "Public","Administrator" |
                    Select-Object -Property Name | Out-GridView -Title "Select a User Account to Backup" -PassThru | Select-Object -ExpandProperty Name
                $UserProfilePath = "\\$ComputerName\c$\Users\" + $UserProfile
                $TechToolsPath = (New-Item -Path "\\filesvr\TechTools$\User_Data" -Name $UserProfile -ItemType Directory -Force).FullName
                Get-ChildItem -Path $UserProfilePath -Exclude 'AppData' |
                    Copy-Item -Destination $TechToolsPath -Recurse -Force -Verbose -ErrorAction SilentlyContinue
                Write-Host "  Copy completed- check techtools$ before continuing...`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error backing up user profile.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Backup-ECBCUserProfile

    Function Copy-ECBCCitrixShortcut {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Copy Citrix Shortcut' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path "C:\ECBCToolset\Shortcuts\Citrix - Use Email Cert for Login.lnk" -Destination "\\$TargetComputer\c$\Users\Public\Desktop\" -Force
                Write-Host "  Copy completed.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error copying citrix shortcut.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Copy-ECBCCitrixShortcut

    Function Copy-ECBCFedlogShortcut {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Copy FEDLOG Shortcut' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                if(Test-Path -Path "\\$TargetComputer\c$\Users\Public\Desktop\FEDLOG.lnk") {
                    Remove-Item -Path "\\$TargetComputer\c$\Users\Public\Desktop\FEDLOG.lnk" -Force
                }
                Copy-Item -Path "C:\ECBCToolset\Shortcuts\FEDLOG.bat" -Destination "\\$TargetComputer\c$\Temp\" -Force
                Copy-Item -Path "C:\ECBCToolset\Shortcuts\FEDLOG.lnk" -Destination "\\$TargetComputer\c$\Users\Public\Desktop\" -Force
                Write-Host "  Copy completed.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error copying fedlog shortcut.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Copy-ECBCFedlogShortcut

    Function Copy-ECBCLoginScripts {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Copy Login Scripts' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path "\\filesvr\TechTools$\ECBCToolset_Applications\LoginScripts\login.BAT" -Destination "\\$TargetComputer\c$\Temp\" -Force
                Copy-Item -Path "\\filesvr\TechTools$\ECBCToolset_Applications\LoginScripts\amsaalogon.vbs" -Destination "\\$TargetComputer\c$\Temp\" -Force
                Write-Host "  Copy completed.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error copying login scripts.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Copy-ECBCLoginScripts

    Function Copy-ECBCLoginScriptShortcut {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Copy Login Script Shortcut' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path "C:\ECBCToolset\Shortcuts\Login.lnk" -Destination "\\$TargetComputer\c$\Users\Public\Desktop\" -Force
                Write-Host "  Copy completed.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error copying login script shortcut.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Copy-ECBCLoginScriptShortcut

    Function Disable-ECBCCACEnforcement {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Remove SmartCard Enforcement' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                REG ADD \\$ComputerName\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system /v scforceoption /t REG_DWORD /d 00000000 /f
                Write-Host ""
            } Catch {
                Write-Host "  Error removing smart card enforcement.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Disable-ECBCCACEnforcement

    Function Enable-ECBCBitLocker {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if((!$ComputerName) -or ($ComputerName -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Enable BitLocker' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Num = ''
            for($i = -5; $i -le -1; ++$i) { if($ComputerName[$i] -match "\d") { $Num = [string]$Num + [string]$ComputerName[$i] } }
            $Num = [string]$Num + [string]$Num
            if($Num.Length -lt 8) {
                $Num = ''
                $Current = ([int] [char] $ComputerName[-2])-64
                if($Current -le 9) {
                    $Num = $Num + '0'
                }
                $Num = $Num + [string]$Current
                $Current = ([int] [char] $ComputerName[-1])-64
                if($Current -le 9) {
                    $Num = $Num + '0'
                }
                $Num = $Num + [string]$Current
                $Num = [string]$Num + [string]$Num
                if($Num.Length -lt 8) {
                    Write-Host "  Error getting PIN from target name. `n" -ForegroundColor Red
                }
            }
            Try {
                Write-Host "  Setting BitLocker PIN to " -NoNewline
                Write-Host "$Num `n" -ForegroundColor Green
                $SecureString = ConvertTo-SecureString $Num -AsPlainText -Force
                $Session = New-PSSession -ComputerName $ComputerName
                Invoke-Command -Session $Session -ScriptBlock {
                    $KP = (Get-BitLockerVolume -MountPoint 'C:').KeyProtector
                    ForEach($Key in $KP) { 
                        Remove-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $Key.KeyProtectorId
                    }
                    Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
                    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -TpmAndPinProtector -Pin $args[0]
                } -ArgumentList $SecureString -ErrorAction Stop
                Remove-PSSession $Session
                Write-Host "  Completed successfully.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error starting BitLocker w/ PIN.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Enable-ECBCBitLocker

    Function Enable-ECBCUSBStorage {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Enable USB Storage' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Write-Host "  ** Do not plug in USB device until after script is run.`n" -ForegroundColor Red
            Pause
            Write-Host "  Enabling USB Storage...`n"
            Try {
                Takeown /F \\$ComputerName\C$\windows\system32\drivers\USBSTOR.SYS /A
                Takeown /F \\$ComputerName\C$\windows\inf\usbstor.inf /A
                icacls \\$ComputerName\C$\windows\system32\drivers\USBSTOR.SYS /grant system:F
                icacls \\$ComputerName\C$\windows\system32\drivers\USBSTOR.SYS /grant Users:F
                icacls \\$ComputerName\C$\windows\inf\usbstor.inf /grant system:F
                icacls \\$ComputerName\C$\windows\inf\usbstor.inf /grant Users:F
                $String = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
                REG ADD \\$ComputerName\HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\$String /v Deny_Read /t REG_DWORD /d 00000000 /f
                REG ADD \\$ComputerName\HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\$String /v Deny_Write /t REG_DWORD /d 00000000 /f
                Write-Host "  Completed successfully.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error running script.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Enable-ECBCUSBStorage

    Function Get-ECBCBitLockerKey {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if((!$ComputerName) -or ($ComputerName -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'BitLocker Key' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if(Test-Path -Path "\\filesvr\eis$\system\SysAdmin\Get-BLRI\DARInfo-$ComputerName.txt") {
                $RecoveryKey = Get-Content -Path "\\filesvr\eis$\system\SysAdmin\Get-BLRI\DARInfo-$ComputerName.txt" -Tail 1
                if($RecoveryKey -match 'msFVE*') {
                    $RecoveryKey = $RecoveryKey.Split(':').Trim()[-1]
                    Write-Host "  BitLocker Recovery Key for $ComputerName `n"
                    Write-Host "  $RecoveryKey `n" -ForegroundColor White
                } else {
                    Write-Host "  Unable to Find BitLocker Recovery Information. `n"
                }
            } else {
                Write-Host "  Unable to Find BitLocker Recovery Information. `n"
            }
            Pause
        }
    }   #Get-ECBCBitLockerKey

    Function Get-ECBCBitLockerStatus {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if((!$ComputerName) -or ($ComputerName -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'BitLocker Status' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Num = ''
            for($i = -5; $i -le -1; ++$i) { if($ComputerName[$i] -match "\d") { $Num = [string]$Num + [string]$ComputerName[$i] } }
            $Num = [string]$Num + [string]$Num
            if($Num.Length -lt 8) {
                $Num = ''
                $Current = ([int] [char] $ComputerName[-2])-64
                if($Current -le 9) {
                    $Num = $Num + '0'
                }
                $Num = $Num + [string]$Current
                $Current = ([int] [char] $ComputerName[-1])-64
                if($Current -le 9) {
                    $Num = $Num + '0'
                }
                $Num = $Num + [string]$Current
                $Num = [string]$Num + [string]$Num
                if($Num.Length -lt 8) {
                    Write-Host "  Error getting PIN from target name. `n" -ForegroundColor Red
                }
            }
            Try {
                $Target = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-BitLockerVolume | Where-Object -Property MountPoint -EQ 'C:' } -ErrorAction Stop
                $BitLockerInfo = [ordered]@{
                    'PIN'           = $Num
                    'Drive'         = $Target.MountPoint
                    'Status'        = $Target.ProtectionStatus
                    '% Encrypted'   = $Target.EncryptionPercentage
                    'Capacity GB'   = $Target.CapacityGB
                    'Volume State'  = $Target.VolumeStatus
                }
                New-Object -TypeName PSObject -Property $BitLockerInfo | Write-ECBCObject
            } Catch {
                $BitLockerInfo = [ordered]@{
                    'PIN'           = $Num
                }
                New-Object -TypeName PSObject -Property $BitLockerInfo | Write-ECBCObject
                Write-Host "  Unable to Find BitLocker Information. `n"
            }
            Pause
        }
    }   #Get-ECBCBitLockerStatus

    Function Get-ECBCComputerADInformation {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if((!$ComputerName) -or ($ComputerName -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Computer AD Information' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $Computer = Get-ADComputer -Identity $ComputerName -Properties Description
            } Catch {
                $Computer = $false
            }
            if($Computer) {
                $Properties = [ordered]@{
                    'Enabled'       = $Computer.Enabled
                    'Description'   = $Computer.Description
                }
                New-Object -TypeName PSObject -Property $Properties | Write-ECBCObject
            } else {
                Write-Host "  Computer not found in AD.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Get-ECBCComputerADInformation

    Function Get-ECBCComputerInformation {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Computer Information' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if(!(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
                Write-Host "  Unable to connect to $ComputerName`n" -ForegroundColor Red
                Pause
                Return
            }
            Try {
                $Session = New-CimSession -ComputerName $ComputerName -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
            } Catch {
                Write-Host "  Unable to connect to $ComputerName`n" -ForegroundColor Red
                Pause
                Break
            }
            $TargetBIOS = Get-CimInstance -CimSession $Session -ClassName Win32_BIOS -Property SerialNumber
            $TargetCS = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystem -Property Name,Manufacturer,Model,UserName
            $TargetOS = Get-CimInstance -CimSession $Session -ClassName Win32_OperatingSystem -Property Caption,BuildNumber
            $TargetNetwork = Get-CimInstance -CimSession $Session -ClassName Win32_NetworkAdapterConfiguration | Where-Object IPAddress -NE $null
            $TargetTPM = Get-CimInstance -CimSession $Session -ClassName Win32_TPM -Namespace 'root\cimv2\security\microsofttpm' -Property SpecVersion
            $Properties = [ordered]@{
                'ComputerName'  = $TargetCS.Name
                'Current User'  = $TargetCS.UserName
                'Manufacturer'  = $TargetCS.Manufacturer
                'Model'         = $TargetCS.Model
                'Service Tag'   = $TargetBIOS.SerialNumber
                'MAC Address'   = $TargetNetwork.MACAddress
                'TPM Version'   = $TargetTPM.SpecVersion
                'OS'            = $TargetOS.Caption
                'OS Build'      = $TargetOS.BuildNumber
            }
            New-Object -TypeName PSObject -Property $Properties | Write-ECBCObject
            Pause
        }
    }   #Get-ECBCComputerInformation

    Function Get-ECBCComputerLogonInfo {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
            if(!(Test-Path -Path "\\filesvr\Machine`$\LogonInfo")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Computer LogonInfo' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $LogonInfo = Get-Content -Path "\\filesvr\Machine`$\LogonInfo\$ComputerName.txt" -Tail 10 -ErrorAction Stop
                [array]::Reverse($LogonInfo)
                foreach($Line in $LogonInfo) {
                    $Line = $Line.Split(',')
                    Write-Host "  $($Line[2]) $($Line[3]) $($Line[1]) `n"
                }
                if((Read-Host -Prompt "Press Enter to continue (or Y to open file)") -eq 'Y') {
                    & "\\filesvr\Machine$\LogonInfo\$ComputerName.txt"
                }
            } Catch {
                Write-Host "  Unable to find computer LogonInfo file.`n"
                Pause
            }
        }
    }   #Get-ECBCComputerLogonInfo

    Function Get-ECBCComputerName {
        Param (
            [Parameter(Mandatory=$true,ParameterSetName='Barcode')]
                $Barcode,
            [Parameter(Mandatory=$true,ParameterSetName='UserName')]
                $UserName
        )
        Begin {
            if(!(Test-Path -Path '\\filesvr\Machine$\LogonInfo')) {
                Return $false
            }
        }
        Process {
            Try {
                if($Barcode) {
                    Return (Get-ChildItem -Path '\\filesvr\Machine$\LogonInfo\' -Filter "*$Barcode.txt").Name.Replace('.txt','')
                } else {
                    Return (Get-Content -Path "\\filesvr\Machine$\LogonInfo\$UserName.txt" -Tail 1 -ErrorAction SilentlyContinue).Split(",")[1]
                }
            } Catch {
                Return $false
            }
        }
    }   #Get-ECBCComputerName

    Function Get-ECBCUserLoginScript {
        Param (
            [Parameter(Mandatory=$true)]
                $UserName
        )
        Begin {
            if(!$UserName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'User Login Script' -TitleColor 'White' -Value $UserName -ValueColor 'Yellow' -Bottom
            if(!(Test-Path -Path "\\filesvr\logon\USERS\$UserName.bat")) {
                Write-Host "  Unable to find user Login Script.`n" -ForegroundColor Red
                Pause
                Break
            } else {
                Get-Content -Path "\\filesvr\logon\USERS\$UserName.bat" | Where-Object { $_ } | ForEach-Object { Write-Host "  $_" }
                if((Read-Host -Prompt "`nPress Enter to continue (or Y to edit login script)") -eq 'Y') {
                    ise "\\filesvr\logon\USERS\$UserName.bat"
                }
            }
        }
    }   #Get-ECBCUserLoginScript

    Function Get-ECBCUserLogonInfo {
        Param (
            [Parameter(Mandatory=$true)]
                $UserName
        )
        Begin {
            if(!$UserName) {
                Break
            }
            if(!(Test-Path -Path "\\filesvr\Machine`$\LogonInfo")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'User LogonInfo' -TitleColor 'White' -Value $UserName -ValueColor 'Yellow' -Bottom
            Try {
                $LogonInfo = Get-Content -Path "\\filesvr\Machine`$\LogonInfo\$UserName.txt" -Tail 10 -ErrorAction Stop
                [array]::Reverse($LogonInfo)
                foreach($Line in $LogonInfo) {
                    $Line = $Line.Split(',')
                    Write-Host "  $($Line[2]) $($Line[3]) $($Line[1]) `n"
                }
                if((Read-Host -Prompt "Press Enter to continue (or Y to open file)") -eq 'Y') {
                    & "\\filesvr\Machine$\LogonInfo\$UserName.txt"
                }
            } Catch {
                Write-Host "  Unable to find user LogonInfo file.`n"
                Pause
            }
        }
    }   #Get-ECBCUserLogonInfo

    Function Get-ECBCUserName {
        Param (
            [Parameter(Mandatory=$true,ParameterSetName='Search')]
                $Search,
            [Parameter(Mandatory=$true,ParameterSetName='ComputerName')]
                $ComputerName
        )
        Begin {
            if(!(Test-Path -Path '\\filesvr\Machine$\LogonInfo')) {
                Return $false
            }
        }
        Process {
            Try {
                if($ComputerName) {
                    $User = (Get-Content -Path "\\filesvr\Machine$\LogonInfo\$ComputerName.txt" -Tail 1 -ErrorAction SilentlyContinue).Split(",")[2]
                    if($User -like "*/*") {
                        Return (Get-Content -Path "\\filesvr\Machine$\LogonInfo\$ComputerName.txt" -Tail 1 -ErrorAction SilentlyContinue).Split(",")[1]
                    } else {
                        Return $User
                    }
                } else {
                    $Results = Get-ChildItem -Path '\\filesvr\Machine$\LogonInfo' -Filter "*$Search*" |
                        Where-Object {$_.LastWriteTime -ge ((Get-Date).AddMonths(-6).ToString("g"))} |
                            Select-Object @{Name='Username';Expression={$_.Name.Replace('.txt','')}}
                }
            } Catch {
                Return $false
            }
            if($Results.Count -eq 0) {
                Return $false
            } elseif ($null -eq $Results.Count) {
                Return $Results.Username
            } else {
                $Results = $Results | Out-GridView -Title 'Select a Target User' -PassThru
                if($null -eq $Results.Count) {
                    Return $Results.Username
                } else {
                    Return $false
                }
            }
        }
    }   #Get-ECBCUserName

    Function Install-ECBCAdobeAcrobatPro {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe Acrobat Pro DC' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Write-Host "  Please close the following applications:`n" -ForegroundColor Red
                Write-Host "    - Adobe Acrobat Reader/Pro" -ForegroundColor Red
                Write-Host "    - Internet Explorer " -ForegroundColor Red
                Write-Host "    - MS Office Applications `n" -ForegroundColor Red
                Pause
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Acrobat DC\Setup.exe"
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Acrobat DC Software\Adobe Acrobat DC Serialization\AdobeSerialization.exe"
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName msiexec.exe /p "\\apgrb7ecgsccmss\SOURCE$\Adobe Acrobat DC Software\Acrobat 1901020098\AcrobatDCUpd1901020098.msp" /qn /norestart
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeAcrobatPro

    Function Install-ECBCAdobeAcrobatReader {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe Reader DC' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Reader DC\SYSMAN_AREADER_DC.exe"
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName msiexec.exe /p "\\apgrb7ecgsccmss\SOURCE$\Adobe Reader DC Software\Reader 1901020098\AcroRdrDCUpd1901020098.msp" /qn /norestart
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeAcrobatReader

    Function Install-ECBCAdobeCCDesignTools {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe CC Design Tools' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if((Read-Host "  Did you verify license tracker for customer? (Y to cont.)") -ne "Y") {
                Break
            }
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Cloud\Adobe-Design-Tools-CCv6-Jan-2019-Win-64\Adobe-Design-Tools-CCv6-Jan-2019-Win-64\Build\setup.exe" --silent
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeCCDesignTools

    Function Install-ECBCAdobeCCImagingTools {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe CC Imaging Tools' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if((Read-Host "  Did you verify license tracker for customer? (Y to cont.)") -ne "Y") {
                Break
            }
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Cloud\Adobe-Imaging-Tools-CCv6-Jan-2019-Win-64\Build\setup.exe" --silent
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeCCImagingTools

    Function Install-ECBCAdobeCCWebTools {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe CC Web Tools' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if((Read-Host "  Did you verify license tracker for customer? (Y to cont.)") -ne "Y") {
                Break
            }
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Cloud\Adobe-Web-Tools-CCv6-Jan-2019-Win-64\Build\setup.exe" --silent
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeCCWebTools

    Function Install-ECBCAdobeCCVideoTools {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Adobe CC Video Tools' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if((Read-Host "  Did you verify license tracker for customer? (Y to cont.)") -ne "Y") {
                Break
            }
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Adobe Cloud\Adobe-CCv6-Video-Tools-2018-Oct-64\Build\setup.exe" --silent
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCAdobeCCVideoTools

    Function Install-ECBCCiscoAnyConnect {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Cisco AnyConnect' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            if(((Test-Connection -ComputerName $ComputerName -Count 1).IPV4Address -match "^131.92.4.\d") -or ($ComputerName -match "^131.92.4.\d")) {
                Write-Host "  Cannot Install Cisco AnyConnect while connected via VPN.`n" -ForegroundColor Red
                Pause
                Break
            }
            Try {
                New-Item -Path "\\$ComputerName\c$\ProgramData" -Name "Cisco\Cisco AnyConnect Secure Mobility Client\Profile" -ItemType Directory -Force | Out-Null
                Copy-Item -Path "\\apgrb7ecgsccmss\SOURCE$\CiscoAnyConnect\CiscoAnyConnect4.6.01098\ECBC_client_profile.xml" -Destination "\\$ComputerName\c$\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\" -Force
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName msiexec.exe /q /i "\\apgrb7ecgsccmss\SOURCE$\CiscoAnyConnect\CiscoAnyConnect4.6.01098\anyconnect-win-4.6.01098-core-vpn-predeploy-k9.msi"
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName msiexec.exe /q /i "\\apgrb7ecgsccmss\SOURCE$\CiscoAnyConnect\CiscoAnyConnect4.6.01098\anyconnect-win-4.6.01098-gina-predeploy-k9.msi" /norestart
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCCiscoAnyConnect

    Function Install-ECBCDameware {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Dameware' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path '\\filesvr\TechTools$\ECBCToolset_Applications\Dameware\DameWareMRC64.exe' -Destination "\\$ComputerName\c$\Temp" -Force
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "C:\Temp\DameWareMRC64.exe" /args "/qn SILENT=yes INSTALLSTANDALONE=0 CENTRALSERVERHOSTNAME=apgrc2ecg-swwhd"
                Remove-Item -Path "\\$ComputerName\c$\Temp\DameWareMRC64.exe" -Force
                Write-Host "  Installation completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCDameware

    Function Install-ECBCGoogleChrome {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Google Chrome' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Google Chrome\Chrome 72.0.3626.119\SYSMAN_GCHROME_72_0_3626_119_files\SYSMAN_GCHROME_72_0_3626_119_app_files\Content_a6928163-f822-4d82-9b15-dd7955073e1a\SYSMAN_GCHROME_72_0_3626_119.exe"
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCGoogleChrome

    Function Install-ECBCHPRM {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'HPRM' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\HPRM\HP Records Management 9.2\64BitInstalls\Setup_HPE_CM_x64.exe" /silent WGS1="ARLAA051004860K.arl.army.mil" DEFAULTDBNAME="ECBC HP RM" PORTNO="1137"
                Copy-Item -Path "\\filesvr\public\HPE-CM Addins\Hewlett-Packard" -Destination "\\$ComputerName\c$\Program Files (x86)\" -Recurse -Force
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Write-Host "  Server: ARLAA051004860K.arl.army.mil`n" -ForegroundColor Yellow
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCHPRM

    Function Install-ECBCJava {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Java' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Java\Java 8 Update 202\Java8Update202PSTools.bat"
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCJava

    Function Install-ECBCMSProjectStandard {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Microsoft Project Standard 2016' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Microsoft\MS Project Standard 2016\setup.exe" /adminfile "\\apgrb7ecgsccmss\SOURCE$\Microsoft\MS Project Standard 2016\Project.MSP"
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCMSProjectStandard

    Function Install-ECBCMSVisioStandard {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Microsoft Visio Standard 2013' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Microsoft\MS Visio Standard 2013\setup.exe" /adminfile "\\apgrb7ecgsccmss\SOURCE$\Microsoft\MS Visio Standard 2013\visio.MSP"
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCMSVisioStandard

    Function Install-ECBCMozillaFirefox {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Mozilla Firefox' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\Mozilla Firefox\Mozilla Firefox 65.0.2 32bit\Firefox_Setup.exe" /S /MaintenanceService=false
                Copy-Item -Path "\\apgrb7ecgsccmss\SOURCE$\Mozilla Firefox\Mozilla Firefox 65.0.2 32bit\mozilla.cfg" -Destination "\\$ComputerName\c$\Program Files (x86)\Mozilla Firefox\" -Force
                Copy-Item -Path "\\apgrb7ecgsccmss\SOURCE$\Mozilla Firefox\Mozilla Firefox 65.0.2 32bit\override.ini" -Destination "\\$ComputerName\c$\Program Files (x86)\Mozilla Firefox\" -Force
                Copy-Item -Path "\\apgrb7ecgsccmss\SOURCE$\Mozilla Firefox\Mozilla Firefox 65.0.2 32bit\local-settings.js" -Destination "\\$ComputerName\c$\Program Files (x86)\Mozilla Firefox\defaults\pref\" -Force
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCMozillaFirefox

    Function Install-ECBCToolset {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'ECBC Toolset' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path "\\filesvr\TechTools$\ECBCToolset" -Destination "\\$ComputerName\c$\" -Recurse -Force
                Invoke-Command -ComputerName $ComputerName -ScriptBlock { Set-ExecutionPolicy RemoteSigned }
                Copy-Item -Path "\\filesvr\TechTools$\ECBCToolset\ECBC Toolset.lnk" -Destination "\\$ComputerName\c$\Users\Public\Desktop" -Force
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCToolset

    Function Install-ECBCVLC {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'VLC' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "\\apgrb7ecgsccmss\SOURCE$\VLC\vlc-3.0.6-win32.exe" /L=1033 /S
                Write-Host "  Install completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during installation.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Install-ECBCVLC

    Function Move-ECBCADComputerSA {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if((!$ComputerName) -or ($ComputerName -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$")) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Move to Serv Acct OU' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $Computer = Get-ADComputer $ComputerName
                $DN = $Computer.DistinguishedName.Split(",")
                $DN[0] = 'OU=Service Accounts'
                $DN = $DN -join ','
                $Computer | Move-ADObject -TargetPath $DN
                Write-Host "  Computer object moved to SA OU. `n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error moving object to SA OU... `n" -ForegroundColor Red
            }
            Pause
        }
    }   #Move-ECBCADComputerSA

    Function Remove-ECBCBuildFromStartup {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Remove Build' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                REG DELETE \\$ComputerName\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Build /f
                Pause
            } Catch {
                Write-Host "  Error during removal.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Remove-ECBCBuildFromStartup

    Function Remove-ECBCMcAfeeDLP {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Remove McAfee DLP' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Copy-Item -Path '\\filesvr\TechTools$\ECBCToolset_Applications\McafeeEndpointRemoval\McAfeeEndpointProductRemoval_2.3.1.37.exe' -Destination "\\$ComputerName\c$\Temp" -Force
                C:\ECBCToolset\PsExec.exe -s \\$ComputerName "C:\Temp\McAfeeEndpointProductRemoval_2.3.1.37.exe" --accepteula --DLP --noreboot
                Remove-Item -Path "\\$ComputerName\c$\Temp\McAfeeEndpointProductRemoval_2.3.1.37.exe" -Force
                Write-Host "  McAfee DLP Removal Completed.`n" -ForegroundColor Green
                Pause
            } Catch {
                Write-Host "  Error during removal.`n" -ForegroundColor Red
                Pause
            }
        }
    }   #Remove-ECBCMcAfeeDLP

    Function Restart-ECBCComputer {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Restart Computer' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                Restart-Computer -ComputerName $ComputerName -Force
            } Catch {
                Write-Host "  Error restarting computer.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Restart-ECBCComputer

    Function Send-ECBCFileTransfer {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName,
            [Parameter(Mandatory=$false)]
                $FilePath = $false
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
            if(!$FilePath) {
                Try {
                    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                    $OpenFileDialog.initialDirectory = C:
                    $OpenFileDialog.filter = "All files (*.*)| *.*"
                    $OpenFileDialog.ShowDialog() | Out-Null
                    $FilePath = $OpenFileDialog.filename
                } Catch {
                    Break
                }
            }
            Try {
                Test-Path -Path $FilePath -ErrorAction Stop
            } Catch {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'File Transfer' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $FolderName = "Transfer_" + (Get-Date -Format "MM-dd-yyyy")
                New-Item -Path "\\$ComputerName\c$\Temp" -Name $FolderName -ItemType Directory -Force | Out-Null
                Copy-Item -Path $FilePath -Destination "\\$ComputerName\c$\Temp\$FolderName" -Force
                Write-Host "  File transfer successful.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error transferring file.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Send-ECBCFileTransfer

    Function Send-ECBCFolderTransfer {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName,
            [Parameter(Mandatory=$false)]
                $FilePath = $false
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
            if(!$FilePath) {
                Try {
                    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                    $FolderName = New-Object System.Windows.Forms.FolderBrowserDialog
                    $FolderName.Description = "Select a Folder"
                    $FolderName.rootfolder = "MyComputer"
                    if($FolderName.ShowDialog() -eq "OK")
                    {
                        $FilePath = $FolderName.SelectedPath
                    } else {
                        Break
                    }
                } Catch {
                    Break
                }
            }
            Try {
                Test-Path -Path $FilePath -ErrorAction Stop
            } Catch {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Folder Transfer' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $FolderName = "Transfer_" + (Get-Date -Format "MM-dd-yyyy")
                New-Item -Path "\\$ComputerName\c$\Temp" -Name $FolderName -ItemType Directory -Force | Out-Null
                Copy-Item -Path $FilePath -Destination "\\$ComputerName\c$\Temp\$FolderName" -Recurse -Force
                Write-Host "  Folder transfer successful.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error transferring folder.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Send-ECBCFolderTransfer

    Function Send-ISVMFileTransfer {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName,
            [Parameter(Mandatory=$false)]
                $FilePath = $false
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
            if(!$FilePath) {
                Try {
                    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                    Write-Host "  `nChoose a file; this tool will clone it to the target." -ForegroundColor Cyan
                    Write-Host "If the parent directory doesn't exist, it will also be created.`n" -ForegroundColor Cyan
                    Pause
                    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                    $OpenFileDialog.initialDirectory = C:
                    $OpenFileDialog.filter = "All files (*.*)| *.*"
                    $OpenFileDialog.ShowDialog() | Out-Null
                    $FilePath = $OpenFileDialog.filename
                    $AdjustedFilePath = $FilePath.Replace('C:\','')
                    $SplitPath = Split-Path -Path "\\$ComputerName\c$\$AdjustedFilePath"
                } Catch {
                    Break
                }
            }
            Try {
                Test-Path -Path $FilePath -ErrorAction Stop
            } Catch {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Clone File to Target' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                New-Item -Path "$SplitPath" -ItemType Directory -Force | Out-Null
                Copy-Item -Path $FilePath -Destination "$SplitPath" -Recurse -Force
                Write-Host "  File clone successful to $SplitPath.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error cloning file. Attempted path is $SplitPath.`n" -ForegroundColor Yellow
            }
            Pause
        }
    }   #Send-ISVMFileTransfer

    Function CheckInstalled {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
              )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Check Installed Programs' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $TargetProgramInquiryDIR = "C:\Admin\ProgramInquiry"
            if (-Not (Test-Path -Path $TargetProgramInquiryDIR)) {
                    New-Item -ItemType Directory -Path $TargetProgramInquiryDIR
                }
            Try {
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
                } | Out-File -FilePath \\localhost\c$\Admin\ProgramInquiry\InstalledPrograms-$ComputerName.txt
                Write-Host "  File saved.`n  C:\Admin\ProgramInquiry\InstalledPrograms-$ComputerName.txt`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error writing file.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #CheckInstalled

    Function GetServices {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
              )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Get Services and Status Thereof' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $TargetServicesInquiryDIR = "C:\Admin\ServicesInquiry"
            if (-Not (Test-Path -Path $TargetServicesInquiryDIR)) {
                    New-Item -ItemType Directory -Path $TargetServicesInquiryDIR
                }
            Try {
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-Service | select DisplayName, Status | Format-Table -AutoSize
                } | Out-File -FilePath \\localhost\c$\Admin\ServicesInquiry\Services-$ComputerName.txt
                Write-Host "  File saved.`n  C:\Admin\ServicesInquiry\Services-$ComputerName.txt`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Error writing file.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #GetServices    

    Function Start-ADMServerBurnerSvcMulti {
        Param (
                [Parameter(Mandatory=$false)]
                $FilePath = $false
        )
        Begin {
            if(!$FilePath) {
                Try {
                    Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
                    Pause
                    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                    $OpenFileDialog.initialDirectory = "C:\"
                    $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
                    $OpenFileDialog.ShowDialog() | Out-Null
                    $FilePath = $OpenFileDialog.filename
                } Catch {
                    Break
                }
            }
            Try {
                Test-Path -Path $FilePath -ErrorAction Stop
            } Catch {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start Backburner Server Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
            $Servers =  Get-Content $FilePath                  
            foreach ($Computer in $Servers)
                {
                    Clear-Host
                    Write-ECBCHeader -Title 'Start Backburner Server Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
                    $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='BACKBURNER_SRV_200'"
                    if($Service.StartService()) {
                        Write-Host "  $Computer - Service started successfully.`n" -ForegroundColor Green
                    } else {
                        Write-Host "  $Computer - Error starting service.`n" -ForegroundColor Red
                    }
                Pause
                }
   }
   }   #Start-ADMServerBurnerSvcMulti

   Function Stop-ADMServerBurnerSvcMulti {
    Param (
            [Parameter(Mandatory=$false)]
            $FilePath = $false
    )
    Begin {
        if(!$FilePath) {
            Try {
                Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
                Pause
                [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFileDialog.initialDirectory = "C:\"
                $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
                $OpenFileDialog.ShowDialog() | Out-Null
                $FilePath = $OpenFileDialog.filename
            } Catch {
                Break
            }
        }
        Try {
            Test-Path -Path $FilePath -ErrorAction Stop
        } Catch {
            Break
        }
    }
    Process {
        Clear-Host
        Write-ECBCHeader -Title 'Stop Backburner Server Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
        $Servers =  Get-Content $FilePath                  
        foreach ($Computer in $Servers)
            {
                Clear-Host
                Write-ECBCHeader -Title 'Stop Backburner Server Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
                $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='BACKBURNER_SRV_200'"
                if($Service.StopService()) {
                    Write-Host "  $Computer - Service stopped successfully.`n" -ForegroundColor Green
                } else {
                    Write-Host "  $Computer - Error stopping service.`n" -ForegroundColor Red
                }
            Pause
            }
}
}   #Stop-ADMServerBurnerSvcMulti

Function Start-VRaySpawnerSvcMulti {
    Param (
            [Parameter(Mandatory=$false)]
            $FilePath = $false
    )
    Begin {
        if(!$FilePath) {
            Try {
                Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
                Pause
                [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFileDialog.initialDirectory = "C:\"
                $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
                $OpenFileDialog.ShowDialog() | Out-Null
                $FilePath = $OpenFileDialog.filename
            } Catch {
                Break
            }
        }
        Try {
            Test-Path -Path $FilePath -ErrorAction Stop
        } Catch {
            Break
        }
    }
    Process {
        Clear-Host
        Write-ECBCHeader -Title 'Start VRay Spawner Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
        $Servers =  Get-Content $FilePath                  
        foreach ($Computer in $Servers)
            {
                Clear-Host
                Write-ECBCHeader -Title 'Start VRay Spawner Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
                $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='VRaySpawner 2018'"
                if($Service.StartService()) {
                    Write-Host "  $Computer - Service started successfully.`n" -ForegroundColor Green
                } else {
                    Write-Host "  $Computer - Error starting service.`n" -ForegroundColor Red
                }
            Pause
            }
}
}   #Start-VRaySpawnerSvcMulti

Function Stop-VRaySpawnerSvcMulti {
Param (
        [Parameter(Mandatory=$false)]
        $FilePath = $false
)
Begin {
    if(!$FilePath) {
        Try {
            Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
            Pause
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "C:\"
            $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
            $OpenFileDialog.ShowDialog() | Out-Null
            $FilePath = $OpenFileDialog.filename
        } Catch {
            Break
        }
    }
    Try {
        Test-Path -Path $FilePath -ErrorAction Stop
    } Catch {
        Break
    }
}
Process {
    Clear-Host
    Write-ECBCHeader -Title 'Stop VRay Spawner Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
    $Servers =  Get-Content $FilePath                  
    foreach ($Computer in $Servers)
        {
            Clear-Host
            Write-ECBCHeader -Title 'Stop VRay Spawner Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='VRaySpawner 2018'"
            if($Service.StopService()) {
                Write-Host "  $Computer - Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  $Computer - Error stopping service.`n" -ForegroundColor Red
            }
        Pause
        }
}
}   #Stop-VRaySpawnerSvcMulti

Function Start-VRayGPUSpawnerSvcMulti {
    Param (
            [Parameter(Mandatory=$false)]
            $FilePath = $false
    )
    Begin {
        if(!$FilePath) {
            Try {
                Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
                Pause
                [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFileDialog.initialDirectory = "C:\"
                $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
                $OpenFileDialog.ShowDialog() | Out-Null
                $FilePath = $OpenFileDialog.filename
            } Catch {
                Break
            }
        }
        Try {
            Test-Path -Path $FilePath -ErrorAction Stop
        } Catch {
            Break
        }
    }
    Process {
        Clear-Host
        Write-ECBCHeader -Title 'Start VRay GPU Spawner Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
        $Servers =  Get-Content $FilePath                  
        foreach ($Computer in $Servers)
            {
                Clear-Host
                Write-ECBCHeader -Title 'Start VRay GPU Spawner Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
                $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='VRayStdSpawner'"
                if($Service.StartService()) {
                    Write-Host "  $Computer - Service started successfully.`n" -ForegroundColor Green
                } else {
                    Write-Host "  $Computer - Error starting service.`n" -ForegroundColor Red
                }
            Pause
            }
}
}   #Start-VRayGPUSpawnerSvcMulti

Function Stop-VRayGPUSpawnerSvcMulti {
Param (
        [Parameter(Mandatory=$false)]
        $FilePath = $false
)
Begin {
    if(!$FilePath) {
        Try {
            Write-Host "Select .txt file with server list in the ensuing dialog window.`n" -ForegroundColor Yellow
            Pause
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = "C:\"
            $OpenFileDialog.filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
            $OpenFileDialog.ShowDialog() | Out-Null
            $FilePath = $OpenFileDialog.filename
        } Catch {
            Break
        }
    }
    Try {
        Test-Path -Path $FilePath -ErrorAction Stop
    } Catch {
        Break
    }
}
Process {
    Clear-Host
    Write-ECBCHeader -Title 'Stop VRay GPU Spawner Service' -TitleColor 'White' -Value Multi -ValueColor 'Yellow' -Bottom
    $Servers =  Get-Content $FilePath                  
    foreach ($Computer in $Servers)
        {
            Clear-Host
            Write-ECBCHeader -Title 'Stop VRay GPU Spawner Service' -TitleColor 'White' -Value Multiple -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter "Name='VRayStdSpawner'"
            if($Service.StopService()) {
                Write-Host "  $Computer - Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  $Computer - Error stopping service.`n" -ForegroundColor Red
            }
        Pause
        }
}
}   #Stop-VRayGPUSpawnerSvcMulti

    Function Start-ADMBurnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start Backburner Manager Service: Input Credentials...' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Credential = Get-Credential NAE\svc.eaadmburner.apgr
            $Service = Get-WmiObject -Class Win32_Service -Credential $Cred -ComputerName $ComputerName -Filter "Name='BACKBURNER_MGR_200'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-ADMBurnerSvc

    Function Start-ADMBurnerSvc_NOCRED {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start Backburner Manager Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='BACKBURNER_MGR_200'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-ADMBurnerSvc_NOCRED

    Function Stop-ADMBurnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Stop Backburner Manager Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='BACKBURNER_MGR_200'"
            if($Service.StopService()) {
                Write-Host "  Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error stopping service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Stop-ADMBurnerSvc

    Function Start-ADMServerBurnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start Backburner Server Service: Input Credentials...' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Credential = Get-Credential NAE\svc.eaadmburner.apgr
            $Service = Get-WmiObject -Class Win32_Service -Credential $Cred -ComputerName $ComputerName -Filter "Name='BACKBURNER_SRV_200'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-ADMServerBurnerSvc

    Function Start-ADMServerBurnerSvc_NOCRED {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start Backburner Server Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='BACKBURNER_SRV_200'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-ADMServerBurnerSvc_NOCRED

    Function Stop-ADMServerBurnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Stop Backburner Server Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='BACKBURNER_SRV_200'"
            if($Service.StopService()) {
                Write-Host "  Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error stopping service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Stop-ADMServerBurnerSvc

    Function Start-VRaySpawnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start VRay Spawner Service: Input Credentials...' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Credential = Get-Credential NAE\svc.eaadmburner.apgr
            $Service = Get-WmiObject -Class Win32_Service -Credential $Cred -ComputerName $ComputerName -Filter "Name='VRaySpawner 2018'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-VRaySpawnerSvc

    Function Start-VRaySpawnerSvc_NOCRED {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start VRay Spawner Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='VRaySpawner 2018'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-VRaySpawnerSvc_NOCRED

    Function Stop-VRaySpawnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Stop VRay Spawner Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='VRaySpawner 2018'"
            if($Service.StopService()) {
                Write-Host "  Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error stopping service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Stop-VRaySpawnerSvc

    Function Start-VRayGPUSpawnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start VRay GPU Spawner Service: Input Credentials...' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Credential = Get-Credential NAE\svc.eaadmburner.apgr
            $Service = Get-WmiObject -Class Win32_Service -Credential $Cred -ComputerName $ComputerName -Filter "Name='VRayStdSpawner'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-VRayGPUSpawnerSvc

    Function Start-VRayGPUSpawnerSvc_NOCRED {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Start VRay GPU Spawner Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='VRayStdSpawner'"
            if($Service.StartService()) {
                Write-Host "  Service started successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error starting service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Start-VRayGPUSpawnerSvc_NOCRED

    Function Stop-VRayGPUSpawnerSvc {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Stop VRay GPU Spawner Service' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            $Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='VRayStdSpawner'"
            if($Service.StopService()) {
                Write-Host "  Service stopped successfully.`n" -ForegroundColor Green
            } else {
                Write-Host "  Error stopping service.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Stop-VRayGPUSpawnerSvc

    Function Start-AMSAASoftware {
        Start "\\filesvr\mission$\Desktop\TechTools\PSTools\ETECH AMSAA Software installs.bat"
    }   #Start-AMSAASoftware

    Function Start-ECBCDamewareTarget {
        Param(
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            if(Test-Path -Path 'C:\Program Files (x86)\SolarWinds\DameWare Remote Support\DWRCC.exe') {
                Start-Process 'C:\Program Files (x86)\SolarWinds\DameWare Remote Support\DWRCC.exe' -ArgumentList " -c: -h: -m:$ComputerName -a:1"
            }elseif(Test-Path -Path 'C:\Program Files\SolarWinds\DameWare Mini Remote Control x64\DWRCC.exe') {
                Start-Process 'C:\Program Files\SolarWinds\DameWare Mini Remote Control x64\DWRCC.exe' -ArgumentList " -c: -h: -m:$ComputerName -a:1"
            }elseif(Test-Path -Path 'C:\Program Files (x86)\SolarWinds\DameWare Mini Remote Control x64\DWRCC.exe') {
                Start-Process 'C:\Program Files (x86)\SolarWinds\DameWare Mini Remote Control x64\DWRCC.exe' -ArgumentList " -c: -h: -m:$ComputerName -a:1"
            }
        }
    }   #Start-ECBCDamewareTarget

    Function Start-ECBCDefaultMMC {
        & "C:\ECBCToolset\Default-ECBC.msc"
    }   #Start-ECBCDefaultMMC

    Function Start-ECBCNotepad {
        notepad
    }   #Start-ECBCNotepad

    Function Start-ECBCToolset {
        & "C:\ECBCToolset\ECBC Toolset.lnk"
    }   #Start-ECBCToolset

    Function Stop-ECBCProcess {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Clear-Host
            Write-ECBCHeader -Title 'Stop Process' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
            Try {
                $Process = (Get-Process -ComputerName $TargetComputer -ErrorAction Stop | Select-Object -Unique | Out-GridView -Title "Select a Process" -PassThru).Name
                if(!$Process) {
                    Break
                }
                Invoke-Command -ComputerName $TargetComputer -ScriptBlock {
                    Stop-Process -Name $Using:Process -Force -ErrorAction Stop
                }
                Write-Host "  Process stopped.`n" -ForegroundColor Green
            } Catch {
                Write-Host "  Unable to stop process on remote PC.`n" -ForegroundColor Red
            }
            Pause
        }
    }   #Stop-ECBCProcess

    Function Test-ECBCComputerConnection {
        Param (
            [Parameter(Mandatory=$true)]
                $ComputerName
        )
        Begin {
            if(!$ComputerName) {
                Break
            }
        }
        Process {
            Try {
                Clear-Host
                Write-ECBCHeader -Title 'Ping Target' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow' -Bottom
                Test-Connection $ComputerName -Count 1 -ErrorAction Stop | Select-Object Address,IPV4Address,ResponseTime | Write-ECBCObject
                Pause
            } Catch {
                Clear-Host
                Write-ECBCHeader -Title 'Ping Target' -TitleColor 'White' -Value $ComputerName -ValueColor 'Yellow'
                Write-Host "`n  Unable to connect to $ComputerName `n" -ForegroundColor Red
                Pause
            }
        }
    }   #Test-ECBCComputerConnection

    Function Update-ECBCToolset {
        Begin {
            if(!(Test-Path -Path '\\filesvr\TechTools$\ECBCToolset')) {
                Break
            }
        }
        Process {
            $LocalVersion = (Get-FileHash -Path 'C:\ECBCToolset\ECBCToolset.ps1' -Algorithm SHA256).Hash
            $TechToolsVersion = (Get-FileHash -Path '\\filesvr\TechTools$\ECBCToolset\ECBCToolset.ps1' -Algorithm SHA256).Hash
            if($LocalVersion -ne $TechToolsVersion) {
                Copy-Item -Path '\\filesvr\TechTools$\ECBCToolset' -Destination 'C:\' -Recurse -Force
                & 'C:\ECBCToolset\ECBC Toolset.lnk'
                Start-Sleep -Seconds 1
                Exit
            }
        }
    }   #Update-ECBCToolset

    Function Write-ECBCHeader {
        Param (
            [Parameter(Mandatory=$true)]
                $Title,
            [Parameter(Mandatory=$false)]
                $TitleColor,
                $Value = $false,
                $ValueColor,
                [switch]$Top,
                [switch]$Bottom
        )
        Begin {
            if($Value) {
                $Title = " $Title"
                $Value = "$Value "
                $Spaces = 70 - ($Title.Length) - ($Value.Length)
                for($i = 1; $i -le $Spaces; ++$i) { $Title = "$Title " }
            } else {
                $Value = ''
                $Spaces = [int](70 - ($Title.Length))/2
                for($i = 1; $i -le $Spaces; ++$i) { $Title = " $Title " }
            }
        }
        Process {
            if($Top) {
                Write-Host ""
            }
            Write-Host "╔══════════════════════════════════════════════════════════════════════╗"
            Write-Host "║" -NoNewline
            if($TitleColor) {
                Write-Host -Object $Title -NoNewline -ForegroundColor $TitleColor -BackgroundColor DarkBlue
            } else {
                Write-Host -Object $Title -NoNewline -BackgroundColor DarkBlue
            }
            if($ValueColor) {
                Write-Host -Object $Value -NoNewline -ForegroundColor $ValueColor -BackgroundColor DarkBlue
            } else {
                Write-Host -Object $Value -NoNewline -BackgroundColor DarkBlue
            }
            Write-Host "║"
            Write-Host "╚══════════════════════════════════════════════════════════════════════╝"
            if($Bottom) {
                Write-Host ""
            }
        }
    }   #Write-ECBCHeader

    Function Write-ECBCObject {
        Param (
            [Parameter(Mandatory=$true,ValueFromPipeline)]
                $Object
        )
        Process {
            $Object.PSObject.Properties | ForEach-Object {
                $Name = $_.Name
                for($i = ($Name.Length + 2); $i -le 17; $i++) { $Name = $Name + ' ' }
                Write-Host "  $Name" -NoNewline
                Write-Host "$($_.Value)`n" -ForegroundColor White
            }
        }
    }   #Write-ECBCObject

#endregion

##  Check for Toolset Updates
    if(!$NoUpdate) {    
        Update-ECBCToolset
    }

Do {

    Clear-Host
    Switch($ToolsetMenu) {
        'ADM' {
            Write-ECBCHeader -Title 'ADM Menu' -TitleColor 'White' -Bottom
            Write-Host "  0.  << Back to Main Menu "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  401. Start Backburner Manager Service"
            Write-Host "  402. Start Backburner Server Service"
            Write-Host "  403. Start VRay Spawner Service"
            Write-Host "  404. Start VRay GPU Spawner Service"
            Write-Host "  501. Start Backburner Manager Service - Use Credentials"
            Write-Host "  502. Start Backburner Server Service - Use Credentials"
            Write-Host "  503. Start VRay Spawner Service - Use Credentials"
            Write-Host "  504. Start VRay GPU Spawner Service - Use Credentials"
            Write-Host "  601. Stop Backburner Manager Service"
            Write-Host "  602. Stop Backburner Server Service"
            Write-Host "  603. Stop VRay Spawner Service"
            Write-Host "  604. Stop VRay GPU Spawner Service"
            Write-Host "  605. Servers - Start Backburner Server Service"
            Write-Host "  606. Servers - Stop Backburner Server Service"
            Write-Host "  607. Servers - Start VRay Spawner Service"
            Write-Host "  608. Servers - Stop VRay Spawner Service"
            Write-Host "  609. Servers - Start VRay GPU Spawner Service"
            Write-Host "  610. Servers - Stop VRay GPU Spawner Service"
            Write-Host "  700. Copy File to Target Location"
            Write-Host "  800. Check Installed Programs"
            Write-Host "  801. Get Services"
        }   #ADM
        'BackupRestore' {
            Write-ECBCHeader -Title 'Backup and Restore Menu ' -TitleColor 'White' -Bottom
            Write-Host "  0.  << Back to Main Menu "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  71. Backup User Profile "
            Break
        }   #BackupRestore
        'BitLocker' {
            Write-ECBCHeader -Title 'BitLocker Menu' -TitleColor 'White' -Bottom
            Write-Host "  0.  << Back to Main Menu "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  91. Check Status                   92. Enable BitLocker "
            Write-Host "  93. Recovery Key "
            Break
        }   #BitLocker
        'Shortcuts' {
            Write-ECBCHeader -Title 'Shortcuts Menu' -TitleColor 'White' -Bottom
            Write-Host "  0.  << Back to Main Menu "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  140. Login Script Shortcut         141. Citrix Shortcut "
            Write-Host "  142. FEDLOG Application "
            Write-ECBCHeader -Title 'Copy to Clipboard ' -TitleColor 'White' -Top -Bottom
            Write-Host "  146. Cert Recovery 1               147. Cert Recovery 2 "
            Write-Host "  148. Cert Recovery 3               149. Cert Recovery 4 "
            Write-Host "  150. Cert Recovery 5               151. Cyber Awareness "
            Write-Host "  152. Mobile Device Tracker "
            Break
        }   #BitLocker
        'Software' {
            Write-ECBCHeader -Title 'Software Install Menu ' -TitleColor 'White' -Bottom
            Write-Host "  0.  << Back to Main Menu "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  101. Cisco AnyConnect VPN          102. Google Chrome "
            Write-Host "  103. Adobe Acrobat Pro             104. Mozilla Firefox "
            Write-Host "  105. MS Project Standard 2016      106. MS Visio Standard 2013 "
            Write-Host "  107. Java                          108. Adobe Reader DC "
            Write-Host "  109. VLC Media Player              110. AMSAA Push Tool "
            Write-Host "  111. HP Records Manager "
            Write-Host "  121. ITMSC Toolset                 122. Dameware "
            Write-Host "  123. Adobe CC Design 2018          124. Adobe CC Imaging 2018 "
            Write-Host "       - Illustrator/InDesign             - Photoshop/Lightroom "
            Write-Host "  125. Adobe CC Web 2018             126. Adobe CC Video 2018 "
            Write-Host "       - Dreamweaver/Animate              - Premiere/After Effects "
            Break
        }   #Software
        Default {
            Write-ECBCHeader -Title 'ITMSC Toolset v2' -TitleColor 'White' -Bottom
            Write-Host "  Type a command name/number or type clear to reset selections. "
            Write-ECBCHeader -Title 'Computer' -TitleColor 'White' -Value $TargetComputer -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  1.  Ping Target                    2.  Computer Information "
            Write-Host "  3.  Logon Info                     4.  De-CAC Target "
            Write-Host "  5.  Launch Dameware                6.  Enable USB Stoarge "
            Write-Host "  7.  Backup & Restore               8.  Restart Computer "
            Write-Host "  9.  BitLocker Menu                 10. Software Install Menu "
            Write-Host "  11. File Transfer                  12. Folder Transfer "
            Write-Host "  13. Check AD Information           14. Shortcuts Menu "
            Write-ECBCHeader -Title 'User' -TitleColor 'White' -Value $TargetUser -ValueColor 'Yellow' -Top -Bottom
            Write-Host "  41. Logon Info                     42. Login Script "
            Write-ECBCHeader -Title 'Other  Tools' -TitleColor 'White' -Top -Bottom
            Write-Host "  51. Default MMC                    52. ITMSC Toolset "
            Write-Host "  53. Notepad "
            Break
        }   #Default
    }   #Switch

    Switch($Command = Read-Host -Prompt "`n`n Enter a command, computer or user name to continue") {
        ''      { Set-Clipboard -Value $TargetComputer; Break }
        0       { $ToolsetMenu = 'Main'; Break }
        1       { Test-ECBCComputerConnection -ComputerName $TargetComputer; Break }
        2       { Get-ECBCComputerInformation -ComputerName $TargetComputer; Break }
        3       { Get-ECBCComputerLogonInfo -ComputerName $TargetComputer; Break }
        4       { Disable-ECBCCACEnforcement -ComputerName $TargetComputer; Break }
        5       { Start-ECBCDamewareTarget -ComputerName $TargetComputer; Break }
        6       { Enable-ECBCUSBStorage -ComputerName $TargetComputer; Break }
        7       { $ToolsetMenu = 'BackupRestore'; Break }
        8       { Restart-ECBCComputer -ComputerName $TargetComputer; Break }
        9       { $ToolsetMenu = 'BitLocker'; Break }
        10      { $ToolsetMenu = 'Software'; Break }
        11      { Send-ECBCFileTransfer -ComputerName $TargetComputer; Break }
        12      { Send-ECBCFolderTransfer -ComputerName $TargetComputer; Break }
        13      { Get-ECBCComputerADInformation -ComputerName $TargetComputer; Break }
        14      { $ToolsetMenu = 'Shortcuts'; Break }
        41      { Get-ECBCUserLogonInfo -UserName $TargetUser; Break }
        42      { Get-ECBCUserLoginScript -UserName $TargetUser; Break }
        51      { Start-ECBCDefaultMMC; Break }
        52      { Start-ECBCToolset; Break }
        53      { Start-ECBCNotepad; Break }
        71      { Backup-ECBCUserProfile -ComputerName $TargetComputer; Break }
        91      { Get-ECBCBitLockerStatus -ComputerName $TargetComputer; Break }
        92      { Enable-ECBCBitLocker -ComputerName $TargetComputer; Break }
        93      { Get-ECBCBitLockerKey -ComputerName $TargetComputer; Break }
        101     { Install-ECBCCiscoAnyConnect -ComputerName $TargetComputer; Break }
        102     { Install-ECBCGoogleChrome -ComputerName $TargetComputer; Break }
        103     { Install-ECBCAdobeAcrobatPro -ComputerName $TargetComputer; Break }
        104     { Install-ECBCMozillaFirefox -ComputerName $TargetComputer; Break }
        105     { Install-ECBCMSProjectStandard -ComputerName $TargetComputer; Break }
        106     { Install-ECBCMSVisioStandard -ComputerName $TargetComputer; Break }
        107     { Install-ECBCJava -ComputerName $TargetComputer; Break }
        108     { Install-ECBCAdobeAcrobatReader -ComputerName $TargetComputer; Break }
        109     { Install-ECBCVLC -ComputerName $TargetComputer; Break }
        110     { Start-AMSAASoftware; Break }
        111     { Install-ECBCHPRM -ComputerName $TargetComputer; Break }
        121     { Install-ECBCToolset -ComputerName $TargetComputer; Break }
        122     { Install-ECBCDameware -ComputerName $TargetComputer; Break }
        123     { Install-ECBCAdobeCCDesignTools -ComputerName $TargetComputer; Break }
        124     { Install-ECBCAdobeCCImagingTools -ComputerName $TargetComputer; Break }
        125     { Install-ECBCAdobeCCWebTools -ComputerName $TargetComputer; Break }
        126     { Install-ECBCAdobeCCVideoTools -ComputerName $TargetComputer; Break }
        140     { Copy-ECBCLoginScriptShortcut -ComputerName $TargetComputer; Break }
        141     { Copy-ECBCCitrixShortcut -ComputerName $TargetComputer; Break }
        142     { Copy-ECBCFedlogShortcut -ComputerName $TargetComputer; Break }
        146     { Set-Clipboard -Value "https://ara-1.c3pki.chamb.disa.mil/ara/Key"; Break }
        147     { Set-Clipboard -Value "https://ara-2.c3pki.den.disa.mil/ara/Key"; Break }
        148     { Set-Clipboard -Value "https://ara-3.csd.disa.mil/ara/ss/"; Break }
        149     { Set-Clipboard -Value "https://ara-4.csd.disa.mil/ara/Key"; Break }
        150     { Set-Clipboard -Value "https://ara-5.csd.disa.mil"; Break }
        151     { Set-Clipboard -Value "https://cs.signal.army.mil/DoDIAA/default.asp"; Break }
        152     { Set-Clipboard -Value "https://webapps.apgea.army.mil/AcqTrack/MobileMenu.aspx"; Break }
        401     { Start-ADMBurnerSvc_NOCRED -ComputerName $TargetComputer; Break }
        402     { Start-ADMServerBurnerSvc_NOCRED -ComputerName $TargetComputer; Break }
        403     { Start-VRaySpawnerSvc_NOCRED -ComputerName $TargetComputer; Break }
        404     { Start-VRayGPUSpawnerSvc_NOCRED -ComputerName $TargetComputer; Break }
        501     { Start-ADMBurnerSvc -ComputerName $TargetComputer; Break }
        502     { Start-ADMServerBurnerSvc -ComputerName $TargetComputer; Break }
        503     { Start-VRaySpawnerSvc -ComputerName $TargetComputer; Break }
        504     { Start-VRayGPUSpawnerSvc -ComputerName $TargetComputer; Break }
        601     { Stop-ADMBurnerSvc -ComputerName $TargetComputer; Break}
        602     { Stop-ADMServerBurnerSvc -ComputerName $TargetComputer; Break}
        603     { Stop-VRaySpawnerSvc -ComputerName $TargetComputer; Break }
        604     { Stop-VRayGPUSpawnerSvc -ComputerName $TargetComputer; Break }
        605     { Start-ADMServerBurnerSvcMulti; Break }
        606     { Stop-ADMServerBurnerSvcMulti; Break }
        607     { Start-VRaySpawnerSvcMulti; Break }
        608     { Stop-VRaySpawnerSvcMulti; Break }
        609     { Start-VRayGPUSpawnerSvcMulti; Break }
        610     { Stop-VRayGPUSpawnerSvcMulti; Break }
        700     { Send-ISVMFileTransfer -ComputerName $TargetComputer; Break }
        800     { CheckInstalled -ComputerName $TargetComputer; Break }
        801     { GetServices -ComputerName $TargetComputer; Break }
        'ADM'   { $ToolsetMenu = 'ADM'; Break }
        'Build' { Remove-ECBCBuildFromStartup -ComputerName $TargetComputer; Break }
        'Clear' { $TargetComputer = $TargetUser = $false; Break }
        'DLP'   { Remove-ECBCMcAfeeDLP -ComputerName $TargetComputer; Break }
        'Exit'  { Break }
        'Kill'  { Stop-ECBCProcess -ComputerName $TargetComputer; Break }
        'Login' { Copy-ECBCLoginScripts -ComputerName $TargetComputer; Break }
        'MoveSA'{ Move-ECBCADComputerSA -ComputerName $TargetComputer; Break }
        'MYPC'  { $TargetComputer = ($env:COMPUTERNAME).ToUpper(); Break }
        'SDPC'  { $TargetComputer = $DefaultComputer; Break }
        'X'     { $TargetComputer = $TargetUser = $false; Break }
        Default {
            #Check for Full IP Address
            if($Command -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$") {
                $TargetComputer = $Command
                Break
            }
            #Check for Short IP Address
            if($Command -match "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){1}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$") {
                $TargetComputer = "131.92.$Command"
                Break
            }
            #Check for Full Computer Name
            if($Command -match "apgr([a-z]*)") {
                $TargetComputer = $Command.ToUpper()
                Break
            }
            #Check for ECBC Notebook
            if($Command -match "nb([a-z])(\d{4})") {
                $TargetComputer = ('APGRNBECG-' + $Command.Substring(2,5)).ToUpper()
                Break
            }
            #Check for AMSAA Notebook
            if($Command -match "nb(\d{5})") {
                $TargetComputer = ('APGRNBECGA' + $Command.Substring(2,5)).ToUpper()
                Break
            }    
            #Check for ECBC Workstation
            if($Command -match "wk([a-z])(\d{4})") {
                $TargetComputer = ('APGRWKECG-' + $Command.Substring(2,5)).ToUpper()
                Break
            }
            #Check for AMSAA Workstation
            if($Command -match "wk(\d{5})") {
                $TargetComputer = ('APGRWKECGA' + $Command.Substring(2,5)).ToUpper()
                Break
            }
            #Check for ECBC/AMSAA Barcode Only
            if(($Command -match "([a-z])(\d{4})") -or ($Command -match "(\d{5})")) {
                $TargetComputer = (Get-ECBCComputerName -Barcode $Command).ToUpper()
                Break
            }
            #Check for UserName Entered
            if($Command -match "(\w{3,})") {
                $Command = Get-ECBCUserName -Search $Command
                if($Command) {
                    $TargetUser = $Command
                    $TargetComputer = (Get-ECBCComputerName -UserName $TargetUser).ToUpper()
                }
                Break
            }
        }   #Default
    }   #Switch

} While ($Command -ne 'Exit')
