if (!$QATTESTPATH) {
    $TestSuitePath = Split-Path -Parent (Split-Path -Path $PSCommandPath)
    Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global
}

Import-Module "$QATTESTPATH\\lib\\WinBase.psm1" -Force -DisableNameChecking

function WTLSendPassWord
{
    Param(
        [Parameter(Mandatory=$True)]
        [int]$ProcessID,

        [Parameter(Mandatory=$True)]
        [string]$VMIPAddress
    )

    $FingerPrintFlag = $true
    $SubShell = New-Object -ComObject "wscript.shell"
    Start-Sleep -Seconds 10
    $SubShell.AppActivate($ProcessID) | out-null

    $KnownHostPath = "C:\\Users\\Administrator\\.ssh\\known_hosts"
    if (Test-Path -Path $KnownHostPath) {
        $FingerPrints = Get-Content -Path $KnownHostPath
        ForEach ($FingerPrint in $FingerPrints) {
            if ($FingerPrint -like ("{0}*" -f $VMIPAddress)) {
                $FingerPrintFlag = $false
            }
        }
    }

    if ($FingerPrintFlag) {
        $SubShell.sendkeys("yes")
        $SubShell.sendkeys("{ENTER}")
    }

    Start-Sleep -Seconds 5
    $SubShell.sendkeys($RemoteUserConfig.Password)
    $SubShell.sendkeys("{ENTER}")
}

# About VMs
function WTLRestartVMs
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$VMNameList,

        [bool]$StopFlag = $true,

        [bool]$TurnOff = $true,

        [bool]$StartFlag = $true,

        [bool]$WaitFlag = $true,

        [bool]$SessionFlag = $true
    )

    if ($StopFlag) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            HV-RestartVMHard `
                -VMName $VMName `
                -StopFlag $StopFlag `
                -TurnOff $TurnOff `
                -StartFlag $false `
                -WaitFlag $false | out-null
        }
    }

    if ($WaitFlag) {
        Start-Sleep -Seconds 30
    }

    if ($StartFlag) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            HV-RestartVMHard `
                -VMName $VMName `
                -StopFlag $false `
                -TurnOff $false `
                -StartFlag $StartFlag `
                -WaitFlag $false | out-null
        }
    }

    if ($WaitFlag) {
        Start-Sleep -Seconds 120
    }

    if ($SessionFlag) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $PSSessionName = ("Session_{0}" -f $_)
            HV-PSSessionCreate `
                -VMName $VMName `
                -PSName $PSSessionName `
                -IsWin $false
        }
    }
}

function WTLCreateVMs
{
    Param(
        [Parameter(Mandatory=$True)]
        [Array]$TestVmOpts,

        [Parameter(Mandatory=$True)]
        [string]$VMSwitch
    )

    $TestVmOpts | ForEach-Object {
        HV-CreateVM -VMConfig $_ -VMSwitch $VMSwitch | out-null
    }
}

function WTLRemoveVMs
{
    $VMList = Get-VM
    if (-not [String]::IsNullOrEmpty($VMList)) {
        Foreach ($VM in $VMList) {
            HV-RemoveVM -VMName $VM.Name | out-null
        }
    }
}

# About run shell command on Linux VM
function WTL-RunShellCommand
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$VMNameList,

        [Parameter(Mandatory=$True)]
        [string]$ShellCommand,

        [Parameter(Mandatory=$True)]
        [string]$RunPath,

        [bool]$OutputFlag = $true,

        [int]$Timeout = 1200
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
        test = [System.Array] @()
    }

    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $ReturnValue.test += @{
            vm = $VMName
            result = $true
            error = "no_error"
        }
    }

    # Run shell command as job
    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $PSSessionName = ("Session_{0}" -f $_)
        $JobName = ("Job_{0}" -f $_)
        $Session = HV-PSSessionCreate `
            -VMName $VMName `
            -PSName $PSSessionName `
            -IsWin $false

        Win-DebugTimestamp -output (
            "{0}: Run shell command > {1}" -f $PSSessionName, $ShellCommand
        )

        $JobError = $null
        $JobStatus = Get-Job `
            -Name $JobName `
            -ErrorAction SilentlyContinue `
            -ErrorVariable JobError

        if ([String]::IsNullOrEmpty($JobError)) {
            Remove-Job -Name $JobName -Force | out-null
        }

        $VMIP = HV-GetVMIPAddress -VMName $VMName
        $LocalShellOutputLogPath = "\\{0}\\STV-tmp\\{1}" -f
            $VMIP,
            $VMDriverInstallPath.ShellOutputLog
        $OutputLogPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.ShellOutputLog

        if (Test-Path -Path $LocalShellOutputLogPath) {
            Remove-Item `
                -Path $LocalShellOutputLogPath `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }

        $JobError = $null
        if ($OutputFlag) {
            Invoke-Command -Session $Session -ScriptBlock {
                Param($RunPath, $ShellCommand, $OutputLogPath)
                cd $RunPath
                echo $ShellCommand | sh > $OutputLogPath
            } -ArgumentList $RunPath, $ShellCommand, $OutputLogPath `
              -JobName $JobName `
              -AsJob `
              -ErrorAction SilentlyContinue `
              -ErrorVariable JobError | out-null
        } else {
            Invoke-Command -Session $Session -ScriptBlock {
                Param($RunPath, $ShellCommand)
                cd $RunPath
                echo $ShellCommand | sh
            } -ArgumentList $RunPath, $ShellCommand `
              -JobName $JobName `
              -AsJob `
              -ErrorAction SilentlyContinue `
              -ErrorVariable JobError | out-null
        }

        if (-not [String]::IsNullOrEmpty($JobError)) {
            $ReturnValue.test | ForEach-Object {
                if ($_.vm -eq $VMName) {
                    if ($_.result) {
                        $_.result = $false
                        $_.error = "command_fail"
                    }

                    if ($ReturnValue.result) {
                        $ReturnValue.result = $false
                        $ReturnValue.error = "command_fail"
                    }
                }
            }
        }
    }

    # Wait shell command to complete
    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $PSSessionName = ("Session_{0}" -f $_)
        $JobName = ("Job_{0}" -f $_)
        $Session = HV-PSSessionCreate `
            -VMName $VMName `
            -PSName $PSSessionName `
            -IsWin $false

        $ShellJobResult = WBase-WaitJobToCompleted `
            -JobName $JobName `
            -Timeout $Timeout `
            -LogKeyWord $PSSessionName

        $ResultTmp = $true
        $ErrorTmp = "no_error"
        if ($ShellJobResult) {
            $ShellRunFlag = Invoke-Command -Session $Session -ScriptBlock {
                echo $?
            }

            if ($ShellRunFlag) {
                $ResultTmp = $true
                $ErrorTmp = "no_error"
            } else {
                $ResultTmp = $false
                $ErrorTmp = "shell_fail"
            }
        } else {
            $ResultTmp = $ShellJobResult.result
            $ErrorTmp = $ShellJobResult.error
        }

        if ($ResultTmp) {
            Win-DebugTimestamp -output (
                "{0}: Run shell command is completed" -f $PSSessionName
            )
        } else {
            Win-DebugTimestamp -output (
                "{0}: Run shell command is failed > {1}" -f
                    $PSSessionName,
                    $ErrorTmp
            )
        }

        $ReturnValue.test | ForEach-Object {
            if ($_.vm -eq $VMName) {
                if ($_.result) {
                    $_.result = $ResultTmp
                    $_.error = $ErrorTmp
                }

                if ($ReturnValue.result) {
                    $ReturnValue.result = $ResultTmp
                    $ReturnValue.error = $ErrorTmp
                }
            }
        }
    }

    return $ReturnValue
}

# About QAT driver
function WTL-InstallAndUninstallQatDriver
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$VMNameList,

        [Parameter(Mandatory=$True)]
        [bool]$Operation,

        [Parameter(Mandatory=$True)]
        [string]$QatDriverName
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    if ($Operation) {
        $LogKeyWord = "Install"
        $InstallShellCommand = "make install -j32"
    } else {
        $LogKeyWord = "Uninstall"
        $InstallShellCommand = "make uninstall -j32"
    }

    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $VMIP = HV-GetVMIPAddress -VMName $VMName
        $LocalDriverNamePath = "\\{0}\\STV-tmp\\{1}" -f
            $VMIP,
            $QatDriverName
        $LocalDriverInstallPath = "\\{0}\\STV-tmp\\{1}" -f
            $VMIP,
            $VMDriverInstallPath.InstallPath

        if (-not (Test-Path -Path $LocalDriverNamePath)) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $false
                $ReturnValue.error = "driver_not_exist"
            }
        }

        if (Test-Path -Path $LocalDriverInstallPath) {
            Remove-Item `
                -Path $LocalDriverInstallPath `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }

        New-Item -Path $LocalDriverInstallPath -ItemType Directory | out-null
    }

    # Decompress QAT Linux driver on VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Decompress QAT Linux driver...")
        $VMInstallPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath
        $ShellCommand = "tar -xvf {0} -C {1}" -f
            $LocationInfo.VF.DriverName,
            $VMInstallPath

        $DecompressShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $STVLinuxPath `
            -OutputFlag $false `
            -Timeout 1200

        if (-not $DecompressShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $DecompressShellResult.result
                $ReturnValue.error = $DecompressShellResult.error
            }
        }

        Win-DebugTimestamp -output ("Decompress QAT Linux driver > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip Decompress QAT Linux driver, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Config QAT Linux driver on VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Config QAT Linux driver...")
        $ShellCommand = "./configure --enable-icp-sriov=guest --enable-legacy-algorithms"
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath

        $ConfigShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 1200

        if (-not $ConfigShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $ConfigShellResult.result
                $ReturnValue.error = $ConfigShellResult.error
            }
        }

        Win-DebugTimestamp -output ("Config QAT Linux driver > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip Config QAT Linux driver, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Make QAT Linux driver on VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Make QAT Linux driver...")
        $ShellCommand = "make -j32"
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath

        $MakeShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 1200

        if (-not $MakeShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $MakeShellResult.result
                $ReturnValue.error = $MakeShellResult.error
            }
        }

        Win-DebugTimestamp -output ("Make QAT Linux driver > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip Make QAT Linux driver, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Install or uninstall QAT Linux driver on VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("{0} QAT Linux driver..." -f $LogKeyWord)
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath

        $InstallShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $InstallShellCommand `
            -RunPath $RunPath `
            -Timeout 1200

        if (-not $InstallShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $InstallShellResult.result
                $ReturnValue.error = $InstallShellResult.error
            }
        }

        Win-DebugTimestamp -output (
            "{0} QAT Linux driver > {1}" -f $LogKeyWord, $ReturnValue.result
        )
    } else {
        Win-DebugTimestamp -output (
            "Skip {0} QAT Linux driver, because Error > {1}" -f $LogKeyWord, $ReturnValue.error
        )
    }

    return $ReturnValue
}

function WBase-CheckDriverInstalled
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$VMNameList
    )

    $ReturnValue = $true

    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $PSSessionName = ("Session_{0}" -f $_)
        $Session = HV-PSSessionCreate `
            -VMName $VMName `
            -PSName $PSSessionName `
            -IsWin $false

        $CheckError = $null
        $CheckStatus = Invoke-Command `
            -Session $Session `
            -ScriptBlock {adf_ctl} `
            -ErrorAction SilentlyContinue `
            -ErrorVariable CheckError

        if ([String]::IsNullOrEmpty($CheckError)) {
            Win-DebugTimestamp -output (
                "{0}: The QAT Linux driver has installed" -f $PSSessionName
            )
        } else {
            Win-DebugTimestamp -output (
                "{0}: The QAT Linux driver has not installed" -f $PSSessionName
            )

            if ($ReturnValue) {$ReturnValue = $false}
        }
    }

    return $ReturnValue
}

# About test ENV init
function WTL-VMVFInfoInit
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMVFOSConfig
    )

    $LocationInfo.VM.Number = $null
    $LocationInfo.VF.Number = $null
    $LocationInfo.VM.OS = $null

    if ([String]::IsNullOrEmpty($VMVFOSConfig)) {
        Win-DebugTimestamp -output ("Host: The config of 'VMVFOS' is not null for HV mode")
    } else {
        $VMVFOSConfig = Split-Path -Path $VMVFOSConfig -Leaf
        $HostVMs = $VMVFOSConfig.split("_")[1]
        $LocationInfo.VM.Number = [int]($HostVMs.Substring(0, $HostVMs.Length - 2))
        $HostVFs = $VMVFOSConfig.split("_")[2]
        $LocationInfo.VF.Number = [int]($HostVFs.Substring(0, $HostVFs.Length - 2))
        $LocationInfo.VM.OS = ($VMVFOSConfig.split("_")[3]).split(".")[0]

        Win-DebugTimestamp -output ("LocationInfo: VMNumber > {0}" -f $LocationInfo.VM.Number)
        Win-DebugTimestamp -output ("LocationInfo: VFNumber > {0}" -f $LocationInfo.VF.Number)
        Win-DebugTimestamp -output ("LocationInfo: VMOS > {0}" -f $LocationInfo.VM.OS)
    }
}

function WTL-ENVInit
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$configFile,

        [bool]$InitVM
    )

    [System.Array] $TestVmOpts = (Get-Content $configFile | ConvertFrom-Json).TestVms
    $VMNameList = @()
    $TestVmOpts | ForEach-Object {
        $VMNameList += $_.Name
    }

    if ($InitVM) {
        # Remove VMs
        WTLRemoveVMs | out-null

        # Create new VM switch or rename existing VM switch.
        $VMSwitch = HV-VMSwitchCreate

        # Create VMs
        WTLCreateVMs -TestVmOpts $TestVmOpts -VMSwitch $VMSwitch | out-null

        # Start VMs
        WTLRestartVMs `
            -VMNameList $VMNameList `
            -StopFlag $false `
            -TurnOff $false `
            -StartFlag $true `
            -WaitFlag $false `
            -SessionFlag $false | out-null

        Start-Sleep -Seconds 120
    }

    # Create SSH keys
    UT-CreateSSHKeys | out-null

    # Copy VF driver and utils file
    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $PSSessionName = ("Session_{0}" -f $_)
        $VMIP = HV-GetVMIPAddress -VMName $VMName

        Win-DebugTimestamp -output ("{0}: Init STV test path..." -f $PSSessionName)

        $VMTestBasePath = "\\{0}\\STV-tmp" -f $VMIP
        $HostPublicKey = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.PublicKeyName
        $VMPublicKey = "{0}\\{1}" -f $VMTestBasePath, $SSHKeys.PublicKeyName
        $HostFreeLoginScript = "{0}\\{1}" -f $LinuxShell.HostPath, $LinuxShell.FreeLogin
        $VMFreeLoginScript = "{0}\\{1}" -f $VMTestBasePath, $LinuxShell.FreeLogin
        $HostVFDriver = "{0}\\{1}" -f $LocationInfo.VF.DriverPath, $LocationInfo.VF.DriverName
        $VMVFDriver = "{0}\\{1}" -f $VMTestBasePath, $LocationInfo.VF.DriverName
        $VMVFDriverPath = "{0}\\{1}" -f $VMTestBasePath, $VMDriverInstallPath.InstallPath

        if (-not (Test-Path -Path $VMVFDriverPath)) {
            New-Item -Path $VMVFDriverPath -ItemType Directory | out-null
        }

        if (Test-Path -Path $VMPublicKey) {
            Remove-Item `
                -Path $VMPublicKey `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }

        if (Test-Path -Path $VMFreeLoginScript) {
            Remove-Item `
                -Path $VMFreeLoginScript `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }

        if (Test-Path -Path $VMVFDriver) {
            Remove-Item `
                -Path $VMVFDriver `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }

        Copy-Item -Path $HostPublicKey -Destination $VMPublicKey | out-null
        Copy-Item -Path $HostFreeLoginScript -Destination $VMFreeLoginScript | out-null
        Copy-Item -Path $HostVFDriver -Destination $VMVFDriver | out-null
    }

    # Start VMs
    WTLRestartVMs `
        -VMNameList $VMNameList `
        -StopFlag $true `
        -TurnOff $false `
        -StartFlag $true `
        -WaitFlag $true `
        -SessionFlag $true | out-null

    if ($InitVM) {
        Win-DebugTimestamp -output ("Install QAT Linux driver on VMs...")
        # Decompress and install QAT Linux driver on VMs
        $InstallStatus = WTL-InstallAndUninstallQatDriver `
            -VMNameList $VMNameList `
            -Operation $true `
            -QatDriverName $LocationInfo.VF.DriverName

        if ($InstallStatus.result) {
            Win-DebugTimestamp -output ("Install QAT Linux driver on VMs > successful")
        } else {
            throw ("Install QAT Linux driver on VMs > {0}" -f $InstallStatus.error)
        }
    }

    $CheckResult = WBase-CheckDriverInstalled -VMNameList $VMNameList
    if (-not $CheckResult) {
        throw ("The QAT Linux driver has not installed")
    }

    if ($InitVM) {
        # Double check QAT driver installed
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $PSSessionName = ("Session_{0}" -f $_)
            $Session = HV-PSSessionCreate `
                -VMName $VMName `
                -PSName $PSSessionName `
                -IsWin $false

            $DeviceStatus = Invoke-Command -Session $Session -ScriptBlock {
                adf_ctl status
            }

            $OutputArray = $DeviceStatus.split("\n")
            $deviceNumber = [int]($OutputArray[1].split(" ")[2])
            $ThrowFlag = $false
            if ($deviceNumber -eq $LocationInfo.VF.Number) {
                $deviceStatusUp = 0
                $deviceStatusDown = 0
                Foreach ($OutputLine in $OutputArray) {
                    if ($OutputLine -match "qat_dev") {
                        $OutputLineArray = $OutputLine.split(" ")
                        if ($OutputLineArray[-1] -eq "up") {
                            $deviceStatusUp += 1
                        } else {
                            Win-DebugTimestamp -output (
                                "{0}: The status is not up > {1}" -f
                                    $PSSessionName,
                                    $OutputLine
                            )

                            $deviceStatusDown += 1
                        }
                    }
                }

                if (($deviceStatusUp -eq $LocationInfo.VF.Number) -and ($deviceStatusDown -eq 0)) {
                    Win-DebugTimestamp -output (
                        "{0}: The number of qat devices is correct > {1}" -f
                            $PSSessionName,
                            $deviceNumber
                    )
                } else {
                    $ThrowFlag = $true
                }
            } else {
                $ThrowFlag = $true
            }

            if ($ThrowFlag) {
                throw (
                    "{0}: The number of qat devices is incorrect > {1}" -f
                        $PSSessionName,
                        $deviceNumber
                )
            }
        }
    }
}

# About base test
function WTLGenerateTestCaseName
{
    Param(
        [Parameter(Mandatory=$True)]
        [object]$OutputLog
    )

    $ReturnValue = [hashtable] @{
        name = $null
        throughput = 0
    }

    $TestCase = [hashtable] @{
        type = "No_Name"
        API = $null
        Algo = $null
        Operation = $null
        KeyLength = 0
        Ecccurve = 0
        Mode = $null
        Block = 0
        CompressType = $null
        CompressionType = $null
        CompressionLevel = 0
        Throughput = 0
        Threads = 0
        Submissions = 0
        Responses = 0
        Iteration = 0
    }

    $OutputLogArray = $OutputLog.split("`r`n")
    $OutputLogArray | ForEach-Object {
        $_ = $_ -replace "\s{2,}", " "

        if ($_ -match "Cipher") {
            $TestCase.type = "Cipher"
            $TestCase.Algo = $_.split(" ")[-1]
        }

        if ($_ -match "Algorithm Chaining") {
            $TestCase.type = "Chaining"
            $Algo1 = ($_.split(" ")[-2]) -replace "-", "_"
            $Algo2 = ($_.split(" ")[-1]) -replace "-", "_"
            $TestCase.Algo = "{0}_{1}" -f $Algo1, $Algo2
        }

        if ($_ -match "RSA CRT") {
            $TestCase.type = "RSA_CRT"
            $TestCase.Algo = "RSA_CRT"
            $TestCase.Operation = $_.split(" ")[-1]
        }

        if ($_ -match "DIFFIE-HELLMAN") {
            $TestCase.type = "DIFFIE"
            $TestCase.Algo = "DIFFIE_HELLMAN_PHASE_{0}" -f $_.split(" ")[-1]
        }

        if ($_ -match "DSA ") {
            $TestCase.type = "DSA"
            $TestCase.Algo = "DSA"
            $TestCase.Operation = $_.split(" ")[-1]
        }

        if ($_ -match "ECDSA") {
            $TestCase.type = "ECDSA"
            $TestCase.Algo = "ECDSA"
            $TestCase.Operation = $_.split(" ")[-1]
        }

        if ($_ -match "API") {
            $TestCase.API = $_.split(" ")[-1]
        }

        if ($_ -match "Direction") {
            $TestCase.Operation = $_.split(" ")[-1]
        }

        if (($_ -match "Modulus Size") -or
            ($_ -match "Packet Size")) {
            $TestCase.KeyLength = "KeyLength{0}" -f $_.split(" ")[-1]
        }

        if ($_ -match "Packet Mix") {
            $TestCase.KeyLength = "KeyLength{0}" -f ($_.split(" ")).split("-")[-1]
        }

        if ($_ -match "EC Size") {
            $TestCase.Ecccurve = "Ecccurve{0}" -f $_.split(" ")[-1]
        }

        if ($_ -match "Mode") {
            $TestCase.Mode = $_.split(" ")[-1]
        }

        if ($_ -match "Packet Size") {
            $TestCase.Block = "Block{0}" -f $_.split(" ")[-1]
        }

        if ($_ -match "Direction") {
            $TestCase.CompressType = ($_.split("(")[0]).split(" ")[-1]
        }

        if ($_ -match "Huffman Type") {
            $TestCase.CompressionType = $_.split(" ")[-1]
        }

        if ($_ -match "Compression Level") {
            $TestCase.CompressionLevel = "Level{0}" -f $_.split(" ")[-1]
        }

        if (($_ -match "Throughput") -or
            ($_ -match "per second")) {
            $TestCase.Throughput = [int]($_.split(" ")[-1])
        }

        if ($_ -match "Threads") {
            $TestCase.Threads = [int]($_.split(" ")[-1])
        }

        if ($_ -match "Submissions") {
            $TestCase.Submissions = [int]($_.split(" ")[-1])
        }

        if ($_ -match "Responses") {
            $TestCase.Responses = [int]($_.split(" ")[-1])
        }
    }

    if ($TestCase.Threads -ne 0) {
        if ($TestCase.Submissions -ne 0) {
            $IterationDivisor = $TestCase.Submissions
        } else {
            if ($TestCase.Responses -ne 0) {
                $IterationDivisor = $TestCase.Responses
            } else {
                $IterationDivisor = 0
            }
        }

        $IterationDividend = $TestCase.Threads
        $TestCase.Iteration = [int]($IterationDivisor/$IterationDividend)
    } else {
        $TestCase.Iteration = 0
    }

    if (($TestCase.type -eq "Cipher") -or
        ($TestCase.type -eq "Chaining")) {
        $ReturnValue.name = "{0}_{1}_{2}_{3}_{4}_Thread{5}_Iteration{6}" -f
            $TestCase.type,
            $TestCase.Algo,
            $TestCase.Operation,
            $TestCase.KeyLength,
            $TestCase.API,
            $TestCase.Threads,
            $TestCase.Iteration
    } elseif (($TestCase.type -eq "RSA_CRT") -or
        ($TestCase.type -eq "DIFFIE") -or
        ($TestCase.type -eq "DSA")) {
        $ReturnValue.name = "{0}_{1}_{2}_Thread{3}_Iteration{4}" -f
            $TestCase.Algo,
            $TestCase.Operation,
            $TestCase.KeyLength,
            $TestCase.Threads,
            $TestCase.Iteration
    } elseif ($TestCase.type -eq "ECDSA") {
        $ReturnValue.name = "{0}_{1}_{2}_Thread{3}_Iteration{4}" -f
            $TestCase.Algo,
            $TestCase.Operation,
            $TestCase.Ecccurve,
            $TestCase.Threads,
            $TestCase.Iteration
    } else {
        if ([String]::IsNullOrEmpty($TestCase.CompressType)) {
            $ReturnValue.name = "{0}_Thread{1}_Iteration{2}" -f
                $TestCase.type,
                $TestCase.Threads,
                $TestCase.Iteration
        } else {
            $ReturnValue.name = "{0}_{1}_{2}_{3}_{4}_{5}_Thread{6}_Iteration{7}" -f
                $TestCase.CompressType,
                $TestCase.CompressionType,
                $TestCase.Mode,
                $TestCase.Block,
                $TestCase.CompressionLevel,
                $TestCase.API,
                $TestCase.Threads,
                $TestCase.Iteration
        }
    }

    $ReturnValue.throughput = $TestCase.Throughput

    return $ReturnValue
}

function WTLCollateTestCaseResult
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$TestCaseResultArray
    )

    $ReturnValue = @()

    # Generate real array of test case name
    $TestNameArray = @()
    Foreach ($TestCaseList in $TestCaseResultArray) {
        Foreach ($TestCaseName in $TestCaseList.TestCaseArray) {
            if (-not ($TestCaseName -in $TestNameArray)) {
                $TestNameArray += $TestCaseName
            }
        }
    }

    # Check test result
    Foreach ($TestName in $TestNameArray) {
        $TestCaseResult = [hashtable] @{
            name = $TestName
            result = $true
            error = "no_error"
            throughput = 0
        }

        Foreach ($TestCaseList in $TestCaseResultArray) {
            if ($TestName -in $TestCaseList.TestCaseArray) {
                if (-not $TestCaseList.TestCaseList[$TestName].result) {
                    if ($TestCaseResult.result) {
                        $TestCaseResult.result = $TestCaseList.TestCaseList[$TestName].result
                        $TestCaseResult.error = $TestCaseList.TestCaseList[$TestName].error
                    }
                }
            } else {
                if ($TestCaseResult.result) {
                    $TestCaseResult.result = $false
                    $TestCaseResult.error = "no_result"
                }
            }
        }

        $ReturnValue += $TestCaseResult
    }

    # Calculate the throughput
    Foreach ($TestCaseResult in $ReturnValue) {
        if ($TestCaseResult.result) {
            $ThroughputTotal = 0
            $CountTotal = 0
            Foreach ($TestCaseList in $TestCaseResultArray) {
                $ThroughputTotal += [int]($TestCaseList.TestCaseList[$TestCaseResult.name].throughput)
                $CountTotal += 1
            }
            $TestCaseResult.throughput = [int]($ThroughputTotal/$CountTotal)
        }
    }

    return $ReturnValue
}

function WTL-CheckOutput
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$TestVmOpts
    )

    #$TestCaseResult = [hashtable] @{
    #    name = $TestName
    #    result = $true
    #    error = "no_error"
    #    throughput = 0
    #}
    #$ReturnValue = @($TestCaseResult)
    $ReturnValue = @()

    $VMNameList = @()
    $TestVmOpts | ForEach-Object {
        $VMNameList += $_.Name
    }

    #$TestCaseList = [hashtable] @{
    #    VM = ""
    #    Number = 0
    #    TestCaseArray = @("TestCaseName")
    #    TestCaseList = [hashtable] @{
    #        TestCaseName = [hashtable] @{
    #            result = $true
    #            error = "no_error"
    #            throughput = 0
    #        }
    #    }
    #}
    #$TestCaseResultArray = @($TestCaseList)
    $TestCaseResultArray = @()

    $LocalOutputLogPath = "{0}\\{1}VM_{2}VF_{3}_Output" -f
        $LocalLinuxPath,
        $LocationInfo.VM.Number,
        $LocationInfo.VF.Number,
        $LocationInfo.VM.OS

    if (Test-Path -Path $LocalOutputLogPath) {
        Remove-Item `
            -Path $LocalOutputLogPath `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop | out-null
    }
    New-Item -Path $LocalOutputLogPath -ItemType Directory | out-null

    # Select test cases to file
    $VMNameList | ForEach-Object {
        $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
        $PSSessionName = ("Session_{0}" -f $_)
        $VMIP = HV-GetVMIPAddress -VMName $VMName
        $LocalShellOutputLogPath = "\\{0}\\STV-tmp\\{1}" -f
            $VMIP,
            $VMDriverInstallPath.ShellOutputLog
        $LocalVMOutputLogPath = "{0}\\{1}" -f $LocalOutputLogPath, $VMName
        $LocalVMOutputLog = "{0}\\{1}" -f $LocalVMOutputLogPath, $VMDriverInstallPath.ShellOutputLog

        Win-DebugTimestamp -output ("{0}: Check the test results" -f $PSSessionName)

        if (Test-Path -Path $LocalVMOutputLogPath) {
            Remove-Item `
                -Path $LocalVMOutputLogPath `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop | out-null
        }
        New-Item -Path $LocalVMOutputLogPath -ItemType Directory | out-null
        Copy-Item -Path $LocalShellOutputLogPath -Destination $LocalVMOutputLog | out-null

        # Select test cases to file
        $ShellOutputLog = Get-Content -Path $LocalVMOutputLog -Raw
        $ShellOutputLogArray = $ShellOutputLog.split("`n")
        $TestResultSwitch = $false
        $TestCaseNumber = 0

        Foreach ($ShellOutputLine in $ShellOutputLogArray) {
            if ($ShellOutputLine -match "---------------------------------------") {
                if ($TestResultSwitch) {
                    # Test result: Stop
                    $TestResultSwitch = $false
                } else {
                    # Test result: Start
                    $TestResultSwitch = $true
                    $TestCaseNumber += 1
                    $TestCaseName = "TestCase_{0}.txt" -f $TestCaseNumber
                    $TestCaseNamePath = "{0}\\{1}" -f $LocalVMOutputLogPath, $TestCaseName
                    if (Test-Path -Path $TestCaseNamePath) {
                        Remove-Item `
                            -Path $TestCaseNamePath `
                            -Force `
                            -Confirm:$false `
                            -ErrorAction Stop | out-null
                    }
                }
            } else {
                if ($TestResultSwitch) {
                    $ShellOutputLine | Out-File $TestCaseNamePath -Append -Encoding ascii
                }
            }
        }

        # Generate the list of test case result
        $TestCaseArray = @()
        $TestCaseList = [hashtable] @{}
        for ($it = 1; $it -le $TestCaseNumber; $it++) {
            $TestCaseFileName = "TestCase_{0}.txt" -f $it
            $TestCaseFilePath = "{0}\\{1}" -f $LocalVMOutputLogPath, $TestCaseFileName
            $TestOutputLog = Get-Content -Path $TestCaseFilePath -Raw

            $GenerateResult = WTLGenerateTestCaseName -OutputLog $TestOutputLog
            $TestCaseName = $GenerateResult.name
            $TestCaseArray += $TestCaseName

            Win-DebugTimestamp -output (
                "{0}: The name of test case > {1}" -f $PSSessionName, $TestCaseName
            )
            Win-DebugTimestamp -output (
                "{0}: The throughput of test case > {1}" -f
                    $PSSessionName,
                    $GenerateResult.throughput
            )
            Win-DebugTimestamp -output (
                "{0}: Output log > {1}" -f $PSSessionName, $TestOutputLog
            )

            $CheckOutputFlag = WBase-CheckOutputLog -OutputLog $TestOutputLog
            if ($CheckOutputFlag) {
                $TestCaseList[$TestCaseName] = [hashtable] @{
                    result = $true
                    error = "no_error"
                    throughput = $GenerateResult.throughput
                }
            } else {
                $TestCaseList[$TestCaseName] = [hashtable] @{
                    result = $false
                    error = "test_fail"
                    throughput = $GenerateResult.throughput
                }
            }
        }

        $TestCaseList = [hashtable] @{
            VM = $_
            Number = $TestCaseNumber
            TestCaseArray = $TestCaseArray
            TestCaseList = $TestCaseList
        }
        $TestCaseResultArray += $TestCaseList

        Win-DebugTimestamp -output (
            "{0}: Check the test results is completed" -f $PSSessionName
        )
    }

    # Collate return value
    $ReturnValue = WTLCollateTestCaseResult -TestCaseResultArray $TestCaseResultArray

    return $ReturnValue
}

# Sample test of Base
function WTL-BaseSample
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$TestVmOpts
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    $VMNameList = @()
    $TestVmOpts | ForEach-Object {
        $VMNameList += $_.Name
    }

    # Make base sample test
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Make base sample test...")
        $ShellCommand = "make samples -j32"
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath
        $MakeShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 1200

        if (-not $MakeShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $MakeShellResult.result
                $ReturnValue.error = $MakeShellResult.error
            }
        }

        Win-DebugTimestamp -output ("Make base sample test > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip make base sample test, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Install base sample test
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Install base sample test...")
        $ShellCommand = "make samples-install -j32"
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath
        $InstallShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 1200

        if (-not $InstallShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $InstallShellResult.result
                $ReturnValue.error = $InstallShellResult.error
            }
        }

        Win-DebugTimestamp -output ("Install base sample test > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip install base sample test, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Run base sample test
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Run base sample test...")
        $ShellCommand = "cpa_sample_code"
        $RunPath = "{0}/{1}" -f $STVLinuxPath, $VMDriverInstallPath.InstallPath
        $RunShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 18000

        if (-not $RunShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $RunShellResult.result
                $ReturnValue.error = $RunShellResult.error
            }
        }

        Win-DebugTimestamp -output ("run base sample test > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip run base sample test, because Error > {0}" -f $ReturnValue.error
        )
    }

    if ($ReturnValue.result) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $VMIP = HV-GetVMIPAddress -VMName $VMName
            $LocalShellOutputLogPath = "\\{0}\\STV-tmp\\{1}" -f
                $VMIP,
                $VMDriverInstallPath.ShellOutputLog

            if (-not (Test-Path -Path $LocalShellOutputLogPath)) {
                if ($ReturnValue.result) {
                    $ReturnValue.result = $false
                    $ReturnValue.error = "no_output"
                }
            }
        }
    }

    return $ReturnValue
}

# Sample test of Performance
function WTL-PerformanceSample
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$TestVmOpts
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    $VMNameList = @()
    $TestVmOpts | ForEach-Object {
        $VMNameList += $_.Name
    }

    $PerformanceSampleCodeName = "Performance-Sample.tar.gz"
    $PerformanceSampleShellName = "Performance-Sample.txt"
    $LocalPerformanceSampleCode = "{0}\\{1}" -f
        $LinuxShell.HostPath,
        $PerformanceSampleCodeName
    $LocalPerformanceSampleShell = "{0}\\{1}" -f
        $LinuxShell.HostPath,
        $PerformanceSampleShellName
    $VMShellTestPath = "{0}/{1}" -f
        $STVLinuxPath,
        $VMDriverInstallPath.ShellTestPath
    $VMShellTestFileName = "{0}/quad/{1}" -f
        $VMShellTestPath,
        $PerformanceSampleShellName

    if (-not (Test-Path -Path $LocalPerformanceSampleCode)) {
        $SourcePerformanceSampleCode = "{0}\\{1}" -f
            $BertaENVInit.LinuxShell.SourcePath,
            $PerformanceSampleCodeName

        Copy-Item `
            -Path $SourcePerformanceSampleCode `
            -Destination $LocalPerformanceSampleCode | out-null
    }

    # Copy performance sample code to VMs
    if ($ReturnValue.result) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $PSSessionName = ("Session_{0}" -f $_)
            $VMIP = HV-GetVMIPAddress -VMName $VMName
            $Session = HV-PSSessionCreate `
                -VMName $VMName `
                -PSName $PSSessionName `
                -IsWin $false

            $RemoteShellTestPath = "\\{0}\\STV-tmp\\{1}" -f
                $VMIP,
                $VMDriverInstallPath.ShellTestPath
            $RemotePerformanceSampleCode = "\\{0}\\STV-tmp\\{1}" -f
                $VMIP,
                $PerformanceSampleCodeName

            Win-DebugTimestamp -output (
                "{0}: Copy performance sample code > {1}" -f
                    $PSSessionName,
                    $RemotePerformanceSampleCode
            )

            if (Test-Path -Path $RemoteShellTestPath) {
                $CheckError = $null
                $CheckStatus = Invoke-Command -Session $Session -ScriptBlock {
                    Param($VMShellTestPath)
                    cd $VMShellTestPath
                    rm -rf *
                } -ArgumentList $VMShellTestPath `
                  -ErrorAction SilentlyContinue `
                  -ErrorVariable CheckError

                if (-not [String]::IsNullOrEmpty($CheckError)) {
                    if ($ReturnValue.result) {
                        $ReturnValue.result = $false
                        $ReturnValue.error = "clear_runpath_fail"
                    }
                }
            } else {
                New-Item -Path $RemoteShellTestPath -ItemType Directory | out-null
            }

            if (Test-Path -Path $RemotePerformanceSampleCode) {
                Remove-Item `
                    -Path $RemotePerformanceSampleCode `
                    -Force `
                    -Confirm:$false `
                    -ErrorAction Stop | out-null
            }

            Copy-Item `
                -Path $LocalPerformanceSampleCode `
                -Destination $RemotePerformanceSampleCode | out-null

            if (-not (Test-Path -Path $RemotePerformanceSampleCode)) {
                $ReturnValue.result = $false
                $ReturnValue.error = "copy_code_fail"
            }
        }
    } else {
        Win-DebugTimestamp -output (
            "Skip copy performance sample code, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Decompress performance sample code to VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Decompress performance sample code...")
        $ShellCommand = "tar -xvf {0} -C {1}" -f
            $PerformanceSampleCodeName,
            $VMShellTestPath

        $DecompressShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $STVLinuxPath `
            -OutputFlag $false `
            -Timeout 1200

        if (-not $DecompressShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $DecompressShellResult.result
                $ReturnValue.error = $DecompressShellResult.error
            }
        }

        Win-DebugTimestamp -output (
            "Decompress performance sample code > {0}" -f $ReturnValue.result
        )
    } else {
        Win-DebugTimestamp -output (
            "Skip Decompress performance sample code, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Build performance sample code to VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Build performance sample code...")
        $ShellCommand = "./build.sh"

        $BuildShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $VMShellTestPath `
            -OutputFlag $false `
            -Timeout 1200

        if (-not $BuildShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $BuildShellResult.result
                $ReturnValue.error = $BuildShellResult.error
            }
        }

        Win-DebugTimestamp -output (
            "Build performance sample code > {0}" -f $ReturnValue.result
        )
    } else {
        Win-DebugTimestamp -output (
            "Skip Build performance sample code, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Copy performance sample shell to VMs
    if ($ReturnValue.result) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $PSSessionName = ("Session_{0}" -f $_)
            $VMIP = HV-GetVMIPAddress -VMName $VMName
            $Session = HV-PSSessionCreate `
                -VMName $VMName `
                -PSName $PSSessionName `
                -IsWin $false

            $RemotePerformanceSampleShell = "\\{0}\\STV-tmp\\{1}\\quad\\{2}" -f
                $VMIP,
                $VMDriverInstallPath.ShellTestPath,
                $PerformanceSampleShellName

            Win-DebugTimestamp -output (
                "{0}: Copy performance sample shell > {1}" -f
                    $PSSessionName,
                    $RemotePerformanceSampleShell
            )

            Copy-Item `
                -Path $LocalPerformanceSampleShell `
                -Destination $RemotePerformanceSampleShell | out-null

            if (-not (Test-Path -Path $RemotePerformanceSampleShell)) {
                $ReturnValue.result = $false
                $ReturnValue.error = "copy_shell_fail"
            }
        }
    } else {
        Win-DebugTimestamp -output (
            "Skip copy performance sample shell, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Add execution permissions to performance sample shell
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Add execution permissions to performance sample shell...")
        $ShellCommand = "chmod 777 {0}" -f $VMShellTestFileName

        $ChmodShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $VMShellTestPath `
            -OutputFlag $false `
            -Timeout 1200

        if (-not $ChmodShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $ChmodShellResult.result
                $ReturnValue.error = $ChmodShellResult.error
            }
        }

        Win-DebugTimestamp -output (
            "Add execution permissions to performance sample shell > {0}" -f $ReturnValue.result
        )
    } else {
        Win-DebugTimestamp -output (
            "Skip add execution permissions, because Error > {0}" -f $ReturnValue.error
        )
    }

    # Run performance sample code to VMs
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Run performance sample test...")
        $ShellCommand = "./testCli -u -e ./{0}" -f $PerformanceSampleShellName
        $RunPath = "{0}/quad" -f $VMShellTestPath
        $RunShellResult = WTL-RunShellCommand `
            -VMNameList $VMNameList `
            -ShellCommand $ShellCommand `
            -RunPath $RunPath `
            -Timeout 18000

        if (-not $RunShellResult.result) {
            if ($ReturnValue.result) {
                $ReturnValue.result = $RunShellResult.result
                $ReturnValue.error = $RunShellResult.error
            }
        }

        Win-DebugTimestamp -output ("run performance sample test > {0}" -f $ReturnValue.result)
    } else {
        Win-DebugTimestamp -output (
            "Skip run performance sample test, because Error > {0}" -f $ReturnValue.error
        )
    }

    if ($ReturnValue.result) {
        $VMNameList | ForEach-Object {
            $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $_)
            $VMIP = HV-GetVMIPAddress -VMName $VMName
            $LocalShellOutputLogPath = "\\{0}\\STV-tmp\\{1}" -f
                $VMIP,
                $VMDriverInstallPath.ShellOutputLog

            if (-not (Test-Path -Path $LocalShellOutputLogPath)) {
                if ($ReturnValue.result) {
                    $ReturnValue.result = $false
                    $ReturnValue.error = "no_output"
                }
            }
        }
    }

    return $ReturnValue
}


Export-ModuleMember -Function *-*
