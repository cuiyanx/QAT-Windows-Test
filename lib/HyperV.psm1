
function HVConvertIecUnitToLong
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$IecValue
    )

    [int]$decValue = [regex]::Match($IecValue, "\d*").Value
    [string]$IecUnit = [regex]::Match($IecValue, "[A-Za-z]+").Value
    [int]$power = 1

    switch ($IecUnit) {
        "KiB" {
            $power = 1
        }
        "MiB" {
            $power = 2
        }
        "GiB" {
            $power = 3
        }
        "TiB" {
            $power = 4
        }
        default {
            return -1
        }
    }

    return ([long]($decValue * [math]::Pow(1024, $power)))
}

# About PSSession
# For Linux: SSH connection
#            The name of VM is not real-name, using IP address of VM
function HV-PSSessionCreate
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [string]$PSName,

        [bool]$IsWin = $true
    )

    HV-WaitVMToCompleted -VMName $VMName -Wait $false | out-null

    if ($IsWin) {
        $VMNameReal = $VMName
    } else {
        $VMNameReal = HV-GetVMIPAddress -VMName $VMName
        $KeyFilePath = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.PrivateKeyName
    }

    $PSSessionStatus = HV-PSSessionCheck -VMName $VMNameReal -PSName $PSName
    if (-not $PSSessionStatus.result) {
        if ($PSSessionStatus.exist) {
            HV-PSSessionRemove -PSName $PSName | out-null
        }

        Win-DebugTimestamp -output ("Create PS session named {0} for VM named {1}" -f $PSName, $VMNameReal)

        for ($i = 1; $i -lt 50; $i++) {
            try {
                if ($IsWin) {
                    New-PSSession `
                        -VMName $VMNameReal `
                        -Credential $WTWCredentials `
                        -Name $PSName | out-null
                } else {
                    New-PSSession `
                        -HostName $VMNameReal `
                        -UserName $RemoteUserConfig.RootName `
                        -KeyFilePath $KeyFilePath `
                        -Name $PSName | out-null
                }

                Start-Sleep -Seconds 5

                $PSSessionStatus = HV-PSSessionCheck -VMName $VMNameReal -PSName $PSName
                if ($PSSessionStatus.result) {
                    Win-DebugTimestamp -output ("Creating PS seesion is successful > {0}" -f $PSName)
                    break
                }
            } catch {
                Win-DebugTimestamp -output ("Creating PS seesion is failed and try again > {0}" -f $i)
                continue
            }
        }

        if ($IsWin) {
            $Session = Get-PSSession -name $PSName
            if (Invoke-Command -Session $Session -ScriptBlock {
                    Param($SiteKeep)
                    Test-Path -Path $SiteKeep.DumpFile
                } -ArgumentList $SiteKeep) {
                $Remote2HostDumpFile = "{0}\\dump_{1}.DMP" -f
                    $LocationInfo.BertaResultPath,
                    $VMNameReal.split("_")[1]
                Copy-Item -FromSession $Session `
                          -Path $SiteKeep.DumpFile `
                          -Destination $Remote2HostDumpFile `
                          -Force `
                          -Confirm:$false | out-null
            }
        }
    }

    return (Get-PSSession -name $PSName)
}

function HV-PSSessionRemove
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PSName
    )

    $PSSessionError = $null
    Remove-PSSession `
        -Name $PSName `
        -ErrorAction SilentlyContinue `
        -ErrorVariable ProcessError | out-null
}

function HV-PSSessionCheck
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [string]$PSName
    )

    $ReturnValue = [hashtable] @{
        result = $false
        exist = $false
    }

    $PSSessionError = $null
    $PSSession = Get-PSSession `
        -Name $PSName `
        -ErrorAction SilentlyContinue `
        -ErrorVariable ProcessError

    if ([String]::IsNullOrEmpty($PSSessionError)) {
        if ($PSSession.ComputerName -eq $VMName) {
            if ($PSSession.state -eq "Opened") {
                $ReturnValue.result = $true
            } else {
                $ReturnValue.result = $false
                $ReturnValue.exist = $true
            }
        } else {
            $ReturnValue.result = $false
            $ReturnValue.exist = $true
        }
    } else {
        $ReturnValue.result = $false
        $ReturnValue.exist = $false
    }

    return $ReturnValue
}

# About VMVFOSConfigs
function HV-GenerateVMVFConfig
{
    Param(
        [string]$ConfigType = "Base"
    )

    $ReturnValue = @()

    if ($LocationInfo.VM.IsWin) {
        if (($ConfigType -eq "SmokeTest") -or ($ConfigType -eq "Stress")) {
            $VMOSs = ("windows2022")
        } else {
            $VMOSs = ("windows2019", "windows2022")
        }
    } else {
        $VMOSs = ("ubuntu2004")
    }

    Foreach ($VMOS in $VMOSs) {
        if ($ConfigType -eq "Base") {
            $VMVFOSName = "3vm_{0}vf_{1}" -f $LocationInfo.PF.Number, $VMOS
            $ReturnValue += $VMVFOSName

            $AllVFs = $LocationInfo.PF.Number * $LocationInfo.PF2VF
            $VMNumber = [Math]::Truncate($AllVFs / 64)
            if ($VMNumber -gt 2) {$VMNumber = 2}
            $VMVFOSName = "{0}vm_64vf_{1}" -f $VMNumber, $VMOS
            $ReturnValue += $VMVFOSName
        } elseif ($ConfigType -eq "Performance") {
            $VMVFOSName = "3vm_{0}vf_{1}" -f ($LocationInfo.PF.Number * 2), $VMOS
            $ReturnValue += $VMVFOSName
        } elseif ($ConfigType -eq "PerfParameter") {
            $AllVFs = $LocationInfo.PF.Number * $LocationInfo.PF2VF
            $VMNumber = [Math]::Truncate($AllVFs / 64)
            if ($VMNumber -gt 2) {$VMNumber = 2}
            $VMVFOSName = "{0}vm_64vf_{1}" -f $VMNumber, $VMOS
            $ReturnValue += $VMVFOSName
        } elseif ($ConfigType -eq "SmokeTest") {
            $VMVFOSName = "3vm_{0}vf_{1}" -f $LocationInfo.PF.Number, $VMOS
            $ReturnValue += $VMVFOSName
        } elseif ($ConfigType -eq "Stress") {
            $VMVFOSName = "12vm_{0}vf_{1}" -f $LocationInfo.PF.Number, $VMOS
            $ReturnValue += $VMVFOSName
        } else {
            throw ("Can not generate VMVFOS configs > {0}" -f $ConfigType)
        }
    }

    return $ReturnValue
}

function HV-VMVFConfigInit
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMVFOSConfig
    )

    $LocationInfo.VM.Number = $null
    $LocationInfo.VF.Number = $null
    $LocationInfo.VM.OS = $null
    $LocationInfo.VM.CPU = 0
    $LocationInfo.VM.Memory = 0
    $LocationInfo.VM.HyperVGeneration = 0
    $LocationInfo.VM.Switch = $null
    $LocationInfo.VM.ImageName = $null
    $LocationInfo.VM.NameArray = [System.Array] @()
    $LocationInfo.VF.PFVFList = [hashtable] @{}

    if ([String]::IsNullOrEmpty($VMVFOSConfig)) {
        Win-DebugTimestamp -output ("Host: The config of 'VMVFOS' is not null for HV mode")
    } else {
        $HostVMs = $VMVFOSConfig.split("_")[0]
        $LocationInfo.VM.Number = [int]($HostVMs.Substring(0, $HostVMs.Length - 2))
        $HostVFs = $VMVFOSConfig.split("_")[1]
        $LocationInfo.VF.Number = [int]($HostVFs.Substring(0, $HostVFs.Length - 2))
        $LocationInfo.VM.OS = ($VMVFOSConfig.split("_")[2]).split(".")[0]
        $LocationInfo.VM.CPU = $LocationInfo.VF.Number
        $LocationInfo.VM.Memory = 32
        $LocationInfo.VM.HyperVGeneration = 1

        $LocationInfo.VM.Switch = HV-VMSwitchCreate -VMSwitchType "Internal"

        if ($LocationInfo.VM.OS -eq "windows2019") {$LocationInfo.VM.ImageName = "windows_server_2019_19624"}
        if ($LocationInfo.VM.OS -eq "windows2022") {$LocationInfo.VM.ImageName = "windows_server_2022_20348"}
        if ($LocationInfo.VM.OS -eq "ubuntu2004") {$LocationInfo.VM.ImageName = "ubuntu_20.04"}

        $VMCountArray = (1..$LocationInfo.VM.Number)
        $VMCountArray | ForEach-Object {
            $LocationInfo.VM.NameArray += "vm{0}" -f $_
        }

        $intPFCount = -1
        $intVFCount = -1
        $StartFlag = $true
        $LocationInfo.VM.NameArray | ForEach-Object {
            $PFVFArray = @()
            $VFCount = 0
            for ($intVF = 0; $intVF -lt $LocationInfo.PF2VF; $intVF++) {
                for ($intPF = 0; $intPF -lt $LocationInfo.PF.Number; $intPF++) {
                    if (($intVF -eq $intVFCount) -and ($intPF -eq $intPFCount)) {
                        $StartFlag = $true
                        continue
                    }

                    if ($StartFlag) {
                        $PFVFArray += [hashtable] @{
                            PF = $intPF
                            VF = $intVF
                        }
                        $VFCount += 1

                        if ($VFCount -eq $LocationInfo.VF.Number) {
                            $StartFlag = $false
                            $intPFCount = $intPF
                            $intVFCount = $intVF
                        }
                    }
                }
            }

            $LocationInfo.VF.PFVFList[$_] = $PFVFArray
        }

        <#
        $LocationInfo.VM.NameArray | ForEach-Object {
            write-host ("--------{0}" -f $_)
            $LocationInfo.VF.PFVFList[$_] | ForEach-Object {
                write-host ("{0} : {1}" -f $_.PF, $_.VF)
            }
        }
        #>

        Win-DebugTimestamp -output ("      VFNumber : {0}" -f $LocationInfo.VF.Number)
        Win-DebugTimestamp -output ("      VMNumber : {0}" -f $LocationInfo.VM.Number)
        Win-DebugTimestamp -output ("          VMOS : {0}" -f $LocationInfo.VM.OS)
        Win-DebugTimestamp -output ("   VMImageName : {0}" -f $LocationInfo.VM.ImageName)
        Win-DebugTimestamp -output ("      VMSwitch : {0}" -f $LocationInfo.VM.Switch)
        Win-DebugTimestamp -output ("      VMMemory : {0}" -f $LocationInfo.VM.Memory)
        Win-DebugTimestamp -output ("         VMCPU : {0}" -f $LocationInfo.VM.CPU)
    }
}

# About VM
function HV-GetVMIPAddress
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName
    )

    $ReturnValue = $null

    $IPAddressArray = Get-VMNetworkAdapter -VMName $VMName
    if ([String]::IsNullOrEmpty($IPAddressArray)) {
        throw ("Can not get IP address > {0}" -f $VMName)
    } else {
        $ReturnValue = $IPAddressArray.IPAddresses[0]
    }

    return $ReturnValue
}

function HV-WaitVMToCompleted
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [string]$VMState = "start",

        [bool]$Wait = $true
    )

    $StopFlag = $true
    $TimeoutFlag = $false
    $TimeInterval = 5
    $SleepTime = 0
    $Time = 1000

    if ($VMState -eq "start") {
        $VMStateFlag = "Running"
    }

    if ($VMState -eq "stop") {
        $VMStateFlag = "Off"
    }

    do {
        Start-Sleep -Seconds $TimeInterval
        $SleepTime += $TimeInterval

        if ($SleepTime -ge $Time) {
            $TimeoutFlag = $true
            $StopFlag = $false
        } else {
             if ((get-vm -name $VMName).State -eq $VMStateFlag) {
                 $StopFlag = $false
             }
        }
    } while ($StopFlag)

    if ($TimeoutFlag) {
        Win-DebugTimestamp -output ("{0} VM '{1}' is false > timeout" -f $VMState, $VMName)
        return $false
    }

    if ($Wait) {
        Start-Sleep -Seconds 60
    }

    return $true
}

function HV-RestartVMHard
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [bool]$StopFlag = $true,

        [bool]$TurnOff = $true,

        [bool]$StartFlag = $true,

        [bool]$WaitFlag = $true
    )

    if ($StopFlag) {
        Win-DebugTimestamp -output ("Stop VM > {0}" -f $VMName)

        if ($TurnOff) {
            Stop-VM -Name $VMName -Force -TurnOff -Confirm:$false -ErrorAction stop | out-null
        } else {
            Stop-VM -Name $VMName -Force -Confirm:$false -ErrorAction stop | out-null
        }
    }

    if ($WaitFlag) {
        Start-Sleep -Seconds 60
    }

    if ($StartFlag) {
        Win-DebugTimestamp -output ("Start VM > {0}" -f $VMName)

        Start-VM -Name $VMName -Confirm:$false -ErrorAction stop | out-null
    }

    if ($WaitFlag) {
        Start-Sleep -Seconds 100
    }
}

function HV-RestartVMSoft
{
    Param(
        [Parameter(Mandatory=$True)]
        [object]$Session
    )

    Win-DebugTimestamp -output ("{0}: Restart the VM" -f $Session.Name)

    Invoke-Command -Session $Session -ScriptBlock {
        shutdown -r -t 0
    } | out-null
}

function HV-CreateVM
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMNameSuffix
    )

    $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $VMNameSuffix)
    $ParentsVM = "{0}\{1}.vhdx" -f
        $VHDAndTestFiles.ParentsVMPath,
        $LocationInfo.VM.ImageName
    $ChildVM = "{0}\\{1}.vhdx" -f $VHDAndTestFiles.ChildVMPath, $VMName

    Win-DebugTimestamp -output ("Create new VM named {0}" -f $VMName)

    try {
        if ([System.IO.File]::Exists($ParentsVM)) {
            Win-DebugTimestamp -output ("Use local Vhd file ({0})" -f $ParentsVM)
        } else {
            Win-DebugTimestamp -output (
                "Copy Vhd file ({0}.vhdx) from remote {1}" -f
                    $LocationInfo.VM.ImageName,
                    $VHDAndTestFiles.SourceVMPath
            )

            $BertaSource = "{0}\\{1}.vhdx" -f
                $VHDAndTestFiles.SourceVMPath,
                $LocationInfo.VM.ImageName
            $BertaDestination = "{0}\\{1}.vhdx" -f
                $VHDAndTestFiles.ParentsVMPath,
                $LocationInfo.VM.ImageName

            Copy-Item `
                -Path $BertaSource `
                -Destination $BertaDestination `
                -Force `
                -ErrorAction Stop | out-null
        }

        Win-DebugTimestamp -output (
            "Create child VHD {0} from parent VHD {1}" -f $ChildVM, $ParentsVM
        )

        New-VHD `
            -ParentPath $ParentsVM `
            -Path $ChildVM `
            -Differencing `
            -ErrorAction Stop | out-null

        $VMMemory = HVConvertIecUnitToLong -IecValue $LocationInfo.VM.Memory

        Win-DebugTimestamp -output (
            "Create new VM instance {0}, {1}, generation {2}" -f
                $VMName,
                $VMMemory,
                $LocationInfo.VM.HyperVGeneration
        )

        New-VM `
            -Name $VMName `
            -MemoryStartupBytes $VMMemory `
            -VHDPath $ChildVM `
            -Generation $LocationInfo.VM.HyperVGeneration `
            -SwitchName $LocationInfo.VM.Switch | out-null

        Set-VM `
            -Name $VMName `
            -ProcessorCount $LocationInfo.VM.CPU `
            -AutomaticStopAction TurnOff `
            -ErrorAction Stop | out-null

        if ($LocationInfo.VM.HyperVGeneration -eq 2) {
            Set-VMFirmware `
                -Name $VMName `
                -EnableSecureBoot Off `
                -ErrorAction Stop | out-null
        }

        HV-AssignableDeviceAdd `
            -VMName $VMName `
            -PFVFArray $LocationInfo.VF.PFVFList[$VMNameSuffix] | out-null
        $CheckResult = HV-AssignableDeviceCheck `
            -VMName $VMName `
            -PFVFArray $LocationInfo.VF.PFVFList[$VMNameSuffix]
        if (-not $CheckResult) {
            throw ("Double check device number is failed")
        }
    } catch {
        Win-DebugTimestamp -output ("Caught error > {0}" -f $_)
    }
}

function HV-RemoveVM
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName
    )

    if (Test-Path -Path $VHDAndTestFiles.ChildVMPath) {
        $VM = Get-VM -Name $VMName
        if (-not [String]::IsNullOrEmpty($VM)) {
            $VMParentPathName = Split-Path -Parent $VM.HardDrives.Path
            if ($VMParentPathName -eq $VHDAndTestFiles.ChildVMPath) {
                if ($VM.State -ne "off") {
                    HV-RestartVMHard `
                        -VMName $VMName `
                        -StopFlag $true `
                        -TurnOff $true `
                        -StartFlag $false `
                        -WaitFlag $false
                }

                Win-DebugTimestamp -output ("Removing VM named {0}" -f $VM.Name)
                Remove-VM -Name $VM.Name -Force -Confirm:$false | out-null
                Remove-Item -Path $VM.HardDrives.Path -Force -Confirm:$false | out-null
            }
        }
    }
}

# About VM switch
function HV-VMSwitchCreate
{
    Param(
        [string]$VMSwitchType = "Internal"
    )

    $ReturnValue = $STVNetNat.SwitchInternal

    if ($VMSwitchType -eq "Internal") {
        $GetVMSwitchError = $null
        $VMSwitch = Get-VMSwitch `
            -Name $STVNetNat.SwitchInternal `
            -SwitchType $VMSwitchType `
            -ErrorAction SilentlyContinue `
            -ErrorVariable GetVMSwitchError

        if ([String]::IsNullOrEmpty($GetVMSwitchError)) {
            $InterfaceIndex = Get-NetAdapter | ForEach-Object {
                if ($_.Name -match $VMSwitchType) {return $_.ifIndex}
            }

            $NetIPAddress = Get-NetIPAddress `
                -InterfaceIndex $InterfaceIndex `
                -AddressFamily IPv4

            $NetIPAddress = $NetIPAddress.IPAddress
            if ($NetIPAddress -ne $STVNetNat.HostIP) {
                Remove-NetIPAddress `
                    -InterfaceIndex $InterfaceIndex `
                    -Confirm:$false `
                    -ErrorAction Stop | Out-Null

                Remove-NetRoute `
                    -InterfaceIndex $InterfaceIndex `
                    -Confirm:$false `
                    -ErrorAction Stop | Out-Null

                New-NetIPAddress `
                    -InterfaceIndex $InterfaceIndex `
                    -IPAddress $STVNetNat.HostIP `
                    -AddressFamily IPv4 `
                    -PrefixLength 24 `
                    -DefaultGateway $STVNetNat.GateWay `
                    -Confirm:$false `
                    -ErrorAction Stop | Out-Null
            }

            Win-DebugTimestamp -output ("Host: Get VM switch(Internal) named {0}" -f $STVNetNat.SwitchInternal)
            $ReturnValue = $STVNetNat.SwitchInternal
        } else {
            New-VMSwitch `
                -Name $STVNetNat.SwitchInternal `
                -SwitchType $VMSwitchType `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null

            $InterfaceIndex = Get-NetAdapter | ForEach-Object {
                if ($_.Name -match $VMSwitchType) {return $_.ifIndex}
            }

            New-NetIPAddress `
                -InterfaceIndex $InterfaceIndex `
                -IPAddress $STVNetNat.HostIP `
                -AddressFamily IPv4 `
                -PrefixLength 24 `
                -DefaultGateway $STVNetNat.GateWay `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null

            Win-DebugTimestamp -output ("Host: Create VM switch(Internal) named {0}" -f $STVNetNat.SwitchInternal)
            $ReturnValue = $STVNetNat.SwitchInternal
        }
    }

    if ($VMSwitchType -eq "External") {
        $GetVMSwitchError = $null
        $VMSwitch = Get-VMSwitch `
            -Name $STVNetNat.SwitchExternal `
            -SwitchType $VMSwitchType `
            -ErrorAction SilentlyContinue `
            -ErrorVariable GetVMSwitchError

        if ([String]::IsNullOrEmpty($GetVMSwitchError)) {
            Win-DebugTimestamp -output ("Host: Get VM switch(External) named {0}" -f $STVNetNat.SwitchExternal)
        } else {
            $HostNetwork =  Get-NetIPAddress | Where-Object {
                $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" -and $_.InterfaceAlias -notmatch "vEthernet"
            }

            if ($HostNetwork.length -ge 1) {
                $VMSwitchList = Get-VMSwitch -SwitchType $VMSwitchType
                if ($VMSwitchList.length -ge 1) {
                    Win-DebugTimestamp -output ("Host: Rename VM switch(External) to {0}" -f $STVNetNat.SwitchExternal)
                    try {
                        Rename-VMSwitch `
                            -VMSwitch $VMSwitchList[0] `
                            -NewName $STVNetNat.SwitchExternal `
                            -Confirm:$false `
                            -ErrorAction Stop | Out-Null
                    } catch {
                        throw ("Error: Rename VM switch(External) > {0}" -f $STVNetNat.SwitchExternal)
                    }
                } else {
                    Win-DebugTimestamp -output ("Host: Create VM switch(External) named {0}" -f $STVNetNat.SwitchExternal)
                    $HostNetwork = $HostNetwork[0]
                    $HostAdapter = Get-NetAdapter -Name $HostNetwork.InterfaceAlias

                    try {
                        New-VMSwitch `
                            -Name $STVNetNat.SwitchExternal `
                            -NetAdapterInterfaceDescription $HostAdapter.InterfaceDescription `
                            -Confirm:$false `
                            -ErrorAction Stop | Out-Null
                    } catch {
                        throw ("Error: Create VM switch(External) > {0}" -f $STVNetNat.SwitchExternal)
                    }
                }
            } else {
                throw ("Error: Can not create VM switch, because no network on host")
            }
        }

        $ReturnValue = $STVNetNat.SwitchExternal
    }

    return $ReturnValue
}

# About VF
function HV-AssignableDeviceAdd
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [array]$PFVFArray
    )

    HV-AssignableDeviceRemove -VMName $VMName | out-null

    $PFVFArray | ForEach-Object {
        ForEach ($localPath in $LocationInfo.PF.PCI) {
            if ($localPath[0] -eq $_.PF) {
                try {
                    Win-DebugTimestamp -output (
                        "Adding QAT VF with InstancePath {0} and VF# {1}" -f
                            $localPath[1], $_.VF
                    )

                    Add-VMAssignableDevice `
                        -VMName $VMName `
                        -LocationPath $localPath[1] `
                        -VirtualFunction $_.VF | out-null
                } catch {
                    throw ("Error: Assigning qat device > {0}" -f $localPath[1])
                }
            }
        }
    }
}

function HV-AssignableDeviceRemove
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName
    )

    Remove-VMAssignableDevice -Verbose -VMName $VMName | out-null
}

function HV-AssignableDeviceCheck
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [array]$PFVFArray
    )

    $ReturnValue = $true

    $TargetDevNember = $PFVFArray.Length
    $CheckDevNember = (Get-VMAssignableDevice -VMName $VMName).Length
    $ReturnValue = ($TargetDevNember -eq $CheckDevNember) ? $true : $false

    if ($ReturnValue) {
        Win-DebugTimestamp -output ("Double check assignable VF number is correct")
    } else {
        Win-DebugTimestamp -output ("Double check assignable VF number is incorrect")
    }

    return $ReturnValue
}


Export-ModuleMember -Function *-*
