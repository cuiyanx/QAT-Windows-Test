
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
        [object]$VMConfig,

        [Parameter(Mandatory=$True)]
        [string]$VMSwitch
    )

    $VMName = ("{0}_{1}" -f $env:COMPUTERNAME, $VMConfig.Name)
    $ParentsVM = "{0}\{1}.vhdx" -f
        $VHDAndTestFiles.ParentsVMPath,
        $VMConfig.VmType
    $ChildVM = "{0}\\{1}.vhdx" -f $VHDAndTestFiles.ChildVMPath, $VMName

    Win-DebugTimestamp -output ("Create new VM named {0}" -f $VMName)

    try {
        if ([System.IO.File]::Exists($ParentsVM)) {
            Win-DebugTimestamp -output ("Use local Vhd file ({0})" -f $VMConfig.VmType)
        } else {
            Win-DebugTimestamp -output (
                "Copy Vhd file ({0}) from remote {1}" -f
                    $VMConfig.VmType,
                    $VHDAndTestFiles.SourceVMPath
            )

            $BertaSource = "{0}\\{1}" -f
                $VHDAndTestFiles.SourceVMPath,
                $VMConfig.VmType
            $BertaDestination = "{0}\\{1}" -f
                $VHDAndTestFiles.ParentsVMPath,
                $VMConfig.VmType

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

        $vMemory = HVConvertIecUnitToLong -IecValue $VMConfig.VMemory

        Win-DebugTimestamp -output (
            "Create new VM instance {0}, {1}, generation {2}" -f
                $VMName,
                $vMemory,
                $VMConfig.HyperVGeneration
        )

        $vm = New-VM `
            -Name $VMName `
            -MemoryStartupBytes $vMemory `
            -VHDPath $ChildVM `
            -Generation $VMConfig.HyperVGeneration `
            -SwitchName $VMSwitch

        Set-VM `
            -Name $VMName `
            -ProcessorCount $VMConfig.Vcpu `
            -AutomaticStopAction TurnOff `
            -ErrorAction Stop | out-null

        if ($VMConfig.HyperVGeneration -eq 2) {
            Set-VMFirmware `
                -Name $VMName `
                -EnableSecureBoot Off `
                -ErrorAction Stop | out-null
        }

        HV-AssignableDeviceAdd -VMName $VMName -QatVF $VMConfig.QatVF
        $CheckResult = HV-AssignableDeviceCheck -VMName $VMName -QatVF $VMConfig.QatVF
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
    $ReturnValue = $VMSwitch_Name_Internal

    # Remove all netnats
    $GetNetNatError = $null
    $GetNetNats = Get-NetNat `
        -ErrorAction SilentlyContinue `
        -ErrorVariable GetNetNatError

    if ([String]::IsNullOrEmpty($GetNetNatError)) {
        foreach ($GetNetNat in $GetNetNats) {
            Remove-NetNat `
                -Name $GetNetNat.Name `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }
    }

    $VMSwitchType = "Internal"
    $GetVMSwitchError = $null
    $VMSwitch = Get-VMSwitch `
        -Name $VMSwitch_Name_Internal `
        -SwitchType $VMSwitchType `
        -ErrorAction SilentlyContinue `
        -ErrorVariable GetVMSwitchError
    if ([String]::IsNullOrEmpty($GetVMSwitchError)) {
        Win-DebugTimestamp -output ("Host: Get VM switch(Internal) named {0}" -f $VMSwitch_Name_Internal)
        $ReturnValue = $VMSwitch_Name_Internal
    } else {
        $VMSwitchType = "External"
        $GetVMSwitchError = $null
        $VMSwitch = Get-VMSwitch `
            -Name $VMSwitch_Name_External `
            -SwitchType $VMSwitchType `
            -ErrorAction SilentlyContinue `
            -ErrorVariable GetVMSwitchError
        if ([String]::IsNullOrEmpty($GetVMSwitchError)) {
            Win-DebugTimestamp -output ("Host: Get VM switch(External) named {0}" -f $VMSwitch_Name_External)
        } else {
            $HostNetwork =  Get-NetIPAddress | Where-Object {
                $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" -and $_.InterfaceAlias -notmatch "vEthernet"
            }

            if ($HostNetwork.length -ge 1) {
                $VMSwitchList = Get-VMSwitch -SwitchType $VMSwitchType
                if ($VMSwitchList.length -ge 1) {
                    Win-DebugTimestamp -output ("Host: Rename VM switch(External) to {0}" -f $VMSwitch_Name_External)
                    try {
                        Rename-VMSwitch `
                            -VMSwitch $VMSwitchList[0] `
                            -NewName $VMSwitch_Name_External `
                            -Confirm:$false `
                            -ErrorAction Stop | Out-Null
                    } catch {
                        throw ("Error: Rename VM switch(External) > {0}" -f $VMSwitch_Name_External)
                    }
                } else {
                    Win-DebugTimestamp -output ("Host: Create VM switch(External) named {0}" -f $VMSwitch_Name_External)
                    $HostNetwork = $HostNetwork[0]
                    $HostAdapter = Get-NetAdapter -Name $HostNetwork.InterfaceAlias

                    try {
                        New-VMSwitch `
                            -Name $VMSwitch_Name_External `
                            -NetAdapterInterfaceDescription $HostAdapter.InterfaceDescription `
                            -Confirm:$false `
                            -ErrorAction Stop | Out-Null
                    } catch {
                        throw ("Error: Create VM switch(External) > {0}" -f $VMSwitch_Name_External)
                    }
                }
            } else {
                throw ("Error: Can not create VM switch, because no network on host")
            }
        }

        $ReturnValue = $VMSwitch_Name_External
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
        [System.Object]$QatVF
    )

    HV-AssignableDeviceRemove -VMName $VMName | out-null

    $QatVF | ForEach-Object {
        ForEach ($localPath in $LocationInfo.PF.PCI) {
            if ($localPath[0] -eq $_[0]) {
                try {
                    Win-DebugTimestamp -output (
                        "Adding QAT VF with InstancePath {0} and VF# {1}" -f
                            $localPath[1], $_[1]
                    )

                    Add-VMAssignableDevice `
                        -VMName $VMName `
                        -LocationPath $localPath[1] `
                        -VirtualFunction $_[1] | out-null
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
        [System.Object]$QatVF
    )

    $ReturnValue = $true

    $TargetDevNember = $QatVF.Length
    $CheckDevNember = (Get-VMAssignableDevice -VMName $VMName).Length
    $ReturnValue = ($TargetDevNember -eq $CheckDevNember) ? $true : $false

    if ($ReturnValue) {
        Win-DebugTimestamp -output ("Double check device number is successful")
    } else {
        Win-DebugTimestamp -output ("Double check device number is failed")
    }

    return $ReturnValue
}


Export-ModuleMember -Function *-*
