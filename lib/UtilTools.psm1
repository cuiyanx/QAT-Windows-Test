
# About tracelog tool
function UT-TraceLogStart
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $TraceLogCheckFlags = [System.Array] @()
    $TraceLogCheckFlags += "IcpQat"

    if ($Remote) {
        $LogKeyWord = $Session.Name
        $TraceLogType = "Remote"
        $TraceLogCheckFlags += "CfQat"
    } else {
        $LogKeyWord = "Host"
        $TraceLogType = "Host"
        if (-not $LocationInfo.HVMode) {$TraceLogCheckFlags += "CfQat"}
    }

    Win-DebugTimestamp -output ("{0}: Start tracelog tool..." -f $LogKeyWord)

    if ($Remote) {
        $TraceLogCheckStatus = Invoke-Command -Session $Session -ScriptBlock {
            Param($TraceLogCheckFlags, $TraceLogOpts)
            $ReturnValue = [hashtable] @{}

            ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
                $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag]
                $StartFlag = $true

                if ($checkProcess[0] -match "successfully") {
                    if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                        &$TraceLogOpts.ExePath -flush $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag] | out-null
                        $StartFlag = $false
                    } else {
                        &$TraceLogOpts.ExePath -stop $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag] | out-null
                        $StartFlag = $true
                        Start-Sleep -Seconds 5
                    }
                }

                if ($StartFlag) {
                    &$TraceLogOpts.ExePath `
                        -start $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag] `
                        -f $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag] `
                        -guid $TraceLogOpts.Guid[$TraceLogCheckFlag] `
                        -rt `
                        -level 3 `
                        -matchanykw 0xFFFFFFFF `
                        -b 200 `
                        -ft 1 `
                        -min 4 `
                        -max 21 `
                        -seq 200 `
                        -hybridshutdown stop | out-null
                }

                $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag]
                if ($checkProcess[0] -match "successfully") {
                    if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                        $ReturnValue[$TraceLogCheckFlag] = $true
                    } else {
                        $ReturnValue[$TraceLogCheckFlag] = $false
                    }
                } else {
                    $ReturnValue[$TraceLogCheckFlag] = $false
                }
            }

            return $ReturnValue
        } -ArgumentList $TraceLogCheckFlags, $TraceLogOpts
    } else {
        $TraceLogCheckStatus = [hashtable] @{}
        ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
            $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag]
            $StartFlag = $true

            if ($checkProcess[0] -match "successfully") {
                if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                    &$TraceLogOpts.ExePath -flush $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag] | out-null
                    $StartFlag = $false
                } else {
                    &$TraceLogOpts.ExePath -stop $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag] | out-null
                    $StartFlag = $true
                    Start-Sleep -Seconds 5
                }
            }

            if ($StartFlag) {
                &$TraceLogOpts.ExePath `
                    -start $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag] `
                    -f $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag] `
                    -guid $TraceLogOpts.Guid[$TraceLogCheckFlag] `
                    -rt `
                    -level 4 `
                    -matchanykw 0xFFFFFFFF `
                    -b 200 `
                    -ft 1 `
                    -min 4 `
                    -max 21 `
                    -seq 200 `
                    -hybridshutdown stop | out-null
            }

            $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag]
            if ($checkProcess[0] -match "successfully") {
                if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $true
                } else {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
                }
            } else {
                $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
            }
        }
    }

    ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
        if ($TraceLogCheckStatus[$TraceLogCheckFlag]) {
            Win-DebugTimestamp -output (
                "{0}: The process named '{1}' is working" -f
                    $LogKeyWord,
                    $TraceLogOpts.SessionName[$TraceLogType][$TraceLogCheckFlag]
            )
        } else {
            Win-DebugTimestamp -output (
                "{0}: The process named '{1}' is not working" -f
                    $LogKeyWord,
                    $TraceLogOpts.SessionName[$TraceLogType][$TraceLogCheckFlag]
            )
        }
    }
}

function UT-TraceLogStop
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $TraceLogCheckFlags = [System.Array] @()
    $TraceLogCheckFlags += "IcpQat"

    if ($Remote) {
        $LogKeyWord = $Session.Name
        $TraceLogType = "Remote"
        $TraceLogCheckFlags += "CfQat"
    } else {
        $LogKeyWord = "Host"
        $TraceLogType = "Host"
        if (-not $LocationInfo.HVMode) {$TraceLogCheckFlags += "CfQat"}
    }

    Win-DebugTimestamp -output ("{0}: Stop tracelog tool..." -f $LogKeyWord)

    if ($Remote) {
        $TraceLogCheckStatus = Invoke-Command -Session $Session -ScriptBlock {
            Param($TraceLogCheckFlags, $TraceLogOpts)
            $ReturnValue = [hashtable] @{}

            ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
                $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag]
                if ($checkProcess[0] -match "successfully") {
                    &$TraceLogOpts.ExePath -stop $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag] | out-null
                    Start-Sleep -Seconds 5
                }

                $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Remote[$TraceLogCheckFlag]
                if ($checkProcess[0] -match "recognized") {
                    if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                        $ReturnValue[$TraceLogCheckFlag] = $true
                    } else {
                        $ReturnValue[$TraceLogCheckFlag] = $false
                    }
                } else {
                    $ReturnValue[$TraceLogCheckFlag] = $false
                }
            }

            return $ReturnValue
        } -ArgumentList $TraceLogCheckFlags, $TraceLogOpts
    } else {
        $TraceLogCheckStatus = [hashtable] @{}
        ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
            $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag]
            if ($checkProcess[0] -match "successfully") {
                &$TraceLogOpts.ExePath -stop $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag] | out-null
                Start-Sleep -Seconds 5
            }

            $checkProcess = &$TraceLogOpts.ExePath -q $TraceLogOpts.SessionName.Host[$TraceLogCheckFlag]
            if ($checkProcess[0] -match "recognized") {
                if (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag]) {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $true
                } else {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
                }
            } else {
                $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
            }
        }
    }

    ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
        if ($TraceLogCheckStatus[$TraceLogCheckFlag]) {
            Win-DebugTimestamp -output (
                "{0}: The process named '{1}' is stopped" -f
                    $LogKeyWord,
                    $TraceLogOpts.SessionName[$TraceLogType][$TraceLogCheckFlag]
            )
        } else {
            Win-DebugTimestamp -output (
                "{0}: The process named '{1}' is not stopped" -f
                    $LogKeyWord,
                    $TraceLogOpts.SessionName[$TraceLogType][$TraceLogCheckFlag]
            )
        }
    }
}

function UT-TraceLogTransfer
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $TraceLogCheckFlags = [System.Array] @()
    $TraceLogCheckFlags += "IcpQat"

    if ($Remote) {
        $LogKeyWord = $Session.Name
        $TraceLogType = "Remote"
        $TraceLogCheckFlags += "CfQat"
    } else {
        $LogKeyWord = "Host"
        $TraceLogType = "Host"
        if (-not $LocationInfo.HVMode) {$TraceLogCheckFlags += "CfQat"}
    }

    Win-DebugTimestamp -output ("{0}: Transfer events to log..." -f $LogKeyWord)

    if ($Remote) {
        $TraceLogCheckStatus = Invoke-Command -Session $Session -ScriptBlock {
            Param($TraceLogCheckFlags, $TraceLogOpts)
            $ReturnValue = [hashtable] @{}

            $CommandArgs = "-f {0}\\*.pdb -p {1} 2>&1" -f
                $TraceLogOpts.PDBPath,
                $TraceLogOpts.FMTPath
            Start-Process -FilePath  $TraceLogOpts.PDBExePath `
                          -ArgumentList $CommandArgs `
                          -NoNewWindow `
                          -Wait | out-null

            ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
                $ReturnValue[$TraceLogCheckFlag] = $true
                if (-not (Test-Path -Path $TraceLogOpts.PDBFullPath[$TraceLogCheckFlag])) {
                    $ReturnValue[$TraceLogCheckFlag] = $false
                }

                if (-not (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag])) {
                    $ReturnValue[$TraceLogCheckFlag] = $false
                }

                if ($ReturnValue[$TraceLogCheckFlag]) {
                    $CommandArgs = "{0} -p {1} -o {2} -nosummary" -f
                        $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag],
                        $TraceLogOpts.FMTPath,
                        $TraceLogOpts.LogFullPath[$TraceLogCheckFlag]
                    Start-Process -FilePath  $TraceLogOpts.FMTExePath `
                                  -ArgumentList $CommandArgs `
                                  -NoNewWindow `
                                  -Wait | out-null

                    if (Test-Path -Path $TraceLogOpts.LogFullPath[$TraceLogCheckFlag]) {
                        $ReturnValue[$TraceLogCheckFlag] = $true
                    } else {
                        $ReturnValue[$TraceLogCheckFlag] = $false
                    }
                }
            }

            return $ReturnValue
        } -ArgumentList $TraceLogCheckFlags, $TraceLogOpts
    } else {
        $CommandArgs = "-f {0}\\*.pdb -p {1} 2>&1" -f
            $TraceLogOpts.PDBPath,
            $TraceLogOpts.FMTPath
        Start-Process -FilePath  $TraceLogOpts.PDBExePath `
                      -ArgumentList $CommandArgs `
                      -NoNewWindow `
                      -Wait | out-null

        $TraceLogCheckStatus = [hashtable] @{}
        ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
            $TraceLogCheckStatus[$TraceLogCheckFlag] = $true
            if (-not (Test-Path -Path $TraceLogOpts.PDBFullPath[$TraceLogCheckFlag])) {
                $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
            }

            if (-not (Test-Path -Path $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag])) {
                $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
            }

            if ($TraceLogCheckStatus[$TraceLogCheckFlag]) {
                $CommandArgs = "{0} -p {1} -o {2} -nosummary" -f
                    $TraceLogOpts.EtlFullPath[$TraceLogCheckFlag],
                    $TraceLogOpts.FMTPath,
                    $TraceLogOpts.LogFullPath[$TraceLogCheckFlag]
                Start-Process -FilePath  $TraceLogOpts.FMTExePath `
                              -ArgumentList $CommandArgs `
                              -NoNewWindow `
                              -Wait | out-null

                if (Test-Path -Path $TraceLogOpts.LogFullPath[$TraceLogCheckFlag]) {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $true
                } else {
                    $TraceLogCheckStatus[$TraceLogCheckFlag] = $false
                }
            }
        }
    }

    ForEach ($TraceLogCheckFlag in $TraceLogCheckFlags) {
        if ($TraceLogCheckStatus[$TraceLogCheckFlag]) {
            Win-DebugTimestamp -output (
                "{0}: The transfer is successful > {1}" -f
                    $LogKeyWord,
                    $TraceLogOpts.LogFullPath[$TraceLogCheckFlag]
            )
        } else {
            Win-DebugTimestamp -output (
                "{0}: The transfer is unsuccessful" -f $LogKeyWord
            )
        }
    }
}

function UT-TraceLogCheck
{
    $ReturnValue = $true

    UT-TraceLogStop -Remote $false | out-null
    UT-TraceLogTransfer -Remote $false | out-null
    $TraceViewContent = Get-Content -Path $TraceLogOpts.LogFullPath.IcpQat

    Foreach ($Number in (0 .. ($LocationInfo.PF.Number - 1))) {
        $startQatDevice = "qat_dev{0} started" -f $Number
        $stopQatDevice = "qat_dev{0} stopped" -f $Number

        if (-not ($TraceViewContent -match $startQatDevice)) {$ReturnValue = $false}
        if (-not ($TraceViewContent -match $stopQatDevice)) {$ReturnValue = $false}
    }

    return $ReturnValue
}

# About driver verifier
function UT-SetDriverVerifier
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$DriverVerifier,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $false

    if ($Remote) {
        $LogKeyWord = $Session.Name
    } else {
        $LogKeyWord = "Host"
    }

    Win-DebugTimestamp -output (
        "{0}: Set driver verifier > {1}" -f $LogKeyWord, $DriverVerifier
    )

    if ($Remote) {
        $RemoteReturnValue = Invoke-Command -Session $Session -ScriptBlock {
            Param($DriverVerifierArgs, $DriverVerifier)
            $VerifierReturn = $false

            if ($DriverVerifier) {
                $VerifierOutput = &$DriverVerifierArgs.ExePath $DriverVerifierArgs.Start.split() $DriverVerifierArgs.Servers.split()
            } else {
                $VerifierOutput = &$DriverVerifierArgs.ExePath $DriverVerifierArgs.Delete.split()
            }

            $VerifierOutput | ForEach-Object {
                if ($_ -match $DriverVerifierArgs.SuccessLog) {$VerifierReturn = $true}
                if ($_ -match $DriverVerifierArgs.NoChangeLog) {$VerifierReturn = $true}
            }

            return $VerifierReturn
        } -ArgumentList $DriverVerifierArgs, $DriverVerifier

        $ReturnValue = $RemoteReturnValue
    } else {
        if ($DriverVerifier) {
            $VerifierCommand = "{0} {1} {2}" -f
                $DriverVerifierArgs.ExePath,
                $DriverVerifierArgs.Start,
                $DriverVerifierArgs.Servers
        } else {
            $VerifierCommand = "{0} {1}" -f
                $DriverVerifierArgs.ExePath,
                $DriverVerifierArgs.Delete
        }

        $VerifierOutput = Invoke-Expression $VerifierCommand 2>&1
        $VerifierOutput | ForEach-Object {
            if ($_ -match $DriverVerifierArgs.SuccessLog) {$ReturnValue = $true}
            if ($_ -match $DriverVerifierArgs.NoChangeLog) {$ReturnValue = $true}
        }
    }

    return $ReturnValue
}

function UT-CheckDriverVerifier
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$CheckFlag,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $false

    if ($Remote) {
        $LogKeyWord = $Session.Name
    } else {
        $LogKeyWord = "Host"
    }

    if ($Remote) {
        $Verifier = Invoke-Command -Session $Session -ScriptBlock {
            Param($DriverVerifierArgs)
            $Verifier = $true
            $MessageFlag = $false

            $VerifierOutput = &$DriverVerifierArgs.ExePath $DriverVerifierArgs.List.split() 2>&1
            $VerifierOutput | ForEach-Object {
                if ($MessageFlag) {
                    if ($_ -match "None") {
                        $Verifier = $false
                    }
                }

                if ($_ -match "Verified Drivers") {
                    $MessageFlag = $true
                }
            }
            return $Verifier
        } -ArgumentList $DriverVerifierArgs
    } else {
        $Verifier = $true
        $MessageFlag = $false
        $VerifierCommand = "{0} {1}" -f
            $DriverVerifierArgs.ExePath,
            $DriverVerifierArgs.List

        $VerifierOutput = Invoke-Expression $VerifierCommand 2>&1
        $VerifierOutput | ForEach-Object {
            if ($MessageFlag) {
                if ($_ -match "None") {
                    $Verifier = $false
                }
            }

            if ($_ -match "Verified Drivers") {
                $MessageFlag = $true
            }
        }
    }

    $ReturnValue = ($CheckFlag -eq $Verifier) ? $true : $false

    Win-DebugTimestamp -output (
        "{0}: Check driver verifier > {1}" -f $LogKeyWord, $ReturnValue
    )

    return $ReturnValue
}

# About bcdedit
function UTSetBCDEDITValue
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$BCDEDITKey,

        [Parameter(Mandatory=$True)]
        [string]$BCDEDITValue,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $false

    if ($Remote) {
        $SetStatusLog = Invoke-Command -Session $Session -ScriptBlock {
            Param($BCDEDITKey, $BCDEDITValue)
            bcdedit -set $BCDEDITKey $BCDEDITValue
        } -ArgumentList $BCDEDITKey, $BCDEDITValue
    } else {
        $SetStatusLog = Invoke-Command -ScriptBlock {
            Param($BCDEDITKey, $BCDEDITValue)
            bcdedit -set $BCDEDITKey $BCDEDITValue
        } -ArgumentList $BCDEDITKey, $BCDEDITValue
    }

    ($SetStatusLog -replace "\s{2,}", " ") | ForEach-Object {
        if ($_ -match "successfully") {
            $ReturnValue = $true
        }
    }

    return $ReturnValue
}

function UTGetBCDEDITValue
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$BCDEDITKey,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $null

    if ($Remote) {
        $GetStatusLog = Invoke-Command -Session $Session -ScriptBlock {
            Param($BCDEDITKey)
            $CurrentFlag = $false
            $ReturnValue = $null
            bcdedit | ForEach-Object {
                if (($_ -match "identifier") -and ($_ -match "current")) {
                    $CurrentFlag = $true
                }

                if ($CurrentFlag) {
                    if ($_ -match $BCDEDITKey) {
                        $ReturnValue = $_
                        $CurrentFlag = $false
                    }
                }
            }

            return $ReturnValue
        } -ArgumentList $BCDEDITKey
    } else {
        $GetStatusLog = Invoke-Command -ScriptBlock {
            Param($BCDEDITKey)
            $CurrentFlag = $false
            $ReturnValue = $null
            bcdedit | ForEach-Object {
                if (($_ -match "identifier") -and ($_ -match "current")) {
                    $CurrentFlag = $true
                }

                if ($CurrentFlag) {
                    if ($_ -match $BCDEDITKey) {
                        $ReturnValue = $_
                        $CurrentFlag = $false
                    }
                }
            }

            return $ReturnValue
        } -ArgumentList $BCDEDITKey
    }

    if (-not [String]::IsNullOrEmpty($GetStatusLog)) {
        $GetStatusLog = $GetStatusLog -replace "\s{2,}", " "
        $ReturnValue = $GetStatusLog.split(" ")[-1]
    }

    return $ReturnValue
}

# About debug mode
function UT-SetDebugMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$DebugMode,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $false

    $SetKey = "debug"
    $SetValue = ($DebugMode) ? "ON" : "OFF"

    if ($Remote) {
        Win-DebugTimestamp -output (
            "{0}: Set Debug mode > {1}" -f $Session.Name, $DebugMode
        )

        $ReturnValue = UTSetBCDEDITValue `
            -BCDEDITKey $SetKey `
            -BCDEDITValue $SetValue `
            -Remote $Remote `
            -Session $Session
    } else {
        Win-DebugTimestamp -output (
            "Host: Set Debug mode > {0}" -f $DebugMode
        )

        $ReturnValue = UTSetBCDEDITValue `
            -BCDEDITKey $SetKey `
            -BCDEDITValue $SetValue `
            -Remote $Remote
    }

    return $ReturnValue
}

function UT-CheckDebugMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$CheckFlag,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $true

    $DebugMode = $false
    $GetKey = "debug"
    $GetValue = $null

    if ($Remote) {
        $GetValue = UTGetBCDEDITValue `
            -BCDEDITKey $GetKey `
            -Remote $Remote `
            -Session $Session
    } else {
        $GetValue = UTGetBCDEDITValue `
            -BCDEDITKey $GetKey `
            -Remote $Remote
    }

    if ([String]::IsNullOrEmpty($GetValue)) {
        $ReturnValue = $false
    } else {
        if ($GetValue -eq "Yes") {
            $DebugMode = $true
        }

        $ReturnValue = ($DebugMode -eq $CheckFlag) ? $true : $false
    }

    if ($Remote) {
        Win-DebugTimestamp -output (
            "{0}: Check Debug mode > {1}" -f $Session.Name, $ReturnValue
        )
    } else {
        Win-DebugTimestamp -output (
            "Host: Check Debug mode > {0}" -f $ReturnValue
        )
    }

    return $ReturnValue
}

# About test mode
function UT-SetTestMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$TestMode,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $false

    $SetKey = "testsigning"
    $SetValue = ($TestMode) ? "ON" : "OFF"

    if ($Remote) {
        Win-DebugTimestamp -output (
            "{0}: Set Test mode > {1}" -f $Session.Name, $TestMode
        )

        $ReturnValue = UTSetBCDEDITValue `
            -BCDEDITKey $SetKey `
            -BCDEDITValue $SetValue `
            -Remote $Remote `
            -Session $Session
    } else {
        Win-DebugTimestamp -output (
            "Host: Set Test mode > {0}" -f $TestMode
        )

        $ReturnValue = UTSetBCDEDITValue `
            -BCDEDITKey $SetKey `
            -BCDEDITValue $SetValue `
            -Remote $Remote
    }

    return $ReturnValue
}

function UT-CheckTestMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$CheckFlag,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $true

    $TestMode = $false
    $GetKey = "testsigning"
    $GetValue = $null

    if ($Remote) {
        $GetValue = UTGetBCDEDITValue `
            -BCDEDITKey $GetKey `
            -Remote $Remote `
            -Session $Session
    } else {
        $GetValue = UTGetBCDEDITValue `
            -BCDEDITKey $GetKey `
            -Remote $Remote
    }

    if ([String]::IsNullOrEmpty($GetValue)) {
        $ReturnValue = $false
    } else {
        if ($GetValue -eq "Yes") {
            $TestMode = $true
        }

        $ReturnValue = ($TestMode -eq $CheckFlag) ? $true : $false
    }

    if ($Remote) {
        Win-DebugTimestamp -output (
            "{0}: Check Test mode > {1}" -f $Session.Name, $ReturnValue
        )
    } else {
        Win-DebugTimestamp -output (
            "Host: Check Test mode > {0}" -f $ReturnValue
        )
    }

    return $ReturnValue
}

# About UQ mode
function UT-SetUQMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$UQMode,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $true

    if ($Remote) {
        $LogKeyWord = $Session.Name
    } else {
        $LogKeyWord = "Host"
    }

    Win-DebugTimestamp -output (
        "{0}: Set UQ mode > {1}" -f $LogKeyWord, $UQMode
    )

    $regeditKey = "HKLM:\SYSTEM\CurrentControlSet\Services\icp_qat4\UQ"
    $SetUQValue = ($UQMode) ? 1 : 0
    $SetFlag = $false

    # Check: exist
    if ($Remote) {
        $LogKeyWord = $Session.Name
        $SetFlag = Invoke-Command -Session $Session -ScriptBlock {
            Param($regeditKey)
            if (Test-Path -Path $regeditKey) {
                return $true
            } else {
                return $false
            }
        } -ArgumentList $regeditKey
    } else {
        $LogKeyWord = "Host"
        if (Test-Path -Path $regeditKey) {
            $SetFlag = $true
        } else {
            $SetFlag = $false
        }
    }

    # Set UQ key value
    if ($SetFlag) {
        Win-DebugTimestamp -output (
            "{0}: Set UQ key as {1}, need to disable and enable qat devices" -f
                $LogKeyWord,
                $SetUQValue
        )

        if ($Remote) {
            Invoke-Command -Session $Session -ScriptBlock {
                Param($regeditKey, $SetUQValue)
                Set-ItemProperty $regeditKey -Name "EnableUQ" -Value $SetUQValue
            } -ArgumentList $regeditKey, $SetUQValue | out-null

            $ReturnValue = UT-CheckUQMode -CheckFlag $UQMode -Session $Session -Remote $Remote
        } else {
            Set-ItemProperty $regeditKey -Name "EnableUQ" -Value $SetUQValue | out-null
            $ReturnValue = UT-CheckUQMode -CheckFlag $UQMode -Remote $Remote
        }
    } else {
        Win-DebugTimestamp -output ("{0}: The UQ key is not exist, no need to set" -f $LogKeyWord)
    }

    return $ReturnValue
}

function UT-CheckUQMode
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$CheckFlag,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $ReturnValue = $true

    if ($Remote) {
        $LogKeyWord = $Session.Name
    } else {
        $LogKeyWord = "Host"
    }

    $regeditKey = "HKLM:\SYSTEM\CurrentControlSet\Services\icp_qat4\UQ"
    $GetFlag = $false

    # Check: exist
    if ($Remote) {
        $GetFlag = Invoke-Command -Session $Session -ScriptBlock {
            Param($regeditKey)
            if (Test-Path -Path $regeditKey) {
                return $true
            } else {
                return $false
            }
        } -ArgumentList $regeditKey
    } else {
        if (Test-Path -Path $regeditKey) {
            $GetFlag = $true
        } else {
            $GetFlag = $false
        }
    }

    # Get UQ key value and compare
    if ($GetFlag) {
        if ($Remote) {
            $UQModeInfo = Invoke-Command -Session $Session -ScriptBlock {
                Param($regeditKey)
                return (Get-ItemProperty $regeditKey).EnableUQ
            } -ArgumentList $regeditKey
        } else {
            $UQModeInfo = (Get-ItemProperty -Path $regeditKey).EnableUQ
        }

        $UQMode = ($UQModeInfo -eq 1) ? $true : $false
        if ($UQMode -eq $CheckFlag) {
            $ReturnValue = $true
        } else {
            $ReturnValue = $false
        }
    } else {
        # The regedit key is null, return true and not changed
        $ReturnValue = $true
    }

    Win-DebugTimestamp -output (
        "{0}: Check UQ mode > {1}" -f $LogKeyWord, $ReturnValue
    )

    return $ReturnValue
}

# About SSH
function UT-SetNoInheritance
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$FilePathName
    )

    Invoke-Command -ScriptBlock {
        Param($FilePathName)
        $localPath = (pwd).path
        $FilePath = Split-Path -Path $FilePathName
        $FileName = Split-Path -Path $FilePathName -Leaf
        cd $FilePath
        takeown /f $FileName
        cacls $FileName /P Administrator:F /E
        cd $localPath
    } -ArgumentList $FilePathName | out-null

    # get current permissions
    $acl = Get-Acl -Path $FilePathName

    # disable inheritance
    $acl.SetAccessRuleProtection($true, $false)

    # set new permissions
    $acl | Set-Acl -Path $FilePathName
}

function UT-CreateSSHKeys
{
    if (-not (Test-Path -Path $SSHKeys.Path)) {
        New-Item -Path $SSHKeys.Path -ItemType Directory | out-null
    }

    $LocalPrivateKey = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.PrivateKeyName
    $LocalPublicKey = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.PublicKeyName
    $LocalConfig = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.ConfigName
    $ConfigInfo = "StrictHostKeyChecking no"
    $LocalKnownHost = "{0}\\{1}" -f $SSHKeys.Path, $SSHKeys.KnownHostName

    if (Test-Path -Path $LocalPrivateKey) {
        Remove-Item `
            -Path $LocalPrivateKey `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop | out-null
    }

    if (Test-Path -Path $LocalPublicKey) {
        Remove-Item `
            -Path $LocalPublicKey `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop | out-null
    }

    if (Test-Path -Path $LocalConfig) {
        Remove-Item `
            -Path $LocalConfig `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop | out-null
    }

    if (Test-Path -Path $LocalKnownHost) {
        Remove-Item `
            -Path $LocalKnownHost `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop | out-null
    }

    Win-DebugTimestamp -output (
        "Host: Create SSH config: {0}" -f $LocalConfig
    )
    $ConfigInfo | Out-File $LocalConfig -Append -Encoding ascii
    # disable inheritance
    UT-SetNoInheritance -FilePathName  $LocalConfig | out-null

    Win-DebugTimestamp -output (
        "Host: Create SSH keys {0} and {1}" -f $LocalPrivateKey, $LocalPublicKey
    )
    Invoke-Command -ScriptBlock {
        Param($LocalPrivateKey)
        ssh-keygen -t "rsa" -f $LocalPrivateKey -P """"
    } -ArgumentList $LocalPrivateKey | out-null
}

# About Certificate
function UT-GetCertSubject
{
    Param(
        [string]$CertFile = $null
    )

    $ReturnValue = $null

    if ([String]::IsNullOrEmpty($CertFile)) {
        $CertFile = $Certificate.HostPF
    }

    $CertInfo = Invoke-Command -ScriptBlock {
        Param($CertFile)
        certutil -Dump $CertFile
    } -ArgumentList $CertFile

    $CertMessageFlag = $false
    ($CertInfo -replace "\s{2,}", "") | ForEach-Object {
        if ($CertMessageFlag) {
            $ReturnValue = $_.Split("=")[1]
            $CertMessageFlag = $false
        }

        if ($_ -match "Subject:") {
            $CertMessageFlag = $true
        }
    }

    return $ReturnValue
}

function UT-SetCertificate
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$CertFile,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    if ($Remote) {
        Invoke-Command -Session $Session -ScriptBlock {
            Param($CertFile)
            certutil -f -addstore TrustedPublisher $CertFile
            certutil -f -addstore root $CertFile
        } -ArgumentList $CertFile | out-null
    } else {
        Invoke-Command -ScriptBlock {
            Param($CertFile)
            certutil -f -addstore TrustedPublisher $CertFile
            certutil -f -addstore root $CertFile
        } -ArgumentList $CertFile | out-null
    }
}

function UT-DelCertificate
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$CertFile,

        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null
    )

    $CertSubject = UT-GetCertSubject -CertFile $CertFile

    if ($Remote) {
        Invoke-Command -Session $Session -ScriptBlock {
            Param($CertSubject)
            $CertFiles = Get-ChildItem -path Cert:\LocalMachine\root
            $CertFiles | ForEach-Object {
                if ($_.Subject -like ("*{0}*" -f $CertSubject)) {
                    $store = Get-Item $_.PSParentPath
                    $store.Open('ReadWrite')
                    $store.Remove($_)
                    $store.Close()
                }
            }

            $CertFiles = Get-ChildItem -path Cert:\LocalMachine\TrustedPublisher
            $CertFiles | ForEach-Object {
                if ($_.Subject -like ("*{0}*" -f $CertSubject)) {
                    $store = Get-Item $_.PSParentPath
                    $store.Open('ReadWrite')
                    $store.Remove($_)
                    $store.Close()
                }
            }
        } -ArgumentList $CertSubject | out-null
    } else {
        Invoke-Command -ScriptBlock {
            Param($CertFile)
            $CertFiles = Get-ChildItem -path Cert:\LocalMachine\root
            $CertFiles | ForEach-Object {
                if ($_.Subject -like ("*{0}*" -f $CertSubject)) {
                    $store = Get-Item $_.PSParentPath
                    $store.Open('ReadWrite')
                    $store.Remove($_)
                    $store.Close()
                }
            }

            $CertFiles = Get-ChildItem -path Cert:\LocalMachine\TrustedPublisher
            $CertFiles | ForEach-Object {
                if ($_.Subject -like ("*{0}*" -f $CertSubject)) {
                    $store = Get-Item $_.PSParentPath
                    $store.Open('ReadWrite')
                    $store.Remove($_)
                    $store.Close()
                }
            }
        } -ArgumentList $CertFile | out-null
    }
}

# About 7z
function UT-Use7z
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$InFile,

        [Parameter(Mandatory=$True)]
        [string]$OutFile
    )

    $ReturnValue = $false

    Import-Module $sevenZipDll
    $OutputLog = Start-SevenZipGzipDecompression -SourceFile $InFile `
                                                 -DestinationPath $OutFile `
                                                 -SevenZipPath $sevenZipExe

    Win-DebugTimestamp -output ("Host: Check output log of 7z tool")
    if ([String]::IsNullOrEmpty($OutputLog)) {
        Win-DebugTimestamp -output ("Host: Output log of 7z tool is null")
        $ReturnValue = $false
    } else {
        $CheckOutputFlag = WBase-CheckOutputLog -OutputLog $OutputLog
        if ($CheckOutputFlag) {
            Win-DebugTimestamp -output ("Host: Use 7z tool is passed")
            $ReturnValue = $true
        } else {
            Win-DebugTimestamp -output ("Host: Error log of 7z tool > {0}" -f $OutputLog)
            $ReturnValue = $false
        }
    }

    return $ReturnValue
}

# WorkAround: 1. Check and set UQ mode by manual,
#                need disable and enable QAT devices to work well
#             2. if system version is greater than 25000,
#                need disable and enable QAT devices to work well
function UT-WorkAround
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Remote,

        [object]$Session = $null,

        [bool]$DisableFlag = $null
    )

    if ($Remote) {
        $LogKeyWord = $Session.Name
    } else {
        $LogKeyWord = "Host"
    }

    Win-DebugTimestamp -output ("{0}: Work around..." -f $LogKeyWord)

    if ($DisableFlag) {
        Win-DebugTimestamp -output (
            "{0}: Need to disable and enable qat device > Reset UQ mode" -f $LogKeyWord
        )
    }

    $DisableDeviceFlag = $DisableFlag
    $regeditKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"

    if ($Remote) {
        $CurrentVersionInfo = Invoke-Command -Session $Session -ScriptBlock {
            Param($regeditKey)
            Get-ItemProperty $regeditKey
        } -ArgumentList $regeditKey
    } else {
        $CurrentVersionInfo = Get-ItemProperty $regeditKey
    }

    if ([int]($CurrentVersionInfo.CurrentBuildNumber) -gt 25000) {
        Win-DebugTimestamp -output (
            "{0}: Need to disable and enable qat device > {1}" -f
                $LogKeyWord,
                $CurrentVersionInfo.CurrentBuildNumber
        )

        $DisableDeviceFlag = $true
    }

    if ($DisableDeviceFlag) {
        if ($Remote) {
            WBase-EnableAndDisableQatDevice `
                -Remote $true `
                -Session $Session | out-null
        } else {
            WBase-EnableAndDisableQatDevice -Remote $false | out-null
        }
    }

    Win-DebugTimestamp -output ("{0}: Work around: End" -f $LogKeyWord)
}


Export-ModuleMember -Function *-*
