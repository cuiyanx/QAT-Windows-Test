
function Berta-ENVInit
{
    <#
    # Copy Test path
    if (Test-Path -Path $BertaENVInit.QATTest.DestinationPath) {
        Remove-Item `
            -Path $BertaENVInit.QATTest.DestinationPath `
            -Recurse `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop
    }

    $QATTestPathLocal = Split-Path -Parent $BertaENVInit.QATTest.DestinationPath
    Copy-Item `
        -Path $BertaENVInit.QATTest.SourcePath `
        -Destination $QATTestPathLocal `
        -Recurse `
        -Force `
        -Confirm:$false `
        -ErrorAction Stop
    #>

    # Update Powershell profile
    $CopyFlag = $false
    $PSProFileLocal = "{0}\\{1}" -f
        $BertaENVInit.PSProFile.DestinationPath,
        $BertaENVInit.PSProFile.FileName
    $PSProFileRemote = "{0}\\{1}" -f
        $BertaENVInit.PSProFile.SourcePath,
        $BertaENVInit.PSProFile.FileName

    if (Test-Path -Path $BertaENVInit.PSProFile.DestinationPath) {
        if (Test-Path -Path $PSProFileLocal) {
            $SourceMD5 = (certutil -hashfile $PSProFileLocal MD5).split("\n")[1]
            $DestinationMD5 = (certutil -hashfile $PSProFileRemote MD5).split("\n")[1]

            if ($SourceMD5 -ne $DestinationMD5) {
                $CopyFlag = $true
                Remove-Item `
                    -Path $PSProFileLocal `
                    -Force `
                    -Confirm:$false `
                    -ErrorAction Stop
            }
        } else {
            $CopyFlag = $true
        }
    } else {
        $CopyFlag = $true
        New-Item `
            -Path $BertaENVInit.PSProFile.DestinationPath `
            -ItemType Directory | out-null
    }

    if ($CopyFlag) {
        Copy-Item `
            -Path $PSProFileRemote `
            -Destination $PSProFileLocal `
            -Recurse `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop
    }
}

function Berta-UpdateMainFiles
{
    $ReturnValue = $false

    ForEach ($SourceFile in $BertaENVInit.BertaClient.SourceFiles) {
        $BertaSource = "{0}\\{1}" -f
            $BertaENVInit.BertaClient.SourcePath,
            $SourceFile
        $BertaDestination = "{0}\\{1}" -f
            $BertaENVInit.BertaClient.DestinationPath,
            $SourceFile

        $SourceMD5 = (certutil -hashfile $BertaSource MD5).split("\n")[1]
        $DestinationMD5 = (certutil -hashfile $BertaDestination MD5).split("\n")[1]

        if ($SourceMD5 -ne $DestinationMD5) {
            $ReturnValue = $true
            Copy-Item `
                -Path $BertaSource `
                -Destination $BertaDestination `
                -Force `
                -ErrorAction Stop | out-null
        }
    }

    return $ReturnValue
}

function Berta-CopyQATTestFiles
{
    $ReturnValue = $false

    if (Test-Path -Path $BertaENVInit.QATTest.SourcePath) {
        if (Test-Path -Path $BertaENVInit.QATTest.DestinationPath) {
            Remove-Item `
                -Path $BertaENVInit.QATTest.DestinationPath `
                -Recurse `
                -Force `
                -Confirm:$false `
                -ErrorAction Stop
        }

        $QATTestPathLocal = Split-Path -Parent $BertaENVInit.QATTest.DestinationPath
        Copy-Item `
            -Path $BertaENVInit.QATTest.SourcePath `
            -Destination $QATTestPathLocal `
            -Recurse `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop

        if (Test-Path -Path $BertaENVInit.QATTest.DestinationPath) {
            $ReturnValue = $true
        } else {
            $ReturnValue = $false
        }
    } else {
        $ReturnValue = $false
    }

    return $ReturnValue
}

function Berta-QatDriverCheck
{
    $CheckList = WBase-CheckDriverInstalled -Remote $false

    return $CheckList
}

function Berta-QatDriverInstall
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$DriverPath,

        [Parameter(Mandatory=$True)]
        [bool]$HVMode,

        [Parameter(Mandatory=$True)]
        [bool]$UQMode
    )

    $LocationInfo.HVMode = $HVMode
    $PFVFDriverPath = WBase-GetDriverPath -BuildPath $DriverPath
    $PFDriverExe = WBase-PFDriverPathInit -PFDriverFullPath $PFVFDriverPath.PF
    WBase-InstallAndUninstallQatDriver -SetupExePath $PFDriverExe `
                                       -Operation $true `
                                       -Remote $false `
                                       -UQMode $UQMode

    return $PsReturnCode.Success
}

function Berta-QatDriverUnInstall
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$DriverPath
    )

    # Remove child vm's
    $VMList = Get-VM
    if (-not [String]::IsNullOrEmpty($VMList)) {
        Foreach ($VM in $VMList) {
            HV-RemoveVM -VMName $VM.Name | out-null
        }
    }

    $PFVFDriverPath = WBase-GetDriverPath -BuildPath $DriverPath
    $PFDriverExe = WBase-PFDriverPathInit -PFDriverFullPath $PFVFDriverPath.PF
    WBase-InstallAndUninstallQatDriver -SetupExePath $PFDriverExe `
                                       -Operation $false `
                                       -Remote $false

    return $PsReturnCode.Success
}

function Berta-CompressReturnFiles
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Path,

        [int]$Threshold = 500KB
    )

    $IgnoreList = @(
        "agent_log.txt",
        "job_2_log.txt",
        "STVTest-ps.log",
        "result.log",
        "results-log.txt"
    )

    try {
        $Files = Get-ChildItem -Path $Path -Exclude $IgnoreList -Recurse -ErrorAction Stop |
            Where-Object {$_.Extension -ne ".zip"}

        foreach ($file in $Files) {
            if ($file.Length -gt $Threshold) {
                $ZipName = "{0}\{1}.zip" -f $file.DirectoryName, $file.BaseName
                Win-DebugTimestamp -output (
                    "{0} is greater than {1}; Compressing to {2} and removing original." -f
                        $file.Name,
                        $Threshold,
                        $ZipName
                )

                Compress-Archive `
                    -LiteralPath ($file.FullName) `
                    -DestinationPath $ZipName `
                    -CompressionLevel Optimal `
                    -Force `
                    -ErrorAction Stop

                Remove-Item -Path $file -Force -Confirm:$false -ErrorAction Stop
            }
        }
    } catch {
        throw ("Error: Compress return file is failed > {0}" -f $file)
    }
}


Export-ModuleMember -Function *-*
