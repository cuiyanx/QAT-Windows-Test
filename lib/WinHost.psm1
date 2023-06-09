if (!$QATTESTPATH) {
    $TestSuitePath = Split-Path -Parent (Split-Path -Path $PSCommandPath)
    Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global
}

Import-Module "$QATTESTPATH\\lib\\WinBase.psm1" -Force -DisableNameChecking
Import-Module $STVMainDll -Force -DisableNameChecking

function WinHost-ENVInit
{
    # Check driver verifier
    $CheckFlag = UT-CheckDriverVerifier `
        -CheckFlag $LocationInfo.VerifierMode `
        -Remote $false
    if (-not $CheckFlag) {
        throw ("Host: Driver verifier is incorrect")
    }

    # Check test mode
    $CheckFlag = UT-CheckTestMode `
        -CheckFlag $LocationInfo.TestMode `
        -Remote $false
    if (-not $CheckFlag) {
        throw ("Host: Test mode is incorrect")
    }

    # Check debug mode
    $CheckFlag = UT-CheckDebugMode `
        -CheckFlag $LocationInfo.DebugMode `
        -Remote $false
    if (-not $CheckFlag) {
        throw ("Host: Debug mode is incorrect")
    }

    # Check UQ mode
    $CheckFlag = UT-CheckUQMode `
        -CheckFlag $LocationInfo.UQMode `
        -Remote $false
    if (-not $CheckFlag) {
        throw ("Host: UQ mode is incorrect")
    }
}

# About base test
function WinHostCheckMD5
{
    Param(
        [bool]$deCompressFlag = $false,

        [string]$CompressProvider = "qat",

        [string]$deCompressProvider = "qat",

        [string]$QatCompressionType = "dynamic",

        [int]$Level = 1,

        [int]$Chunk = 64,

        [string]$TestPathName = $null,

        [string]$TestFileType = "high",

        [int]$TestFileSize = 200
    )

    $ReturnValue = [hashtable] @{
        SourceFile = $null
        OutFile = $null
    }

    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $ParcompOpts.PathName
    }

    $TestSourceFile = "{0}\\{1}{2}.txt" -f $STVWinPath, $TestFileType, $TestFileSize
    $TestParcompPath = "{0}\\{1}" -f $STVWinPath, $TestPathName
    $deCompressPath = "{0}\\{1}" -f $STVWinPath, $ParcompOpts.MD5PathName
    $TestParcompOutFileList = @()
    $deCompressSourceFileList = @()
    $TestParcompOutFileMD5List = @()

    if (Test-Path -Path $deCompressPath) {
        Get-Item -Path $deCompressPath | Remove-Item -Recurse
    }
    New-Item -Path $deCompressPath -ItemType Directory

    $TestParcompOutFileArray = Get-ChildItem -Path $TestParcompPath
    $TestParcompOutFileArray | ForEach-Object {
        if (($_.Name -ne $ParcompOpts.OutputLog) -and
            ($_.Name -ne $ParcompOpts.ErrorLog) -and
            ($_.Name -ne $ParcompOpts.InputFileName)) {
            $TestParcompOutFileList += $_.FullName

            if (!$deCompressFlag) {
                $deCompressSourceFile = "{0}\\{1}" -f $deCompressPath, $_.Name
                $deCompressSourceFileList += $deCompressSourceFile
                Copy-Item -Path $_.FullName -Destination $deCompressSourceFile
            }
        }
    }

    $TestSourceFileMD5 = Invoke-Command -ScriptBlock {
        Param($TestSourceFile)
        certutil -hashfile $TestSourceFile MD5
    } -ArgumentList $TestSourceFile
    $TestSourceFileMD5 = ($TestSourceFileMD5).split("\n")[1]

    if ($deCompressFlag) {
        ForEach ($TestParcompOutFile in $TestParcompOutFileList) {
            $TestParcompOutFileMD5 = Invoke-Command -ScriptBlock {
                Param($TestParcompOutFile)
                certutil -hashfile $TestParcompOutFile MD5
            } -ArgumentList $TestParcompOutFile
            $TestParcompOutFileMD5 = ($TestParcompOutFileMD5).split("\n")[1]
            $TestParcompOutFileMD5List += $TestParcompOutFileMD5
        }
    } else {
        $TestParcompOutFile = "{0}\\{1}" -f $TestParcompPath, $ParcompOpts.OutputFileName
        ForEach ($deCompressSourceFile in $deCompressSourceFileList) {
            $deCompressOut = WBase-Parcomp -Side "host" `
                                           -deCompressFlag $true `
                                           -CompressProvider $CompressProvider `
                                           -deCompressProvider $deCompressProvider `
                                           -QatCompressionType $QatCompressionType `
                                           -Level $Level `
                                           -Chunk $Chunk `
                                           -TestPathName $TestPathName `
                                           -TestFilelocation "VM" `
                                           -TestFilefullPath $deCompressSourceFile

            $TestParcompOutFileMD5 = Invoke-Command -ScriptBlock {
                Param($TestParcompOutFile)
                certutil -hashfile $TestParcompOutFile MD5
            } -ArgumentList $TestParcompOutFile
            $TestParcompOutFileMD5 = ($TestParcompOutFileMD5).split("\n")[1]
            $TestParcompOutFileMD5List += $TestParcompOutFileMD5
        }
    }

    $ReturnValue.SourceFile = $TestSourceFileMD5
    $ReturnValue.OutFile = $TestParcompOutFileMD5List

    return $ReturnValue
}

function WinHostErrorHandle
{
    Param(
        [Parameter(Mandatory=$True)]
        [array]$TestResult,

        [string]$IcpQatFileName = "C:\\STV-tmp\\tracelog_IcpQat",

        [string]$CfQatFileName = "C:\\STV-tmp\\tracelog_CfQat",

        [bool]$Transfer = $false
    )

    # Stop trace and transfer tracelog file
    UT-TraceLogStop -Remote $false | out-null
    if ($Transfer) {UT-TraceLogTransfer -Remote $false | out-null}

    # Handle:
    #    -Copy tracelog file to 'BertaResultPath'
    Win-DebugTimestamp -output ("Host: Copy tracelog etl files to 'BertaResultPath'")
    $HostIcpQatFile = "{0}_host.etl" -f $IcpQatFileName
    $HostCfQatFile = "{0}_host.etl" -f $CfQatFileName
    $HostIcpQatFileName = $TraceLogOpts.EtlFullPath.IcpQat
    $HostCfQatFileName = $TraceLogOpts.EtlFullPath.CfQat

    if (Test-Path -Path $HostIcpQatFileName) {
        Copy-Item -Path $HostIcpQatFileName -Destination $HostIcpQatFile -Force -Confirm:$false | out-null
        Get-Item -Path $HostIcpQatFileName | Remove-Item -Recurse
    }

    if (Test-Path -Path $HostCfQatFileName) {
        Copy-Item -Path $HostCfQatFileName -Destination $HostCfQatFile -Force -Confirm:$false | out-null
        Get-Item -Path $HostCfQatFileName | Remove-Item -Recurse
    }
}

# Test: installer check
function WinHost-InstallerCheckBase
{
    Param(
        [string]$BertaResultPath,

        [bool]$parcompFlag = $true,

        [bool]$cngtestFlag = $false
    )

    # Base on QAT Windows driver installed
    $ReturnValue = [hashtable] @{
        install = [hashtable] @{
            service = [hashtable] @{
                result = $true
                error = "no_error"
            }
            device = [hashtable] @{
                result = $true
                error = "no_error"
            }
            library = [hashtable] @{
                result = $true
                error = "no_error"
            }
        }
        uninstall = [hashtable] @{
            service = [hashtable] @{
                result = $true
                error = "no_error"
            }
            device = [hashtable] @{
                result = $true
                error = "no_error"
            }
            library = [hashtable] @{
                result = $true
                error = "no_error"
            }
        }
        parcomp = [hashtable] @{
            result = $true
            error = "no_error"
        }
        cngtest = [hashtable] @{
            result = $true
            error = "no_error"
        }
    }

    $CheckTypes = [System.Array] @("service", "device", "library")
    $QatDriverServices = [System.Array] @()
    if ($parcompFlag) {
        $QatDriverServices += $LocationInfo.IcpQatName
        $QatDriverServices += "cfqat"
    }

    if ($cngtestFlag) {$QatDriverServices += "cpmprovuser"}

    $QatDriverLibs = [System.Array] @(
        "C:\\Program Files\\Intel\Intel(R) QuickAssist Technology\\Compression\\Library\\qatzip.lib",
        "C:\\Program Files\\Intel\Intel(R) QuickAssist Technology\\Compression\\Library\\libqatzip.lib"
    )

    # Run QAT Windows driver check: install
    Foreach ($CheckType in $CheckTypes) {
        Win-DebugTimestamp -output ("Host: After QAT driver installed, double check > {0}" -f $CheckType)
        $CheckTestResult = WBase-CheckQatDriver -Side "host" `
                                                -Type $CheckType `
                                                -Operation $true `
                                                -QatDriverServices $QatDriverServices `
                                                -QatDriverLibs $QatDriverLibs

        if ($CheckType -eq "service") {
            $ReturnValue.install.service.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.install.service.error = "install_service_fail"
            }
        } elseif ($CheckType -eq "device") {
            $ReturnValue.install.device.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.install.device.error = "install_device_fail"
            }
        } elseif ($CheckType -eq "library") {
            $ReturnValue.install.library.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.install.library.error = "install_library_fail"
            }
        }
    }

    # Run parcomp test after QAT Windows driver installed
    if ($parcompFlag) {
        Win-DebugTimestamp -output ("After QAT driver installed, double check > run parcomp test")
        $parcompTestResult = WinHost-ParcompBase -deCompressFlag $false `
                                                 -CompressProvider "qat" `
                                                 -deCompressProvider "qat" `
                                                 -QatCompressionType "dynamic" `
                                                 -BertaResultPath $BertaResultPath

        Win-DebugTimestamp -output ("Running parcomp test is completed > {0}" -f $parcompTestResult.result)

        $ReturnValue.parcomp.result = $parcompTestResult.result
        $ReturnValue.parcomp.error = $parcompTestResult.error
    }

    # Run CNGTest after QAT Windows driver installed
    if ($cngtestFlag) {
        Win-DebugTimestamp -output ("After QAT driver installed, double check > run cngtest")
        $CNGTestTestResult = WinHost-CNGTestBase -algo "rsa" -BertaResultPath $BertaResultPath

        Win-DebugTimestamp -output ("Running cngtest is completed > {0}" -f $CNGTestTestResult.result)

        $ReturnValue.cngtest.result = $CNGTestTestResult.result
        $ReturnValue.cngtest.error = $CNGTestTestResult.error
    }

    # Uninstall QAT Windows driver
    Win-DebugTimestamp -output ("Host: uninstall Qat driver")
    WBase-InstallAndUninstallQatDriver -SetupExePath $LocationInfo.PF.DriverExe `
                                       -Operation $false `
                                       -Remote $false

    WBase-CheckDriverInstalled -Remote $false | out-null

    # Run QAT Windows driver check: uninstall
    Foreach ($CheckType in $CheckTypes) {
        Win-DebugTimestamp -output ("Host: After QAT driver uninstalled, double check > {0}" -f $CheckType)
        $CheckTestResult = WBase-CheckQatDriver -Side "host" `
                                                -Type $CheckType `
                                                -Operation $false `
                                                -QatDriverServices $QatDriverServices `
                                                -QatDriverLibs $QatDriverLibs

        if ($CheckType -eq "service") {
            $ReturnValue.uninstall.service.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.uninstall.service.error = "uninstall_service_fail"
            }
        } elseif ($CheckType -eq "device") {
            $ReturnValue.uninstall.device.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.uninstall.device.error = "uninstall_device_fail"
            }
        } elseif ($CheckType -eq "library") {
            $ReturnValue.uninstall.library.result = $CheckTestResult
            if (!$CheckTestResult) {
                $ReturnValue.uninstall.library.error = "uninstall_library_fail"
            }
        }
    }

    return $ReturnValue
}

# Test: installer disable and enable
function WinHost-InstallerCheckDisable
{
    Param(
        [string]$BertaResultPath,

        [bool]$parcompFlag = $true,

        [bool]$cngtestFlag = $false
    )

    # Base on QAT Windows driver installed
    $ReturnValue = [hashtable] @{
        disable = [hashtable] @{
            result = $true
            error = "no_error"
        }
        parcomp = [hashtable] @{
            result = $true
            error = "no_error"
        }
        cngtest = [hashtable] @{
            result = $true
            error = "no_error"
        }
    }

    # Run simple parcomp test to check qat driver work well
    if ($parcompFlag) {
        Win-DebugTimestamp -output ("After QAT driver installed, double check > run parcomp test")
        $parcompTestResult = WinHost-ParcompBase -deCompressFlag $false `
                                                 -CompressProvider "qat" `
                                                 -deCompressProvider "qat" `
                                                 -QatCompressionType "dynamic" `
                                                 -BertaResultPath $BertaResultPath

        Win-DebugTimestamp -output ("Running parcomp test is completed > {0}" -f $parcompTestResult.result)

        $ReturnValue.parcomp.result = $parcompTestResult.result
        $ReturnValue.parcomp.error = $parcompTestResult.error
    }

    # Run simple cngtest to check qat driver work well
    if ($cngtestFlag) {
        Win-DebugTimestamp -output ("After QAT driver installed, double check > run cngtest")
        $CNGTestTestResult = WinHost-CNGTestBase -algo "rsa"

        Win-DebugTimestamp -output ("Running cngtest is completed > {0}" -f $CNGTestTestResult.result)

        $ReturnValue.cngtest.result = $CNGTestTestResult.result
        $ReturnValue.cngtest.error = $CNGTestTestResult.error
    }

    # Run disable and enable qat device on VMs
    Win-DebugTimestamp -output ("Run 'disable' and 'enable' operation on VMs")
    $disableStatus = WBase-EnableAndDisableQatDevice -Remote $false

    Win-DebugTimestamp -output ("The disable and enable operation > {0}" -f $disableStatus)
    if (!$disableStatus) {
        $ReturnValue.disable.result = $disableStatus
        $ReturnValue.disable.error = "disable_failed"
    }

    # Run simple parcomp test again to check qat driver work well
    if ($parcompFlag) {
        Win-DebugTimestamp -output ("After QAT driver disable and enable, double check > run parcomp test")
        $parcompTestResult = WinHost-ParcompBase -deCompressFlag $false `
                                                 -CompressProvider "qat" `
                                                 -deCompressProvider "qat" `
                                                 -QatCompressionType "dynamic" `
                                                 -BertaResultPath $BertaResultPath

        Win-DebugTimestamp -output ("Running parcomp test is completed > {0}" -f $parcompTestResult.result)

        if ($ReturnValue.parcomp.result) {
            $ReturnValue.parcomp.result = $parcompTestResult.result
            $ReturnValue.parcomp.error = $parcompTestResult.error
        }
    }

    # Run simple cngtest again to check qat driver work well
    if ($cngtestFlag) {
        Win-DebugTimestamp -output ("After QAT driver disable and enable, double check > run cngtest")
        $CNGTestTestResult = WinHost-CNGTestBase -algo "rsa"

        Win-DebugTimestamp -output ("Running cngtest is completed > {0}" -f $CNGTestTestResult.result)

        if ($ReturnValue.cngtest.result) {
            $ReturnValue.cngtest.result = $CNGTestTestResult.result
            $ReturnValue.cngtest.error = $CNGTestTestResult.error
        }
    }

    # No need collate return value
    return $ReturnValue
}

# Test: base test of parcomp
function WinHost-ParcompBase
{
    Param(
        [bool]$deCompressFlag = $false,

        [string]$CompressProvider = "qat",

        [string]$deCompressProvider = "qat",

        [string]$QatCompressionType = "dynamic",

        [int]$Level = 1,

        [int]$Chunk = 64,

        [string]$TestFilefullPath = $null,

        [string]$TestPathName = $null,

        [string]$BertaResultPath = "C:\\temp",

        [string]$TestFileType = "high",

        [int]$TestFileSize = 200,

        [string]$TestType = "Parameter"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    $TestSourceFile = "{0}\\{1}{2}.txt" -f
        $STVWinPath,
        $TestFileType,
        $TestFileSize
    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $ParcompOpts.PathName
    }

    # Run tracelog
    UT-TraceLogStart -Remote $false | out-null

    # Run parcomp exe
    if ($deCompressFlag) {
        Win-DebugTimestamp -output (
            "Host: Start to {0} test (decompress) with {1} provider!" -f
                $TestType,
                $deCompressProvider
        )
    } else {
        Win-DebugTimestamp -output (
            "Host: Start to {0} test (compress) test with {1} provider!" -f
                $TestType,
                $CompressProvider
        )
    }

    $ParcompTestResult = WBase-Parcomp -Side "host" `
                                       -deCompressFlag $deCompressFlag `
                                       -CompressProvider $CompressProvider `
                                       -deCompressProvider $deCompressProvider `
                                       -QatCompressionType $QatCompressionType `
                                       -Level $Level `
                                       -Chunk $Chunk `
                                       -TestPathName $TestPathName `
                                       -TestFilefullPath $TestFilefullPath `
                                       -TestFileType $TestFileType `
                                       -TestFileSize $TestFileSize

    # Get parcomp test result
    $ReturnValue.result = $ParcompTestResult.result
    $ReturnValue.error = $ParcompTestResult.error

    # Double check the output file
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output (
            "Host: Double check the output file of {0} test" -f $TestType
        )
        $TestParcompOutFile = "{0}\\{1}\\{2}" -f
            $STVWinPath,
            $TestPathName,
            $ParcompOpts.OutputFileName

        # The parcomp operation is Compress, need to deCompress the output file and check the match
        if ($deCompressProvider -eq "7zip") {
            $TestdeCompressPath = "{0}\\{1}" -f
                $STVWinPath,
                $ParcompOpts.sevenZipPathName
            if (-not (Test-Path -Path $TestdeCompressPath)) {
                New-Item -Path $TestdeCompressPath -ItemType Directory
            }
            Copy-Item -Path $TestParcompOutFile -Destination $TestdeCompressPath

            $TestdeCompressInFile = "{0}\\{1}" -f
                $TestdeCompressPath,
                $ParcompOpts.OutputFileName
            $TestdeCompressOutFile = "{0}\\{1}" -f
                $TestdeCompressPath,
                ($ParcompOpts.OutputFileName).split(".")[0]
            if (Test-Path -Path $TestdeCompressOutFile) {
                Get-Item -Path $TestdeCompressOutFile | Remove-Item -Recurse
            }

            Win-DebugTimestamp -output (
                "Host: deCompress the output file of {0} test > {1}" -f
                    $TestType,
                    $sevenZipExe
            )
            $Use7zflag = UT-Use7z -InFile $TestdeCompressInFile -OutFile $TestdeCompressPath
            $Use7zflagTmp = $null
            if (!($Use7zflag.gettype().Name -eq "Boolean")) {
                Foreach ($Member in $Use7zflag) {
                    if ($Member.gettype().Name -eq "Boolean") {
                        $Use7zflagTmp = $Member
                    }
                }

                $Use7zflag = $Use7zflagTmp
            }

            if ($Use7zflag) {
                Win-DebugTimestamp -output ("Host: The deCompress test is passed")
                $TestParcompOutFileMD5 = certutil -hashfile $TestdeCompressOutFile MD5
                $TestParcompOutFileMD5 = ($TestParcompOutFileMD5).split("\n")[1]

                $TestSourceFileMD5 = Invoke-Command -ScriptBlock {
                    Param($TestSourceFile)
                    certutil -hashfile $TestSourceFile MD5
                } -ArgumentList $TestSourceFile
                $TestSourceFileMD5 = ($TestSourceFileMD5).split("\n")[1]
            } else {
                Win-DebugTimestamp -output ("Host: The deCompress test is failed")
                $ReturnValue.result = $false
                $ReturnValue.error = "decompress_7zip_failed"
                return
            }
        } else {
            $CheckMD5Result = WinHostCheckMD5 -deCompressFlag $deCompressFlag `
                                              -CompressProvider $CompressProvider `
                                              -deCompressProvider $deCompressProvider `
                                              -QatCompressionType $QatCompressionType `
                                              -Level $Level `
                                              -Chunk $Chunk `
                                              -TestPathName $TestPathName `
                                              -TestFileType $TestFileType `
                                              -TestFileSize $TestFileSize

            if (($CheckMD5Result.OutFile).gettype().Name -eq "String") {
                $TestParcompOutFileMD5 = $CheckMD5Result.OutFile
            } else {
                $TestParcompOutFileMD5 = $CheckMD5Result.OutFile[0]
            }

            $TestSourceFileMD5 = $CheckMD5Result.SourceFile
        }

        Win-DebugTimestamp -output ("Host: The MD5 value of source file > {0}" -f $TestSourceFileMD5)
        Win-DebugTimestamp -output ("Host: The MD5 value of {0} test output file > {1}" -f $TestType, $TestParcompOutFileMD5)

        if ($TestParcompOutFileMD5 -eq $TestSourceFileMD5) {
            Win-DebugTimestamp -output ("Host: The output file of {0} test and the source file are matched" -f $TestType)
        } else {
            Win-DebugTimestamp -output ("Host: The output file of {0} test and the source file are not matched" -f $TestType)
            $ReturnValue.result = $false
            $ReturnValue.error = "MD5_no_matched"
        }
    } else {
        Win-DebugTimestamp -output ("Host: Skip checking the output file of {0} test, because Error > {1}" -f $TestType, $ReturnValue.error)
    }

    # Handle all error
    if (!$ReturnValue.result) {
        if ($TestType -eq "Parameter") {
            if ($deCompressFlag) {
                $CompressionType = "deCompress"
                $CompressionProvider = $deCompressProvider
            } else {
                $CompressionType = "Compress"
                $CompressionProvider = $CompressProvider
            }

            $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_chunk{3}" -f $BertaResultPath,
                                                                                $CompressionType,
                                                                                $CompressionProvider,
                                                                                $Chunk

            $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_chunk{3}" -f $BertaResultPath,
                                                                              $CompressionType,
                                                                              $CompressionProvider,
                                                                              $Chunk

            if (!$deCompressFlag) {
                $Remote2HostIcpQatFile = "{0}_level{1}" -f $Remote2HostIcpQatFile, $Level
                $Remote2HostCfQatFile = "{0}_level{1}" -f $Remote2HostCfQatFile, $Level
            }

            if ($deCompressProvider -eq "qat") {
                $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $QatCompressionType
                $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $QatCompressionType
            }
        } elseif ($TestType -eq "Compat") {
            $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_Compress_{1}_deCompress_{2}" -f $BertaResultPath,
                                                                                           $CompressProvider,
                                                                                           $deCompressProvider

            $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_Compress_{1}_deCompress_{2}" -f $BertaResultPath,
                                                                                         $CompressProvider,
                                                                                         $deCompressProvider
        }

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile  | out-null
    }

    return $ReturnValue
}

# Test: performance test of parcomp
function WinHost-ParcompPerformance
{
    Param(
        [bool]$deCompressFlag = $false,

        [string]$CompressProvider = "qat",

        [string]$deCompressProvider = "qat",

        [string]$QatCompressionType = "dynamic",

        [int]$Level = 1,

        [int]$numThreads = 6,

        [int]$numIterations = 200,

        [int]$blockSize = 4096,

        [int]$Chunk = 64,

        [string]$TestFilefullPath = $null,

        [string]$TestPathName = $null,

        [string]$BertaResultPath = "C:\\temp",

        [string]$TestFileType = "high",

        [int]$TestFileSize = 200,

        [string]$TestType = "Performance"
    )

    # Test type 'Performance' and 'BanchMark' base on Host
    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
        testOps = 0
        TestFileType = $TestFileType
    }

    $ParcompType = "Performance"
    $runParcompType = "Process"

    $TestSourceFile = "{0}\\{1}{2}.txt" -f $STVWinPath, $TestFileType, $TestFileSize
    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $ParcompOpts.PathName
    }
    $TestPath = "{0}\\{1}" -f $STVWinPath, $TestPathName
    $TestParcompInFile = "{0}\\{1}" -f $TestPath, $ParcompOpts.InputFileName
    $TestParcompOutFile = "{0}\\{1}" -f $TestPath, $ParcompOpts.OutputFileName
    $TestParcompOutLog = "{0}\\{1}" -f $TestPath, $ParcompOpts.OutputLog
    $TestParcompErrorLog = "{0}\\{1}" -f $TestPath, $ParcompOpts.ErrorLog

    # Stop trace log tool
    UT-TraceLogStop -Remote $false | out-null

    # Run parcomp exe
    if ($deCompressFlag) {
        Win-DebugTimestamp -output ("Host: Start to {0} test (decompress) with {1} provider!" -f $TestType, $deCompressProvider)
    } else {
        Win-DebugTimestamp -output ("Host: Start to {0} test (compress) with {1} provider!" -f $TestType, $CompressProvider)
    }

    $ParcompTestResult = WBase-Parcomp -Side "host" `
                                       -deCompressFlag $deCompressFlag `
                                       -CompressProvider $CompressProvider `
                                       -deCompressProvider $deCompressProvider `
                                       -QatCompressionType $QatCompressionType `
                                       -Level $Level `
                                       -Chunk $Chunk `
                                       -blockSize $blockSize `
                                       -numThreads $numThreads `
                                       -numIterations $numIterations `
                                       -ParcompType $ParcompType `
                                       -runParcompType $runParcompType `
                                       -TestPathName $TestPathName `
                                       -TestFilefullPath $TestFilefullPath `
                                       -TestFileType $TestFileType `
                                       -TestFileSize $TestFileSize

    # Check parcomp test process number
    $CheckProcessNumberFlag = WBase-CheckProcessNumber -ProcessName "parcomp"
    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckProcessNumberFlag.result
        $ReturnValue.error = $CheckProcessNumberFlag.error
    }

    # Wait parcomp test process to complete
    $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "parcomp" -Remote $false
    if ($ReturnValue.result) {
        $ReturnValue.result = $WaitProcessFlag.result
        $ReturnValue.error = $WaitProcessFlag.error
    }

    # Check parcomp test result
    $CheckOutput = WBase-CheckOutput `
        -TestOutputLog $TestParcompOutLog `
        -TestErrorLog $TestParcompErrorLog `
        -Remote $false `
        -keyWords "Mbps"

    $ReturnValue.result = $CheckOutput.result
    $ReturnValue.error = $CheckOutput.error
    $ReturnValue.testOps = $CheckOutput.testOps

    if ($TestType -eq "Parameter") {
        # Double check the output files
        if ($ReturnValue.result) {
            Win-DebugTimestamp -output ("Host: Double check the output file of performance test ({0})" -f $TestType)
            $MD5MatchFlag = $true

            # The parcomp operation is Compress, need to deCompress the output file and check the match
            $CheckMD5Result = WinHostCheckMD5 -deCompressFlag $deCompressFlag `
                                              -CompressProvider $CompressProvider `
                                              -deCompressProvider $deCompressProvider `
                                              -QatCompressionType $QatCompressionType `
                                              -Level $Level `
                                              -Chunk $Chunk `
                                              -TestFileType $TestFileType `
                                              -TestFileSize $TestFileSize `
                                              -TestPathName $TestPathName

            $TestSourceFileMD5 = $CheckMD5Result.SourceFile
            Win-DebugTimestamp -output ("Host: The MD5 value of source file > {0}" -f $TestSourceFileMD5)
            $FileCount = 0
            ForEach ($TestParcompOutFileMD5 in $CheckMD5Result.OutFile) {
                Win-DebugTimestamp -output ("Host: The MD5 value of performance test ({0}) output file {1} > {2}" -f $TestType,
                                                                                                                     $FileCount,
                                                                                                                     $TestParcompOutFileMD5)
                $FileCount++
                if ($TestParcompOutFileMD5 -ne $TestSourceFileMD5) {$MD5MatchFlag = $false}
            }
            if ($MD5MatchFlag) {
                Win-DebugTimestamp -output ("Host: The output file of performance test ({0}) and the source file are matched" -f $TestType)
            } else {
                Win-DebugTimestamp -output ("Host: The output file of performance test ({0}) and the source file are not matched" -f $TestType)

                $ReturnValue.result = $false
                $ReturnValue.error = "MD5_no_matched"
            }
        } else {
            Win-DebugTimestamp -output ("Host: Skip checking the output files of performance test ({0}), because Error > {1}" -f $TestType, $ReturnValue.error)
        }
    }

    # Handle all errors
    if (!$ReturnValue.result) {
        if ($TestType -eq "Performance") {
            if ($deCompressFlag) {
                $CompressionType = "deCompress"
                $CompressionProvider = $deCompressProvider
            } else {
                $CompressionType = "Compress"
                $CompressionProvider = $CompressProvider
            }

            $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_{3}{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                                    $CompressionType,
                                                                                                    $CompressionProvider,
                                                                                                    $TestFileType,
                                                                                                    $TestFileSize,
                                                                                                    $Chunk,
                                                                                                    $blockSize

            $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_{3}{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                                  $CompressionType,
                                                                                                  $CompressionProvider,
                                                                                                  $TestFileType,
                                                                                                  $TestFileSize,
                                                                                                  $Chunk,
                                                                                                  $blockSize

            $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_{3}{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                       $CompressionType,
                                                                                       $CompressionProvider,
                                                                                       $TestFileType,
                                                                                       $TestFileSize,
                                                                                       $Chunk,
                                                                                       $blockSize
        } elseif ($TestType -eq "Parameter") {
            $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_threads{3}_iterations{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                                                      $CompressionType,
                                                                                                                      $CompressionProvider,
                                                                                                                      $numThreads,
                                                                                                                      $numIterations,
                                                                                                                      $Chunk,
                                                                                                                      $blockSize

            $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_threads{3}_iterations{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                                                    $CompressionType,
                                                                                                                    $CompressionProvider,
                                                                                                                    $numThreads,
                                                                                                                    $numIterations,
                                                                                                                    $Chunk,
                                                                                                                    $blockSize

            $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_threads{3}_iterations{4}_chunk{5}_blockSize{6}" -f $BertaResultPath,
                                                                                                         $CompressionType,
                                                                                                         $CompressionProvider,
                                                                                                         $numThreads,
                                                                                                         $numIterations,
                                                                                                         $Chunk,
                                                                                                         $blockSize
        }

        if (!$deCompressFlag) {
            $Remote2HostIcpQatFile = "{0}_level{1}" -f $Remote2HostIcpQatFile, $Level
            $Remote2HostCfQatFile = "{0}_level{1}" -f $Remote2HostCfQatFile, $Level
            $Remote2HostDumpFile = "{0}_level{1}" -f $Remote2HostDumpFile, $Level
        }

        if ($deCompressProvider -eq "qat") {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $QatCompressionType
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $QatCompressionType
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $QatCompressionType
        }

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile  | out-null
    }

    return $ReturnValue
}

# Test: SWFallback test of parcomp
function WinHost-ParcompSWfallback
{
    Param(
        [string]$CompressType = "Compress",

        [string]$CompressProvider = "qat",

        [string]$deCompressProvider = "qat",

        [string]$QatCompressionType = "dynamic",

        [int]$Level = 1,

        [int]$numThreads = 6,

        [int]$numIterations = 200,

        [int]$blockSize = 4096,

        [int]$Chunk = 64,

        [string]$TestFilefullPath = $null,

        [string]$TestFileType = "high",

        [int]$TestFileSize = 200,

        [string]$TestType = "heartbeat",

        [string]$QatDriverZipPath = $null,

        [string]$BertaResultPath = "C:\\temp"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    $SWFallbackCheck = [hashtable] @{
        Hardware2Software = "Hardware compression failed, attempting software fallback"
        HandleQATError = "handleQatError() failed"
        HandleSWFallbackError = "handleSWFallback() failed"
    }

    $ParcompType = "Fallback"
    $runParcompType = "Process"
    $CompressTestPath = $ParcompOpts.CompressPathName
    $deCompressTestPath = $ParcompOpts.deCompressPathName

    # Run tracelog
    UT-TraceLogStart -Remote $false | out-null

    # Run parcomp exe
    Win-DebugTimestamp -output ("Host: Start to {0} test ({1}) with {2} provider!" -f $TestType,
                                                                                      $CompressType,
                                                                                      $deCompressProvider)

    $ProcessCount = 0
    if (($CompressType -eq "Compress") -or ($CompressType -eq "All")) {
        $ProcessCount += 1
        $CompressTestResult = WBase-Parcomp -Side "host" `
                                            -deCompressFlag $false `
                                            -CompressProvider $CompressProvider `
                                            -deCompressProvider $deCompressProvider `
                                            -QatCompressionType $QatCompressionType `
                                            -Level $Level `
                                            -Chunk $Chunk `
                                            -blockSize $blockSize `
                                            -numThreads $numThreads `
                                            -numIterations $numIterations `
                                            -ParcompType $ParcompType `
                                            -runParcompType $runParcompType `
                                            -TestPathName $CompressTestPath `
                                            -TestFilefullPath $TestFilefullPath `
                                            -TestFileType $TestFileType `
                                            -TestFileSize $TestFileSize

        Start-Sleep -Seconds 5
    }

    if (($CompressType -eq "deCompress") -or ($CompressType -eq "All")) {
        $ProcessCount += 1
        $deCompressTestResult = WBase-Parcomp -Side "host" `
                                              -deCompressFlag $true `
                                              -CompressProvider $CompressProvider `
                                              -deCompressProvider $deCompressProvider `
                                              -QatCompressionType $QatCompressionType `
                                              -Level $Level `
                                              -Chunk $Chunk `
                                              -blockSize $blockSize `
                                              -numThreads $numThreads `
                                              -numIterations $numIterations `
                                              -ParcompType $ParcompType `
                                              -runParcompType $runParcompType `
                                              -TestPathName $deCompressTestPath `
                                              -TestFilefullPath $TestFilefullPath `
                                              -TestFileType $TestFileType `
                                              -TestFileSize $TestFileSize

        Start-Sleep -Seconds 5
    }

    # Check parcomp test process number
    $CheckProcessNumberFlag = WBase-CheckProcessNumber -ProcessName "parcomp" -ProcessNumber $ProcessCount
    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckProcessNumberFlag.result
        $ReturnValue.error = $CheckProcessNumberFlag.error
    }

    # Operation: heartbeat, disable, upgrade
    if ($ReturnValue.result) {
        if ($TestType -eq "heartbeat") {
            Win-DebugTimestamp -output ("Run 'heartbeat' operation on local host")
            $heartbeatStatus = WBase-HeartbeatQatDevice -LogPath $BertaResultPath

            Win-DebugTimestamp -output ("The heartbeat operation > {0}" -f $heartbeatStatus)
            if (-not $heartbeatStatus) {
                $ReturnValue.result = $heartbeatStatus
                $ReturnValue.error = "heartbeat_failed"
            }
        } elseif ($TestType -eq "disable") {
            Win-DebugTimestamp -output ("Run 'disable' and 'enable' operation on local host")
            $disableStatus = WBase-EnableAndDisableQatDevice -Remote $false

            Win-DebugTimestamp -output ("The disable and enable operation > {0}" -f $disableStatus)
            if (-not $disableStatus) {
                $ReturnValue.result = $disableStatus
                $ReturnValue.error = "disable_failed"
            }
        } elseif ($TestType -eq "upgrade") {
            Win-DebugTimestamp -output ("Run 'upgrade' operation on local host")
            $upgradeStatus = WBase-UpgradeQatDevice

            Win-DebugTimestamp -output ("The upgrade operation > {0}" -f $upgradeStatus)
            if (-not $upgradeStatus) {
                Win-DebugTimestamp -output ("The upgrade operation is failed")
                $ReturnValue.result = $upgradeStatus
                $ReturnValue.error = "upgrade_failed"
            }
        } else {
            Win-DebugTimestamp -output ("The fallback test does not support test type > {0}" -f $TestType)
            $ReturnValue.result = $false
            $ReturnValue.error = ("test_type_{0}" -f $TestType)
        }
    } else {
        Win-DebugTimestamp -output ("Host: Skip {0} operation, because Error > {1}" -f $TestType, $ReturnValue.error)
    }

    # Wait parcomp test process to complete
    $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "parcomp" -Remote $false
    if ($ReturnValue.result) {
        $ReturnValue.result = $WaitProcessFlag.result
        $ReturnValue.error = $WaitProcessFlag.error
    }

    # Check parcomp test result
    $CompressTestOutLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $CompressTestPath, $ParcompOpts.OutputLog
    $CompressTestErrorLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $CompressTestPath, $ParcompOpts.ErrorLog
    $deCompressTestOutLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $deCompressTestPath, $ParcompOpts.OutputLog
    $deCompressTestErrorLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $deCompressTestPath, $ParcompOpts.ErrorLog

    if (($CompressType -eq "Compress") -or ($CompressType -eq "All")) {
        $CheckOutput = WBase-CheckOutput `
            -TestOutputLog $CompressTestOutLogPath `
            -TestErrorLog $CompressTestErrorLogPath `
            -Remote $false `
            -keyWords "Mbps"

        if ($ReturnValue.result) {
            $ReturnValue.result = $CheckOutput.result
            $ReturnValue.error = $CheckOutput.error
        }
    }

    if (($CompressType -eq "deCompress") -or ($CompressType -eq "All")) {
        $CheckOutput = WBase-CheckOutput `
            -TestOutputLog $deCompressTestOutLogPath `
            -TestErrorLog $deCompressTestErrorLogPath `
            -Remote $false `
            -keyWords "Mbps"

        if ($ReturnValue.result) {
            $ReturnValue.result = $CheckOutput.result
            $ReturnValue.error = $CheckOutput.error
        }
    }

    # Double check the output files
    if ($ReturnValue.result) {
        if (($CompressType -eq "Compress") -or ($CompressType -eq "All")) {
            Win-DebugTimestamp -output ("Host: Double check the output file of fallback test (compress)")
            $MD5MatchFlag = $true
            $CheckMD5Result = WinHostCheckMD5 -deCompressFlag $false `
                                              -CompressProvider $CompressProvider `
                                              -deCompressProvider $deCompressProvider `
                                              -QatCompressionType $QatCompressionType `
                                              -Level $Level `
                                              -Chunk $Chunk `
                                              -TestFileType $TestFileType `
                                              -TestFileSize $TestFileSize `
                                              -TestPathName $CompressTestPath

            $TestSourceFileMD5 = $CheckMD5Result.SourceFile
            Win-DebugTimestamp -output ("Host: The MD5 value of source file > {0}" -f $TestSourceFileMD5)
            $FileCount = 0
            ForEach ($TestParcompOutFileMD5 in $CheckMD5Result.OutFile) {
                Win-DebugTimestamp -output ("Host: The MD5 value of fallback test (compress) output file {0} > {1}" -f $FileCount, $TestParcompOutFileMD5)
                $FileCount++
                if ($TestParcompOutFileMD5 -ne $TestSourceFileMD5) {$MD5MatchFlag = $false}
            }
            if ($MD5MatchFlag) {
                Win-DebugTimestamp -output ("Host: The output file of fallback test (compress) and the source file are matched!")
            } else {
                Win-DebugTimestamp -output ("Host: The output file of fallback test (compress) and the source file are not matched!")

                $ReturnValue.result = $false
                $ReturnValue.error = "MD5_no_matched"
            }
        }

        if (($CompressType -eq "deCompress") -or ($CompressType -eq "All")) {
            Win-DebugTimestamp -output ("Host: Double check the output file of fallback test (decompress)")
            $MD5MatchFlag = $true
            $CheckMD5Result = WinHostCheckMD5 -deCompressFlag $true `
                                              -CompressProvider $CompressProvider `
                                              -deCompressProvider $deCompressProvider `
                                              -QatCompressionType $QatCompressionType `
                                              -Level $Level `
                                              -Chunk $Chunk `
                                              -TestFileType $TestFileType `
                                              -TestFileSize $TestFileSize `
                                              -TestPathName $deCompressTestPath

            $TestSourceFileMD5 = $CheckMD5Result.SourceFile
            Win-DebugTimestamp -output ("Host: The MD5 value of source file > {0}" -f $TestSourceFileMD5)
            $FileCount = 0
            ForEach ($TestParcompOutFileMD5 in $CheckMD5Result.OutFile) {
                Win-DebugTimestamp -output ("Host: The MD5 value of fallback test (decompress) output file {0} > {1}" -f $FileCount, $TestParcompOutFileMD5)
                $FileCount++
                if ($TestParcompOutFileMD5 -ne $TestSourceFileMD5) {$MD5MatchFlag = $false}
            }
            if ($MD5MatchFlag) {
                Win-DebugTimestamp -output ("Host: The output file of fallback test (decompress) and the source file are matched!")
            } else {
                Win-DebugTimestamp -output ("Host: The output file of fallback test (decompress) and the source file are not matched!")

                if ($ReturnValue.result) {$ReturnValue.result = $false}
                if ($ReturnValue.error -ne "MD5_no_matched") {$ReturnValue.error = "MD5_no_matched"}
            }
        }
    } else {
        Win-DebugTimestamp -output ("Host: Skip checking the output files of fallback test, because Error > {0}" -f $ReturnValue.error)
    }

    # Run parcomp test after fallback test
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Double check: Run parcomp test after fallback test")
        $parcompTestResult = WinHost-ParcompBase -deCompressFlag $false `
                                                 -CompressProvider $CompressProvider `
                                                 -deCompressProvider $CompressProvider `
                                                 -QatCompressionType $QatCompressionType `
                                                 -BertaResultPath $BertaResultPath

        Win-DebugTimestamp -output ("Double check: The parcomp test is completed > {0}" -f $parcompTestResult.result)
        if (!$parcompTestResult.result) {
            $ReturnValue.result = $parcompTestResult.result
            $ReturnValue.error = $parcompTestResult.error
        }
    }

    # Handle all errors
    if (!$ReturnValue.result) {
        $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                       $CompressType,
                                                                       $CompressProvider,
                                                                       $TestType

        $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                     $CompressType,
                                                                     $CompressProvider,
                                                                     $TestType

        $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_{3}" -f $BertaResultPath,
                                                          $CompressType,
                                                          $CompressProvider,
                                                          $TestType

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile | out-null
    }

    return $ReturnValue
}

# Test: base test of CNGTest
function WinHost-CNGTestBase
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$algo,

        [string]$operation = "encrypt",

        [string]$provider = "qa",

        [int]$keyLength = 2048,

        [string]$ecccurve = "nistP256",

        [string]$padding = "pkcs1",

        [string]$numThreads = 96,

        [string]$numIter = 10000,

        [string]$TestPathName = $null,

        [string]$BertaResultPath = "C:\\temp"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $CNGTestOpts.PathName
    }

    $TestPath = "{0}\\{1}" -f $STVWinPath, $TestPathName
    $CNGTestOutLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.OutputLog
    $CNGTestErrorLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.ErrorLog

    # Run tracelog
    UT-TraceLogStart -Remote $false | out-null

    # Run CNGTest exe
    Win-DebugTimestamp -output ("Host: Start to {0} test ({1}) with {2} provider!" -f $algo,
                                                                                      $operation,
                                                                                      $provider)

    $CNGTestResult = WBase-CNGTest -Side "host" `
                                   -algo $algo `
                                   -operation $operation `
                                   -provider $provider `
                                   -keyLength $keyLength `
                                   -ecccurve $ecccurve `
                                   -padding $padding `
                                   -numThreads $numThreads `
                                   -numIter $numIter `
                                   -TestPathName $TestPathName

    # Check CNGTest test process number
    $CheckProcessNumberFlag = WBase-CheckProcessNumber -ProcessName "cngtest"
    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckProcessNumberFlag.result
        $ReturnValue.error = $CheckProcessNumberFlag.error
    }

    # Wait CNGTest test process to complete
    $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "cngtest" -Remote $false
    if ($ReturnValue.result) {
        $ReturnValue.result = $WaitProcessFlag.result
        $ReturnValue.error = $WaitProcessFlag.error
    }

    # Check CNGTest test result
    $CheckOutput = WBase-CheckOutput `
        -TestOutputLog $CNGTestOutLog `
        -TestErrorLog $CNGTestErrorLog `
        -Remote $false `
        -keyWords "Ops/s"

    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckOutput.result
        $ReturnValue.error = $CheckOutput.error
    }

    # Handle all errors
    if (!$ReturnValue.result) {
        $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                       $provider,
                                                                       $algo,
                                                                       $operation

        $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                     $provider,
                                                                     $algo,
                                                                     $operation

        $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_{3}" -f $BertaResultPath,
                                                          $provider,
                                                          $algo,
                                                          $operation

        if (($algo -eq "ecdsa") -and ($algo -eq "ecdh")) {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $ecccurve
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $ecccurve
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $ecccurve
        } else {
            $Remote2HostIcpQatFile = "{0}_keyLength{1}" -f $Remote2HostIcpQatFile, $keyLength
            $Remote2HostCfQatFile = "{0}_keyLength{1}" -f $Remote2HostCfQatFile, $keyLength
            $Remote2HostDumpFile = "{0}_keyLength{1}" -f $Remote2HostDumpFile, $keyLength
        }

        if ($algo -eq "rsa") {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $padding
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $padding
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $padding
        }

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile  | out-null
    }

    return $ReturnValue
}

# Test: performance test of CNGTest
function WinHost-CNGTestPerformance
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$algo,

        [string]$operation = "encrypt",

        [string]$provider = "qa",

        [int]$keyLength = 2048,

        [string]$ecccurve = "nistP256",

        [string]$padding = "pkcs1",

        [string]$numThreads = 96,

        [string]$numIter = 10000,

        [string]$TestPathName = $null,

        [string]$BertaResultPath = "C:\\temp",

        [string]$TestType = "Performance"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        testOps = 0
        error = "no_error"
    }

    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $CNGTestOpts.PathName
    }

    $TestPath = "{0}\\{1}" -f $STVWinPath, $TestPathName
    $CNGTestOutLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.OutputLog
    $CNGTestErrorLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.ErrorLog

    # Stop trace log tool
    UT-TraceLogStop -Remote $false | out-null

    # Run CNGTest exe
    Win-DebugTimestamp -output ("Host: Start to {0} test ({1}) with {2} provider!" -f $algo,
                                                                                      $operation,
                                                                                      $provider)

    $CNGTestResult = WBase-CNGTest -Side "host" `
                                   -algo $algo `
                                   -operation $operation `
                                   -provider $provider `
                                   -keyLength $keyLength `
                                   -ecccurve $ecccurve `
                                   -padding $padding `
                                   -numThreads $numThreads `
                                   -numIter $numIter `
                                   -TestPathName $TestPathName

    # Check CNGTest test process number
    $CheckProcessNumberFlag = WBase-CheckProcessNumber -ProcessName "cngtest"
    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckProcessNumberFlag.result
        $ReturnValue.error = $CheckProcessNumberFlag.error
    }

    # Wait CNGTest test process to complete
    $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "cngtest" -Remote $false
    if ($ReturnValue.result) {
        $ReturnValue.result = $WaitProcessFlag.result
        $ReturnValue.error = $WaitProcessFlag.error
    }

    # Check CNGTest test result
    $CheckOutput = WBase-CheckOutput `
        -TestOutputLog $CNGTestOutLog `
        -TestErrorLog $CNGTestErrorLog `
        -Remote $false `
        -keyWords "Ops/s"

    $ReturnValue.result = $CheckOutput.result
    $ReturnValue.error = $CheckOutput.error
    $ReturnValue.testOps = $CheckOutput.testOps

    # Handle all errors
    if (!$ReturnValue.result) {
        $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                       $provider,
                                                                       $algo,
                                                                       $operation

        $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                     $provider,
                                                                     $algo,
                                                                     $operation

        $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_{3}" -f $BertaResultPath,
                                                          $provider,
                                                          $algo,
                                                          $operation

        if (($algo -eq "ecdsa") -and ($algo -eq "ecdh")) {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $ecccurve
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $ecccurve
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $ecccurve
        } else {
            $Remote2HostIcpQatFile = "{0}_keyLength{1}" -f $Remote2HostIcpQatFile, $keyLength
            $Remote2HostCfQatFile = "{0}_keyLength{1}" -f $Remote2HostCfQatFile, $keyLength
            $Remote2HostDumpFile = "{0}_keyLength{1}" -f $Remote2HostDumpFile, $keyLength
        }

        if ($algo -eq "rsa") {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $padding
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $padding
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $padding
        }

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile  | out-null
    }

    return $ReturnValue
}

# Test: SWFallback test of CNGTest
function WinHost-CNGTestSWfallback
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$algo,

        [string]$operation = "encrypt",

        [string]$provider = "qa",

        [int]$keyLength = 2048,

        [string]$ecccurve = "nistP256",

        [string]$padding = "pkcs1",

        [string]$numThreads = 96,

        [string]$numIter = 10000,

        [string]$TestPathName = $null,

        [string]$BertaResultPath = "C:\\temp",

        [string]$TestType = "heartbeat"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    if ([String]::IsNullOrEmpty($TestPathName)) {
        $TestPathName = $CNGTestOpts.PathName
    }

    $TestPath = "{0}\\{1}" -f $STVWinPath, $TestPathName
    $CNGTestOutLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.OutputLog
    $CNGTestErrorLog = "{0}\\{1}" -f $TestPath, $CNGTestOpts.ErrorLog

    # Run tracelog
    UT-TraceLogStart -Remote $false | out-null

    # Run CNGTest exe
    Win-DebugTimestamp -output ("Host: Start to {0} test ({1}) with {2} operation!" -f $TestType,
                                                                                       $algo,
                                                                                       $operation)

    $CNGTestResult = WBase-CNGTest -Side "host" `
                                   -algo $algo `
                                   -operation $operation `
                                   -provider $provider `
                                   -keyLength $keyLength `
                                   -ecccurve $ecccurve `
                                   -padding $padding `
                                   -numThreads $numThreads `
                                   -numIter $numIter `
                                   -TestPathName $TestPathName

    # Check CNGTest test process number
    $CheckProcessNumberFlag = WBase-CheckProcessNumber -ProcessName "cngtest"
    if ($ReturnValue.result) {
        $ReturnValue.result = $CheckProcessNumberFlag.result
        $ReturnValue.error = $CheckProcessNumberFlag.error
    }

    # Operation: heartbeat, disable, upgrade
    if ($ReturnValue.result) {
        if ($TestType -eq "heartbeat") {
            Win-DebugTimestamp -output ("Run 'heartbeat' operation on local host")
            $heartbeatStatus = WBase-HeartbeatQatDevice -LogPath $BertaResultPath

            Win-DebugTimestamp -output ("The heartbeat operation > {0}" -f $heartbeatStatus)
            if (-not $heartbeatStatus) {
                $ReturnValue.result = $heartbeatStatus
                $ReturnValue.error = "heartbeat_failed"
            }
        } elseif ($TestType -eq "disable") {
            Win-DebugTimestamp -output ("Run 'disable' and 'enable' operation on local host")
            $disableStatus = WBase-EnableAndDisableQatDevice -Remote $false

            Win-DebugTimestamp -output ("The disable and enable operation > {0}" -f $disableStatus)
            if (-not $disableStatus) {
                $ReturnValue.result = $disableStatus
                $ReturnValue.error = "disable_failed"
            }
        } elseif ($TestType -eq "upgrade") {
            Win-DebugTimestamp -output ("Run 'upgrade' operation on local host")
            $upgradeStatus = WBase-UpgradeQatDevice

            Win-DebugTimestamp -output ("The upgrade operation > {0}" -f $upgradeStatus)
            if (-not $upgradeStatus) {
                Win-DebugTimestamp -output ("The upgrade operation is failed")
                $ReturnValue.result = $upgradeStatus
                $ReturnValue.error = "upgrade_failed"
            }
        } else {
            Win-DebugTimestamp -output ("The fallback test does not support test type > {0}" -f $TestType)
            $ReturnValue.result = $false
            $ReturnValue.error = ("test_type_{0}" -f $TestType)
        }
    } else {
        Win-DebugTimestamp -output ("Host: Skip {0} operation, because Error > {1}" -f $TestType, $ReturnValue.error)
    }

    # Wait CNGTest test process to complete
    $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "cngtest" -Remote $false
    if ($ReturnValue.result) {
        $ReturnValue.result = $WaitProcessFlag.result
        $ReturnValue.error = $WaitProcessFlag.error
    }

    # Check CNGTest test result
    $CheckOutput = WBase-CheckOutput `
        -TestOutputLog $CNGTestOutLog `
        -TestErrorLog $CNGTestErrorLog `
        -Remote $false `
        -keyWords "Ops/s"

    $ReturnValue.result = $CheckOutput.result
    $ReturnValue.error = $CheckOutput.error

    # Run CNGTest after fallback test
    if ($ReturnValue.result) {
        Win-DebugTimestamp -output ("Double check: Run CNGTest after fallback test")

        $CNGTestTestResult = WinHost-CNGTestBase -algo $algo

        Win-DebugTimestamp -output ("Running cngtest is completed > {0}" -f $CNGTestTestResult.result)

        if ($ReturnValue.result) {
            $ReturnValue.result = $CNGTestTestResult.result
            $ReturnValue.error = $CNGTestTestResult.error
        }
    }

    # Handle all errors
    if (!$ReturnValue.result) {
        $Remote2HostIcpQatFile = "{0}\\tracelog_IcpQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                       $provider,
                                                                       $algo,
                                                                       $operation

        $Remote2HostCfQatFile = "{0}\\tracelog_CfQat_{1}_{2}_{3}" -f $BertaResultPath,
                                                                     $provider,
                                                                     $algo,
                                                                     $operation

        $Remote2HostDumpFile = "{0}\\dump_{1}_{2}_{3}" -f $BertaResultPath,
                                                          $provider,
                                                          $algo,
                                                          $operation

        if (($algo -eq "ecdsa") -and ($algo -eq "ecdh")) {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $ecccurve
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $ecccurve
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $ecccurve
        } else {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $keyLength
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $keyLength
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $keyLength
        }

        if ($algo -eq "rsa") {
            $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $padding
            $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $padding
            $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $padding
        }

        $Remote2HostIcpQatFile = "{0}_{1}" -f $Remote2HostIcpQatFile, $TestType
        $Remote2HostCfQatFile = "{0}_{1}" -f $Remote2HostCfQatFile, $TestType
        $Remote2HostDumpFile = "{0}_{1}" -f $Remote2HostDumpFile, $TestType

        WinHostErrorHandle -TestResult $ReturnValue `
                           -IcpQatFileName $Remote2HostIcpQatFile `
                           -CfQatFileName $Remote2HostCfQatFile  | out-null
    }

    return $ReturnValue
}

# Test: stress test of parcomp and CNGTest
function WinHost-Stress
{
    Param(
        [bool]$RunParcomp = $true,

        [bool]$RunCNGtest = $true,

        [string]$BertaResultPath = "C:\\temp"
    )

    $ReturnValue = [hashtable] @{
        result = $true
        error = "no_error"
    }

    $ParcompType = "Performance"
    $runParcompType = "Process"
    $CompressType = "All"
    $CompressTestPath = $ParcompOpts.CompressPathName
    $deCompressTestPath = $ParcompOpts.deCompressPathName
    $CNGTestPath = $CNGTestOpts.PathName

    # Run test
    if ($RunParcomp) {
        Win-DebugTimestamp -output ("Host: Start to compress test")
        $CompressTestResult = WBase-Parcomp -Side "host" `
                                            -deCompressFlag $false `
                                            -ParcompType $ParcompType `
                                            -runParcompType $runParcompType `
                                            -TestPathName $CompressTestPath

        Start-Sleep -Seconds 5

        Win-DebugTimestamp -output ("Host: Start to decompress test")
        $deCompressTestResult = WBase-Parcomp -Side "host" `
                                              -deCompressFlag $true `
                                              -ParcompType $ParcompType `
                                              -runParcompType $runParcompType `
                                              -TestPathName $deCompressTestPath

        Start-Sleep -Seconds 5
    }

    if ($RunCNGtest) {
        Win-DebugTimestamp -output ("Host: Start to cng test")
        $CNGTestResult = WBase-CNGTest -Side "host" -algo "rsa"
    }

    # Get test result
    if ($RunParcomp) {
        $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "parcomp" -Remote $false
        if ($ReturnValue.result) {
            $ReturnValue.result = $WaitProcessFlag.result
            $ReturnValue.error = $WaitProcessFlag.error
        }

        $CompressTestOutLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $CompressTestPath, $ParcompOpts.OutputLog
        $CompressTestErrorLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $CompressTestPath, $ParcompOpts.ErrorLog
        $deCompressTestOutLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $deCompressTestPath, $ParcompOpts.OutputLog
        $deCompressTestErrorLogPath = "{0}\\{1}\\{2}" -f $STVWinPath, $deCompressTestPath, $ParcompOpts.ErrorLog

        $CheckOutput = WBase-CheckOutput `
            -TestOutputLog $CompressTestOutLogPath `
            -TestErrorLog $CompressTestErrorLogPath `
            -Remote $false `
            -keyWords "Mbps"

        if ($ReturnValue.result) {
            $ReturnValue.result = $CheckOutput.result
            $ReturnValue.error = $CheckOutput.error
        }

        $CheckOutput = WBase-CheckOutput `
            -TestOutputLog $deCompressTestOutLogPath `
            -TestErrorLog $deCompressTestErrorLogPath `
            -Remote $false `
            -keyWords "Mbps"

        if ($ReturnValue.result) {
            $ReturnValue.result = $CheckOutput.result
            $ReturnValue.error = $CheckOutput.error
        }

        if ($ReturnValue.result) {
            Win-DebugTimestamp -output ("Host: The parcomp test ({0}) of stress is passed" -f $CompressType)
        }
    }

    if ($RunCNGtest) {
        $WaitProcessFlag = WBase-WaitProcessToCompleted -ProcessName "cngtest" -Remote $false
        if ($ReturnValue.result) {
            $ReturnValue.result = $WaitProcessFlag.result
            $ReturnValue.error = $WaitProcessFlag.error
        }

        $CNGTestOutLog = "{0}\\{1}\\{2}" -f $STVWinPath, $CNGTestPath, $CNGTestOpts.OutputLog
        $CNGTestErrorLog = "{0}\\{1}\\{2}" -f $STVWinPath, $CNGTestPath, $CNGTestOpts.ErrorLog

        $CheckOutput = WBase-CheckOutput `
            -TestOutputLog $CNGTestOutLog `
            -TestErrorLog $CNGTestErrorLog `
            -Remote $false `
            -keyWords "Ops/s"

        if ($ReturnValue.result) {
            $ReturnValue.result = $CheckOutput.result
            $ReturnValue.error = $CheckOutput.error
        }

        if ($ReturnValue.result) {
            Win-DebugTimestamp -output ("Host: The CNGtest of stress is passed")
        }
    }

    return $ReturnValue
}


Export-ModuleMember -Function *-*
