Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [bool]$RunOnLocal = $false,

    [bool]$InitVM = $true,

    [array]$VMVFOSConfigs = $null,

    [bool]$UQMode = $false,

    [bool]$TestMode = $true,

    [bool]$VerifierMode = $true,

    [bool]$DebugMode = $false,

    [string]$DriverPath = "C:\\cy-work\\qat_driver\\",

    [string]$ResultFile = "result.log"
)

$TestSuitePath = Split-Path -Path $PSCommandPath
Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global

Import-Module "$QATTESTPATH\\lib\\WinHost.psm1" -Force -DisableNameChecking
Import-Module "$QATTESTPATH\\lib\\Win2Win.psm1" -Force -DisableNameChecking
WBase-ReturnFilesInit `
    -BertaResultPath $BertaResultPath `
    -ResultFile $ResultFile | out-null
$TestSuiteName = (Split-Path -Path $PSCommandPath -Leaf).Split(".")[0]
$CompareFile = "{0}\\CompareFile_{1}.log" -f
    $BertaResultPath,
    $TestSuiteName

try {
    $BertaConfig = [hashtable] @{}
    if ($RunOnLocal) {
        $BertaConfig["UQ_mode"] = $UQMode
        $BertaConfig["test_mode"] = $TestMode
        $BertaConfig["driver_verifier"] = $VerifierMode
        $BertaConfig["DebugMode"] = $DebugMode
        $LocationInfo.WriteLogToConsole = $true
        $LocalBuildPath = $DriverPath
    } else {
        $FilePath = Join-Path -Path $BertaResultPath -ChildPath "task.json"
        $out = Get-Content -LiteralPath $FilePath | ConvertFrom-Json -AsHashtable

        $BertaConfig["UQ_mode"] = $out.config.UQ_mode
        $BertaConfig["test_mode"] = ($out.config.test_mode -eq "true") ? $true : $false
        $BertaConfig["driver_verifier"] = ($out.config.driver_verifier -eq "true") ? $true : $false
        $BertaConfig["DebugMode"] = $false

        $job2 = $out.jobs | Where-Object {$_.job_id -eq 2}
        $LocalBuildPath = $job2.bld_path
    }

    $LocationInfo.HVMode = $true
    $LocationInfo.IsWin = $true
    $LocationInfo.VM.IsWin = $true
    $PFVFDriverPath = WBase-GetDriverPath -BuildPath $LocalBuildPath

    # Init QAT type
    WBase-HostDeviceInit | out-null

    [System.Array]$CompareTypes = ("true", "false")

    # Special: For All
    # Init CNGTest
    [System.Array]$SmokeTestCNGTestTypes = (
        "Base",
        "Performance",
        "Heartbeat",
        "Disable"
    )
    [System.Array]$CNGtestConfigs = (
        [hashtable] @{
            Algo = "rsa"
            keyLength = 2048
            Operation = "encrypt"
            Padding = "oaep"
        },
        [hashtable] @{
            Algo = "rsa"
            keyLength = 2048
            Operation = "decrypt"
            Padding = "oaep"
        },
        [hashtable] @{
            Algo = "ecdh"
            Ecccurve = "nistP256"
            Operation = "derivekey"
        },
        [hashtable] @{
            Algo = "ecdh"
            Ecccurve = "nistP256"
            Operation = "secretagreement"
        },
        [hashtable] @{
            Algo = "ecdsa"
            Ecccurve = "nistP256"
            Operation = "sign"
        },
        [hashtable] @{
            Algo = "ecdsa"
            Ecccurve = "nistP256"
            Operation = "verify"
        }
    )
    $CNGtestProvider = "qa"
    $CNGtestnumThreads = 96
    $CNGtestnumIter = 10000
    $CNGtestTestPathName = "CNGTest"

    # Init parcomp
    [System.Array]$SmokeTestParcompTypes = (
        "Base",
        "Performance",
        "Heartbeat",
        "Disable"
    )
    [System.Array]$ParcompTypes = (
        "Compress",
        "deCompress"
    )
    $ParcompProvider = "qat"
    $ParcompChunkSize = 64
    $ParcompnumThreads = 8
    $ParcompnumIter = 100
    $ParcompTestPathName = "ParcompTest"
    $ParcompTestFileType = "calgary"
    $ParcompTestFileSize = 200

    # Init installer
    [System.Array]$SmokeTestInstallerTypes = ("Disable")
    [System.Array]$InstallerTypes = (
        "disable",
        "parcomp",
        "cngtest"
    )

    # Init UQ type
    [System.Array]$SmokeTestUQTypes = @()
    if ($BertaConfig["UQ_mode"] -eq "All") {
        $SmokeTestUQTypes += "false"
        $SmokeTestUQTypes += "true"
        $BertaConfig["UQ_mode"] = $false
        Win-DebugTimestamp -output ("Will run SmokeTest with UQ and NUQ mode....")
    } elseif ($BertaConfig["UQ_mode"] -eq "true") {
        $SmokeTestUQTypes += "true"
        $BertaConfig["UQ_mode"] = $true
        Win-DebugTimestamp -output ("Will run SmokeTest with UQ mode....")
    } else {
        $SmokeTestUQTypes += "false"
        $BertaConfig["UQ_mode"] = $false
        Win-DebugTimestamp -output ("Will run SmokeTest with NUQ mode....")
    }

    # Init test platform type and test tools
    $HostPlatformType = $true
    $HostToolParcomp = $true
    $HostToolCNGTest = $true
    $HVModePlatformType = $true
    $HVModeToolParcomp = $true
    $HVModeToolCNGTest = $true

    # Init VM VF OS for HyperV mode
    if ([String]::IsNullOrEmpty($VMVFOSConfigs)) {
        if ($LocationInfo.QatType -eq "QAT20") {
            [System.Array]$VMVFOSConfigs = ("1vm_8vf_windows2022")
        } elseif ($LocationInfo.QatType -eq "QAT17") {
            [System.Array]$VMVFOSConfigs = ("1vm_3vf_windows2022")
        } elseif ($LocationInfo.QatType -eq "QAT18") {
            [System.Array]$VMVFOSConfigs = ("1vm_3vf_windows2022")
        }
    }

    # If driver verifier is true, will not support performance test
    if ($BertaConfig["driver_verifier"]) {
        [System.Array]$SmokeTestCNGTestTypes = ("Base", "Heartbeat", "Disable")
        [System.Array]$SmokeTestParcompTypes = ("Base", "Heartbeat", "Disable")
    }

    Foreach ($CompareType in $CompareTypes) {
        if ($CompareType -eq "true") {
            $CompareFlag = $true
            Win-DebugTimestamp -output (
                "Create compare file: {0}" -f $CompareFile
            )
        }

        if ($CompareType -eq "false") {
            $CompareFlag = $false
        }

        Foreach ($SmokeTestUQType in $SmokeTestUQTypes) {
            Win-DebugTimestamp -output ("Host: Test UQ mode > {0}" -f $SmokeTestUQType)

            if ($SmokeTestUQType -eq "true") {
                $BertaConfig["UQ_mode"] = $true

                # Special: For QAT17
                if ($LocationInfo.QatType -eq "QAT17") {
                    Win-DebugTimestamp -output (
                        "Host: {0} can not support UQ mode" -f $LocationInfo.QatType
                    )

                    continue
                }

                # Special: For QAT18
                if ($LocationInfo.QatType -eq "QAT18") {
                    Win-DebugTimestamp -output (
                        "Host: {0} can not support UQ mode" -f $LocationInfo.QatType
                    )

                    continue
                }

                # Special: For QAT20
                if ($LocationInfo.QatType -eq "QAT20") {
                    $HostPlatformType = $true
                    $HostToolParcomp = $true
                    $HostToolCNGTest = $true
                    $HVModePlatformType = $false
                    $HVModeToolParcomp = $false
                    $HVModeToolCNGTest = $false

                    if ($BertaConfig["driver_verifier"]) {
                        [System.Array]$SmokeTestCNGTestTypes = ("Base")
                        [System.Array]$SmokeTestParcompTypes = ("Base", "Heartbeat")
                    } else {
                        [System.Array]$SmokeTestCNGTestTypes = ("Base", "Performance")
                        [System.Array]$SmokeTestParcompTypes = ("Base", "Performance", "Heartbeat")
                    }
                }
            }

            if ($SmokeTestUQType -eq "false") {
                $BertaConfig["UQ_mode"] = $false

                # Special: For QAT17
                if ($LocationInfo.QatType -eq "QAT17") {
                    $HostPlatformType = $true
                    $HostToolParcomp = $true
                    $HostToolCNGTest = $true
                    $HVModePlatformType = $true
                    $HVModeToolParcomp = $true
                    $HVModeToolCNGTest = $false
                }

                # Special: For QAT18
                if ($LocationInfo.QatType -eq "QAT18") {
                    $HostPlatformType = $true
                    $HostToolParcomp = $true
                    $HostToolCNGTest = $false
                    $HVModePlatformType = $true
                    $HVModeToolParcomp = $true
                    $HVModeToolCNGTest = $false

                    if ($BertaConfig["driver_verifier"]) {
                        [System.Array]$SmokeTestParcompTypes = (
                            "Base"
                        )
                    } else {
                        [System.Array]$SmokeTestParcompTypes = (
                            "Base",
                            "Performance"
                        )
                    }
                }

                # Special: For QAT20
                if ($LocationInfo.QatType -eq "QAT20") {
                    $HostPlatformType = $true
                    $HostToolParcomp = $true
                    $HostToolCNGTest = $true
                    $HVModePlatformType = $true
                    $HVModeToolParcomp = $true
                    $HVModeToolCNGTest = $true

                    if ($BertaConfig["driver_verifier"]) {
                        [System.Array]$SmokeTestCNGTestTypes = ("Base", "Heartbeat", "Disable")
                        [System.Array]$SmokeTestParcompTypes = ("Base", "Heartbeat", "Disable")
                    } else {
                        [System.Array]$SmokeTestCNGTestTypes = ("Base", "Performance", "Heartbeat", "Disable")
                        [System.Array]$SmokeTestParcompTypes = ("Base", "Performance", "Heartbeat", "Disable")
                    }
                }
            }

            $UQString = ($BertaConfig["UQ_mode"]) ? "UQ" : "NUQ"
            $SmokeTestBanchMarkFile = "{0}\\banchmark\\SmokeTest_{1}_{2}_banchmark.log" -f
                $QATTESTPATH,
                $LocationInfo.QatType,
                $UQString

            # Host
            if ($HostPlatformType) {
                if (!$CompareFlag) {
                    $LocationInfo.HVMode = $false
                    $LocationInfo.IsWin = $true
                    $LocationInfo.VM.IsWin = $null
                    WBase-LocationInfoInit -BertaResultPath $BertaResultPath `
                                           -QatDriverFullPath $PFVFDriverPath `
                                           -BertaConfig $BertaConfig | out-null

                    Win-DebugTimestamp -output ("Host: Initialize test environment....")
                    WinHost-ENVInit | out-null

                    Win-DebugTimestamp -output ("Host: Start to run test case....")
                }

                # Test: CNGTest
                if ($HostToolCNGTest) {
                    Foreach ($SmokeTestCNGTestType in $SmokeTestCNGTestTypes) {
                        Win-DebugTimestamp -output (
                            "Host: Run CNGTest ---- {0}" -f $SmokeTestCNGTestType
                        )

                        if ($SmokeTestCNGTestType -eq "Base") {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Base_qa" -f
                                $LocationInfo.QatType,
                                $UQString

                            Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                if ($CNGtestConfig.Algo -eq "rsa") {
                                    $keyLength = $CNGtestConfig.keyLength
                                    $ecccurve = "nistP256"
                                    $padding = $CNGtestConfig.Padding

                                    $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $keyLength,
                                        $padding
                                } else {
                                    $keyLength = 2048
                                    $ecccurve = $CNGtestConfig.Ecccurve
                                    $padding = "pkcs1"

                                    $testName = "{0}_{1}_{2}_{3}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $ecccurve
                                }

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $CNGTestResult = WinHost-CNGTestBase `
                                        -algo $CNGtestConfig.Algo `
                                        -operation $CNGtestConfig.Operation `
                                        -provider $CNGtestProvider `
                                        -keyLength $keyLength `
                                        -padding $padding `
                                        -ecccurve $ecccurve `
                                        -numThreads $CNGtestnumThreads `
                                        -numIter $CNGtestnumIter `
                                        -TestPathName $CNGtestTestPathName `
                                        -BertaResultPath $BertaResultPath

                                    if ($CNGTestResult.result) {
                                        $CNGTestResult.result = $TestResultToBerta.Pass
                                    } else {
                                        $CNGTestResult.result = $TestResultToBerta.Fail
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $CNGTestResult.result
                                        e = $CNGTestResult.error
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }

                        if ($SmokeTestCNGTestType -eq "Performance") {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Perf_qa" -f
                                $LocationInfo.QatType,
                                $UQString

                            Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                if ($CNGtestConfig.Algo -eq "rsa") {
                                    $keyLength = $CNGtestConfig.keyLength
                                    $ecccurve = "nistP256"
                                    $padding = $CNGtestConfig.Padding

                                    $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $keyLength,
                                        $padding
                                } else {
                                    $keyLength = 2048
                                    $ecccurve = $CNGtestConfig.Ecccurve
                                    $padding = "pkcs1"

                                    $testName = "{0}_{1}_{2}_{3}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $ecccurve
                                }

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $CNGTestResult = WinHost-CNGTestPerformance `
                                        -algo $CNGtestConfig.Algo `
                                        -operation $CNGtestConfig.Operation `
                                        -provider $CNGtestProvider `
                                        -keyLength $keyLength `
                                        -padding $padding `
                                        -ecccurve $ecccurve `
                                        -numThreads $CNGtestnumThreads `
                                        -numIter $CNGtestnumIter `
                                        -TestPathName $CNGtestTestPathName `
                                        -BertaResultPath $BertaResultPath `
                                        -TestType "Performance"

                                    if ($CNGTestResult.result) {
                                        $CheckOpsResult = WBase-CheckTestOps `
                                            -BanchMarkFile $SmokeTestBanchMarkFile `
                                            -testOps $CNGTestResult.testOps `
                                            -Provider $CNGtestProvider `
                                            -algo $CNGtestConfig.Algo `
                                            -operation $CNGtestConfig.Operation `
                                            -keyLength $keyLength `
                                            -ecccurve $ecccurve `
                                            -padding $padding

                                        if ($CheckOpsResult.result) {
                                            $CNGTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $CNGTestResult.result = $TestResultToBerta.Fail
                                            $CNGTestResult.error = "performance_degradation"
                                        }

                                        $CNGTestResult["banckmarkOps"] = $CheckOpsResult.banckmarkOps
                                    } else {
                                        $CNGTestResult.result = $TestResultToBerta.Fail
                                        $CNGTestResult["banckmarkOps"] = 0
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $CNGTestResult.result
                                        e = $CNGTestResult.error
                                        testOps = $CNGTestResult.testOps
                                        banckmarkOps = $CNGTestResult.banckmarkOps
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }

                        if (($SmokeTestCNGTestType -eq "Heartbeat") -or
                            ($SmokeTestCNGTestType -eq "Disable")) {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Fallback_qa" -f
                                $LocationInfo.QatType,
                                $UQString

                            if ($SmokeTestCNGTestType -eq "Heartbeat") {$TestType = "heartbeat"}
                            if ($SmokeTestCNGTestType -eq "Disable") {$TestType = "disable"}
                            Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                if ($CNGtestConfig.Algo -eq "rsa") {
                                    if ($CNGtestConfig.Padding -ne "oaep") {
                                        continue
                                    }
                                } elseif ($CNGtestConfig.Algo -eq "ecdh") {
                                    if ($CNGtestConfig.Operation -ne "secretagreement") {
                                        continue
                                    }
                                } else {
                                    continue
                                }

                                if ($CNGtestConfig.Algo -eq "rsa") {
                                    $keyLength = $CNGtestConfig.keyLength
                                    $ecccurve = "nistP256"
                                    $padding = $CNGtestConfig.Padding

                                    $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $keyLength,
                                        $padding
                                } else {
                                    $keyLength = 2048
                                    $ecccurve = $CNGtestConfig.Ecccurve
                                    $padding = "pkcs1"

                                    $testName = "{0}_{1}_{2}_{3}" -f
                                        $testNameHeader,
                                        $CNGtestConfig.Algo,
                                        $CNGtestConfig.Operation,
                                        $ecccurve
                                }

                                $testName = "{0}_{1}" -f $testName, $TestType

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $CNGTestResult = WinHost-CNGTestSWfallback `
                                        -algo $CNGtestConfig.Algo `
                                        -operation $CNGtestConfig.Operation `
                                        -provider $CNGtestProvider `
                                        -keyLength $keyLength `
                                        -padding $padding `
                                        -ecccurve $ecccurve `
                                        -numThreads $CNGtestnumThreads `
                                        -numIter $CNGtestnumIter `
                                        -TestPathName $CNGtestTestPathName `
                                        -BertaResultPath $BertaResultPath `
                                        -TestType $TestType

                                    if ($CNGTestResult.result) {
                                        $CNGTestResult.result = $TestResultToBerta.Pass
                                    } else {
                                        $CNGTestResult.result = $TestResultToBerta.Fail
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $CNGTestResult.result
                                        e = $CNGTestResult.error
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }
                    }
                }

                # Test: Parcomp
                if ($HostToolParcomp) {
                    Foreach ($SmokeTestParcompType in $SmokeTestParcompTypes) {
                        Win-DebugTimestamp -output (
                            "Host: Run Parcomp test ---- {0}" -f $SmokeTestParcompType
                        )

                        if ($SmokeTestParcompType -eq "Base") {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Base" -f
                                $LocationInfo.QatType,
                                $UQString

                            Foreach ($ParcompType in $ParcompTypes) {
                                if ($ParcompType -eq "Compress") {$deCompressFlag = $false}
                                if ($ParcompType -eq "deCompress") {$deCompressFlag = $true}
                                $testName = "{0}_{1}_{2}_chunk{3}" -f
                                    $testNameHeader,
                                    $ParcompProvider,
                                    $ParcompType,
                                    $ParcompChunkSize

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $ParcompBaseTestResult = WinHost-ParcompBase `
                                        -deCompressFlag $deCompressFlag `
                                        -CompressProvider $ParcompProvider `
                                        -deCompressProvider $ParcompProvider `
                                        -Chunk $ParcompChunkSize `
                                        -TestPathName $ParcompTestPathName `
                                        -BertaResultPath $BertaResultPath `
                                        -TestFileType $ParcompTestFileType `
                                        -TestFileSize $ParcompTestFileSize `
                                        -TestType "Parameter"

                                    if ($ParcompBaseTestResult.result) {
                                        $ParcompBaseTestResult.result = $TestResultToBerta.Pass
                                    } else {
                                        $ParcompBaseTestResult.result = $TestResultToBerta.Fail
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $ParcompBaseTestResult.result
                                        e = $ParcompBaseTestResult.error
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }

                        if ($SmokeTestParcompType -eq "Performance") {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Perf" -f
                                $LocationInfo.QatType,
                                $UQString

                            Foreach ($ParcompType in $ParcompTypes) {
                                if ($ParcompType -eq "Compress") {$deCompressFlag = $false}
                                if ($ParcompType -eq "deCompress") {$deCompressFlag = $true}
                                $testName = "{0}_{1}_{2}_chunk{3}" -f
                                    $testNameHeader,
                                    $ParcompProvider,
                                    $ParcompType,
                                    $ParcompChunkSize

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $PerformanceTestResult = WinHost-ParcompPerformance `
                                        -deCompressFlag $deCompressFlag `
                                        -CompressProvider $ParcompProvider `
                                        -deCompressProvider $ParcompProvider `
                                        -numThreads $ParcompnumThreads `
                                        -numIterations $ParcompnumIter `
                                        -Chunk $ParcompChunkSize `
                                        -TestPathName $ParcompTestPathName `
                                        -BertaResultPath $BertaResultPath `
                                        -TestFileType $ParcompTestFileType `
                                        -TestFileSize $ParcompTestFileSize `
                                        -TestType "Performance"

                                    if ($PerformanceTestResult.result) {
                                        $CheckOpsResult = WBase-CheckTestOps `
                                            -BanchMarkFile $SmokeTestBanchMarkFile `
                                            -testOps $PerformanceTestResult.testOps `
                                            -Provider $ParcompProvider `
                                            -Level 1 `
                                            -CompressionType "dynamic" `
                                            -CompressOperation $ParcompType `
                                            -TestFileType $ParcompTestFileType `
                                            -TestFileSize $ParcompTestFileSize `
                                            -Chunk $ParcompChunkSize `
                                            -blockSize 4096

                                        if ($CheckOpsResult.result) {
                                            $PerformanceTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $PerformanceTestResult.result = $TestResultToBerta.Fail
                                            $PerformanceTestResult.error = "performance_degradation"
                                        }

                                        $PerformanceTestResult["banckmarkOps"] = $CheckOpsResult.banckmarkOps
                                    } else {
                                        $PerformanceTestResult.result = $TestResultToBerta.Fail
                                        $PerformanceTestResult["banckmarkOps"] = 0
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $PerformanceTestResult.result
                                        e = $PerformanceTestResult.error
                                        testOps = $PerformanceTestResult.testOps
                                        banckmarkOps = $PerformanceTestResult.banckmarkOps
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }

                        if (($SmokeTestParcompType -eq "Heartbeat") -or
                            ($SmokeTestParcompType -eq "Disable")) {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Fallback" -f
                                $LocationInfo.QatType,
                                $UQString

                            if ($SmokeTestParcompType -eq "Heartbeat") {$TestType = "heartbeat"}
                            if ($SmokeTestParcompType -eq "Disable") {$TestType = "disable"}
                            Foreach ($ParcompType in $ParcompTypes) {
                                $testName = "{0}_{1}_{2}_{3}" -f
                                    $testNameHeader,
                                    $ParcompProvider,
                                    $ParcompType,
                                    $TestType

                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    $SWFallbackTestResult = WinHost-ParcompSWfallback `
                                        -CompressType $ParcompType `
                                        -CompressProvider $ParcompProvider `
                                        -deCompressProvider $ParcompProvider `
                                        -numThreads $ParcompnumThreads `
                                        -numIterations $ParcompnumIter `
                                        -Chunk $ParcompChunkSize `
                                        -BertaResultPath $BertaResultPath `
                                        -TestFileType $ParcompTestFileType `
                                        -TestFileSize $ParcompTestFileSize `
                                        -TestType $TestType

                                    if ($SWFallbackTestResult.result) {
                                        $SWFallbackTestResult.result = $TestResultToBerta.Pass
                                    } else {
                                        $SWFallbackTestResult.result = $TestResultToBerta.Fail
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $SWFallbackTestResult.result
                                        e = $SWFallbackTestResult.error
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }
                    }
                }

                # Test: Check
                Foreach ($SmokeTestInstallerType in $SmokeTestInstallerTypes) {
                    Win-DebugTimestamp -output (
                        "Host: Run Check test ---- {0}" -f $SmokeTestInstallerType
                    )

                    $InstallerTypes = @()
                    if ($HostToolParcomp) {
                        $parcompFlag = $true
                        $InstallerTypes += "parcomp"
                    } else {
                        $parcompFlag = $false
                    }

                    if ($HostToolCNGTest) {
                        $cngtestFlag = $true
                        $InstallerTypes += "cngtest"
                    } else {
                        $cngtestFlag = $false
                    }

                    if ($InstallerTypes.length -ne 0) {
                        $InstallerTypes += "disable"

                        if ($SmokeTestInstallerType -eq "Disable") {
                            $testNameHeader = "SmokeTest_Host_{0}_{1}_Check" -f
                                $LocationInfo.QatType,
                                $UQString

                            if (!$CompareFlag) {
                                $InstallerCheckTestResult = WinHost-InstallerCheckDisable `
                                    -parcompFlag $parcompFlag `
                                    -cngtestFlag $cngtestFlag `
                                    -BertaResultPath $BertaResultPath
                            }

                            Foreach ($InstallerType in $InstallerTypes) {
                                if ((!$parcompFlag) -and ($InstallerType -eq "parcomp")) {continue}
                                if ((!$cngtestFlag) -and ($InstallerType -eq "cngtest")) {continue}

                                $testName = "{0}_{1}" -f $testNameHeader, $InstallerType
                                if ($CompareFlag) {
                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $TestResultToBerta.NotRun
                                        e = "no_error"
                                    }

                                    WBase-WriteTestResult `
                                        -TestResult $TestCaseResultsList `
                                        -ResultFile $CompareFile
                                } else {
                                    if ($InstallerCheckTestResult[$InstallerType]["result"]) {
                                        $InstallerCheckTestResult[$InstallerType]["result"] = $TestResultToBerta.Pass
                                    } else {
                                        $InstallerCheckTestResult[$InstallerType]["result"] = $TestResultToBerta.Fail
                                    }

                                    $TestCaseResultsList = [hashtable] @{
                                        tc = $testName
                                        s = $InstallerCheckTestResult[$InstallerType]["result"]
                                        e = $InstallerCheckTestResult[$InstallerType]["error"]
                                    }

                                    WBase-WriteTestResult -TestResult $TestCaseResultsList
                                }
                            }
                        }
                    } else {
                        Win-DebugTimestamp -output (
                            "Host: Skip Check test ---- {0}" -f $SmokeTestInstallerType
                        )
                    }
                }
            }

            # HVMode
            if ($HVModePlatformType) {
                if (!$CompareFlag) {
                    $LocationInfo.HVMode = $true
                    $LocationInfo.IsWin = $true
                    $LocationInfo.VM.IsWin = $true
                    WBase-LocationInfoInit -BertaResultPath $BertaResultPath `
                                           -QatDriverFullPath $PFVFDriverPath `
                                           -BertaConfig $BertaConfig | out-null
                }

                Foreach ($VMVFOSConfig in $VMVFOSConfigs) {
                    if (!$CompareFlag) {
                        Win-DebugTimestamp -output ("HVMode: Initialize test environment....")
                        $ENVConfig = "{0}\\vmconfig\\{1}_{2}.json" -f
                            $QATTESTPATH,
                            $LocationInfo.QatType,
                            $VMVFOSConfig

                        WTW-VMVFInfoInit -VMVFOSConfig $ENVConfig
                        WTW-ENVInit -configFile $ENVConfig -InitVM $InitVM
                        [System.Array] $TestVmOpts = (Get-Content $ENVConfig | ConvertFrom-Json).TestVms

                        Win-DebugTimestamp -output ("HVMode: Start to run test case....")
                    }

                    # Test: CNGTest
                    if ($HVModeToolCNGTest) {
                        Foreach ($SmokeTestCNGTestType in $SmokeTestCNGTestTypes) {
                            Win-DebugTimestamp -output (
                                "HVMode: Run CNGTest ---- {0}" -f $SmokeTestCNGTestType
                            )

                            if ($SmokeTestCNGTestType -eq "Base") {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Base_qa" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                    if ($CNGtestConfig.Algo -eq "rsa") {
                                        $keyLength = $CNGtestConfig.keyLength
                                        $ecccurve = "nistP256"
                                        $padding = $CNGtestConfig.Padding

                                        $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $keyLength,
                                            $padding
                                    } else {
                                        $keyLength = 2048
                                        $ecccurve = $CNGtestConfig.Ecccurve
                                        $padding = "pkcs1"

                                        $testName = "{0}_{1}_{2}_{3}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $ecccurve
                                    }

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $CNGTestResult = WTW-CNGTestBase `
                                            -TestVmOpts $TestVmOpts `
                                            -algo $CNGtestConfig.Algo `
                                            -operation $CNGtestConfig.Operation `
                                            -provider $CNGtestProvider `
                                            -keyLength $keyLength `
                                            -padding $padding `
                                            -ecccurve $ecccurve `
                                            -numThreads $CNGtestnumThreads `
                                            -numIter $CNGtestnumIter `
                                            -TestPathName $CNGtestTestPathName `
                                            -BertaResultPath $BertaResultPath

                                        if ($CNGTestResult.result) {
                                            $CNGTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $CNGTestResult.result = $TestResultToBerta.Fail
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $CNGTestResult.result
                                            e = $CNGTestResult.error
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }

                            if ($SmokeTestCNGTestType -eq "Performance") {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Perf_qa" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                    if ($CNGtestConfig.Algo -eq "rsa") {
                                        $keyLength = $CNGtestConfig.keyLength
                                        $ecccurve = "nistP256"
                                        $padding = $CNGtestConfig.Padding

                                        $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $keyLength,
                                            $padding
                                    } else {
                                        $keyLength = 2048
                                        $ecccurve = $CNGtestConfig.Ecccurve
                                        $padding = "pkcs1"

                                        $testName = "{0}_{1}_{2}_{3}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $ecccurve
                                    }

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $CNGTestResult = WTW-CNGTestPerformance `
                                            -TestVmOpts $TestVmOpts `
                                            -algo $CNGtestConfig.Algo `
                                            -operation $CNGtestConfig.Operation `
                                            -provider $CNGtestProvider `
                                            -keyLength $keyLength `
                                            -padding $padding `
                                            -ecccurve $ecccurve `
                                            -numThreads $CNGtestnumThreads `
                                            -numIter $CNGtestnumIter `
                                            -TestPathName $CNGtestTestPathName `
                                            -BertaResultPath $BertaResultPath `
                                            -TestType "Performance"

                                        if ($CNGTestResult.result) {
                                            $CheckOpsResult = WBase-CheckTestOps `
                                                -BanchMarkFile $SmokeTestBanchMarkFile `
                                                -testOps $CNGTestResult.testOps `
                                                -Provider $CNGtestProvider `
                                                -algo $CNGtestConfig.Algo `
                                                -operation $CNGtestConfig.Operation `
                                                -keyLength $keyLength `
                                                -ecccurve $ecccurve `
                                                -padding $padding

                                            if ($CheckOpsResult.result) {
                                                $CNGTestResult.result = $TestResultToBerta.Pass
                                            } else {
                                                $CNGTestResult.result = $TestResultToBerta.Fail
                                                $CNGTestResult.error = "performance_degradation"
                                            }

                                            $CNGTestResult["banckmarkOps"] = $CheckOpsResult.banckmarkOps
                                        } else {
                                            $CNGTestResult.result = $TestResultToBerta.Fail
                                            $CNGTestResult["banckmarkOps"] = 0
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $CNGTestResult.result
                                            e = $CNGTestResult.error
                                            testOps = $CNGTestResult.testOps
                                            banckmarkOps = $CNGTestResult.banckmarkOps
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }

                            if (($SmokeTestCNGTestType -eq "Heartbeat") -or
                                ($SmokeTestCNGTestType -eq "Disable")) {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Fallback_qa" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                if ($SmokeTestCNGTestType -eq "Heartbeat") {$TestType = "heartbeat"}
                                if ($SmokeTestCNGTestType -eq "Disable") {$TestType = "disable"}
                                Foreach ($CNGtestConfig in $CNGtestConfigs) {
                                    if ($CNGtestConfig.Algo -eq "rsa") {
                                        if ($CNGtestConfig.Padding -ne "oaep") {
                                            continue
                                        }
                                    } elseif ($CNGtestConfig.Algo -eq "ecdh") {
                                        if ($CNGtestConfig.Operation -ne "secretagreement") {
                                            continue
                                        }
                                    } else {
                                        continue
                                    }

                                    if ($CNGtestConfig.Algo -eq "rsa") {
                                        $keyLength = $CNGtestConfig.keyLength
                                        $ecccurve = "nistP256"
                                        $padding = $CNGtestConfig.Padding

                                        $testName = "{0}_{1}_{2}_{3}_{4}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $keyLength,
                                            $padding
                                    } else {
                                        $keyLength = 2048
                                        $ecccurve = $CNGtestConfig.Ecccurve
                                        $padding = "pkcs1"

                                        $testName = "{0}_{1}_{2}_{3}" -f
                                            $testNameHeader,
                                            $CNGtestConfig.Algo,
                                            $CNGtestConfig.Operation,
                                            $ecccurve
                                    }

                                    $testName = "{0}_{1}" -f $testName, $TestType

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $CNGTestResult = WTW-CNGTestSWfallback `
                                            -TestVmOpts $TestVmOpts `
                                            -algo $CNGtestConfig.Algo `
                                            -operation $CNGtestConfig.Operation `
                                            -provider $CNGtestProvider `
                                            -keyLength $keyLength `
                                            -padding $padding `
                                            -ecccurve $ecccurve `
                                            -numThreads $CNGtestnumThreads `
                                            -numIter $CNGtestnumIter `
                                            -TestPathName $CNGtestTestPathName `
                                            -BertaResultPath $BertaResultPath `
                                            -TestType $TestType

                                        if ($CNGTestResult.result) {
                                            $CNGTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $CNGTestResult.result = $TestResultToBerta.Fail
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $CNGTestResult.result
                                            e = $CNGTestResult.error
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }
                        }
                    }

                    # Test: Parcomp
                    if ($HVModeToolParcomp) {
                        Foreach ($SmokeTestParcompType in $SmokeTestParcompTypes) {
                            Win-DebugTimestamp -output (
                                "HVMode: Run Parcomp test ---- {0}" -f $SmokeTestParcompType
                            )

                            if ($SmokeTestParcompType -eq "Base") {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Base" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                Foreach ($ParcompType in $ParcompTypes) {
                                    if ($ParcompType -eq "Compress") {$deCompressFlag = $false}
                                    if ($ParcompType -eq "deCompress") {$deCompressFlag = $true}
                                    $testName = "{0}_{1}_{2}_chunk{3}" -f
                                        $testNameHeader,
                                        $ParcompProvider,
                                        $ParcompType,
                                        $ParcompChunkSize

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $ParcompBaseTestResult = WTW-ParcompBase `
                                            -TestVmOpts $TestVmOpts `
                                            -deCompressFlag $deCompressFlag `
                                            -CompressProvider $ParcompProvider `
                                            -deCompressProvider $ParcompProvider `
                                            -Chunk $ParcompChunkSize `
                                            -TestPathName $ParcompTestPathName `
                                            -BertaResultPath $BertaResultPath `
                                            -TestFileType $ParcompTestFileType `
                                            -TestFileSize $ParcompTestFileSize `
                                            -TestType "Parameter"

                                        if ($ParcompBaseTestResult.result) {
                                            $ParcompBaseTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $ParcompBaseTestResult.result = $TestResultToBerta.Fail
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $ParcompBaseTestResult.result
                                            e = $ParcompBaseTestResult.error
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }

                            if ($SmokeTestParcompType -eq "Performance") {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Perf" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                Foreach ($ParcompType in $ParcompTypes) {
                                    if ($ParcompType -eq "Compress") {$deCompressFlag = $false}
                                    if ($ParcompType -eq "deCompress") {$deCompressFlag = $true}
                                    $testName = "{0}_{1}_{2}_chunk{3}" -f
                                        $testNameHeader,
                                        $ParcompProvider,
                                        $ParcompType,
                                        $ParcompChunkSize

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $PerformanceTestResult = WTW-ParcompPerformance `
                                            -TestVmOpts $TestVmOpts `
                                            -deCompressFlag $deCompressFlag `
                                            -CompressProvider $ParcompProvider `
                                            -deCompressProvider $ParcompProvider `
                                            -numThreads $ParcompnumThreads `
                                            -numIterations $ParcompnumIter `
                                            -Chunk $ParcompChunkSize `
                                            -TestPathName $ParcompTestPathName `
                                            -BertaResultPath $BertaResultPath `
                                            -TestFileType $ParcompTestFileType `
                                            -TestFileSize $ParcompTestFileSize `
                                            -TestType "Performance"

                                        if ($PerformanceTestResult.result) {
                                            $CheckOpsResult = WBase-CheckTestOps `
                                                -BanchMarkFile $SmokeTestBanchMarkFile `
                                                -testOps $PerformanceTestResult.testOps `
                                                -Provider $ParcompProvider `
                                                -Level 1 `
                                                -CompressionType "dynamic" `
                                                -CompressOperation $ParcompType `
                                                -TestFileType $ParcompTestFileType `
                                                -TestFileSize $ParcompTestFileSize `
                                                -Chunk $ParcompChunkSize `
                                                -blockSize 4096

                                            if ($CheckOpsResult.result) {
                                                $PerformanceTestResult.result = $TestResultToBerta.Pass
                                            } else {
                                                $PerformanceTestResult.result = $TestResultToBerta.Fail
                                                $PerformanceTestResult.error = "performance_degradation"
                                            }

                                            $PerformanceTestResult["banckmarkOps"] = $CheckOpsResult.banckmarkOps
                                        } else {
                                            $PerformanceTestResult.result = $TestResultToBerta.Fail
                                            $PerformanceTestResult["banckmarkOps"] = 0
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $PerformanceTestResult.result
                                            e = $PerformanceTestResult.error
                                            testOps = $PerformanceTestResult.testOps
                                            banckmarkOps = $PerformanceTestResult.banckmarkOps
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }

                            if (($SmokeTestParcompType -eq "Heartbeat") -or
                                ($SmokeTestParcompType -eq "Disable")) {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Fallback" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                if ($SmokeTestParcompType -eq "Heartbeat") {$TestType = "heartbeat"}
                                if ($SmokeTestParcompType -eq "Disable") {$TestType = "disable"}
                                Foreach ($ParcompType in $ParcompTypes) {
                                    $testName = "{0}_{1}_{2}_{3}" -f
                                        $testNameHeader,
                                        $ParcompProvider,
                                        $ParcompType,
                                        $TestType

                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        $SWFallbackTestResult = WTW-ParcompSWfallback `
                                            -TestVmOpts $TestVmOpts `
                                            -CompressType $ParcompType `
                                            -CompressProvider $ParcompProvider `
                                            -deCompressProvider $ParcompProvider `
                                            -numThreads $ParcompnumThreads `
                                            -numIterations $ParcompnumIter `
                                            -Chunk $ParcompChunkSize `
                                            -BertaResultPath $BertaResultPath `
                                            -TestFileType $ParcompTestFileType `
                                            -TestFileSize $ParcompTestFileSize `
                                            -TestType $TestType

                                        if ($SWFallbackTestResult.result) {
                                            $SWFallbackTestResult.result = $TestResultToBerta.Pass
                                        } else {
                                            $SWFallbackTestResult.result = $TestResultToBerta.Fail
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $SWFallbackTestResult.result
                                            e = $SWFallbackTestResult.error
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }
                        }
                    }

                    # Test: Check
                    Foreach ($SmokeTestInstallerType in $SmokeTestInstallerTypes) {
                        Win-DebugTimestamp -output (
                            "HVMode: Run Check test ---- {0}" -f $SmokeTestInstallerType
                        )

                        $InstallerTypes = @()
                        if ($HVModeToolParcomp) {
                            $parcompFlag = $true
                            $InstallerTypes += "parcomp"
                        } else {
                            $parcompFlag = $false
                        }

                        if ($HVModeToolCNGTest) {
                            $cngtestFlag = $true
                            $InstallerTypes += "cngtest"
                        } else {
                            $cngtestFlag = $false
                        }

                        if ($InstallerTypes.length -ne 0) {
                            $InstallerTypes += "disable"

                            if ($SmokeTestInstallerType -eq "Disable") {
                                $testNameHeader = "SmokeTest_WTW_{0}_{1}_{2}_Check" -f
                                    $LocationInfo.QatType,
                                    $UQString,
                                    $VMVFOSConfig

                                if (!$CompareFlag) {
                                    $InstallerCheckTestResult = WTW-InstallerCheckDisable `
                                        -TestVmOpts $TestVmOpts `
                                        -parcompFlag $parcompFlag `
                                        -cngtestFlag $cngtestFlag `
                                        -BertaResultPath $BertaResultPath
                                }

                                Foreach ($InstallerType in $InstallerTypes) {
                                    if ((!$parcompFlag) -and ($InstallerType -eq "parcomp")) {continue}
                                    if ((!$cngtestFlag) -and ($InstallerType -eq "cngtest")) {continue}

                                    $testName = "{0}_{1}" -f $testNameHeader, $InstallerType
                                    if ($CompareFlag) {
                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $TestResultToBerta.NotRun
                                            e = "no_error"
                                        }

                                        WBase-WriteTestResult `
                                            -TestResult $TestCaseResultsList `
                                            -ResultFile $CompareFile
                                    } else {
                                        if ($InstallerCheckTestResult[$InstallerType]["result"]) {
                                            $InstallerCheckTestResult[$InstallerType]["result"] = $TestResultToBerta.Pass
                                        } else {
                                            $InstallerCheckTestResult[$InstallerType]["result"] = $TestResultToBerta.Fail
                                        }

                                        $TestCaseResultsList = [hashtable] @{
                                            tc = $testName
                                            s = $InstallerCheckTestResult[$InstallerType]["result"]
                                            e = $InstallerCheckTestResult[$InstallerType]["error"]
                                        }

                                        WBase-WriteTestResult -TestResult $TestCaseResultsList
                                    }
                                }
                            }
                        } else {
                            Win-DebugTimestamp -output (
                                "HVMode: Skip Check test ---- {0}" -f $SmokeTestInstallerType
                            )
                        }
                    }
                }
            }
        }

        if ($CompareFlag) {
            Win-DebugTimestamp -output (
                "Complete compare file: {0}" -f $CompareFile
            )
        }
    }
} catch {
    Win-DebugTimestamp -output $_
} finally {
    WBase-CompareTestResult -CompareFile $CompareFile
    Win-DebugTimestamp -output ("Ending $($MyInvocation.MyCommand)")
}
