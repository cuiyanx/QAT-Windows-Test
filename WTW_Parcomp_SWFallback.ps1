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

    [string]$runTestCase = $null,

    [string]$DriverPath = "C:\\cy-work\\qat_driver\\",

    [string]$ResultFile = "result.log"
)

$TestSuitePath = Split-Path -Path $PSCommandPath
Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global

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

        $BertaConfig["UQ_mode"] = ($out.config.UQ_mode -eq "true") ? $true : $false
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

    WBase-LocationInfoInit -BertaResultPath $BertaResultPath `
                           -QatDriverFullPath $PFVFDriverPath `
                           -BertaConfig $BertaConfig | out-null

    [System.Array]$CompareTypes = ("true", "false")

    # Special: For All
    if ([String]::IsNullOrEmpty($runTestCase)) {
        [System.Array]$ParcompProvider = ("qat", "qatgzip", "qatgzipext")
        [System.Array]$ParcompCompressionType = ("dynamic")
        [System.Array]$ParcompCompressionLevel = (1)
        [System.Array]$ParcompChunk = (256)
        [System.Array]$ParcompBlock = (4096)
        [System.Array]$ParcompThread = (8)
        [System.Array]$ParcompIteration = (200)
        [System.Array]$TestFileNameArray.Type = ("high")
        [System.Array]$TestFileNameArray.Size = (200)
    } else {
        $AnalyzeResult = WBase-AnalyzeTestCaseName -TestCaseName $runTestCase
        [System.Array]$ParcompProvider = $AnalyzeResult.Parcomp.Provider
        [System.Array]$ParcompChunk = $AnalyzeResult.Parcomp.Chunk
        [System.Array]$ParcompBlock = $AnalyzeResult.Parcomp.Block
        [System.Array]$ParcompCompressType = $AnalyzeResult.Parcomp.CompressType
        [System.Array]$ParcompCompressionLevel = $AnalyzeResult.Parcomp.Level
        [System.Array]$ParcompCompressionType = $AnalyzeResult.Parcomp.CompressionType
        [System.Array]$ParcompIteration = $AnalyzeResult.Parcomp.Iteration
        [System.Array]$ParcompThread = $AnalyzeResult.Parcomp.Thread
        [System.Array]$TestFileNameArray.Type = $AnalyzeResult.Parcomp.TestFileType
        [System.Array]$TestFileNameArray.Size = $AnalyzeResult.Parcomp.TestFileSize
        [System.Array]$AllTestType.Operation = $AnalyzeResult.Operation
        [System.Array]$VMVFOSConfigs = $AnalyzeResult.VMVFOS
    }

    $TestFilefullPath = $null

    if ([String]::IsNullOrEmpty($VMVFOSConfigs)) {
        if ($LocationInfo.QatType -eq "QAT20") {
            [System.Array]$VMVFOSConfigs = (
                "3vm_8vf_windows2022",
                "2vm_64vf_windows2022",
                "3vm_8vf_windows2019",
                "2vm_64vf_windows2019"
            )
        } elseif ($LocationInfo.QatType -eq "QAT17") {
            [System.Array]$VMVFOSConfigs = (
                "3vm_3vf_windows2022",
                "1vm_48vf_windows2022"
            )
        } elseif ($LocationInfo.QatType -eq "QAT18") {
            [System.Array]$VMVFOSConfigs = (
                "1vm_3vf_windows2022",
                "1vm_64vf_windows2022"
            )
        }
    }

    # Special: For QAT17
    if ($LocationInfo.QatType -eq "QAT17") {
        if ($LocationInfo.UQMode) {
            throw ("QAT17: On the HVMode, not support UQ Mode.")
        }
    }

    # Special: For QAT18
    if ($LocationInfo.QatType -eq "QAT18") {
        if ($LocationInfo.UQMode) {
            throw ("QAT18: On the HVMode, not support UQ Mode.")
        }
    }

    # Special: For QAT20
    if ($LocationInfo.QatType -eq "QAT20") {
        if ($LocationInfo.UQMode) {
            throw ("QAT20: On the HVMode, not support UQ Mode.")
        }
    }

    # Parcomp: Generate test case list based on config
    $TestCaseList = WBase-GenerateParcompTestCase `
        -ArrayProvider $ParcompProvider `
        -ArrayChunk $ParcompChunk `
        -ArrayBlock $ParcompBlock `
        -ArrayCompressType $ParcompCompressType `
        -ArrayCompressionType $ParcompCompressionType `
        -ArrayCompressionLevel $ParcompCompressionLevel `
        -ArrayIteration $ParcompIteration `
        -ArrayThread $ParcompThread `
        -ArrayTestFileType $TestFileNameArray.Type`
        -ArrayTestFileSize $TestFileNameArray.Size

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

        Foreach ($VMVFOSConfig in $VMVFOSConfigs) {
            $UQString = ($LocationInfo.UQMode) ? "UQ" : "NUQ"
            $testNameHeader = "Regression_WTW_{0}_{1}_{2}_Fallback" -f
                $LocationInfo.QatType,
                $UQString,
                $VMVFOSConfig

            if (-not $CompareFlag) {
                Win-DebugTimestamp -output ("Initialize test environment....")
                $ENVConfig = "{0}\\vmconfig\\{1}_{2}.json" -f
                    $QATTESTPATH,
                    $LocationInfo.QatType,
                    $VMVFOSConfig

                WTW-VMVFInfoInit -VMVFOSConfig $ENVConfig | out-null
                WTW-ENVInit -configFile $ENVConfig -InitVM $InitVM | out-null
                [System.Array] $TestVmOpts = (Get-Content $ENVConfig | ConvertFrom-Json).TestVms

                Win-DebugTimestamp -output ("Start to run test case....")
            }

            Foreach ($TestCase in $TestCaseList) {
                Foreach ($TestType in $AllTestType.Operation) {
                    # WorkAround: https://jira.devtools.intel.com/browse/QAT20-29817
                    if (($TestType -eq "heartbeat") -and ($VMVFOSConfig -match "2vm_64vf_")) {continue}

                    # deCompress: qatgzip and qatgzipext not support -k -t -Q
                    if (($TestCase.Provider -eq "qatgzip") -or
                        ($TestCase.Provider -eq "qatgzipext")) {
                        if (($TestCase.CompressType -eq "deCompress") -or
                            ($TestCase.CompressType -eq "All")) {
                            continue
                        }
                    }

                    $testName = "{0}_{1}_{2}_Thread{3}_Iteration{4}_Block{5}_Chunk{6}_{7}{8}" -f
                        $testNameHeader,
                        $TestCase.Provider,
                        $TestCase.CompressType,
                        $TestCase.Thread,
                        $TestCase.Iteration,
                        $TestCase.Block,
                        $TestCase.Chunk,
                        $TestCase.TestFileType,
                        $TestCase.TestFileSize

                    if ($TestCase.CompressType -eq "Compress") {
                        $testName = "{0}_Level{1}" -f
                            $testName,
                            $TestCase.CompressionLevel
                    }

                    if ($TestCase.Provider -eq "qat") {
                        $testName = "{0}_{1}" -f
                            $testName,
                            $TestCase.CompressionType
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
                        Win-DebugTimestamp -output ("Start to run test case > {0}" -f $testName)

                        $SWFallbackTestResult = WTW-ParcompSWfallback `
                            -TestVmOpts $TestVmOpts `
                            -CompressType $TestCase.CompressType `
                            -CompressProvider $TestCase.Provider `
                            -deCompressProvider $TestCase.Provider `
                            -QatCompressionType $TestCase.CompressionType `
                            -Level $TestCase.CompressionLevel `
                            -numThreads $TestCase.Thread `
                            -numIterations $TestCase.Iteration `
                            -blockSize $TestCase.Block `
                            -Chunk $TestCase.Chunk `
                            -TestFilefullPath $TestFilefullPath `
                            -BertaResultPath $BertaResultPath `
                            -TestFileType $TestCase.TestFileType `
                            -TestFileSize $TestCase.TestFileSize `
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
