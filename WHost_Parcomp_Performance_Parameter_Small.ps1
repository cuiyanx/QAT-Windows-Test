Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [bool]$RunOnLocal = $false,

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

Import-Module "$QATTESTPATH\\lib\\WinHost.psm1" -Force -DisableNameChecking
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

    $LocationInfo.HVMode = $false
    $LocationInfo.IsWin = $true
    $LocationInfo.VM.IsWin = $null
    $PFVFDriverPath = WBase-GetDriverPath -BuildPath $LocalBuildPath

    WBase-LocationInfoInit -BertaResultPath $BertaResultPath `
                           -QatDriverFullPath $PFVFDriverPath `
                           -BertaConfig $BertaConfig | out-null

    [System.Array]$CompareTypes = ("true", "false")

    # Special: For All
    if ([String]::IsNullOrEmpty($runTestCase)) {
        [System.Array]$ParcompProvider = ("qat")
        [System.Array]$ParcompCompressType = ("Compress", "deCompress")
        [System.Array]$ParcompCompressionLevel = (1)
        [System.Array]$ParcompChunk = (256)
        [System.Array]$ParcompBlock = (1024, 2048, 4096, 8192)
        [System.Array]$ParcompThread = (8)
        [System.Array]$ParcompIteration = (1, 200)
        [System.Array]$TestFileNameArray.Type = ("calgary")
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
    }

    $TestPathName = "ParcompTest"
    $TestType = "Parameter"
    $TestFilefullPath = $null

    # Special: For QAT17
    if ($LocationInfo.QatType -eq "QAT17") {
        if ($LocationInfo.UQMode) {
            throw ("QAT17: On the Host, not support UQ Mode.")
        }
    }

    # Special: For QAT18
    if ($LocationInfo.QatType -eq "QAT18") {
        if ($LocationInfo.UQMode) {
            throw ("QAT18: On the Host, not support UQ Mode.")
        }
    }

    # Special: For QAT20
    if ($LocationInfo.QatType -eq "QAT20") {
        if ($LocationInfo.UQMode) {
            if ([String]::IsNullOrEmpty($runTestCase)) {
                [System.Array]$ParcompProvider = ("qat", "qatlz4")
            }
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
            Win-DebugTimestamp -output ("Initialize test environment....")
            WinHost-ENVInit | out-null

            Win-DebugTimestamp -output ("Start to run test case....")
        }

        $UQString = ($LocationInfo.UQMode) ? "UQ" : "NUQ"
        $testNameHeader = "Regression_Host_{0}_{1}_Perf_Parameter" -f
            $LocationInfo.QatType,
            $UQString

        Foreach ($TestCase in $TestCaseList) {
            # deCompress: qatgzip and qatgzipext not support -k -t -Q
            if (($TestCase.Provider -eq "qatgzip") -or
                ($TestCase.Provider -eq "qatgzipext")) {
                if (($TestCase.CompressType -eq "deCompress") -or
                    ($TestCase.CompressType -eq "All")) {
                    continue
                }
            }

            if ($TestCase.CompressType -eq "Compress") {$deCompressFlag = $false}
            if ($TestCase.CompressType -eq "deCompress") {$deCompressFlag = $true}

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

                $PerformanceTestResult = WinHost-ParcompPerformance `
                    -deCompressFlag $deCompressFlag `
                    -CompressProvider $TestCase.Provider `
                    -deCompressProvider $TestCase.Provider `
                    -QatCompressionType $TestCase.CompressionType `
                    -Level $TestCase.CompressionLevel `
                    -Chunk $TestCase.Chunk `
                    -numThreads $TestCase.Thread `
                    -numIterations $TestCase.Iteration `
                    -blockSize $TestCase.Block `
                    -TestPathName $TestPathName `
                    -TestFilefullPath $TestFilefullPath `
                    -BertaResultPath $BertaResultPath `
                    -TestFileType $TestCase.TestFileType `
                    -TestFileSize $TestCase.TestFileSize `
                    -TestType $TestType

                if ($PerformanceTestResult.result) {
                    $PerformanceTestResult.result = $TestResultToBerta.Pass
                } else {
                    $PerformanceTestResult.result = $TestResultToBerta.Fail
                }

                $TestCaseResultsList = [hashtable] @{
                    tc = $testName
                    s = $PerformanceTestResult.result
                    e = $PerformanceTestResult.error
                }

                WBase-WriteTestResult -TestResult $TestCaseResultsList
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
