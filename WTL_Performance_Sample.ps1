Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [bool]$RunOnLocal = $false,

    [bool]$InitVM = $true,

    [array]$VMVFOSConfigs = $null,

    [bool]$UQMode = $false,

    [bool]$TestMode = $true,

    [bool]$VerifierMode = $false,

    [bool]$DebugMode = $false,

    [string]$DriverPath = "C:\\cy-work\\qat_driver\\",

    [string]$ResultFile = "result.log"
)

$TestSuitePath = Split-Path -Path $PSCommandPath
Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global

Import-Module "$QATTESTPATH\\lib\\Win2Linux.psm1" -Force -DisableNameChecking
WBase-ReturnFilesInit `
    -BertaResultPath $BertaResultPath `
    -ResultFile $ResultFile | out-null

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
    $LocationInfo.VM.IsWin = $false
    $PFVFDriverPath = WBase-GetDriverPath -BuildPath $LocalBuildPath

    WBase-LocationInfoInit -BertaResultPath $BertaResultPath `
                           -QatDriverFullPath $PFVFDriverPath `
                           -BertaConfig $BertaConfig | out-null

    # Special: For All
    if ([String]::IsNullOrEmpty($VMVFOSConfigs)) {
        [System.Array]$VMVFOSConfigs = HV-GenerateVMVFConfig -ConfigType "Performance"
    }

    Foreach ($VMVFOSConfig in $VMVFOSConfigs) {
        $UQString = ($LocationInfo.UQMode) ? "UQ" : "NUQ"
        $testNameHeader = "Regression_WTL_{0}_{1}_{2}_Performance_Sample" -f
            $LocationInfo.QatType,
            $UQString,
            $VMVFOSConfig
        $BanchMarkFile = "{0}\\banchmark\\WTL_{1}_{2}_{3}_sample_banchmark.log" -f
            $QATTESTPATH,
            $LocationInfo.QatType,
            $UQString,
            $VMVFOSConfig

        Win-DebugTimestamp -output ("Initialize test environment....")
        WTL-ENVInit -VMVFOSConfig $VMVFOSConfig -InitVM $InitVM| out-null

        Win-DebugTimestamp -output ("Start to run test case....")
        $RunTestResult = WTL-PerformanceSample
        $testName = "{0}_Run_Linux_Shell" -f $testNameHeader
        if ($RunTestResult.result) {
            $RunTestResult.result = $TestResultToBerta.Pass
        } else {
            $RunTestResult.result = $TestResultToBerta.Fail
        }

        $TestCaseResultsList = [hashtable] @{
            tc = $testName
            s = $RunTestResult.result
            e = $RunTestResult.error
        }

        WBase-WriteTestResult -TestResult $TestCaseResultsList

        if ($RunTestResult.result) {
            Win-DebugTimestamp -output ("Start to check test case result....")
            $TestResultList = WTL-CheckOutput
            Foreach ($TestResult in $TestResultList) {
                $testName = "{0}_{1}" -f $testNameHeader, $TestResult.name

                $CheckOpsResult = WBase-CheckTestOps `
                    -BanchMarkFile $BanchMarkFile `
                    -testOps $TestResult.throughput `
                    -testName $testName

                if ($TestResult.result -and !$CheckOpsResult.result) {
                    $TestResult.result = $CheckOpsResult.result
                    $TestResult.error = "performance_degradation"
                }

                if ($TestResult.result) {
                    $TestResult.result = $TestResultToBerta.Pass
                } else {
                    $TestResult.result = $TestResultToBerta.Fail
                }

                $TestCaseResultsList = [hashtable] @{
                    tc = $testName
                    s = $TestResult.result
                    e = $TestResult.error
                    testOps = $TestResult.throughput
                    banckmarkOps = $CheckOpsResult.banckmarkOps
                }

                WBase-WriteTestResult -TestResult $TestCaseResultsList
            }
        }
    }
} catch {
    Win-DebugTimestamp -output $_
} finally {
    Win-DebugTimestamp -output ("Ending $($MyInvocation.MyCommand)")
}
