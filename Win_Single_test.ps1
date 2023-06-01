Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [Parameter(Mandatory=$True)]
    [string]$TestName,

    [Parameter(Mandatory=$True)]
    [string]$DriverPath = "C:\\cy-work\\qat_driver\\",

    [int]$Iteration = 1,

    [bool]$InitVM = $true,

    [string]$ResultFile = "result.log"
)

$TestSuitePath = Split-Path -Path $PSCommandPath
Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global
Import-Module "$QATTESTPATH\\lib\\WinBase.psm1" -Force -DisableNameChecking

$RunOnLocal = 1
$InitVMInt = ($InitVM) ? 1 : 0
try {
    For ($i = 1; $i -le $Iteration; $i++) {
        Win-DebugTimestamp -output (
            "Start to run test case {0} time > {1}" -f $i, $TestName
        )

        if (($TestName -match "Installer") -or
            ($TestName -match "Check") -or
            ($TestName -match "Base_Compat") -or
            ($TestName -match "Base_Sample") -or
            ($TestName -match "Performance_Sample") -or
            ($TestName -match "Stress") -or
            ($TestName -match "SmokeTest")) {
            throw ("The single test is not support this test case")
        } else {
            if ($TestName -match "Base_Parameter") {
                if ($TestName -match "Host") {
                    $TestSuiteName = "{0}\\WHost_Parcomp_Base_Parameter.ps1" -f $QATTESTPATH
                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal
                    Invoke-Expression $runCommand
                }

                if ($TestName -match "WTW") {
                    $TestSuiteName = "{0}\\WTW_Parcomp_Base_Parameter.ps1" -f $QATTESTPATH
                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -InitVM {5}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal,
                        $InitVMInt
                    Invoke-Expression $runCommand
                    if ($InitVMInt) {$InitVMInt = 0}
                }
            }

            if ($TestName -match "Perf_Parameter") {
                if ($TestName -match "Host") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_Parameter.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_Performance_Parameter.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal
                    Invoke-Expression $runCommand
                }

                if ($TestName -match "WTW") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_Parameter.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_Performance_Parameter.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -InitVM {5}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal,
                        $InitVMInt
                    Invoke-Expression $runCommand
                    if ($InitVMInt) {$InitVMInt = 0}
                }
            }

            if ($TestName -match "Performance") {
                if ($TestName -match "Host") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_Performance.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_Performance.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal
                    Invoke-Expression $runCommand
                }

                if ($TestName -match "WTW") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_Performance.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_Performance.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -InitVM {5}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal,
                        $InitVMInt
                    Invoke-Expression $runCommand
                    if ($InitVMInt) {$InitVMInt = 0}
                }
            }

            if ($TestName -match "Fallback") {
                if ($TestName -match "Host") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_SWFallback.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_SWFallback.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal
                    Invoke-Expression $runCommand
                }

                if ($TestName -match "WTW") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_SWFallback.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_SWFallback.ps1" -f $QATTESTPATH
                    }

                    $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -InitVM {5}" -f
                        $TestSuiteName,
                        $BertaResultPath,
                        $DriverPath,
                        $TestName,
                        $RunOnLocal,
                        $InitVMInt
                    Invoke-Expression $runCommand
                    if ($InitVMInt) {$InitVMInt = 0}
                }
            }
        }
    }
} catch {
    Win-DebugTimestamp -output $_
} finally {
    Win-DebugTimestamp -output ("Ending $($MyInvocation.MyCommand)")
}
