Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [Parameter(Mandatory=$True)]
    [string]$TestName,

    [Parameter(Mandatory=$True)]
    [string]$DriverPath = "C:\\cy-work\\qat_driver\\",

    [int]$Iteration = 1,

    [bool]$InitVM = $true,

    [bool]$RunOnLocal = $true,

    [bool]$DebugMode = $false,

    [string]$ResultFile = "result.log"
)

$TestSuitePath = Split-Path -Path $PSCommandPath
Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global
Import-Module "$QATTESTPATH\\lib\\WinBase.psm1" -Force -DisableNameChecking

$InitVMInt = ($InitVM) ? 1 : 0
$RunOnLocalInt = ($RunOnLocal) ? 1 : 0
$DebugModeInt = ($DebugMode) ? 1 : 0
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
            if ($TestName -match "Host") {
                if ($TestName -match "Base_Parameter") {
                    $TestSuiteName = "{0}\\WHost_Parcomp_Base_Parameter.ps1" -f $QATTESTPATH
                }

                if ($TestName -match "Perf_Parameter") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_Parameter.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_Performance_Parameter_Small.ps1" -f $QATTESTPATH
                    }
                }

                if ($TestName -match "Performance") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_Performance.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_Performance.ps1" -f $QATTESTPATH
                    }
                }

                if ($TestName -match "Fallback") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WHost_CNGtest_SWFallback.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WHost_Parcomp_SWFallback.ps1" -f $QATTESTPATH
                    }
                }

                $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -DebugMode {5}" -f
                    $TestSuiteName,
                    $BertaResultPath,
                    $DriverPath,
                    $TestName,
                    $RunOnLocalInt,
                    $DebugModeInt
            }

            if ($TestName -match "WTW") {
                if ($TestName -match "Base_Parameter") {
                    $TestSuiteName = "{0}\\WHost_Parcomp_Base_Parameter.ps1" -f $QATTESTPATH
                }

                if ($TestName -match "Perf_Parameter") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_Parameter.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_Performance_Parameter.ps1" -f $QATTESTPATH
                    }
                }

                if ($TestName -match "Performance") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_Performance.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_Performance.ps1" -f $QATTESTPATH
                    }
                }

                if ($TestName -match "Fallback") {
                    if ($TestName -match "_qa_") {
                        $TestSuiteName = "{0}\\WTW_CNGtest_SWFallback.ps1" -f $QATTESTPATH
                    } else {
                        $TestSuiteName = "{0}\\WTW_Parcomp_SWFallback.ps1" -f $QATTESTPATH
                    }
                }

                $runCommand = "{0} -BertaResultPath {1} -DriverPath {2} -runTestCase {3} -RunOnLocal {4} -InitVM {5} -DebugMode {6}" -f
                    $TestSuiteName,
                    $BertaResultPath,
                    $DriverPath,
                    $TestName,
                    $RunOnLocalInt,
                    $InitVMInt,
                    $DebugModeInt
            }

            Invoke-Expression $runCommand
            if ($InitVMInt) {$InitVMInt = 0}
        }
    }
} catch {
    Win-DebugTimestamp -output $_
} finally {
    Win-DebugTimestamp -output ("Ending $($MyInvocation.MyCommand)")
}
