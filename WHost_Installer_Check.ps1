Param(
    [Parameter(Mandatory=$True)]
    [string]$BertaResultPath,

    [bool]$RunOnLocal = $false,

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
    [System.Array]$InstallerTypes = (
        "install",
        "uninstall",
        "parcomp",
        "cngtest"
    )
    [System.Array]$CheckTypes = (
        "service",
        "device",
        "library"
    )
    $parcompFlag = $true
    $cngtestFlag = $true

    # Special: For QAT17
    if ($LocationInfo.QatType -eq "QAT17") {
        if ($LocationInfo.UQMode) {
            throw ("QAT17: On the Host, not support UQ Mode.")
        }

        $cngtestFlag = $false
    }

    # Special: For QAT18
    if ($LocationInfo.QatType -eq "QAT18") {
        if ($LocationInfo.UQMode) {
            throw ("QAT18: On the Host, not support UQ Mode.")
        }

        $cngtestFlag = $false
    }

    # Special: For QAT20
    if ($LocationInfo.QatType -eq "QAT20") {
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
            Win-DebugTimestamp -output ("Initialize test environment....")
            WinHost-ENVInit | out-null

            Win-DebugTimestamp -output ("Start to run test case....")
        }

        $UQString = ($LocationInfo.UQMode) ? "UQ" : "NUQ"
        $testNameHeader = "Regression_Host_{0}_{1}_Installer" -f
            $LocationInfo.QatType,
            $UQString

        if (-not $CompareFlag) {
            $TestResultList = WinHost-InstallerCheckBase `
                -parcompFlag $parcompFlag `
                -cngtestFlag $cngtestFlag `
                -BertaResultPath $BertaResultPath
        }

        Foreach ($InstallerType in $InstallerTypes) {
            Foreach ($CheckType in $CheckTypes) {
                if ((!$parcompFlag) -and
                    ($InstallerType -eq "parcomp")) {
                    continue
                }
                if ((!$cngtestFlag) -and
                    ($InstallerType -eq "cngtest")) {
                    continue
                }
                # The parcomp and cngtest test not support CheckTypes
                # Skip and base on "service" for test 1 time
                if (($InstallerType -eq "parcomp") -and
                    ($CheckType -ne "service")) {
                    continue
                }
                if (($InstallerType -eq "cngtest") -and
                    ($CheckType -ne "service")) {
                    continue
                }

                if (($InstallerType -eq "install") -or
                    ($InstallerType -eq "uninstall")) {
                    $testName = "{0}_{1}_{2}" -f
                        $testNameHeader,
                        $InstallerType,
                        $CheckType
                } else {
                    $testName = "{0}_{1}" -f
                        $testNameHeader,
                        $InstallerType
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
                    if (($InstallerType -eq "install") -or
                        ($InstallerType -eq "uninstall")) {
                        if ($TestResultList[$InstallerType][$CheckType]["result"]) {
                            $TestResultList[$InstallerType][$CheckType]["result"] = $TestResultToBerta.Pass
                        } else {
                            $TestResultList[$InstallerType][$CheckType]["result"] = $TestResultToBerta.Fail
                        }

                        $TestCaseResultsList = [hashtable] @{
                            tc = $testName
                            s = $TestResultList[$InstallerType][$CheckType]["result"]
                            e = $TestResultList[$InstallerType][$CheckType]["error"]
                        }
                    } else {
                        if ($TestResultList[$InstallerType]["result"]) {
                            $TestResultList[$InstallerType]["result"] = $TestResultToBerta.Pass
                        } else {
                            $TestResultList[$InstallerType]["result"] = $TestResultToBerta.Fail
                        }

                        $TestCaseResultsList = [hashtable] @{
                            tc = $testName
                            s = $TestResultList[$InstallerType]["result"]
                            e = $TestResultList[$InstallerType]["error"]
                        }
                    }

                    WBase-WriteTestResult -TestResult $TestCaseResultsList
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
