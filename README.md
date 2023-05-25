# QAT-Windows-Test
This repo is the some test for QAT driver base on windows platform using PowerShell script.
Support test windows host and windows VM base on windows Host and Linux VM base on windows host.
Support to run on Berta system or on local.
Support run test suite or run single test case.

## Prerequisites
* Need `PowerShell 7.x`
* Need Test files: `\\10.67.115.211\mountBertaCTL\vms\vhd\WinTestFile` to `C:\vhd\WinTestFile`
* If with HVMode, Need the image files: `\\10.67.115.211\mountBertaCTL\vms\vhd` to `C:\vhd`

## Ready to the QAT windows driver
### Driver config file: `pfvf_build.txt`
```shell
PF QAT2.0.W.2.0.0-00538
VF QAT2.0.W.2.0.0-00538
```
or
```shell
PF PF-driver-path\\QAT2.0.W.2.0.0-00538
VF VF-driver-path\\QAT2.0.W.2.0.0-00538
```
### Driver `PDB` files: `CfQat.pdb` and `icp_qat4.pdb` and `CpmProvUser.pdb`
### Driver certificate: `qat_cert.cer`
### Driver `zip` file: `QAT2.0.W.2.x.x-xxxxx.zip`

## Run test suite
```sh
$ .\<name of powershell script>.ps1 -BertaResultPath <Path of test result> -DriverPath <Path of QAT driver>
```
```shell
-BertaResultPath      The path of test result.
-RunOnLocal           [option] '$false', run this test suite on the local PC.
-UQMode               [option] '$false', disable and enable the UQ mode.
-TestMode             [option] '$true', disable and enable the Test mode.
-VerifierMode         [option] '$true', disable and enable the driver verifier, the default value is `$false` for performance test.
-runTestCase          [option] '$null', run single test case.
-DriverPath           [option] 'C:\\cy-work\\qat_driver\\', the path of QAT driver.
-ResultFile           [option] 'result.log', the file of test result.
-InitVM               [option] '$true', Initialize or not the VM for HVMode.
-VMVFOSConfigs        [option] '$null', Specify the configuration of the VM for HVMode.
```

## Run single test case
```sh
$ .\Win_Single_test.ps1 -BertaResultPath <Path of test result> -DriverPath <Path of QAT driver> -TestName <Name of test case> -Iteration <Iteration of test case>
```
```shell
-BertaResultPath      The path of test result.
-TestName             The name of test case.
-DriverPath           The path of QAT driver.
-Iteration           [option] '1', the iteration of test case.
-ResultFile           [option] 'result.log', the file of test result.
```
