# Global Variables
if (!$QATTESTPATH) {
    $TestSuitePath = Split-Path -Parent (Split-Path -Path $PSCommandPath)
    Set-Variable -Name "QATTESTPATH" -Value $TestSuitePath -Scope global
}

Set-Variable -Name "STVWinPath" -Value "C:\\STV-tmp" -Scope global
Set-Variable -Name "STVLinuxPath" -Value "/home/administrator/STV-tmp" -Scope global
Set-Variable -Name "VMSwitch_Name" -Value "Mgmt" -Scope global

$global:sevenZipExe = "{0}\\utils\\7z.exe" -f $QATTESTPATH
$global:sevenZipDll = "{0}\\lib\\SevenZip.dll" -f $QATTESTPATH
$global:STVMainDll = "{0}\\lib\\StvMain.dll" -f $QATTESTPATH
$global:AdfCtlExe = "{0}\\utils\\adf_ctl.exe" -f $QATTESTPATH
$global:LocalPFDriverPath = "{0}\\PFDriver" -f $STVWinPath
$global:LocalVFDriverPath = "{0}\\VFDriver" -f $STVWinPath
$global:LocalLinuxPath = "{0}\\Linux" -f $STVWinPath

# About QAT driver
$global:Certificate = [hashtable] @{
    HostPF = "{0}\\qat_cert.cer" -f $LocalPFDriverPath
    HostVF = "{0}\\qat_cert.cer" -f $LocalVFDriverPath
    Remote = "{0}\\qat_cert.cer" -f $STVWinPath
    Subject = $null
}

$global:QatDriverInstallArgs = [hashtable] @{
    HyperV = "/passive /qn HYPERVMODE=1"
    Install = "/passive /qn"
    UQHyperV = "/passive /qn HYPERVMODE=1"
    UQInstall = "/passive /qn"
    Uninstall = "/x /qn"
    InstallPath = "C:\\Program Files\\Intel\\Intel(R) QuickAssist Technology"
}

$global:FriendlyNames = [System.Array] @(
    "Intel(R) C62x Accelerator*",
    "Intel(R) 4xxx Accelerator*",
    "Intel(R) C4xxx Accelerator*"
)

$global:LinuxShell = [hashtable] @{
    HostPath = "{0}\\LinuxShell" -f $QATTESTPATH
    FreeLogin = "Help-Free-Login.sh"
}

$global:VMDriverInstallPath = [hashtable] @{
    InstallPath = "qat_driver"
    QatSetupPath = "QuickAssist\\Setup\\QatSetup.exe"
    ShellOutputLog = "ShellOutput.log"
    ShellTestPath = "ShellTestPath"
}

# About driver verifier tool
$global:DriverVerifierArgs = [hashtable] @{
    ExePath = "C:\\Windows\\System32\\verifier.exe"
    Start = "/flags 0x201BA /driver"
    List = "/querysettings"
    Delete = "/reset"
    SuccessLog = "The system reboot is required for the changes to take effect."
    NoChangeLog = "No settings were changed."
    Servers = "icp_qat.sys icp_qat4.sys cfqat.sys cpmprovuser.sys"
}

# About trace log tool
$global:TraceLogOpts = [hashtable] @{
    Guid = [hashtable] @{
        IcpQat = "'#f1057c32-3432-43ee-a282-c8a7086d25d9'"
        CfQat = "'#9b523b97-ac34-4e88-9a9d-fe16d4c9fddb'"
    }
    Host = [hashtable] @{
        ExePath = "{0}\\utils\\tracelog.exe" -f $QATTESTPATH
        PDBExePath = "{0}\\utils\\tracepdb.exe" -f $QATTESTPATH
        FMTExePath = "{0}\\utils\\tracefmt.exe" -f $QATTESTPATH
        TraceLogFullPath = "{0}\\TraceLog" -f $STVWinPath
        FMTFullPath = "{0}\\TraceLog\\FMT" -f $STVWinPath
        PDBFullPath = "{0}\\TraceLog\\PDB" -f $STVWinPath
        IcpQat = [hashtable] @{
            SessionName = "qatwin_host_icpqat"
            StartArgs = "-rt -level 5 -matchanykw 0xFFFFFFFF -b 200 -ft 1 -min 4 -max 21 -seq 200 -hybridshutdown stop"
            PDBFullPath = "{0}\\icp_qat.pdb" -f $LocalPFDriverPath
            PDBCopyPath = "{0}\\TraceLog\\PDB\\icp_qat.pdb" -f $STVWinPath
            EtlFullPath = "{0}\\TraceLog\\TraceLog_icpqat.etl" -f $STVWinPath
            LogFullPath = "{0}\\TraceLog\\TraceLog_icpqat.log" -f $STVWinPath
        }
        CfQat = [hashtable] @{
            SessionName = "qatwin_host_cfqat"
            StartArgs = "-rt -level 5 -matchanykw 0xFFFFFFFF -b 200 -ft 1 -min 4 -max 21 -seq 200 -hybridshutdown stop"
            PDBFullPath = "{0}\\CfQat.pdb" -f $LocalPFDriverPath
            PDBCopyPath = "{0}\\TraceLog\\PDB\\CfQat.pdb" -f $STVWinPath
            EtlFullPath = "{0}\\TraceLog\\TraceLog_cfqat.etl" -f $STVWinPath
            LogFullPath = "{0}\\TraceLog\\TraceLog_cfqat.log" -f $STVWinPath
        }
    }
    Remote = [hashtable] @{
        ExePath = "{0}\\tracelog.exe" -f $STVWinPath
        PDBExePath = "{0}\\tracepdb.exe" -f $STVWinPath
        FMTExePath = "{0}\\tracefmt.exe" -f $STVWinPath
        TraceLogFullPath = "{0}\\TraceLog" -f $STVWinPath
        FMTFullPath = "{0}\\TraceLog\\FMT" -f $STVWinPath
        PDBFullPath = "{0}\\TraceLog\\PDB" -f $STVWinPath
        IcpQat = [hashtable] @{
            SessionName = "qatwin_remote_icpqat"
            StartArgs = "-rt -level 3 -matchanykw 0xFFFFFFFF -b 200 -ft 1 -min 4 -max 21 -seq 200 -hybridshutdown stop"
            PDBFullPath = "{0}\\icp_qat.pdb" -f $LocalVFDriverPath
            PDBCopyPath = "{0}\\TraceLog\\PDB\\icp_qat.pdb" -f $STVWinPath
            EtlFullPath = "{0}\\TraceLog\\TraceLog_icpqat.etl" -f $STVWinPath
            LogFullPath = "{0}\\TraceLog\\TraceLog_icpqat.log" -f $STVWinPath
        }
        CfQat = [hashtable] @{
            SessionName = "qatwin_remote_cfqat"
            StartArgs = "-rt -level 3 -matchanykw 0xFFFFFFFF -b 200 -ft 1 -min 4 -max 21 -seq 200 -hybridshutdown stop"
            PDBFullPath = "{0}\\CfQat.pdb" -f $LocalVFDriverPath
            PDBCopyPath = "{0}\\TraceLog\\PDB\\CfQat.pdb" -f $STVWinPath
            EtlFullPath = "{0}\\TraceLog\\TraceLog_cfqat.etl" -f $STVWinPath
            LogFullPath = "{0}\\TraceLog\\TraceLog_cfqat.log" -f $STVWinPath
        }
    }
}

$global:TraceLogCommand = [hashtable] @{
    Host = [hashtable] @{
        PDBToFMT = "-f {0}\\*.pdb -p {1} 2>&1" -f
            $TraceLogOpts.Host.PDBFullPath,
            $TraceLogOpts.Host.FMTFullPath
        IcpQat = [hashtable] @{
            Start = "{0} -start {1} -f {2} -guid {3} {4}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.IcpQat.SessionName,
                $TraceLogOpts.Host.IcpQat.EtlFullPath,
                $TraceLogOpts.Guid.IcpQat,
                $TraceLogOpts.Host.IcpQat.StartArgs
            Flush = "{0} -flush {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.IcpQat.SessionName
            List = "{0} -q {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.IcpQat.SessionName
            Stop = "{0} -stop {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.IcpQat.SessionName
            FMTToLog = "{0} -p {1} -o {2} -nosummary" -f
                $TraceLogOpts.Host.IcpQat.EtlFullPath,
                $TraceLogOpts.Host.FMTFullPath,
                $TraceLogOpts.Host.IcpQat.LogFullPath
            Transfer = "-process {0} -pdb {1} -o {2} -nosummary" -f
                $TraceLogOpts.Host.IcpQat.EtlFullPath,
                $TraceLogOpts.Host.IcpQat.PDBCopyPath,
                $TraceLogOpts.Host.IcpQat.LogFullPath
        }
        CfQat = [hashtable] @{
            Start = "{0} -start {1} -f {2} -guid {3} {4}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.CfQat.SessionName,
                $TraceLogOpts.Host.CfQat.EtlFullPath,
                $TraceLogOpts.Guid.CfQat,
                $TraceLogOpts.Host.CfQat.StartArgs
            Flush = "{0} -flush {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.CfQat.SessionName
            List = "{0} -q {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.CfQat.SessionName
            Stop = "{0} -stop {1}" -f
                $TraceLogOpts.Host.ExePath,
                $TraceLogOpts.Host.CfQat.SessionName
            FMTToLog = "{0} -p {1} -o {2} -nosummary" -f
                $TraceLogOpts.Host.CfQat.EtlFullPath,
                $TraceLogOpts.Host.FMTFullPath,
                $TraceLogOpts.Host.CfQat.LogFullPath
            Transfer = "-process {0} -pdb {1} -o {2} -nosummary" -f
                $TraceLogOpts.Host.CfQat.EtlFullPath,
                $TraceLogOpts.Host.CfQat.PDBCopyPath,
                $TraceLogOpts.Host.CfQat.LogFullPath
        }
    }
    Remote = [hashtable] @{
        PDBToFMT = "-f {0}\\*.pdb -p {1} 2>&1" -f
            $TraceLogOpts.Remote.PDBFullPath,
            $TraceLogOpts.Remote.FMTFullPath
        IcpQat = [hashtable] @{
            Start = "{0} -start {1} -f {2} -guid {3} {4}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.IcpQat.SessionName,
                $TraceLogOpts.Remote.IcpQat.EtlFullPath,
                $TraceLogOpts.Guid.IcpQat,
                $TraceLogOpts.Remote.IcpQat.StartArgs
            Flush = "{0} -flush {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.IcpQat.SessionName
            List = "{0} -q {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.IcpQat.SessionName
            Stop = "{0} -stop {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Host.IcpQat.SessionName
            FMTToLog = "{0} -p {1} -o {2} -nosummary" -f
                $TraceLogOpts.Remote.IcpQat.EtlFullPath,
                $TraceLogOpts.Remote.FMTFullPath,
                $TraceLogOpts.Remote.IcpQat.LogFullPath
            Transfer = "-process {0} -pdb {1} -o {2} -nosummary" -f
                $TraceLogOpts.Remote.IcpQat.EtlFullPath,
                $TraceLogOpts.Remote.IcpQat.PDBCopyPath,
                $TraceLogOpts.Remote.IcpQat.LogFullPath
        }
        CfQat = [hashtable] @{
            Start = "{0} -start {1} -f {2} -guid {3} {4}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.CfQat.SessionName,
                $TraceLogOpts.Remote.CfQat.EtlFullPath,
                $TraceLogOpts.Guid.CfQat,
                $TraceLogOpts.Remote.CfQat.StartArgs
            Flush = "{0} -flush {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.CfQat.SessionName
            List = "{0} -q {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Remote.CfQat.SessionName
            Stop = "{0} -stop {1}" -f
                $TraceLogOpts.Remote.ExePath,
                $TraceLogOpts.Host.CfQat.SessionName
            FMTToLog = "{0} -p {1} -o {2} -nosummary" -f
                $TraceLogOpts.Remote.CfQat.EtlFullPath,
                $TraceLogOpts.Remote.FMTFullPath,
                $TraceLogOpts.Remote.CfQat.LogFullPath
            Transfer = "-process {0} -pdb {1} -o {2} -nosummary" -f
                $TraceLogOpts.Remote.CfQat.EtlFullPath,
                $TraceLogOpts.Remote.CfQat.PDBCopyPath,
                $TraceLogOpts.Remote.CfQat.LogFullPath
        }
    }
}

# About SSH tool
$global:SSHKeys = [hashtable] @{
    Path = "C:\\Users\\Administrator\\.ssh"
    PrivateKeyName = "id_rsa"
    PublicKeyName = "id_rsa.pub"
    ConfigName = "Config"
    KnownHostName = "known_hosts"
}

# About login
$global:RemoteUserConfig =  [hashtable] @{
    UserName = "administrator"
    Password = "root.1234"
    RootName = "root"
}

$global:WTWSecPassword = ConvertTo-SecureString `
    -String $RemoteUserConfig.Password `
    -AsPlainText `
    -Force

$global:WTWCredentials = New-Object `
    -TypeName "System.Management.Automation.PSCredential" `
    -ArgumentList $RemoteUserConfig.UserName, $WTWSecPassword

# About Test type
$global:AllTestType = [hashtable] @{
    Type = [System.Array] @(
        "Base",
        "Performance",
        "Static",
        "Fallback"
    )
    Operation = [System.Array] @(
        "heartbeat",
        "disable",
        "upgrade"
    )
}

# About parcomp tool
$global:ParcompOpts = [hashtable] @{
    ParcompPath = "C:\\Program Files\\Intel\\Intel(R) QuickAssist Technology\\Compression"
    ParcompExeName = "parcomp.exe"
    OutputLog = "TestParcompOutLog.txt"
    ErrorLog = "TestParcompErrorLog.txt"
    OutputFileName = "TestParcompOut.gz"
    InputFileName = "TestParcompIn.txt"
    PathName = "ParcompTest"
    CompressPathName = "CompressTest"
    deCompressPathName = "deCompressTest"
    sevenZipPathName = "7zip"
    MD5PathName = "CheckMD5"
}

$global:ParcompProvider = [System.Array] @(
    "qat",
    "qatzlib",
    "qatgzip",
    "qatgzipext"
)

$global:ParcompChunk = [System.Array] @(1, 2, 8, 16, 64, 128, 256, 512)

$global:ParcompBlock = [System.Array] @(1024, 2048, 4096, 8192)

$global:ParcompIteration = [System.Array] @(1, 800)

$global:ParcompThread = [System.Array] @(1, 64)

$global:ParcompCompressType = [System.Array] @(
    "Compress",
    "deCompress",
    "All"
)

$global:ParcompCompressionLevel = [System.Array] @(1, 2, 3, 4)

$global:ParcompCompressionType = [System.Array] @(
    "static",
    "dynamic"
)

# About CNGTest tool
$global:CNGTestOpts = [hashtable] @{
    CNGTestPath = "C:\\Program Files\\Intel\\Intel(R) QuickAssist Technology\\Crypto\\Samples\\bin"
    CNGTestExeName = "cngtest.exe"
    OutputLog = "CNGTestOutLog.txt"
    ErrorLog = "CNGTestErrorLog.txt"
    PathName = "CNGTest"
}

$global:CNGTestProvider = [System.Array] @(
    "sw",
    "qa"
)

$global:CNGTestAlgo = [System.Array] @(
    "rsa",
    "ecdsa",
    "dsa",
    "ecdh",
    "dh"
)

$global:CNGTestEcccurve = [System.Array] @(
    "nistP256",
    "nistP384",
    "nistP521",
    "curve25519"
)

$global:CNGTestKeyLength = [System.Array] @(
    2048,
    3072,
    4096
)

$global:CNGTestPadding = [System.Array] @(
    "pkcs1",
    "oaep",
    "pss"
)

$global:CNGTestOperation = [System.Array] @(
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "derivekey",
    "secretderive",
    "secretagreement"
)

$global:CNGTestIteration = [System.Array] @(1, 100000)

$global:CNGTestThread = [System.Array] @(1, 96)

# About Berta
$global:BertaENVInit = [hashtable] @{
    BertaClient = [hashtable] @{
        SourcePath = "\\10.67.115.211\\mountBertaCTL\\berta"
        SourceFiles = [System.Array] @(
            "wrappers\\qatwin.py",
            "wrappers\\qatinstaller.py",
            "wrappers\\buildinstallers.py",
            "utils.py",
            "getaddr.py",
            "agent.py"
        )
        DestinationPath = "C:\\berta"
    }
    QATTest = [hashtable] @{
        SourcePath = "\\10.67.115.211\\mountBertaCTL\\QatTestBerta"
        DestinationPath = "C:\\QatTestBerta"
    }
    PSProFile = [hashtable] @{
        FileName = "Microsoft.PowerShell_profile.ps1"
        SourcePath = "\\10.67.115.211\\mountBertaCTL\\tools"
        DestinationPath = "C:\\Users\\Administrator\\Documents\\PowerShell"
    }
    LinuxShell = [hashtable] @{
        SourcePath = "\\10.67.115.211\\mountBertaCTL\\LinuxShellCode"
    }
}

$global:TestResultToBerta = [hashtable] @{
    Error = "Erro"
    Fail = "Fail"
    NotRun = "NRun"
    Pass = "Pass"
}

# About athers
$global:SiteKeep = [hashtable] @{
    DumpFile = "C:\\Windows\\MEMORY.DMP"
}

$global:VMState = [hashtable] @{
    Off = "Off"
    On = "Running"
}

$global:VHDAndTestFiles = [hashtable] @{
    SourceVMPath = "\\10.67.115.211\\mountBertaCTL\\vms\\vhd"
    ParentsVMPath = "C:\\vhd"
    ChildVMPath = "C:\vhd\WTWChildVhds"
    SourceTestPath = "C:\\vhd\\WinTestFile"
}

$global:TestFileNameArray = [hashtable] @{
    Type = [System.Array] @("high", "random", "calgary")
    Size = [System.Array] @(200, 999)
}

# About info of location
$global:LocationInfo = [hashtable] @{
    IsWin = $null
    HVMode = $null
    UQMode = $null
    TestMode = $null
    DebugMode = $null
    VerifierMode = $null
    QatType = $null
    FriendlyName = $null
    BertaResultPath = $null
    IcpQatName = $null
    WriteLogToConsole = $false
    WriteLogToFile = $false
    PF = [hashtable] @{
        Number = 0
        PCI = [System.Array] @()
        DriverPath = $null
        DriverName = $null
        DriverExe = $null
    }
    VF = [hashtable] @{
        Number = 0
        DriverPath = $null
        DriverName = $null
    }
    VM = [hashtable] @{
        Number = 0
        OS = $null
        IsWin = $null
    }
}


Export-ModuleMember -Variable *-*
