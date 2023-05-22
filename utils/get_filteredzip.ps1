<#
.SYNOPSIS
Script used to get certain files from a zip archive.

.DESCRIPTION
Script used to get certain files from a zip archive.
The output topology will be a flat directory structure.
Zip archive must be compatible with .NET zip implementation.

Requires Powershell 7.0 and above.

.PARAMETER ZipArchive
[string] The full path to zip archive.

.PARAMETER OutputPath
[string] The output path to extract.
         Directory will be created if it doesn't exist.

.PARAMETER Filter
[string] Name to match from ZipArchive.

.PARAMETER MinimumSize
[int] Minimum byte size. Default will eliminate folders.
#>


Param(
    [Parameter(Mandatory=$True)]
    [string]$ZipArchive,

    [Parameter(Mandatory=$True)]
    [string]$OutputPath,

    [Parameter(Mandatory=$True)]
    [string]$Filter,

    [int]$MinimumSize = 1
)

if (-not [System.IO.File]::Exists(($ZipArchive))) {
    throw "File not found -> $ZipArchive."
}

if (-not (Test-Path $OutputPath)) {
    Write-Host "Output path -> $OutputPath not found; creating path."
    New-Item $OutputPath -ItemType Directory -Force -Confirm:$false
}

try {
    $zipFile = [System.IO.Compression.ZipFile]::OpenRead($ZipArchive)
    $zipFile.Entries | Where-Object {$_.FullName -match $Filter -and $_.CompressedLength -ge $MinimumSize} |
        ForEach-Object {
            $FileName = [System.IO.Path]::Combine($OutputPath, $_.Name)
            Write-Host "Attempting to extract -> $FileName."
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $FileName, $true)
        }
} catch {
    Write-Host $_.ScriptStackTrace
} finally {
    Write-Host "Closing $ZipArchive."
    $zipFile.Dispose()
}
