Param(
    [string]$infile
)

$infile = "C:\share\QatTestBerta\examples\qat_c62x.bin"

# Create backup of infile in directory
$infileDir = Split-Path -Path $infile
$backupfile = "$infileDir\backup.bin"

$byteArray = [System.IO.File]::ReadAllBytes($infile)
[System.IO.File]::WriteAllBytes($backupfile, $byteArray)

# Increment first byte by 1 and write to original filename
$byteArray[0]++
[System.IO.File]::WriteAllBytes($infile, $byteArray)

# Checksum to see if they are different
if ((Get-FileHash $infile -Algorithm SHA512).Hash -eq (Get-FileHash $backupfile -Algorithm SHA512).Hash)
{
    Write-Warning "Files should be different"
    return -1
}

# Try to load the driver


# Return FW file back to normal and remove backup
Get-Item $infile | Remove-Item -Force
Get-Item $backupfile | Rename-Item -NewName $infile -Force

return 0