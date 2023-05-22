# Parse performance to friendly csv output

Param(
    [string]$infile,
    [string]$outfile = "output.csv"
)

$file = Get-Content $infile

# Remove header line
$file = $file[1..($file.Length)]

# Create output csv
"sep=," | Out-File $outfile -Force
"Provider, Threads, Block Size (Bytes), Huffman, Outstanding Jobs, Compression Level, Chunk Size, Throughput (Mbps)" | Out-File $outfile -Append

foreach ($line in $file)
{
    $currLine = ""

    $provider = [regex]::Match($line, '-(qat|qatms|qatzlib)-')
    if ($provider.Success)
    {
        $currLine += ("{0}, " -f $provider.Value.Trim('-'))
    }

    $threads = [regex]::Match($line, '(?<=-t)\d*')
    if ($threads.Success)
    {
        if ($line -cmatch '-Q')
        {
            $currLine += '-Q'
        }

        $currLine += (" {0}, " -f $threads.Value)
    }

    $blockSize = [regex]::Match($line, '(?<=-k)\d*')
    if ($blockSize.Success)
    {
        $currLine += ("{0}, " -f $blockSize.Value)
    }

    $huffman = [regex]::Match($line, '(-s|-D)')
    if ($huffman.Success)
    {
        if ($huffman.Value -eq "-s")
        {
            $value = "Static"
        }
        elseif ($huffman.Value -eq "-D")
        {
            $value = "Dynamic"
        }
        $currLine += ("{0}, " -f $value)
    }

    $jobs = [regex]::Match($line, '(?<=-j)\d*')
    if ($jobs.Success)
    {
        $currLine += ("{0}, " -f $jobs.Value)
    }

    $level = [regex]::Match($line, '(?<=-l)\d*')
    if ($level.Success)
    {
        $currLine += ("{0}, " -f $level.Value)
    }

    $chunkSize = [regex]::Match($line, '(?<=-c)\d*')
    if ($chunkSize.Success)
    {
        $currLine += ("{0}, " -f $chunkSize.Value)
    }

    $throughput = [regex]::Match($line, '(?<=Throughput Mbps:\s)\d*.\d*')
    if ($throughput.Success)
    {
        $currLine += ("{0}, " -f $throughput.Value)
    }

    $currLine | Out-File $outfile -Append
}