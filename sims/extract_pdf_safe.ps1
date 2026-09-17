
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$targetFile = "C:\Users\ochak\Downloads\rel8stack\scratch\construction_database_expanded.csv"
$pdfFile = Join-Path $sourceDir "КСС(52716655).pdf"

if (-not (Test-Path $pdfFile)) { Exit }

$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open($pdfFile, $false, $true)
    $tempTxt = Join-Path $sourceDir "temp_pdf.txt"
    $doc.SaveAs([ref]$tempTxt, [ref]2) # wdFormatText = 2
    $doc.Close()
} catch {
    Write-Host "Error opening PDF"
}
$word.Quit()

$u_m3 = [char]0x043C + "3"
$u_m2 = [char]0x043C + "2"
$u_kg = [char]0x043A + [char]0x0433
$u_br = [char]0x0431 + [char]0x0440
$u_m = [char]0x043C
$u_t = [char]0x0442
$unitsRegex = "(" + $u_m3 + "|" + $u_m2 + "|" + $u_kg + "|" + $u_br + "|" + $u_m + "|" + $u_t + "|m2|m3|m|kg|pcs)"

$lines = Get-Content $tempTxt
$pdfResults = @()
$currentCat = "Разни"
$pdfCount = 0

foreach ($line in $lines) {
    $line = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    # Heuristic for PDF rows: Desc ... Unit ... Quantity ... Price ... Total
    # Often quantities/prices have spaces as thousands separators or commas as decimals.
    if ($line -match "(.*)\s+$unitsRegex\s+([\d\s,.]+)\s+([\d\s,.]+)\s+([\d\s,.]+)$") {
        $d = $matches[1].Trim()
        $u = $matches[2].Trim()
        $pStr = $matches[4].Replace(" ", "").Replace(",", ".")
        $val = 0.0
        if ([double]::TryParse($pStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$val)) {
            if ($val -gt 0) {
                $pdfResults += New-Object PSObject -Property @{ Cat = $currentCat; Desc = $d; Unit = $u; Price = $val }
                $pdfCount++
            }
        }
    } elseif ($line.Length -gt 5 -and $line.Length -lt 100 -and -not ($line -match "\d")) {
        $currentCat = $line
    }
}

foreach ($item in $pdfResults) {
    $csvLine = "`"$($item.Cat)`",`"`",`"$($item.Desc.Replace('"', '""'))`",`"$($item.Unit)`",$($item.Price.ToString('F2', [System.Globalization.CultureInfo]::InvariantCulture)),`"КСС(52716655).pdf`""
    $csvLine | Out-File -FilePath $targetFile -Append -Encoding UTF8
}

Write-Host "SUMMARY: КСС(52716655).pdf - $pdfCount items"
Remove-Item $tempTxt -ErrorAction SilentlyContinue
