
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$targetFile = "C:\Users\ochak\Downloads\rel8stack\scratch\construction_database_expanded.csv"

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false
$word = New-Object -ComObject Word.Application
$word.Visible = $false

$allResults = @()
$files = Get-ChildItem -Path $sourceDir -Include *.xls, *.xlsx, *.pdf -Recurse

foreach ($file in $files) {
    $fileName = $file.Name
    if ($file.Extension -like ".xls*") {
        try {
            $wb = $excel.Workbooks.Open($file.FullName)
            $fileCount = 0
            foreach ($sheet in $wb.Worksheets) {
                $usedRange = $sheet.UsedRange
                $rows = $usedRange.Rows.Count
                if ($rows -lt 2) { continue }

                # Try common column sets: (Desc, Unit, Price)
                $colSets = @(@(2, 3, 5), @(2, 4, 7), @(2, 3, 4), @(1, 2, 5))
                $bestSheetCount = 0
                $bestSheetResults = @()

                foreach ($set in $colSets) {
                    $dC = $set[0]; $uC = $set[1]; $pC = $set[2]
                    $currentCat = $sheet.Name
                    $tempRes = @()
                    $tempCount = 0

                    for ($r = 1; $r -le $rows; $r++) {
                        $d = [string]$usedRange.Cells.Item($r, $dC).Value2
                        $u = [string]$usedRange.Cells.Item($r, $uC).Value2
                        $p = $usedRange.Cells.Item($r, $pC).Value2

                        if ([string]::IsNullOrWhiteSpace($d)) { continue }

                        $pVal = 0.0
                        $isNum = ($p -is [double] -or $p -is [decimal])
                        if ($isNum) { $pVal = [double]$p }

                        # Row validation heuristic:
                        # 1. Price > 0
                        # 2. Unit is 1-5 chars long (m, m2, m3, kg, br, etc.)
                        # 3. Description is longer than 5 chars
                        if ($pVal -gt 0 -and $u.Length -ge 1 -and $u.Length -le 5 -and $d.Length -gt 5) {
                            $tempRes += New-Object PSObject -Property @{ Cat = $currentCat; Desc = $d; Unit = $u; Price = $pVal }
                            $tempCount++
                        } elseif ($u.Length -eq 0 -and $pVal -eq 0 -and $d.Length -gt 5 -and $d.Length -lt 200) {
                            $currentCat = $d.Trim()
                        }
                    }
                    if ($tempCount -gt $bestSheetCount) {
                        $bestSheetCount = $tempCount
                        $bestSheetResults = $tempRes
                    }
                }
                foreach ($r in $bestSheetResults) {
                    $allResults += New-Object PSObject -Property @{ Category = $r.Cat; Code = ""; Description = $r.Desc; Unit = $r.Unit; Price = $r.Price; Note = $fileName }
                }
                $fileCount += $bestSheetCount
            }
            $wb.Close($false)
            Write-Host "SUMMARY: $($fileName) - $fileCount items"
        } catch {
            Write-Host "Error: $($fileName)"
        }
    } elseif ($file.Extension -eq ".pdf") {
        try {
            $doc = $word.Documents.Open($file.FullName, $false, $true)
            $txtPath = Join-Path $sourceDir "temp_agnostic.txt"
            $doc.SaveAs([ref]$txtPath, 2)
            $doc.Close()
            $lines = Get-Content $txtPath
            $pdfCount = 0
            $currentCat = "Разни"
            foreach ($line in $lines) {
                $line = $line.Trim()
                if ($line.Length -lt 10) { continue }
                # Regex for: Desc ... Unit(1-5 chars) ... Quantity ... Price ... Total
                if ($line -match "(.*)\s+(\S{1,5})\s+([\d\s,.]+)\s+([\d\s,.]+)\s+([\d\s,.]+)$") {
                    $d = $matches[1].Trim()
                    $u = $matches[2].Trim()
                    $pStr = $matches[4].Replace(" ", "").Replace(",", ".")
                    $v = 0.0
                    if ([double]::TryParse($pStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)) {
                        if ($v -gt 0) {
                            $allResults += New-Object PSObject -Property @{ Category = $currentCat; Code = ""; Description = $d; Unit = $u; Price = $v; Note = $fileName }
                            $pdfCount++
                        }
                    }
                } elseif ($line.Length -lt 100 -and -not ($line -match "\d")) {
                    $currentCat = $line
                }
            }
            Write-Host "SUMMARY: $($fileName) - $pdfCount items"
            Remove-Item $txtPath -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Error PDF: $($fileName)"
        }
    }
}

$excel.Quit()
$word.Quit()

foreach ($item in $allResults) {
    $csvLine = "`"$($item.Category)`",`"`",`"$($item.Description.Replace('"', '""').Replace("`n"," ").Replace("`r"," "))`",`"$($item.Unit)`",$($item.Price.ToString('F2', [System.Globalization.CultureInfo]::InvariantCulture)),`"$($item.Note)`""
    $csvLine | Out-File -FilePath $targetFile -Append -Encoding UTF8
}
