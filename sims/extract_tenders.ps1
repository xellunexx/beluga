
# Set output encoding to UTF8 for correct Bulgarian characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$targetFile = "C:\Users\ochak\Downloads\rel8stack\scratch\construction_database_expanded.csv"

# Keywords for header identification (Bulgarian)
$descKeywords = @("Описание", "вид на работите", "наименование", "СМР", "Наименование")
$unitKeywords = @("мярка", "мерна единица", "ед.м.", "ед. м.", "Ед.")
$priceKeywords = @("ед. цена", "единична цена", "Рц за еденица")

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$allResults = @()

$files = Get-ChildItem -Path $sourceDir -Include *.xls, *.xlsx, *.pdf -Recurse

foreach ($file in $files) {
    $fileName = $file.Name
    $filePath = $file.FullName

    if ($fileName -like "*.xls*") {
        Write-Host "Processing Excel: $($fileName)"
        try {
            $workbook = $excel.Workbooks.Open($filePath)
            $fileExtractedCount = 0

            foreach ($sheet in $workbook.Worksheets) {
                # Skip sheets that look like recaps or payroll
                if ($sheet.Name -like "*РЕКАП*" -or $sheet.Name -like "*ведомост*" -or $sheet.Name -like "*форма 19*") { continue }

                $usedRange = $sheet.UsedRange
                $rowCount = $usedRange.Rows.Count
                $colCount = $usedRange.Columns.Count

                if ($rowCount -lt 2) { continue }

                $headerRow = -1
                $descCol = -1
                $unitCol = -1
                $priceCol = -1

                # Scan first 30 rows for headers
                for ($r = 1; $r -le [Math]::Min(30, $rowCount); $r++) {
                    for ($c = 1; $c -le $colCount; $c++) {
                        $cellValue = [string]$usedRange.Cells.Item($r, $c).Value2
                        if ([string]::IsNullOrWhiteSpace($cellValue)) { continue }

                        foreach ($k in $descKeywords) { if ($cellValue -match $k) { $descCol = $c; break } }
                        foreach ($k in $unitKeywords) { if ($cellValue -match $k) { $unitCol = $c; break } }
                        foreach ($k in $priceKeywords) { if ($cellValue -match $k) { $priceCol = $c; break } }
                    }
                    if ($descCol -ne -1 -and ($unitCol -ne -1 -or $priceCol -ne -1)) {
                        $headerRow = $r
                        break
                    }
                }

                if ($descCol -ne -1) {
                    $currentCategory = $sheet.Name
                    $startRow = if ($headerRow -eq -1) { 1 } else { $headerRow + 1 }

                    for ($r = $startRow; $r -le $rowCount; $r++) {
                        $desc = [string]$usedRange.Cells.Item($r, $descCol).Value2
                        if ([string]::IsNullOrWhiteSpace($desc)) { continue }

                        $unit = if ($unitCol -ne -1) { [string]$usedRange.Cells.Item($r, $unitCol).Value2 } else { "" }
                        $price = if ($priceCol -ne -1) { $usedRange.Cells.Item($r, $priceCol).Value2 } else { $null }

                        $isPriceNum = ($price -is [double] -or $price -is [decimal])
                        $priceVal = if ($isPriceNum) { [double]$price } else { 0 }

                        # Category detection: no unit, no price, not a number in description
                        if ([string]::IsNullOrWhiteSpace($unit) -and $priceVal -eq 0 -and -not ($desc -match "^\d+$")) {
                             if ($desc.Length -gt 2 -and $desc.Length -lt 200) {
                                $currentCategory = $desc.Trim()
                             }
                             continue
                        }

                        if (-not [string]::IsNullOrWhiteSpace($unit) -and $priceVal -gt 0) {
                            $allResults += New-Object PSObject -Property @{
                                Category = $currentCategory
                                Code = ""
                                Description = $desc.Replace("`n", " ").Replace("`r", " ").Replace('"', '""').Trim()
                                Unit = $unit.Trim()
                                Price = $priceVal
                                Note = $fileName
                            }
                            $fileExtractedCount++
                        }
                    }
                }
            }
            $workbook.Close($false)
            Write-Host "SUMMARY: $($fileName) - $fileExtractedCount items"
        } catch {
            Write-Host "Error processing $($fileName) - $($_.Exception.Message)"
        }
    }
}
$excel.Quit()

# PDF Processing
$pdfFile = $files | Where-Object { $_.Extension -eq ".pdf" } | Select-Object -First 1
if ($pdfFile) {
    Write-Host "Processing PDF: $($pdfFile.Name)"
    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $doc = $word.Documents.Open($pdfFile.FullName, $false, $true)
        $tempTxt = Join-Path $sourceDir "temp_pdf.txt"
        $doc.SaveAs([ref]$tempTxt, [ref]2) # wdFormatText = 2
        $doc.Close()
        $word.Quit()

        $lines = Get-Content $tempTxt
        $pdfCount = 0
        $currentCategory = "Разни"
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # Match: Description ... Unit ... Quantity ... Price ... Total
            if ($line -match "(.*)\s+(м3|м2|кг|бр|м'|т|m2|m3|m)\s+([\d\s,.]+)\s+([\d\s,.]+)\s+([\d\s,.]+)$") {
                $desc = $matches[1].Trim()
                $unit = $matches[2].Trim()
                $priceStr = $matches[4].Replace(" ", "").Replace(",", ".")
                $val = 0.0
                if ([double]::TryParse($priceStr, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$val)) {
                    $allResults += New-Object PSObject -Property @{
                        Category = $currentCategory
                        Code = ""
                        Description = $desc.Replace('"', '""')
                        Unit = $unit
                        Price = $val
                        Note = $pdfFile.Name
                    }
                    $pdfCount++
                }
            } elseif ($line.Length -gt 5 -and $line.Length -lt 100 -and -not ($line -match "\d")) {
                $currentCategory = $line
            }
        }
        Write-Host "SUMMARY: $($pdfFile.Name) - $pdfCount items"
        Remove-Item $tempTxt -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Error processing PDF $($pdfFile.Name) - $($_.Exception.Message)"
    }
}

# Append to CSV with UTF8 encoding (BOM included for Excel compatibility)
foreach ($item in $allResults) {
    $csvLine = "`"$($item.Category)`",`"$($item.Code)`",`"$($item.Description)`",`"$($item.Unit)`",$($item.Price.ToString('F2', [System.Globalization.CultureInfo]::InvariantCulture)),`"$($item.Note)`""
    $csvLine | Out-File -FilePath $targetFile -Append -Encoding UTF8
}
