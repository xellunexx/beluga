
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$targetFile = "C:\Users\ochak\Downloads\rel8stack\scratch\construction_database_expanded.csv"

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$allResults = @()
$files = Get-ChildItem -Path $sourceDir -Include *.xls, *.xlsx -Recurse

# Bulgarian units as hex codes
$u_m3 = [char]0x043C + "3"
$u_m2 = [char]0x043C + "2"
$u_kg = [char]0x043A + [char]0x0433
$u_br = [char]0x0431 + [char]0x0440
$u_m = [char]0x043C
$u_t = [char]0x0442
$units = @($u_m3, $u_m2, $u_kg, $u_br, $u_m, $u_t, "m", "m2", "m3", "kg", "pcs")

foreach ($file in $files) {
    $fileName = $file.Name
    try {
        $wb = $excel.Workbooks.Open($file.FullName)
        $extractedCount = 0
        foreach ($sheet in $wb.Worksheets) {
            $usedRange = $sheet.UsedRange
            $rowCount = $usedRange.Rows.Count
            if ($rowCount -lt 5) { continue }

            # Common column sets to try: (Desc, Unit, Price)
            $colSets = @( @(2, 3, 5), @(2, 4, 7), @(2, 3, 4) )

            foreach ($set in $colSets) {
                $dCol = $set[0]; $uCol = $set[1]; $pCol = $set[2]
                $tempCount = 0
                $tempResults = @()
                $currentCat = $sheet.Name

                for ($r = 1; $r -le $rowCount; $r++) {
                    $d = [string]$usedRange.Cells.Item($r, $dCol).Value2
                    $u = [string]$usedRange.Cells.Item($r, $uCol).Value2
                    $p = $usedRange.Cells.Item($r, $pCol).Value2

                    if ([string]::IsNullOrWhiteSpace($d)) { continue }

                    $isPrice = ($p -is [double] -or $p -is [decimal])
                    $pVal = if ($isPrice) { [double]$p } else { 0 }

                    # If it looks like a category (long desc, no unit, no price)
                    if ([string]::IsNullOrWhiteSpace($u) -and $pVal -eq 0) {
                        if ($d.Length -gt 5 -and $d.Length -lt 200) { $currentCat = $d.Trim() }
                        continue
                    }

                    # If it matches a unit or has a price
                    $isUnit = $false
                    foreach ($uu in $units) { if ($u -eq $uu -or $u -like "*$uu*") { $isUnit = $true; break } }

                    if ($isUnit -and $pVal -gt 0) {
                        $tempResults += New-Object PSObject -Property @{
                            Cat = $currentCat; Desc = $d; Unit = $u; Price = $pVal
                        }
                        $tempCount++
                    }
                }

                if ($tempCount -gt $extractedCount) {
                    $extractedCount = $tempCount
                    $bestResults = $tempResults
                }
            }

            if ($extractedCount -gt 0) {
                foreach ($res in $bestResults) {
                    $allResults += New-Object PSObject -Property @{
                        Category = $res.Cat
                        Code = ""
                        Description = $res.Desc.Replace("`n"," ").Replace("`r"," ").Replace('"', '""').Trim()
                        Unit = $res.Unit.Trim()
                        Price = $res.Price
                        Note = $fileName
                    }
                }
            }
        }
        $wb.Close($false)
        Write-Host "SUMMARY: $($fileName) - $extractedCount items"
    } catch {
        Write-Host "Error: $($fileName)"
    }
}
$excel.Quit()

# Simple CSV output using ASCII-safe names
foreach ($item in $allResults) {
    $line = "`"$($item.Category)`",`"$($item.Code)`",`"$($item.Description)`",`"$($item.Unit)`",$($item.Price.ToString('F2', [System.Globalization.CultureInfo]::InvariantCulture)),`"$($item.Note)`""
    $line | Out-File -FilePath $targetFile -Append -Encoding UTF8
}
