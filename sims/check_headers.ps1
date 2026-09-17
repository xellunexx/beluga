
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$files = Get-ChildItem -Path $sourceDir -Include *.xls, *.xlsx -Recurse

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false

foreach ($file in $files) {
    Write-Host "Checking $($file.Name)"
    try {
        $wb = $excel.Workbooks.Open($file.FullName)
        foreach ($sheet in $wb.Worksheets) {
            Write-Host "  Sheet: $($sheet.Name)"
            $usedRange = $sheet.UsedRange
            for ($r = 1; $r -le [Math]::Min(10, $usedRange.Rows.Count); $r++) {
                $rowText = ""
                for ($c = 1; $c -le [Math]::Min(10, $usedRange.Columns.Count); $c++) {
                    $val = $usedRange.Cells.Item($r, $c).Value2
                    $rowText += "[$($val)] "
                }
                Write-Host "    Row $($r) - $($rowText)"
            }
        }
        $wb.Close($false)
    } catch {
        Write-Host "    Error: $($_.Exception.Message)"
    }
}
$excel.Quit()
