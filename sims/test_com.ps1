
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$files = Get-ChildItem -Path $sourceDir -Include *.xls, *.xlsx, *.pdf -Recurse

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false

foreach ($file in $files) {
    if ($file.Extension -like ".xls*") {
        Write-Host "Opening $($file.Name)"
        try {
            $wb = $excel.Workbooks.Open($file.FullName)
            Write-Host "Success: $($wb.Name) with $($wb.Sheets.Count) sheets"
            $wb.Close($false)
        } catch {
            Write-Host "Error: $($_.Exception.Message)"
        }
    }
}
$excel.Quit()
