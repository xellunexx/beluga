
$sourceDir = "C:\Users\ochak\Downloads\jvuz\tenderscompleted\"
$pdfFile = Join-Path $sourceDir "КСС(52716655).pdf"
$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open($pdfFile, $false, $true)
    $tempTxt = Join-Path $sourceDir "debug_pdf.txt"
    $doc.SaveAs([ref]$tempTxt, [ref]2)
    $doc.Close()
    Write-Host "PDF converted successfully"
} catch {
    Write-Host "Error: $($_.Exception.Message)"
}
$word.Quit()
