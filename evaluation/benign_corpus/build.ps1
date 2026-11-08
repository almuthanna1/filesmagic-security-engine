# Builds the known-benign real-world corpus with real producers: Microsoft Word, Excel and PowerPoint
# (COM automation), LibreOffice (headless) and Microsoft Edge (headless print to PDF).
# Every file is authored here from neutral text, without macros, with personal information removed.
# Office embeds timestamps, so a rebuild gives different bytes: the committed files and manifest.json
# are the reference copy; this script is how they were made.
#
#   pwsh evaluation/benign_corpus/build.ps1
#
# Linked pictures, the custom template and the external workbook point at C:\tmp\fm-benign\, which
# this script creates (a neutral path, so no user name ends up in a file).
$ErrorActionPreference = "Stop"
$missing = [System.Reflection.Missing]::Value  # COM: omitted optional arguments
$out = Join-Path $PSScriptRoot "files"
$ext = "C:\tmp\fm-benign"
New-Item -ItemType Directory -Force $out, $ext | Out-Null
$soffice = "C:\Program Files\LibreOffice\program\soffice.com"
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$loProfile = "-env:UserInstallation=file:///C:/tmp/fm-benign/lo-profile"
$text = "The community garden committee met to review the spring planting plan. Volunteers will " +
        "prepare twelve raised beds, repair the tool shed and run two open days for local schools."

# --- assets: a small chart picture, an HTML page, a CSV, a source workbook --------------------------
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 480, 240
$g = [System.Drawing.Graphics]::FromImage($bmp); $g.Clear([System.Drawing.Color]::White)
$brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::SteelBlue)
foreach ($i in 0..5) { $h = 40 + 25 * $i; $g.FillRectangle($brush, 30 + 75 * $i, 220 - $h, 50, $h) }
$g.Dispose(); $bmp.Save("$ext\chart.png", [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
$html = @"
<!doctype html><html><head><meta charset="utf-8"><title>Garden plan</title></head><body>
<h1>Community garden plan</h1><p>$text</p>
<h2>Beds</h2><table border="1"><tr><th>Bed</th><th>Crop</th><th>Volunteers</th></tr>
<tr><td>1</td><td>Tomatoes</td><td>3</td></tr><tr><td>2</td><td>Beans</td><td>2</td></tr></table>
<p>More information: <a href="https://www.niu.edu/">NIU</a>.</p>
</body></html>
"@
Set-Content -Encoding utf8 "$ext\plan-noform.html" ($html -replace '(?s)<form>.*</form>', '')
"Bed,Crop,Volunteers,Hours`n" + ((1..20 | ForEach-Object { "$_,Crop $_,$($_ % 4 + 1),$($_ * 3)" }) -join "`n") |
    Set-Content -Encoding utf8 "$ext\beds.csv"

function Done($name) { "built $name" }
function Try-Build($name, [scriptblock]$body) {
    try { & $body; Done $name } catch { "FAILED $name : $($_.Exception.Message)" }
}

# --- Excel -------------------------------------------------------------------------------------------
$xl = New-Object -ComObject Excel.Application; $xl.Visible = $false; $xl.DisplayAlerts = $false
function New-Book { $b = $xl.Workbooks.Add(); $b.RemovePersonalInformation = $true; $b }
function Fill($sheet) {
    $sheet.Range("A1:C1").Value2 = @("Bed", "Crop", "Volunteers")
    foreach ($r in 2..11) { $sheet.Cells($r, 1).Value2 = $r - 1; $sheet.Cells($r, 2).Value2 = "Crop $($r - 1)"; $sheet.Cells($r, 3).Value2 = ($r % 4) + 1 }
    $sheet.Range("C12").Formula = "=SUM(C2:C11)"
}
Try-Build "source workbook (external link target)" {
    $b = New-Book; Fill $b.Worksheets(1); $b.Worksheets(1).Name = "Data"; $b.SaveAs("$ext\source.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-01-excel-formulas" {
    $b = New-Book; Fill $b.Worksheets(1); $b.SaveAs("$out\xlsx-01-excel-formulas.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-02-excel-chart-formatting" {
    $b = New-Book; $s = $b.Worksheets(1); Fill $s
    $chart = $s.Shapes.AddChart2(201, 51); $chart.Chart.SetSourceData($s.Range("B1:C11"))
    $s.Range("C2:C11").FormatConditions.AddDatabar() | Out-Null
    $notes = $b.Worksheets.Add(); $notes.Name = "Notes"; $notes.Range("A1").Value2 = [string]$text
    $b.SaveAs("$out\xlsx-02-excel-chart-formatting.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-03-excel-hyperlinks-validation" {
    $b = New-Book; $s = $b.Worksheets(1); Fill $s
    $s.Hyperlinks.Add($s.Range("E1"), "https://www.niu.edu/", "", "", "NIU website") | Out-Null
    $s.Range("D2:D11").Validation.Add(3, 1, 1, "Yes,No")
    $b.SaveAs("$out\xlsx-03-excel-hyperlinks-validation.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-04-excel-external-workbook-link" {
    $b = New-Book; $s = $b.Worksheets(1); $s.Range("A1").Value2 = "Total from source"
    $s.Range("B1").Formula = "='C:\tmp\fm-benign\[source.xlsx]Data'!C12"
    $b.SaveAs("$out\xlsx-04-excel-external-workbook-link.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-05-excel-table-pivot" {
    $b = New-Book; $s = $b.Worksheets(1); $s.Name = "Data"; Fill $s; $s.Range("C12").ClearContents() | Out-Null
    $s.ListObjects.Add(1, $s.Range("A1:C11"), $null, 1) | Out-Null
    $p = $b.Worksheets.Add(); $p.Name = "Pivot"
    $b.PivotCaches().Create(1, "Data!R1C1:R11C3").CreatePivotTable("Pivot!R1C1", "Beds") | Out-Null
    $b.SaveAs("$out\xlsx-05-excel-table-pivot.xlsx", 51); $b.Close($false) }
Try-Build "xlsx-06-excel-picture-notes" {
    $b = New-Book; $s = $b.Worksheets(1); Fill $s
    $s.Shapes.AddPicture("$ext\chart.png", 0, -1, 250, 10, 240, 120) | Out-Null
    $s.Range("B2").AddComment("Check seed stock before ordering.") | Out-Null
    $b.SaveAs("$out\xlsx-06-excel-picture-notes.xlsx", 51); $b.Close($false) }
Try-Build "pdf-02-excel-export" {
    $b = $xl.Workbooks.Open("$out\xlsx-02-excel-chart-formatting.xlsx"); $b.ExportAsFixedFormat(0, "$out\pdf-02-excel-export.pdf"); $b.Close($false) }
$xl.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl)

# --- Word --------------------------------------------------------------------------------------------
$wd = New-Object -ComObject Word.Application; $wd.Visible = $false; $wd.DisplayAlerts = 0
function New-Doc($template) {
    $d = if ($template) { $wd.Documents.Add($template) } else { $wd.Documents.Add() }
    $d.RemovePersonalInformation = $true; $d
}
function Para($d, $t, $style) { $p = $d.Content.Paragraphs.Add(); $p.Range.Text = $t; if ($style) { $p.Range.Style = $d.Styles.Item([object][int]$style) }; $p.Range.InsertParagraphAfter() }
Try-Build "docx-01-word-plain" {
    $d = New-Doc; Para $d "Garden plan" -2; Para $d $text; Para $d "Next steps" -3; Para $d "Order seeds and compost."
    $d.Tables.Add($d.Paragraphs.Last.Range, 3, 3) | Out-Null
    $d.SaveAs2("$out\docx-01-word-plain.docx", 16); $d.Close(0) }
Try-Build "docx-02-word-rich" {
    # Insert at a collapsed range at the end: replacing the final paragraph mark is refused.
    function End { $e = $d.Content; $e.Collapse(0); $e }
    $d = New-Doc; Para $d "Garden report" -2; Para $d "Contents"
    $d.TablesOfContents.Add((End)) | Out-Null; (End).InsertParagraphAfter()
    Para $d "Summary" -3; Para $d $text
    $d.Sections(1).Headers(1).Range.Text = "Community garden committee"
    $d.Sections(1).Footers(1).Range.Text = "Draft for discussion"
    $r = $d.Paragraphs($d.Paragraphs.Count - 1).Range
    $d.Footnotes.Add($r) | Out-Null; $d.Comments.Add($r, "Confirm bed count.") | Out-Null
    $d.InlineShapes.AddPicture("$ext\chart.png", $false, $true, (End)) | Out-Null; (End).InsertParagraphAfter()
    $d.Hyperlinks.Add((End), "https://www.niu.edu/", $missing, $missing, "NIU website") | Out-Null
    $d.TrackRevisions = $true; (End).InsertAfter(" Added at the meeting."); $d.TrackRevisions = $false
    $d.TablesOfContents(1).Update()
    $d.SaveAs2("$out\docx-02-word-rich.docx", 16); $d.Close(0) }
Try-Build "docx-03-word-embedded-excel" {
    $d = New-Doc; Para $d "Volunteer table"; Para $d $text
    $d.InlineShapes.AddOLEObject($missing, "$out\xlsx-01-excel-formulas.xlsx", $false, $false, $missing, $missing, $missing, $d.Paragraphs.Last.Range) | Out-Null
    $d.SaveAs2("$out\docx-03-word-embedded-excel.docx", 16); $d.Close(0) }
Try-Build "docx-04-word-linked-picture" {
    $d = New-Doc; Para $d "Planting chart (linked picture)"; Para $d $text
    $d.InlineShapes.AddPicture("$ext\chart.png", $true, $false, $d.Paragraphs.Last.Range) | Out-Null
    $d.SaveAs2("$out\docx-04-word-linked-picture.docx", 16); $d.Close(0) }
Try-Build "docx-05-word-custom-template" {
    $t = New-Doc; Para $t "Committee template" -2; $t.SaveAs2("$ext\committee.dotx", 14); $t.Close(0)
    $d = New-Doc "$ext\committee.dotx"; Para $d $text
    $d.SaveAs2("$out\docx-05-word-custom-template.docx", 16); $d.Close(0) }
Try-Build "docx-06-word-content-controls" {
    $d = New-Doc; Para $d "Volunteer sign-up"; Para $d "Date: "
    $d.ContentControls.Add(6, $d.Paragraphs(2).Range) | Out-Null; Para $d "Role: "
    $c = $d.ContentControls.Add(4, $d.Paragraphs(3).Range); $c.DropdownListEntries.Add("Planting") | Out-Null; $c.DropdownListEntries.Add("Watering") | Out-Null
    $d.SaveAs2("$out\docx-06-word-content-controls.docx", 16); $d.Close(0) }
Try-Build "pdf-01-word-export" {
    $d = $wd.Documents.Open("$out\docx-02-word-rich.docx"); $d.ExportAsFixedFormat("$out\pdf-01-word-export.pdf", 17, $false, 0, 0, 0, 0, 0, $true, $true, 1)
    $d.Close(0) }
Try-Build "pdf-06-word-export-pdfa" {  # PDF/A-1 (UseISO19005_1)
    $d = $wd.Documents.Open("$out\docx-01-word-plain.docx")
    $d.ExportAsFixedFormat("$out\pdf-06-word-export-pdfa.pdf", 17, $false, 0, 0, 0, 0, 0, $true, $true, 1, $true, $true, $true)
    $d.Close(0) }
$wd.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wd)

# --- PowerPoint --------------------------------------------------------------------------------------
$pp = New-Object -ComObject PowerPoint.Application
function New-Deck { $p = $pp.Presentations.Add(0); $p.RemovePersonalInformation = -1; $p }
function Title($p, $i, $t, $body) {
    $s = $p.Slides.Add($i, $(if ($body) { 2 } else { 1 })); $s.Shapes(1).TextFrame.TextRange.Text = $t
    if ($body) { $s.Shapes(2).TextFrame.TextRange.Text = $body }; $s
}
Try-Build "pptx-01-ppt-plain" {
    $p = New-Deck; Title $p 1 "Garden plan" | Out-Null; Title $p 2 "Spring" "Twelve beds`rTool shed repair`rTwo open days" | Out-Null
    $p.SaveAs("$out\pptx-01-ppt-plain.pptx", 24); $p.Close() }
Try-Build "pptx-02-ppt-pictures-notes" {
    $p = New-Deck; $s = Title $p 1 "Planting chart"; $s.Shapes.AddPicture("$ext\chart.png", 0, -1, 100, 150, 480, 240) | Out-Null
    $s.NotesPage.Shapes.Placeholders(2).TextFrame.TextRange.Text = "Mention the school open days."
    $p.SaveAs("$out\pptx-02-ppt-pictures-notes.pptx", 24); $p.Close() }
Try-Build "pptx-03-ppt-chart-table" {
    # Charts need a document window (kept minimised).
    $p = $pp.Presentations.Add(-1); $p.Windows(1).WindowState = 2; $p.RemovePersonalInformation = -1
    $s = Title $p 1 "Volunteers"; $c = $s.Shapes.AddChart2(201, 51, 50, 120, 400, 300, $true).Chart
    # The deck's RemovePersonalInformation does not reach the chart's embedded workbook.
    $wb = $c.ChartData.Workbook; $wb.RemovePersonalInformation = $true; $wb.Close(); $s.Shapes.AddTable(3, 3, 480, 120, 300, 120) | Out-Null
    $p.SaveAs("$out\pptx-03-ppt-chart-table.pptx", 24); $p.Close() }
Try-Build "pptx-04-ppt-hyperlinks-actions" {
    $p = New-Deck; $s = Title $p 1 "Links" "NIU website`rBack to start"
    $r = $s.Shapes(2).TextFrame.TextRange
    $r.Paragraphs(1).ActionSettings(1).Hyperlink.Address = "https://www.niu.edu/"
    Title $p 2 "Second slide" | Out-Null; $p.Slides(2).Shapes(1).ActionSettings(1).Action = 3
    $p.SaveAs("$out\pptx-04-ppt-hyperlinks-actions.pptx", 24); $p.Close() }
Try-Build "pptx-05-ppt-transitions-animations" {
    $p = New-Deck; foreach ($i in 1..3) { $s = Title $p $i "Step $i" "Detail for step $i"
        $s.SlideShowTransition.EntryEffect = 3844; $s.TimeLine.MainSequence.AddEffect($s.Shapes(2), 10) | Out-Null }
    $p.SaveAs("$out\pptx-05-ppt-transitions-animations.pptx", 24); $p.Close() }
Try-Build "pptx-06-ppt-embedded-excel" {
    $p = New-Deck; $s = Title $p 1 "Volunteer table"
    $s.Shapes.AddOLEObject(80, 140, 500, 250, "", "$out\xlsx-01-excel-formulas.xlsx", 0, "", 0, "", 0) | Out-Null
    $p.SaveAs("$out\pptx-06-ppt-embedded-excel.pptx", 24); $p.Close() }
Try-Build "pdf-03-powerpoint-export" {
    $p = $pp.Presentations.Open("$out\pptx-02-ppt-pictures-notes.pptx", -1, 0, 0); $p.SaveAs("$out\pdf-03-powerpoint-export.pdf", 32); $p.Close() }
$pp.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($pp)

# --- LibreOffice and Edge ----------------------------------------------------------------------------
function LO($in, $filter, $infilter, $name) {
    $tmp = Join-Path $ext "lo-out"; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    $a = @($loProfile, "--headless", "--convert-to", $filter, "--outdir", $tmp); if ($infilter) { $a += "--infilter=$infilter" }
    & $soffice @a $in | Out-Null
    $made = Get-ChildItem $tmp | Select-Object -First 1
    if (-not $made) { throw "LibreOffice produced nothing" }
    Move-Item -Force $made.FullName (Join-Path $out $name)
}
$pdf = 'pdf:writer_pdf_Export:{0}'
Try-Build "pdf-04-libreoffice-tagged" { LO "$ext\plan-noform.html" ($pdf -f '{"UseTaggedPDF":{"type":"boolean","value":"true"}}') "HTML (StarWriter)" "pdf-04-libreoffice-tagged.pdf" }
Try-Build "pdf-05-libreoffice-pdfa" { LO "$ext\plan-noform.html" ($pdf -f '{"SelectPdfVersion":{"type":"long","value":"2"}}') "HTML (StarWriter)" "pdf-05-libreoffice-pdfa.pdf" }
Try-Build "pdf-07-libreoffice-hybrid" { LO "$ext\plan-noform.html" ($pdf -f '{"IsAddStream":{"type":"boolean","value":"true"}}') "HTML (StarWriter)" "pdf-07-libreoffice-hybrid.pdf" }
Try-Build "docx-07-libreoffice" { LO "$ext\plan-noform.html" 'docx:MS Word 2007 XML' "HTML (StarWriter)" "docx-07-libreoffice.docx" }
Try-Build "xlsx-07-libreoffice" { LO "$ext\beds.csv" 'xlsx:Calc MS Excel 2007 XML' "CSV:44,34,76,1" "xlsx-07-libreoffice.xlsx" }
Try-Build "pptx-07-libreoffice-roundtrip" { LO "$out\pptx-02-ppt-pictures-notes.pptx" 'pptx:Impress MS PowerPoint 2007 XML' $null "pptx-07-libreoffice-roundtrip.pptx" }
Try-Build "pdf-08-edge-print" {
    & $edge --headless --disable-gpu --no-pdf-header-footer "--user-data-dir=$ext\edge-profile" "--print-to-pdf=$out\pdf-08-edge-print.pdf" "file:///$($ext -replace '\\','/')/plan-noform.html" 2>$null | Out-Null
    Start-Sleep 3; if (-not (Test-Path "$out\pdf-08-edge-print.pdf")) { throw "Edge produced nothing" } }
