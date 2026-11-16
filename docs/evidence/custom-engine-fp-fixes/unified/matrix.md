| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | vba-chains | ooxml-links | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | n/a | n/a | SAFE | 546.97 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 546.45 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 546.12 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 545.5 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 544.57 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 545.45 |
| 5a-pdf-auto-js-unrelated-attachment | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 544.76 |
| 5b-pdf-auto-js-exports-attachment | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | n/a | n/a | MALICIOUS | 567.77 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | SAFE | 632.96 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 640.87 |
| 6c-docx-template-referenced-by-settings | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SUSPICIOUS | SUSPICIOUS | 571.77 |
| 6d-docx-linked-picture | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | SAFE | 553.83 |
| 6g-docx-linked-picture-file-share | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 552.34 |
| 6e-docx-embedded-object-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 556.01 |
| 6f-docx-embedded-object-not-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 556.27 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | SAFE | SAFE | SUSPICIOUS | 554.22 |
