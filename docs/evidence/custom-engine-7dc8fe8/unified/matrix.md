| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | SAFE | 586.88 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | SUSPICIOUS | 586.0 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | SUSPICIOUS | 587.53 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS | 584.39 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | 590.69 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | 583.92 |
| 5a-pdf-auto-js-unrelated-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS | 587.97 |
| 5b-pdf-auto-js-exports-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | MALICIOUS | 587.66 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | SAFE | 586.12 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | SUSPICIOUS | 585.89 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | SUSPICIOUS | 584.94 |
