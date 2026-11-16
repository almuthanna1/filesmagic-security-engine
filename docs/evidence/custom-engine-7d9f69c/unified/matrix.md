| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | vba-chains | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | n/a | SAFE | 589.47 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | SUSPICIOUS | 588.28 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | SUSPICIOUS | 589.78 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | 586.68 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | SUSPICIOUS | 583.41 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | SUSPICIOUS | 590.41 |
| 5a-pdf-auto-js-unrelated-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | 588.52 |
| 5b-pdf-auto-js-exports-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | n/a | MALICIOUS | 588.57 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | 588.25 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 587.7 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | SAFE | SUSPICIOUS | 590.38 |
