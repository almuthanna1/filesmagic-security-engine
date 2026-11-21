| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | pdf-integrity | vba-chains | ooxml-links | word-fields | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | SAFE | n/a | n/a | n/a | SAFE | 664.35 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | SAFE | n/a | n/a | n/a | SUSPICIOUS | 678.58 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | SAFE | n/a | n/a | n/a | SUSPICIOUS | 697.18 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | SAFE | n/a | n/a | n/a | SUSPICIOUS | 704.8 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | SAFE | n/a | n/a | n/a | SUSPICIOUS | 722.86 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | SAFE | n/a | n/a | n/a | SUSPICIOUS | 647.85 |
| 5a-pdf-auto-js-unrelated-attachment | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | SAFE | n/a | n/a | n/a | SUSPICIOUS | 639.26 |
| 5b-pdf-auto-js-exports-attachment | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | SAFE | n/a | n/a | n/a | MALICIOUS | 717.22 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SAFE | 712.16 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SUSPICIOUS | 619.38 |
| 6c-docx-template-referenced-by-settings | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | 633.0 |
| 6d-docx-linked-picture | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SAFE | 631.4 |
| 6g-docx-linked-picture-file-share | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SUSPICIOUS | 623.5 |
| 6e-docx-embedded-object-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SUSPICIOUS | 627.83 |
| 6f-docx-embedded-object-not-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | n/a | SAFE | SAFE | SUSPICIOUS | 626.85 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | n/a | SAFE | SAFE | SAFE | SUSPICIOUS | 673.55 |
