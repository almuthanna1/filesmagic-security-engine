| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | vba-chains | ooxml-links | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | n/a | n/a | SAFE | 592.05 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 599.38 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 597.22 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 594.08 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 593.93 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 591.2 |
| 5a-pdf-auto-js-unrelated-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 596.17 |
| 5b-pdf-auto-js-exports-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | n/a | n/a | MALICIOUS | 593.98 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | SAFE | 594.29 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 598.57 |
| 6c-docx-template-referenced-by-settings | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SUSPICIOUS | SUSPICIOUS | 596.14 |
| 6d-docx-linked-picture | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SUSPICIOUS | SUSPICIOUS | 595.65 |
| 6e-docx-embedded-object-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 605.66 |
| 6f-docx-embedded-object-not-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 599.77 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | SAFE | SAFE | SUSPICIOUS | 597.58 |
