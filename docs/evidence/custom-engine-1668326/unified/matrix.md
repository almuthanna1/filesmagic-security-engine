| case | yara-x | office | pdf | custom | yara-x-engine | pdf-chains | vba-chains | ooxml-links | aggregate | wall p50 ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | n/a | SAFE | SAFE | SAFE | SAFE | n/a | n/a | SAFE | 568.92 |
| 2-pdf-form-keystroke-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 576.03 |
| 2b-pdf-open-at-page-click-js | SAFE | n/a | SUSPICIOUS | SAFE | SAFE | SAFE | n/a | n/a | SUSPICIOUS | 572.19 |
| 2c-pdf-open-at-page-page-open-js | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 572.9 |
| 3-pdf-escaped-openaction-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 566.62 |
| 4-pdf-objstm-escaped-js | SAFE | n/a | SUSPICIOUS | SUSPICIOUS | SAFE | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 570.06 |
| 5a-pdf-auto-js-unrelated-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS | n/a | n/a | SUSPICIOUS | 608.62 |
| 5b-pdf-auto-js-exports-attachment | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | MALICIOUS | n/a | n/a | MALICIOUS | 578.14 |
| 6a-docx-hyperlink | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | SAFE | 576.67 |
| 6b-docx-external-template | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 604.76 |
| 6c-docx-template-referenced-by-settings | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SUSPICIOUS | SUSPICIOUS | 561.14 |
| 6d-docx-linked-picture | SAFE | SAFE | n/a | SAFE | SAFE | n/a | n/a | SAFE | SAFE | 554.34 |
| 6g-docx-linked-picture-file-share | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 553.56 |
| 6e-docx-embedded-object-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 553.93 |
| 6f-docx-embedded-object-not-displayed | SAFE | SUSPICIOUS | n/a | SAFE | SAFE | n/a | n/a | SAFE | SUSPICIOUS | 555.28 |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | SUSPICIOUS | n/a | SUSPICIOUS | SAFE | n/a | SAFE | SAFE | SUSPICIOUS | 551.46 |
