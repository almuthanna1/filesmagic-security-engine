# Offline VM validation

- Status: **completed**
- Commit `15126e8d25b8c3f433fa331bc546a7dff9443e97`, clean tree: True; engine 0.2.0; rules `0be9918509e95e639f866291dc297c45c8e72812d602fb149fad3484435ae3b0`, engine rules `988d991efb218328c97e8c00500ed6b434a33ee8e961548e817e159cc9f35b4e`
- Linux-7.0.0-38-generic-x86_64-with-glibc2.39, Python 3.11.18; confinement `filesmagic-eval-python (enforce)`; strict isolation True; host network {'checked': True, 'offline': True, 'usable_routes_v4': 0, 'usable_routes_v6': 0}; drift []
- Trials: synthetic 20, corpus and corrupt 5

## Contributions

| Claim | Result |
|---|---|
| 5a: unified SUSPICIOUS (the attachment is not on the automatic chain); reference MALICIOUS | PASS |
| 5b: unified MALICIOUS with ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT | PASS |
| refined YARA-X rule fires on every automatic page-open/OpenAction script case (2c, 5a, 5b) | PASS |
| refined YARA-X rule is silent on the user-triggered cases (2, 2b), which the reference rule flags | PASS |
| VBA call graph: case 7 reports ENGINE_VBA_CALL_PATH_UNDETERMINED and keeps the reference macro findings | PASS |
| OOXML correlation: 6c template used on open -> ENGINE_OFFICE_EXTERNAL_ON_OPEN; 6g file share keeps OFFICE_EXTERNAL_NETWORK_PATH; 6e/6f object displayed / not displayed | PASS |
| false-positive corrections: docx-04, xlsx-04 (local targets) and pdf-07 (verified attachment) SAFE in unified, SUSPICIOUS in reference | PASS |
| docx-05 local template lowered to LOW but not cleared (SUSPICIOUS) | PASS |
| C7 positives: c7a nested DDEAUTO MALICIOUS, c7c remote INCLUDETEXT and c7d file-share INCLUDEPICTURE SUSPICIOUS (reference SAFE on all three), each with its C7 rule; c7b keeps OFFICE_DDEAUTO_FIELD | PASS |
| C7 negatives: c7e DDEAUTO only in a tracked deletion and c7f ordinary fields SAFE in both engines, C7 evidence INFO only | PASS |
| corrupted documents fail closed (UNABLE_TO_SCAN) in both engines | PASS |

## Against the expected results

Windows evidence: 102 of 102 scan results identical (verdict and every finding, INFO included).
C7 cases: 12 of 12 verdicts as expected (evaluation.cases.field_cases; the rules are checked in Contributions).


## Results

| Set | File | Engine | Verdict | Failed scanners | Wall p50 ms | Scanner p50 ms |
|---|---|---|---|---|---|---|
| synthetic | 1-pdf-clean | reference | SAFE | - | 347.77 | yara-x 0.64, pdf 0.59, custom 0.08 |
| synthetic | 1-pdf-clean | unified | SAFE | - | 476.92 | yara-x 0.67, pdf 0.97, custom 0.09, yara-x-engine 0.47, pdf-chains 0.62 |
| synthetic | 2-pdf-form-keystroke-js | reference | SUSPICIOUS | - | 412.09 | yara-x 0.85, pdf 0.83, custom 0.1 |
| synthetic | 2-pdf-form-keystroke-js | unified | SUSPICIOUS | - | 548.19 | yara-x 1.16, pdf 1.92, custom 0.13, yara-x-engine 0.56, pdf-chains 1.08 |
| synthetic | 2b-pdf-open-at-page-click-js | reference | SUSPICIOUS | - | 411.72 | yara-x 0.63, pdf 0.85, custom 0.1 |
| synthetic | 2b-pdf-open-at-page-click-js | unified | SUSPICIOUS | - | 377.67 | yara-x 0.7, pdf 1.17, custom 0.1, yara-x-engine 0.46, pdf-chains 0.96 |
| synthetic | 2c-pdf-open-at-page-page-open-js | reference | SUSPICIOUS | - | 316.64 | yara-x 0.55, pdf 0.76, custom 0.09 |
| synthetic | 2c-pdf-open-at-page-page-open-js | unified | SUSPICIOUS | - | 321.4 | yara-x 0.56, pdf 0.83, custom 0.09, yara-x-engine 0.45, pdf-chains 0.67 |
| synthetic | 3-pdf-escaped-openaction-js | reference | SUSPICIOUS | - | 290.69 | yara-x 0.61, pdf 0.64, custom 0.2 |
| synthetic | 3-pdf-escaped-openaction-js | unified | SUSPICIOUS | - | 346.49 | yara-x 0.5, pdf 0.83, custom 0.19, yara-x-engine 0.39, pdf-chains 0.65 |
| synthetic | 4-pdf-objstm-escaped-js | reference | SUSPICIOUS | - | 280.31 | yara-x 0.46, pdf 0.84, custom 0.22 |
| synthetic | 4-pdf-objstm-escaped-js | unified | SUSPICIOUS | - | 307.61 | yara-x 0.47, pdf 0.96, custom 0.24, yara-x-engine 0.31, pdf-chains 0.65 |
| synthetic | 5a-pdf-auto-js-unrelated-attachment | reference | MALICIOUS | - | 288.57 | yara-x 0.51, pdf 0.97, custom 0.13 |
| synthetic | 5a-pdf-auto-js-unrelated-attachment | unified | SUSPICIOUS | - | 377.06 | yara-x 0.52, pdf 1.15, custom 0.14, yara-x-engine 0.54, pdf-chains 0.95 |
| synthetic | 5b-pdf-auto-js-exports-attachment | reference | MALICIOUS | - | 368.46 | yara-x 0.91, pdf 1.24, custom 0.17 |
| synthetic | 5b-pdf-auto-js-exports-attachment | unified | MALICIOUS | - | 412.23 | yara-x 0.75, pdf 1.45, custom 0.13, yara-x-engine 0.57, pdf-chains 1.08 |
| synthetic | 6a-docx-hyperlink | reference | SAFE | - | 329.35 | yara-x 0.41, office 2.35, custom 0.75 |
| synthetic | 6a-docx-hyperlink | unified | SAFE | - | 490.07 | yara-x 0.87, office 3.26, custom 1.32, yara-x-engine 0.55, ooxml-links 0.95, word-fields 0.45 |
| synthetic | 6b-docx-external-template | reference | SUSPICIOUS | - | 443.29 | yara-x 0.61, office 3.53, custom 1.15 |
| synthetic | 6b-docx-external-template | unified | SUSPICIOUS | - | 502.44 | yara-x 0.41, office 2.31, custom 0.75, yara-x-engine 0.34, ooxml-links 1.11, word-fields 0.61 |
| synthetic | 6c-docx-template-referenced-by-settings | reference | SUSPICIOUS | - | 397.15 | yara-x 0.77, office 3.91, custom 1.74 |
| synthetic | 6c-docx-template-referenced-by-settings | unified | SUSPICIOUS | - | 473.33 | yara-x 0.73, office 3.05, custom 0.96, yara-x-engine 0.46, ooxml-links 1.01, word-fields 0.74 |
| synthetic | 6d-docx-linked-picture | reference | SAFE | - | 570.57 | yara-x 0.98, office 4.92, custom 1.66 |
| synthetic | 6d-docx-linked-picture | unified | SAFE | - | 359.17 | yara-x 0.43, office 2.45, custom 0.76, yara-x-engine 0.48, ooxml-links 0.77, word-fields 0.41 |
| synthetic | 6g-docx-linked-picture-file-share | reference | SUSPICIOUS | - | 344.66 | yara-x 0.46, office 2.32, custom 0.91 |
| synthetic | 6g-docx-linked-picture-file-share | unified | SUSPICIOUS | - | 368.45 | yara-x 0.43, office 2.48, custom 0.76, yara-x-engine 0.36, ooxml-links 0.78, word-fields 0.48 |
| synthetic | 6e-docx-embedded-object-displayed | reference | SUSPICIOUS | - | 269.9 | yara-x 0.41, office 2.58, custom 0.91 |
| synthetic | 6e-docx-embedded-object-displayed | unified | SUSPICIOUS | - | 316.82 | yara-x 0.43, office 2.54, custom 0.67, yara-x-engine 0.39, ooxml-links 0.75, word-fields 0.41 |
| synthetic | 6f-docx-embedded-object-not-displayed | reference | SUSPICIOUS | - | 1579.12 | yara-x 1.37, office 13.49, custom 5.16 |
| synthetic | 6f-docx-embedded-object-not-displayed | unified | SUSPICIOUS | - | 324.27 | yara-x 0.44, office 2.58, custom 0.7, yara-x-engine 0.38, ooxml-links 0.69, word-fields 0.38 |
| synthetic | 7-docx-macro-declaration-mismatch | reference | SUSPICIOUS | - | 308.95 | yara-x 0.59, office 2.2, custom 0.87 |
| synthetic | 7-docx-macro-declaration-mismatch | unified | SUSPICIOUS | - | 367.49 | yara-x 0.48, office 2.21, custom 0.91, yara-x-engine 0.38, vba-chains 0.19, ooxml-links 0.63, word-fields 0.53 |
| corpus | docx-01-word-plain.docx | reference | SAFE | - | 290.36 | yara-x 0.71, office 3.06, custom 2.02 |
| corpus | docx-01-word-plain.docx | unified | SAFE | - | 385.68 | yara-x 0.49, office 2.43, custom 1.89, yara-x-engine 0.36, ooxml-links 0.7, word-fields 4.93 |
| corpus | docx-02-word-rich.docx | reference | SAFE | - | 368.16 | yara-x 0.57, office 4.25, custom 3.1 |
| corpus | docx-02-word-rich.docx | unified | SAFE | - | 392.13 | yara-x 0.35, office 4.23, custom 3.33, yara-x-engine 0.56, ooxml-links 1.78, word-fields 7.22 |
| corpus | docx-03-word-embedded-excel.docx | reference | SAFE | - | 339.82 | yara-x 0.55, office 2.77, custom 2.52 |
| corpus | docx-03-word-embedded-excel.docx | unified | SAFE | - | 343.54 | yara-x 0.44, office 2.37, custom 1.82, yara-x-engine 0.39, ooxml-links 1.26, word-fields 4.38 |
| corpus | docx-04-word-linked-picture.docx | reference | SUSPICIOUS | - | 282.08 | yara-x 0.49, office 2.57, custom 1.88 |
| corpus | docx-04-word-linked-picture.docx | unified | SAFE | - | 439.17 | yara-x 1.05, office 2.96, custom 2.97, yara-x-engine 1.02, ooxml-links 4.07, word-fields 14.79 |
| corpus | docx-05-word-custom-template.docx | reference | SUSPICIOUS | - | 383.08 | yara-x 1.17, office 2.7, custom 3.95 |
| corpus | docx-05-word-custom-template.docx | unified | SUSPICIOUS | - | 346.92 | yara-x 0.54, office 2.14, custom 1.58, yara-x-engine 0.4, ooxml-links 1.14, word-fields 3.9 |
| corpus | docx-06-word-content-controls.docx | reference | SAFE | - | 332.75 | yara-x 0.38, office 2.63, custom 3.02 |
| corpus | docx-06-word-content-controls.docx | unified | SAFE | - | 380.9 | yara-x 0.4, office 2.52, custom 2.71, yara-x-engine 0.49, ooxml-links 1.24, word-fields 6.81 |
| corpus | docx-07-libreoffice.docx | reference | SAFE | - | 272.49 | yara-x 0.42, office 1.28, custom 0.96 |
| corpus | docx-07-libreoffice.docx | unified | SAFE | - | 315.9 | yara-x 0.43, office 1.4, custom 1.13, yara-x-engine 0.3, ooxml-links 1.71, word-fields 2.12 |
| corpus | pdf-01-word-export.pdf | reference | SAFE | - | 257.28 | yara-x 0.4, pdf 1.77, custom 1.41 |
| corpus | pdf-01-word-export.pdf | unified | SAFE | - | 337.35 | yara-x 0.46, pdf 2.17, custom 1.5, yara-x-engine 0.36, pdf-chains 4.63 |
| corpus | pdf-02-excel-export.pdf | reference | SAFE | - | 295.23 | yara-x 0.69, pdf 1.78, custom 1.51 |
| corpus | pdf-02-excel-export.pdf | unified | SAFE | - | 346.11 | yara-x 0.49, pdf 1.97, custom 1.62, yara-x-engine 0.36, pdf-chains 8.63 |
| corpus | pdf-03-powerpoint-export.pdf | reference | SAFE | - | 264.96 | yara-x 0.42, pdf 1.23, custom 0.78 |
| corpus | pdf-03-powerpoint-export.pdf | unified | SAFE | - | 308.09 | yara-x 0.31, pdf 1.23, custom 0.77, yara-x-engine 0.32, pdf-chains 2.55 |
| corpus | pdf-04-libreoffice-tagged.pdf | reference | SAFE | - | 282.59 | yara-x 0.73, pdf 1.48, custom 1.62 |
| corpus | pdf-04-libreoffice-tagged.pdf | unified | SAFE | - | 1767.88 | yara-x 1.46, pdf 8.24, custom 7.4, yara-x-engine 2.66, pdf-chains 33.87 |
| corpus | pdf-05-libreoffice-pdfa.pdf | reference | SAFE | - | 264.88 | yara-x 0.54, pdf 1.7, custom 2.16 |
| corpus | pdf-05-libreoffice-pdfa.pdf | unified | SAFE | - | 317.29 | yara-x 0.41, pdf 1.65, custom 2.13, yara-x-engine 0.34, pdf-chains 4.94 |
| corpus | pdf-06-word-export-pdfa.pdf | reference | SAFE | - | 258.77 | yara-x 0.43, pdf 1.21, custom 1.45 |
| corpus | pdf-06-word-export-pdfa.pdf | unified | SAFE | - | 366.8 | yara-x 0.52, pdf 1.4, custom 1.69, yara-x-engine 0.5, pdf-chains 4.6 |
| corpus | pdf-07-libreoffice-hybrid.pdf | reference | SUSPICIOUS | - | 339.89 | yara-x 0.69, pdf 1.93, custom 2.66 |
| corpus | pdf-07-libreoffice-hybrid.pdf | unified | SAFE | - | 1900.16 | yara-x 2.48, pdf 14.04, custom 13.7, yara-x-engine 2.58, pdf-chains 45.11 |
| corpus | pdf-08-edge-print.pdf | reference | SAFE | - | 1823.98 | yara-x 2.59, pdf 10.17, custom 13.15 |
| corpus | pdf-08-edge-print.pdf | unified | SAFE | - | 3123.07 | yara-x 2.8, pdf 13.11, custom 15.77, yara-x-engine 4.06, pdf-chains 50.94 |
| corpus | pptx-01-ppt-plain.pptx | reference | SAFE | - | 275.93 | yara-x 0.47, office 2.96, custom 3.56 |
| corpus | pptx-01-ppt-plain.pptx | unified | SAFE | - | 319.91 | yara-x 0.41, office 3.38, custom 3.54, yara-x-engine 0.4, ooxml-links 2.32 |
| corpus | pptx-02-ppt-pictures-notes.pptx | reference | SAFE | - | 287.9 | yara-x 0.53, office 3.15, custom 3.99 |
| corpus | pptx-02-ppt-pictures-notes.pptx | unified | SAFE | - | 310.69 | yara-x 0.46, office 3.23, custom 3.62, yara-x-engine 0.46, ooxml-links 2.47 |
| corpus | pptx-03-ppt-chart-table.pptx | reference | SAFE | - | 274.23 | yara-x 0.41, office 2.76, custom 3.49 |
| corpus | pptx-03-ppt-chart-table.pptx | unified | SAFE | - | 402.17 | yara-x 0.6, office 4.25, custom 4.96, yara-x-engine 0.41, ooxml-links 4.36 |
| corpus | pptx-04-ppt-hyperlinks-actions.pptx | reference | SAFE | - | 315.51 | yara-x 0.48, office 3.32, custom 4.04 |
| corpus | pptx-04-ppt-hyperlinks-actions.pptx | unified | SAFE | - | 2182.97 | yara-x 1.29, office 17.86, custom 20.89, yara-x-engine 1.81, ooxml-links 15.11 |
| corpus | pptx-05-ppt-transitions-animations.pptx | reference | SAFE | - | 285.24 | yara-x 0.57, office 3.52, custom 4.36 |
| corpus | pptx-05-ppt-transitions-animations.pptx | unified | SAFE | - | 318.76 | yara-x 0.44, office 3.61, custom 4.54, yara-x-engine 0.39, ooxml-links 3.31 |
| corpus | pptx-06-ppt-embedded-excel.pptx | reference | SAFE | - | 349.43 | yara-x 0.52, office 3.66, custom 4.02 |
| corpus | pptx-06-ppt-embedded-excel.pptx | unified | SAFE | - | 322.44 | yara-x 0.46, office 2.73, custom 3.79, yara-x-engine 0.39, ooxml-links 2.65 |
| corpus | pptx-07-libreoffice-roundtrip.pptx | reference | SAFE | - | 278.25 | yara-x 0.44, office 2.02, custom 4.32 |
| corpus | pptx-07-libreoffice-roundtrip.pptx | unified | SAFE | - | 313.38 | yara-x 0.46, office 1.88, custom 4.76, yara-x-engine 0.37, ooxml-links 2.86 |
| corpus | xlsx-01-excel-formulas.xlsx | reference | SAFE | - | 266.07 | yara-x 0.37, office 1.71, custom 1.16 |
| corpus | xlsx-01-excel-formulas.xlsx | unified | SAFE | - | 378.37 | yara-x 0.53, office 2.06, custom 1.21, yara-x-engine 0.45, ooxml-links 0.64 |
| corpus | xlsx-02-excel-chart-formatting.xlsx | reference | SAFE | - | 329.5 | yara-x 0.48, office 2.5, custom 2.72 |
| corpus | xlsx-02-excel-chart-formatting.xlsx | unified | SAFE | - | 391.54 | yara-x 0.37, office 2.86, custom 1.83, yara-x-engine 0.45, ooxml-links 1.25 |
| corpus | xlsx-03-excel-hyperlinks-validation.xlsx | reference | SAFE | - | 313.53 | yara-x 0.52, office 2.29, custom 1.99 |
| corpus | xlsx-03-excel-hyperlinks-validation.xlsx | unified | SAFE | - | 294.44 | yara-x 0.43, office 2.25, custom 1.0, yara-x-engine 0.36, ooxml-links 0.96 |
| corpus | xlsx-04-excel-external-workbook-link.xlsx | reference | SUSPICIOUS | - | 264.52 | yara-x 0.72, office 2.38, custom 1.14 |
| corpus | xlsx-04-excel-external-workbook-link.xlsx | unified | SAFE | - | 313.43 | yara-x 0.39, office 2.24, custom 1.03, yara-x-engine 0.35, ooxml-links 0.94 |
| corpus | xlsx-05-excel-table-pivot.xlsx | reference | SAFE | - | 269.28 | yara-x 0.44, office 2.38, custom 1.68 |
| corpus | xlsx-05-excel-table-pivot.xlsx | unified | SAFE | - | 295.38 | yara-x 0.39, office 2.03, custom 1.37, yara-x-engine 0.58, ooxml-links 1.07 |
| corpus | xlsx-06-excel-picture-notes.xlsx | reference | SAFE | - | 269.5 | yara-x 0.42, office 1.88, custom 1.64 |
| corpus | xlsx-06-excel-picture-notes.xlsx | unified | SAFE | - | 304.01 | yara-x 0.36, office 2.12, custom 1.23, yara-x-engine 0.38, ooxml-links 0.83 |
| corpus | xlsx-07-libreoffice.xlsx | reference | SAFE | - | 290.36 | yara-x 0.56, office 0.66, custom 0.96 |
| corpus | xlsx-07-libreoffice.xlsx | unified | SAFE | - | 374.55 | yara-x 0.47, office 0.74, custom 1.81, yara-x-engine 0.42, ooxml-links 0.89 |
| corpus | fw9.pdf | reference | MALICIOUS | - | 363.9 | yara-x 0.56, pdf 32.03, custom 8.56 |
| corpus | fw9.pdf | unified | SUSPICIOUS | - | 422.79 | yara-x 0.53, pdf 20.71, custom 8.56, yara-x-engine 0.51, pdf-chains 21.79 |
| corpus | fw4.pdf | reference | MALICIOUS | - | 318.42 | yara-x 0.49, pdf 37.38, custom 12.87 |
| corpus | fw4.pdf | unified | SUSPICIOUS | - | 374.27 | yara-x 0.61, pdf 26.45, custom 12.72, yara-x-engine 0.45, pdf-chains 26.9 |
| corpus | f1040.pdf | reference | MALICIOUS | - | 431.36 | yara-x 0.8, pdf 59.48, custom 16.2 |
| corpus | f1040.pdf | unified | SUSPICIOUS | - | 443.58 | yara-x 0.71, pdf 45.16, custom 13.97, yara-x-engine 0.61, pdf-chains 44.03 |
| corpus | NST-EST2023-POP.xlsx | reference | SAFE | - | 286.03 | yara-x 0.58, office 2.01, custom 1.35 |
| corpus | NST-EST2023-POP.xlsx | unified | SAFE | - | 313.82 | yara-x 0.6, office 1.89, custom 1.69, yara-x-engine 0.36, ooxml-links 0.84 |
| corrupt | corrupt-truncated-pdf | reference | UNABLE_TO_SCAN | pdf, custom | 286.52 | yara-x 0.39, pdf 0.27, custom 0.03 |
| corrupt | corrupt-truncated-pdf | unified | UNABLE_TO_SCAN | pdf, custom, pdf-chains | 330.52 | yara-x 0.57, pdf 0.35, custom 0.03, yara-x-engine 0.32, pdf-chains 0.13 |
| corrupt | corrupt-truncated-docx | reference | UNABLE_TO_SCAN | office, custom | 944.98 | yara-x 1.0, office 0.61, custom 0.05 |
| corrupt | corrupt-truncated-docx | unified | UNABLE_TO_SCAN | office, custom, vba-chains, ooxml-links, word-fields | 306.41 | yara-x 0.56, office 0.15, custom 0.03, yara-x-engine 0.3, vba-chains 0.03, ooxml-links 0.02, word-fields 0.01 |
| c7 | c7a-docx-nested-ddeauto | reference | SAFE | - | 330.91 | yara-x 0.53, office 2.35, custom 0.74 |
| c7 | c7a-docx-nested-ddeauto | unified | MALICIOUS | - | 302.16 | yara-x 0.43, office 2.0, custom 0.51, yara-x-engine 0.3, ooxml-links 0.6, word-fields 0.58 |
| c7 | c7b-docx-ddeauto-cmd | reference | MALICIOUS | - | 268.15 | yara-x 0.51, office 1.99, custom 0.49 |
| c7 | c7b-docx-ddeauto-cmd | unified | MALICIOUS | - | 322.81 | yara-x 0.45, office 1.78, custom 0.59, yara-x-engine 0.32, ooxml-links 0.48, word-fields 0.44 |
| c7 | c7c-docx-remote-includetext | reference | SAFE | - | 302.82 | yara-x 0.49, office 2.3, custom 0.68 |
| c7 | c7c-docx-remote-includetext | unified | SUSPICIOUS | - | 347.62 | yara-x 0.42, office 2.12, custom 0.65, yara-x-engine 0.38, ooxml-links 0.62, word-fields 0.5 |
| c7 | c7d-docx-remote-includepicture | reference | SAFE | - | 316.34 | yara-x 0.43, office 2.43, custom 0.62 |
| c7 | c7d-docx-remote-includepicture | unified | SUSPICIOUS | - | 308.55 | yara-x 0.39, office 1.9, custom 0.74, yara-x-engine 0.35, ooxml-links 0.49, word-fields 0.43 |
| c7 | c7e-docx-deleted-ddeauto | reference | SAFE | - | 273.92 | yara-x 0.48, office 1.97, custom 0.49 |
| c7 | c7e-docx-deleted-ddeauto | unified | SAFE | - | 323.0 | yara-x 0.5, office 2.12, custom 0.55, yara-x-engine 0.37, ooxml-links 0.84, word-fields 0.53 |
| c7 | c7f-docx-ordinary-fields | reference | SAFE | - | 334.08 | yara-x 0.45, office 2.3, custom 0.68 |
| c7 | c7f-docx-ordinary-fields | unified | SAFE | - | 333.78 | yara-x 0.54, office 2.46, custom 0.73, yara-x-engine 0.38, ooxml-links 0.52, word-fields 0.75 |
