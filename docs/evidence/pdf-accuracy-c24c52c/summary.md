# PDF accuracy study: results

before `2d586f6`, after `c24c52c` (uncommitted changes); 3 trial(s) per scan; Windows-11-10.0.26300-SP0, Python 3.14.3.

Samples: dev/ambiguous 5, dev/attachment 5, dev/benign 3, dev/dangerous 3, dev/no-attachment 4, heldout/benign 59, regression/benign 29, regression/case 22.


## Confusion matrices: dev

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 1 | 2 | 0 | 0 |
| before/reference | no-attachment | 1 | 3 | 0 | 0 |
| before/reference | attachment | 0 | 5 | 0 | 0 |
| before/reference | ambiguous | 0 | 5 | 0 | 0 |
| before/reference | dangerous | 0 | 0 | 3 | 0 |
| before/unified | benign | 1 | 2 | 0 | 0 |
| before/unified | no-attachment | 1 | 3 | 0 | 0 |
| before/unified | attachment | 0 | 5 | 0 | 0 |
| before/unified | ambiguous | 0 | 5 | 0 | 0 |
| before/unified | dangerous | 0 | 0 | 3 | 0 |
| after/reference | benign | 1 | 2 | 0 | 0 |
| after/reference | no-attachment | 1 | 3 | 0 | 0 |
| after/reference | attachment | 0 | 5 | 0 | 0 |
| after/reference | ambiguous | 0 | 5 | 0 | 0 |
| after/reference | dangerous | 0 | 0 | 3 | 0 |
| after/unified | benign | 2 | 1 | 0 | 0 |
| after/unified | no-attachment | 4 | 0 | 0 | 0 |
| after/unified | attachment | 0 | 5 | 0 | 0 |
| after/unified | ambiguous | 0 | 5 | 0 | 0 |
| after/unified | dangerous | 0 | 0 | 3 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 3 | 0 (95% CI [0.0, 0.5615]) | 2 (95% CI [0.2077, 0.9385]) |
| before/unified | 3 | 0 (95% CI [0.0, 0.5615]) | 2 (95% CI [0.2077, 0.9385]) |
| after/reference | 3 | 0 (95% CI [0.0, 0.5615]) | 2 (95% CI [0.2077, 0.9385]) |
| after/unified | 3 | 0 (95% CI [0.0, 0.5615]) | 1 (95% CI [0.0615, 0.7923]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 1 | 0 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 2 | 1 |
| before/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 1 | 1 |
| before/unified | `yara-x:PDF_Embedded_File:LOW` | 1 | 1 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 1 | 0 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 2 | 1 |
| after/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 1 | 1 |

## Confusion matrices: heldout

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 56 | 0 | 3 | 0 |
| before/unified | benign | 56 | 3 | 0 | 0 |
| after/reference | benign | 56 | 0 | 3 | 0 |
| after/unified | benign | 56 | 3 | 0 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 59 | 3 (95% CI [0.0174, 0.1392]) | 3 (95% CI [0.0174, 0.1392]) |
| before/unified | 59 | 0 (95% CI [0.0, 0.0611]) | 3 (95% CI [0.0174, 0.1392]) |
| after/reference | 59 | 3 (95% CI [0.0174, 0.1392]) | 3 (95% CI [0.0174, 0.1392]) |
| after/unified | 59 | 0 (95% CI [0.0, 0.0611]) | 3 (95% CI [0.0174, 0.1392]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 3 | 0 |
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| before/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/reference | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |
| before/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 3 | 0 |
| before/unified | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| before/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/unified | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| before/unified | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 3 | 0 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| after/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/reference | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |
| after/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 3 | 0 |
| after/unified | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| after/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/unified | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| after/unified | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |

## Confusion matrices: regression

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 25 | 4 | 0 | 0 |
| before/unified | benign | 28 | 1 | 0 | 0 |
| after/reference | benign | 25 | 4 | 0 | 0 |
| after/unified | benign | 28 | 1 | 0 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 29 | 0 (95% CI [0.0, 0.117]) | 4 (95% CI [0.055, 0.3056]) |
| before/unified | 29 | 0 (95% CI [0.0, 0.117]) | 1 (95% CI [0.0061, 0.1718]) |
| after/reference | 29 | 0 (95% CI [0.0, 0.117]) | 4 (95% CI [0.055, 0.3056]) |
| after/unified | 29 | 0 (95% CI [0.0, 0.117]) | 1 (95% CI [0.0061, 0.1718]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `office:OFFICE_EXTERNAL_AUTOLOAD:MEDIUM` | 1 | 1 |
| before/reference | `office:OFFICE_EXTERNAL_NETWORK_PATH:MEDIUM` | 2 | 2 |
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 1 | 0 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 1 | 0 |
| before/unified | `ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW` | 1 | 1 |
| after/reference | `office:OFFICE_EXTERNAL_AUTOLOAD:MEDIUM` | 1 | 1 |
| after/reference | `office:OFFICE_EXTERNAL_NETWORK_PATH:MEDIUM` | 2 | 2 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 1 | 0 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 1 | 0 |
| after/unified | `ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW` | 1 | 1 |

## Changes between before and after

| sample | split | class | engine | before | after | removed | added |
|---|---|---|---|---|---|---|---|
| D2 | dev | benign | unified | SUSPICIOUS | SAFE | yara-x:PDF_Embedded_File:LOW | - |
| S01-empty-tree | dev | no-attachment | unified | SUSPICIOUS | SAFE | yara-x:PDF_Embedded_File:LOW | - |
| S02-empty-dict-af-null | dev | no-attachment | unified | SUSPICIOUS | SAFE | yara-x:PDF_Embedded_File:LOW | - |
| S03-empty-tree-indirect | dev | no-attachment | unified | SUSPICIOUS | SAFE | yara-x:PDF_Embedded_File:LOW | - |
| S17-empty-tree-auto-launch | dev | dangerous | unified | MALICIOUS | MALICIOUS | yara-x:PDF_Embedded_File:LOW | - |

HIGH/CRITICAL findings lost: none. Non-deterministic scans: none.


## Outcomes after (unified)

| sample | split | class | verdict | outcome | non-INFO rules |
|---|---|---|---|---|---|
| D1 | dev | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| D2 | dev | benign | SAFE | correct | - |
| D3 | dev | benign | SAFE | correct | - |
| independent/f1040.pdf | heldout | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| independent/fw4.pdf | heldout | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| independent/fw9.pdf | heldout | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| files/docx-05-word-custom-template.docx | regression | benign | SUSPICIOUS | unexpected warning | ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW |
| S01-empty-tree | dev | no-attachment | SAFE | correct | - |
| S02-empty-dict-af-null | dev | no-attachment | SAFE | correct | - |
| S03-empty-tree-indirect | dev | no-attachment | SAFE | correct | - |
| S04-empty-tree-object-stream | dev | no-attachment | SAFE | correct | - |
| S05-text-attachment | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| S06-mz-bytes-text-name | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| S07-c2pa-manifest-with-svg-script | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, yara-x:SVG_Script_Content:MEDIUM |
| S08-orphan-attachment-empty-tree | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| S09-file-attachment-annotation | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| S10-dangling-tree-entry | dev | ambiguous | SUSPICIOUS | correct | yara-x:PDF_Embedded_File:LOW |
| S11-incremental-update-removes-attachment | dev | ambiguous | SUSPICIOUS | correct | yara-x:PDF_Embedded_File:LOW |
| S12-broken-xref | dev | ambiguous | SUSPICIOUS | correct | yara-x:PDF_Embedded_File:LOW |
| S13-marker-in-page-text | dev | ambiguous | SUSPICIOUS | correct | yara-x:PDF_Embedded_File:LOW |
| S14-marker-after-eof | dev | ambiguous | SUSPICIOUS | correct | yara-x:PDF_Embedded_File:LOW |
| S15-auto-js-exports-attachment | dev | dangerous | MALICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH, yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger:MEDIUM |
| S16-auto-launch-embedded-exe | dev | dangerous | MALICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH, pdf:PDF_EMBEDDED_EXECUTABLE:HIGH, pdf:PDF_LAUNCH_ACTION:HIGH, yara-x:PDF_Launch_Action:HIGH |
| S17-empty-tree-auto-launch | dev | dangerous | MALICIOUS | correct | pdf-chains:ENGINE_PDF_AUTO_CHAIN_LAUNCH:HIGH, pdf:PDF_LAUNCH_ACTION:HIGH, yara-x:PDF_Launch_Action:HIGH |

(Rows not shown: held-out and regression documents with a correct outcome.)

## Latency (ms)

| run | scope | n | median | p95 | max |
|---|---|---|---|---|---|
| before/reference | all scans, wall | 390 | 595.08 | 825.62 | 906.7 |
| before/reference | PDF scans, wall | 177 | 644.06 | 876.51 | 906.7 |
| before/reference | custom (completed) | 390 | 3.01 | 131.459 | 268.74 |
| before/reference | office (completed) | 189 | 2.5 | 4.504 | 5.311 |
| before/reference | office (not_applicable) | 201 | 0.0 | 0.006 | 0.008 |
| before/reference | pdf (completed) | 201 | 1.53 | 16.999 | 44.956 |
| before/reference | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.027 |
| before/reference | yara-x (completed) | 390 | 0.44 | 2.849 | 4.498 |
| before/unified | all scans, wall | 390 | 642.27 | 927.26 | 1162.2 |
| before/unified | PDF scans, wall | 177 | 684.34 | 962.06 | 1162.2 |
| before/unified | custom (completed) | 390 | 3.06 | 134.32 | 276.408 |
| before/unified | office (completed) | 189 | 2.68 | 4.656 | 5.421 |
| before/unified | office (not_applicable) | 201 | 0.0 | 0.006 | 0.078 |
| before/unified | ooxml-links (completed) | 189 | 2.08 | 12.196 | 18.923 |
| before/unified | ooxml-links (not_applicable) | 201 | 0.0 | 0.005 | 0.191 |
| before/unified | pdf (completed) | 201 | 1.61 | 15.9 | 46.67 |
| before/unified | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.016 |
| before/unified | pdf-chains (completed) | 201 | 5.88 | 81.332 | 115.181 |
| before/unified | pdf-chains (not_applicable) | 189 | 0.01 | 0.01 | 0.014 |
| before/unified | vba-chains (completed) | 3 | 0.15 | 0.154 | 0.154 |
| before/unified | vba-chains (not_applicable) | 387 | 0.01 | 0.453 | 0.771 |
| before/unified | word-fields (completed) | 63 | 0.52 | 5.27 | 5.796 |
| before/unified | word-fields (not_applicable) | 327 | 0.0 | 3.058 | 7.283 |
| before/unified | yara-x (completed) | 390 | 0.43 | 2.925 | 4.482 |
| before/unified | yara-x-engine (completed) | 390 | 0.39 | 1.008 | 1.801 |
| after/reference | all scans, wall | 390 | 563.67 | 695.53 | 837.18 |
| after/reference | PDF scans, wall | 177 | 570.69 | 764.31 | 837.18 |
| after/reference | custom (completed) | 390 | 3.01 | 125.199 | 254.461 |
| after/reference | office (completed) | 189 | 2.53 | 4.207 | 4.675 |
| after/reference | office (not_applicable) | 201 | 0.0 | 0.005 | 0.007 |
| after/reference | pdf (completed) | 201 | 1.56 | 14.679 | 40.864 |
| after/reference | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.082 |
| after/reference | yara-x (completed) | 390 | 0.42 | 2.482 | 4.045 |
| after/unified | all scans, wall | 390 | 600.0 | 790.16 | 967.77 |
| after/unified | PDF scans, wall | 177 | 613.84 | 854.49 | 967.77 |
| after/unified | custom (completed) | 390 | 2.93 | 124.384 | 255.656 |
| after/unified | office (completed) | 189 | 2.67 | 4.332 | 5.415 |
| after/unified | office (not_applicable) | 201 | 0.0 | 0.004 | 0.005 |
| after/unified | ooxml-links (completed) | 189 | 2.06 | 11.287 | 18.719 |
| after/unified | ooxml-links (not_applicable) | 201 | 0.0 | 0.007 | 0.009 |
| after/unified | pdf (completed) | 201 | 1.53 | 15.202 | 42.063 |
| after/unified | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.009 |
| after/unified | pdf-chains (completed) | 201 | 6.28 | 75.689 | 106.784 |
| after/unified | pdf-chains (not_applicable) | 189 | 0.0 | 0.009 | 0.021 |
| after/unified | vba-chains (completed) | 3 | 0.14 | 0.161 | 0.161 |
| after/unified | vba-chains (not_applicable) | 387 | 0.01 | 0.4 | 0.57 |
| after/unified | word-fields (completed) | 63 | 0.5 | 5.282 | 5.67 |
| after/unified | word-fields (not_applicable) | 327 | 0.0 | 2.568 | 6.166 |
| after/unified | yara-x (completed) | 390 | 0.42 | 2.559 | 4.038 |
| after/unified | yara-x-engine (completed) | 390 | 0.36 | 1.15 | 1.865 |
