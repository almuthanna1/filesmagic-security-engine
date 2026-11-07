Frozen runs: commit `1668326`, 16 fixtures x 20 trials per engine.

| Case | Role | Reference | Unified | Added (non-correlation) | Removed | Qualified | Undetermined |
|---|---|---|---|---|---|---|---|
| 1-pdf-clean | control | SAFE | SAFE | - | - | - | - |
| 2-pdf-form-keystroke-js | benign-content | SUSPICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_USER_TRIGGERED_SCRIPT (INFO) | yara-x:PDF_JavaScript_With_Automatic_Action (MEDIUM) | Evidence correlation: replaced PDF_JavaScript_With_Automatic_Action (YARA-X) by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which did not match: the bytes show every /OpenAction and /AA here is not automatic. | - |
| 2b-pdf-open-at-page-click-js | benign-content | SUSPICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_USER_TRIGGERED_SCRIPT (INFO) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM)<br>yara-x:PDF_JavaScript_With_Automatic_Action (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT (PDF scanner) by the action-chain rules; replaced PDF_JavaScript_With_Automatic_Action (YARA-X) by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which did not match: the bytes show every /OpenAction and /AA here is not automatic. | - |
| 2c-pdf-open-at-page-page-open-js | indicator | SUSPICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT (MEDIUM)<br>yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger (MEDIUM) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM)<br>yara-x:PDF_JavaScript_With_Automatic_Action (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT (PDF scanner) by the action-chain rules; replaced PDF_JavaScript_With_Automatic_Action (YARA-X) by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which also matched. | - |
| 3-pdf-escaped-openaction-js | indicator | SUSPICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT (MEDIUM) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT (PDF scanner) by the action-chain rules. | - |
| 4-pdf-objstm-escaped-js | indicator | SUSPICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT (MEDIUM) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT (PDF scanner) by the action-chain rules. | - |
| 5a-pdf-auto-js-unrelated-attachment | indicator | MALICIOUS | SUSPICIOUS | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT (MEDIUM)<br>yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger (MEDIUM) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM)<br>pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (HIGH)<br>yara-x:PDF_JavaScript_With_Automatic_Action (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT, PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner) by the action-chain rules; replaced PDF_JavaScript_With_Automatic_Action (YARA-X) by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which also matched. | - |
| 5b-pdf-auto-js-exports-attachment | indicator | MALICIOUS | MALICIOUS | pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT (HIGH)<br>yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger (MEDIUM) | pdf:PDF_AUTO_JAVASCRIPT (MEDIUM)<br>pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (HIGH)<br>yara-x:PDF_JavaScript_With_Automatic_Action (MEDIUM) | Evidence correlation: replaced PDF_AUTO_JAVASCRIPT, PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner) by the action-chain rules; replaced PDF_JavaScript_With_Automatic_Action (YARA-X) by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which also matched. | - |
| 6a-docx-hyperlink | control | SAFE | SAFE | ooxml-links:ENGINE_OFFICE_EXTERNAL_NOT_ACTIVATED (INFO) | - | - | - |
| 6b-docx-external-template | indicator | SUSPICIOUS | SUSPICIOUS | ooxml-links:ENGINE_OFFICE_EXTERNAL_NOT_ACTIVATED (INFO) | - | Evidence correlation: OFFICE_EXTERNAL_AUTOLOAD (Office scanner) kept although no part Office loads references it: its use is not demonstrated. | - |
| 6c-docx-template-referenced-by-settings | indicator | SUSPICIOUS | SUSPICIOUS | ooxml-links:ENGINE_OFFICE_EXTERNAL_ON_OPEN (MEDIUM) | - | Evidence correlation: OFFICE_EXTERNAL_AUTOLOAD (Office scanner) confirmed: a part Office loads references an external target used on open. | - |
| 6d-docx-linked-picture | benign-content | SAFE | SAFE | ooxml-links:ENGINE_OFFICE_LINKED_PICTURE (INFO) | - | - | - |
| 6g-docx-linked-picture-file-share | indicator | SUSPICIOUS | SUSPICIOUS | ooxml-links:ENGINE_OFFICE_LINKED_PICTURE (INFO) | - | - | - |
| 6e-docx-embedded-object-displayed | benign-content | SUSPICIOUS | SUSPICIOUS | ooxml-links:ENGINE_OFFICE_EMBEDDED_OBJECT_DISPLAYED (INFO) | - | Evidence correlation: OFFICE_EMBEDDED_OLE (Office scanner) kept; the object is shown in the document and runs only when activated. | - |
| 6f-docx-embedded-object-not-displayed | benign-content | SUSPICIOUS | SUSPICIOUS | ooxml-links:ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED (INFO) | - | Evidence correlation: OFFICE_EMBEDDED_OLE (Office scanner) kept; no element shows the object in the document. | - |
| 7-docx-macro-declaration-mismatch | indicator | SUSPICIOUS | SUSPICIOUS | vba-chains:ENGINE_VBA_CALL_PATH_UNDETERMINED (INFO) | - | - | ENGINE_VBA_CALL_PATH_UNDETERMINED |

| Latency (ms, pooled) | Reference p50 | Reference p95 | Unified p50 | Unified p95 |
|---|---|---|---|---|
| wall | 555.51 | 629.422 | 567.58 | 629.136 |
| startup_and_ipc | 553.74 | 627.591 | 565.04 | 626.589 |
| scanning | 2.22 | 3.715 | 3.24 | 4.404 |

| Scanner (unified run) | runs | p50 ms | p95 ms |
|---|---|---|---|
| yara-x | 320 | 0.37 | 0.526 |
| pdf | 160 | 0.61 | 0.869 |
| custom | 320 | 0.5 | 0.745 |
| yara-x-engine | 320 | 0.33 | 0.454 |
| pdf-chains | 160 | 0.38 | 0.594 |
| office | 160 | 1.87 | 2.601 |
| ooxml-links | 160 | 0.41 | 0.624 |
| vba-chains | 20 | 0.14 | 0.209 |
