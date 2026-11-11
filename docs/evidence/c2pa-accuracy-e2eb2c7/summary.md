# C2PA accuracy study: results

before `9882cbf`, after `e2eb2c7`; 3 trial(s) per scan; Windows-11-10.0.26300-SP0, Python 3.14.3.

Samples: dev/ambiguous 1, dev/attachment 1, dev/attack-string 32, dev/benign 4, dev/c2pa-active 15, dev/c2pa-benign 14, dev/c2pa-deceptive 11, dev/c2pa-malformed 12, dev/dangerous 2, heldout/benign 7, heldout/c2pa-benign 24, regression/ambiguous 5, regression/attachment 5, regression/benign 90, regression/case 22, regression/dangerous 3, regression/no-attachment 4.


## Confusion matrices: dev

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 2 | 1 | 1 | 0 |
| before/reference | c2pa-benign | 0 | 14 | 0 | 0 |
| before/reference | attack-string | 0 | 32 | 0 | 0 |
| before/reference | c2pa-active | 0 | 15 | 0 | 0 |
| before/reference | c2pa-deceptive | 0 | 11 | 0 | 0 |
| before/reference | c2pa-malformed | 0 | 12 | 0 | 0 |
| before/reference | dangerous | 0 | 0 | 2 | 0 |
| before/reference | attachment | 0 | 1 | 0 | 0 |
| before/reference | ambiguous | 0 | 1 | 0 | 0 |
| before/unified | benign | 2 | 1 | 1 | 0 |
| before/unified | c2pa-benign | 0 | 14 | 0 | 0 |
| before/unified | attack-string | 0 | 32 | 0 | 0 |
| before/unified | c2pa-active | 0 | 15 | 0 | 0 |
| before/unified | c2pa-deceptive | 0 | 11 | 0 | 0 |
| before/unified | c2pa-malformed | 0 | 12 | 0 | 0 |
| before/unified | dangerous | 0 | 0 | 2 | 0 |
| before/unified | attachment | 0 | 1 | 0 | 0 |
| before/unified | ambiguous | 0 | 1 | 0 | 0 |
| after/reference | benign | 2 | 1 | 1 | 0 |
| after/reference | c2pa-benign | 0 | 14 | 0 | 0 |
| after/reference | attack-string | 0 | 32 | 0 | 0 |
| after/reference | c2pa-active | 0 | 15 | 0 | 0 |
| after/reference | c2pa-deceptive | 0 | 11 | 0 | 0 |
| after/reference | c2pa-malformed | 0 | 12 | 0 | 0 |
| after/reference | dangerous | 0 | 0 | 2 | 0 |
| after/reference | attachment | 0 | 1 | 0 | 0 |
| after/reference | ambiguous | 0 | 1 | 0 | 0 |
| after/unified | benign | 3 | 0 | 1 | 0 |
| after/unified | c2pa-benign | 14 | 0 | 0 | 0 |
| after/unified | attack-string | 19 | 13 | 0 | 0 |
| after/unified | c2pa-active | 0 | 15 | 0 | 0 |
| after/unified | c2pa-deceptive | 0 | 11 | 0 | 0 |
| after/unified | c2pa-malformed | 0 | 12 | 0 | 0 |
| after/unified | dangerous | 0 | 0 | 2 | 0 |
| after/unified | attachment | 0 | 1 | 0 | 0 |
| after/unified | ambiguous | 0 | 1 | 0 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 18 | 1 (95% CI [0.0099, 0.2576]) | 16 (95% CI [0.672, 0.969]) |
| before/unified | 18 | 1 (95% CI [0.0099, 0.2576]) | 16 (95% CI [0.672, 0.969]) |
| after/reference | 18 | 1 (95% CI [0.0099, 0.2576]) | 16 (95% CI [0.672, 0.969]) |
| after/unified | 18 | 1 (95% CI [0.0099, 0.2576]) | 1 (95% CI [0.0099, 0.2576]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 1 | 0 |
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 1 | 0 |
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 16 | 0 |
| before/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 1 | 0 |
| before/reference | `pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH` | 1 | 0 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 15 | 0 |
| before/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 16 | 15 |
| before/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 1 | 0 |
| before/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 1 | 0 |
| before/unified | `pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH` | 1 | 0 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 1 | 0 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 1 | 0 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 16 | 0 |
| after/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 1 | 0 |
| after/reference | `pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH` | 1 | 0 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 15 | 0 |
| after/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 1 | 0 |
| after/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 1 | 0 |
| after/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 1 | 0 |
| after/unified | `pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH` | 1 | 0 |

## Confusion matrices: heldout

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 4 | 3 | 0 | 0 |
| before/reference | c2pa-benign | 0 | 24 | 0 | 0 |
| before/unified | benign | 4 | 3 | 0 | 0 |
| before/unified | c2pa-benign | 0 | 24 | 0 | 0 |
| after/reference | benign | 4 | 3 | 0 | 0 |
| after/reference | c2pa-benign | 0 | 24 | 0 | 0 |
| after/unified | benign | 6 | 1 | 0 | 0 |
| after/unified | c2pa-benign | 21 | 3 | 0 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 31 | 0 (95% CI [0.0, 0.1103]) | 27 (95% CI [0.7115, 0.9487]) |
| before/unified | 31 | 0 (95% CI [0.0, 0.1103]) | 27 (95% CI [0.7115, 0.9487]) |
| after/reference | 31 | 0 (95% CI [0.0, 0.1103]) | 27 (95% CI [0.7115, 0.9487]) |
| after/unified | 31 | 0 (95% CI [0.0, 0.1103]) | 4 (95% CI [0.0513, 0.2885]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 26 | 0 |
| before/reference | `pdf:PDF_ENCRYPTED:MEDIUM` | 1 | 1 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 26 | 0 |
| before/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 26 | 26 |
| before/unified | `pdf:PDF_ENCRYPTED:MEDIUM` | 1 | 1 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 26 | 0 |
| after/reference | `pdf:PDF_ENCRYPTED:MEDIUM` | 1 | 1 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 26 | 0 |
| after/unified | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | 3 | 3 |
| after/unified | `pdf:PDF_ENCRYPTED:MEDIUM` | 1 | 1 |

## Confusion matrices: regression

| run | class | SAFE | SUSPICIOUS | MALICIOUS | UNABLE_TO_SCAN |
|---|---|---|---|---|---|
| before/reference | benign | 82 | 5 | 3 | 0 |
| before/reference | no-attachment | 1 | 3 | 0 | 0 |
| before/reference | attachment | 0 | 5 | 0 | 0 |
| before/reference | ambiguous | 0 | 5 | 0 | 0 |
| before/reference | dangerous | 0 | 0 | 3 | 0 |
| before/unified | benign | 86 | 4 | 0 | 0 |
| before/unified | no-attachment | 4 | 0 | 0 | 0 |
| before/unified | attachment | 0 | 5 | 0 | 0 |
| before/unified | ambiguous | 0 | 5 | 0 | 0 |
| before/unified | dangerous | 0 | 0 | 3 | 0 |
| after/reference | benign | 82 | 5 | 3 | 0 |
| after/reference | no-attachment | 1 | 3 | 0 | 0 |
| after/reference | attachment | 0 | 5 | 0 | 0 |
| after/reference | ambiguous | 0 | 5 | 0 | 0 |
| after/reference | dangerous | 0 | 0 | 3 | 0 |
| after/unified | benign | 86 | 4 | 0 | 0 |
| after/unified | no-attachment | 4 | 0 | 0 | 0 |
| after/unified | attachment | 0 | 5 | 0 | 0 |
| after/unified | ambiguous | 0 | 5 | 0 | 0 |
| after/unified | dangerous | 0 | 0 | 3 | 0 |

| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |
|---|---|---|---|
| before/reference | 90 | 3 (95% CI [0.0114, 0.0935]) | 8 (95% CI [0.0457, 0.1657]) |
| before/unified | 90 | 0 (95% CI [0.0, 0.0409]) | 4 (95% CI [0.0174, 0.1088]) |
| after/reference | 90 | 3 (95% CI [0.0114, 0.0935]) | 8 (95% CI [0.0457, 0.1657]) |
| after/unified | 90 | 0 (95% CI [0.0, 0.0409]) | 4 (95% CI [0.0174, 0.1088]) |

Per-rule contributions on benign documents (documents with the rule; documents where it is the only non-INFO finding):

| run | rule | documents | sole |
|---|---|---|---|
| before/reference | `office:OFFICE_EXTERNAL_AUTOLOAD:MEDIUM` | 1 | 1 |
| before/reference | `office:OFFICE_EXTERNAL_NETWORK_PATH:MEDIUM` | 2 | 2 |
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 3 | 0 |
| before/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 4 | 0 |
| before/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/reference | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| before/reference | `yara-x:PDF_Embedded_File:LOW` | 5 | 1 |
| before/unified | `ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW` | 1 | 1 |
| before/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 3 | 0 |
| before/unified | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| before/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| before/unified | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| before/unified | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |
| after/reference | `office:OFFICE_EXTERNAL_AUTOLOAD:MEDIUM` | 1 | 1 |
| after/reference | `office:OFFICE_EXTERNAL_NETWORK_PATH:MEDIUM` | 2 | 2 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/reference | `pdf:PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD:HIGH` | 3 | 0 |
| after/reference | `pdf:PDF_EMBEDDED_FILE:LOW` | 4 | 0 |
| after/reference | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/reference | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| after/reference | `yara-x:PDF_Embedded_File:LOW` | 5 | 1 |
| after/unified | `ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW` | 1 | 1 |
| after/unified | `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM` | 3 | 0 |
| after/unified | `pdf:PDF_EMBEDDED_FILE:LOW` | 3 | 0 |
| after/unified | `pdf:PDF_JAVASCRIPT:MEDIUM` | 3 | 0 |
| after/unified | `pdf:PDF_XFA_FORM:LOW` | 3 | 0 |
| after/unified | `yara-x:PDF_Embedded_File:LOW` | 3 | 0 |

## Changes between before and after

| sample | split | class | engine | before | after | removed | added |
|---|---|---|---|---|---|---|---|
| D1 | dev | benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH01 | heldout | benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH02 | heldout | benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CD04-derived | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CD05-derived | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CD06-derived | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CD07-derived | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CD08-derived | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA02-01 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA02-03 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA02-05 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA03-01 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA03-02 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA03-03 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA03-04 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA03-05 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-01 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-02 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-03 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-04 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-05 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-06 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-07 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-08 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-09 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA04-10 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CA05-01 | dev | attack-string | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH08-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH09-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH10-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH11-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH12-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH13-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH14-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH15-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH16-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH17-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH18-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH19-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH20-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH21-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH22-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH23-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH24-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH25-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH26-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH27-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| CH28-derived | heldout | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C01-cbor-only | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C02-jpeg-thumbnail | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C03-png-thumbnail | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C04-static-svg-icon | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C05-json-assertion | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C06-salt-and-padding | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C07-named-manifest-c2pa | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C08-two-manifest-stores | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |
| C09-with-verified-odt | dev | c2pa-benign | unified | SUSPICIOUS | SAFE | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW | - |

HIGH/CRITICAL findings lost: none. Non-deterministic scans: none.


## Outcomes after (unified)

| sample | split | class | verdict | outcome | non-INFO rules |
|---|---|---|---|---|---|
| D1 | dev | benign | SAFE | correct | - |
| independent/f1040.pdf | regression | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| independent/fw4.pdf | regression | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| independent/fw9.pdf | regression | benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_EMBEDDED_FILE:LOW, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_XFA_FORM:LOW, yara-x:PDF_Embedded_File:LOW |
| files/docx-05-word-custom-template.docx | regression | benign | SUSPICIOUS | unexpected warning | ooxml-links:ENGINE_OFFICE_LOCAL_TEMPLATE:LOW |
| CD01 | dev | benign | SAFE | correct | - |
| CD02 | dev | benign | SAFE | correct | - |
| CD03 | dev | benign | MALICIOUS | false positive | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH |
| CH07 | heldout | benign | SUSPICIOUS | unexpected warning | pdf:PDF_ENCRYPTED:MEDIUM |
| CD04-derived | dev | c2pa-benign | SAFE | correct | - |
| CD05-derived | dev | c2pa-benign | SAFE | correct | - |
| CD06-derived | dev | c2pa-benign | SAFE | correct | - |
| CD07-derived | dev | c2pa-benign | SAFE | correct | - |
| CD08-derived | dev | c2pa-benign | SAFE | correct | - |
| CA01-01 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA01-02 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA01-03 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA01-04 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA02-01 | dev | attack-string | SAFE | reported | - |
| CA02-02 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA02-03 | dev | attack-string | SAFE | reported | - |
| CA02-04 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA02-05 | dev | attack-string | SAFE | reported | - |
| CA03-01 | dev | attack-string | SAFE | reported | - |
| CA03-02 | dev | attack-string | SAFE | reported | - |
| CA03-03 | dev | attack-string | SAFE | reported | - |
| CA03-04 | dev | attack-string | SAFE | reported | - |
| CA03-05 | dev | attack-string | SAFE | reported | - |
| CA03-06 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-07 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-08 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-09 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-10 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-11 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA03-12 | dev | attack-string | SUSPICIOUS | reported | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CA04-01 | dev | attack-string | SAFE | reported | - |
| CA04-02 | dev | attack-string | SAFE | reported | - |
| CA04-03 | dev | attack-string | SAFE | reported | - |
| CA04-04 | dev | attack-string | SAFE | reported | - |
| CA04-05 | dev | attack-string | SAFE | reported | - |
| CA04-06 | dev | attack-string | SAFE | reported | - |
| CA04-07 | dev | attack-string | SAFE | reported | - |
| CA04-08 | dev | attack-string | SAFE | reported | - |
| CA04-09 | dev | attack-string | SAFE | reported | - |
| CA04-10 | dev | attack-string | SAFE | reported | - |
| CA05-01 | dev | attack-string | SAFE | reported | - |
| CH29-derived | heldout | c2pa-benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CH30-derived | heldout | c2pa-benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| CH31-derived | heldout | c2pa-benign | SUSPICIOUS | unexpected warning | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C01-cbor-only | dev | c2pa-benign | SAFE | correct | - |
| C02-jpeg-thumbnail | dev | c2pa-benign | SAFE | correct | - |
| C03-png-thumbnail | dev | c2pa-benign | SAFE | correct | - |
| C04-static-svg-icon | dev | c2pa-benign | SAFE | correct | - |
| C05-json-assertion | dev | c2pa-benign | SAFE | correct | - |
| C06-salt-and-padding | dev | c2pa-benign | SAFE | correct | - |
| C07-named-manifest-c2pa | dev | c2pa-benign | SAFE | correct | - |
| C08-two-manifest-stores | dev | c2pa-benign | SAFE | correct | - |
| C09-with-verified-odt | dev | c2pa-benign | SAFE | correct | - |
| C10-svg-script | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, yara-x:SVG_Script_Content:MEDIUM |
| C11-svg-onload | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, yara-x:SVG_Script_Content:MEDIUM |
| C12-svg-foreign-object | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C13-svg-javascript-link | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, yara-x:SVG_Script_Content:MEDIUM |
| C14-svg-external-image | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C15-svg-style | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C16-svg-stylesheet-instruction | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C17-svg-dtd-entity | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C18-svg-external-use | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C19-svg-set-href | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, yara-x:SVG_Script_Content:MEDIUM |
| C20-svg-external-fill | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C21-html-in-data-box | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C22-xss-in-claim-title | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C23-bidi-override-in-label | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C24-user-link-javascript | dev | c2pa-active | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf:PDF_JAVASCRIPT:MEDIUM |
| C30-mz-declared-jpeg | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C31-jpeg-html-after-eoi | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C32-jpeg-script-in-comment | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C33-png-zip-after-iend | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C34-declared-png-holds-jpeg | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C35-external-reference | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C36-mz-as-c2pa-manifest | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C37-store-named-html | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C38-uuid-content-box | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C39-compressed-manifest | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C40-not-a-manifest-store | dev | c2pa-deceptive | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C50-truncated | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C51-trailing-bytes | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C52-box-beyond-parent | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C53-nesting-too-deep | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C54-too-many-boxes | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C55-cbor-trailing | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C56-cbor-invalid-utf8 | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C57-cbor-repeated-key | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C58-cbor-unterminated | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C59-json-repeated-key | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C60-png-bad-crc | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C61-jpeg-without-eoi | dev | c2pa-malformed | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C70-auto-js-exports-manifest | dev | dangerous | MALICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH, pdf:PDF_JAVASCRIPT:MEDIUM, pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH, yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger:MEDIUM |
| C71-auto-launch-manifest | dev | dangerous | MALICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW, pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH, pdf:PDF_LAUNCH_ACTION:HIGH, yara-x:PDF_Launch_Action:HIGH |
| C72-with-text-attachment | dev | attachment | SUSPICIOUS | correct | pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW |
| C73-added-by-incremental-update | dev | ambiguous | SUSPICIOUS | correct | pdf:PDF_EMBEDDED_FILE:LOW, yara-x:PDF_Embedded_File:LOW |

(Rows not shown: held-out and regression documents with a correct outcome.)

## Latency (ms)

| run | scope | n | median | p95 | max |
|---|---|---|---|---|---|
| before/reference | all scans, wall | 756 | 595.46 | 683.77 | 901.27 |
| before/reference | PDF scans, wall | 543 | 597.59 | 706.32 | 901.27 |
| before/reference | custom (completed) | 756 | 0.83 | 70.526 | 268.128 |
| before/reference | office (completed) | 189 | 2.63 | 4.033 | 5.6 |
| before/reference | office (not_applicable) | 567 | 0.0 | 0.005 | 0.057 |
| before/reference | pdf (completed) | 567 | 0.74 | 8.796 | 39.353 |
| before/reference | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.007 |
| before/reference | yara-x (completed) | 756 | 0.43 | 2.042 | 4.205 |
| before/unified | all scans, wall | 756 | 629.25 | 764.42 | 1067.09 |
| before/unified | PDF scans, wall | 543 | 631.02 | 805.47 | 1067.09 |
| before/unified | custom (completed) | 756 | 0.87 | 71.763 | 274.111 |
| before/unified | office (completed) | 189 | 2.88 | 4.556 | 5.334 |
| before/unified | office (not_applicable) | 567 | 0.0 | 0.005 | 0.049 |
| before/unified | ooxml-links (completed) | 189 | 2.04 | 11.333 | 17.981 |
| before/unified | ooxml-links (not_applicable) | 567 | 0.0 | 0.004 | 0.033 |
| before/unified | pdf (completed) | 567 | 0.76 | 8.574 | 42.372 |
| before/unified | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.012 |
| before/unified | pdf-chains (completed) | 564 | 0.74 | 57.779 | 109.505 |
| before/unified | pdf-chains (failed) | 3 | 3.12 | 3.564 | 3.564 |
| before/unified | pdf-chains (not_applicable) | 189 | 0.01 | 0.011 | 0.063 |
| before/unified | vba-chains (completed) | 3 | 0.15 | 0.184 | 0.184 |
| before/unified | vba-chains (not_applicable) | 753 | 0.0 | 0.338 | 1.49 |
| before/unified | word-fields (completed) | 63 | 0.43 | 5.834 | 7.413 |
| before/unified | word-fields (not_applicable) | 693 | 0.0 | 2.088 | 5.999 |
| before/unified | yara-x (completed) | 756 | 0.43 | 2.022 | 4.953 |
| before/unified | yara-x-engine (completed) | 756 | 0.34 | 0.848 | 1.973 |
| after/reference | all scans, wall | 756 | 582.07 | 695.75 | 2152.9 |
| after/reference | PDF scans, wall | 543 | 582.21 | 719.08 | 2152.9 |
| after/reference | custom (completed) | 756 | 0.84 | 71.35 | 263.238 |
| after/reference | office (completed) | 189 | 2.6 | 4.129 | 5.068 |
| after/reference | office (not_applicable) | 567 | 0.0 | 0.005 | 0.017 |
| after/reference | pdf (completed) | 567 | 0.75 | 8.579 | 40.919 |
| after/reference | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.007 |
| after/reference | yara-x (completed) | 756 | 0.43 | 2.043 | 5.025 |
| after/unified | all scans, wall | 756 | 619.26 | 772.83 | 1602.03 |
| after/unified | PDF scans, wall | 543 | 619.14 | 843.56 | 1602.03 |
| after/unified | custom (completed) | 756 | 0.85 | 71.614 | 264.302 |
| after/unified | office (completed) | 189 | 2.78 | 4.679 | 5.266 |
| after/unified | office (not_applicable) | 567 | 0.0 | 0.004 | 0.008 |
| after/unified | ooxml-links (completed) | 189 | 1.95 | 11.344 | 18.996 |
| after/unified | ooxml-links (not_applicable) | 567 | 0.0 | 0.005 | 0.055 |
| after/unified | pdf (completed) | 567 | 0.75 | 9.286 | 39.329 |
| after/unified | pdf (not_applicable) | 189 | 0.0 | 0.005 | 0.026 |
| after/unified | pdf-chains (completed) | 564 | 0.94 | 58.611 | 115.353 |
| after/unified | pdf-chains (failed) | 3 | 3.11 | 3.373 | 3.373 |
| after/unified | pdf-chains (not_applicable) | 189 | 0.01 | 0.009 | 0.016 |
| after/unified | vba-chains (completed) | 3 | 0.17 | 0.346 | 0.346 |
| after/unified | vba-chains (not_applicable) | 753 | 0.0 | 0.325 | 1.557 |
| after/unified | word-fields (completed) | 63 | 0.46 | 5.614 | 5.963 |
| after/unified | word-fields (not_applicable) | 693 | 0.0 | 1.882 | 6.277 |
| after/unified | yara-x (completed) | 756 | 0.42 | 2.07 | 7.364 |
| after/unified | yara-x-engine (completed) | 756 | 0.35 | 0.797 | 5.141 |
