| case | store bytes | PDF bytes | verdict | attachment rule | unified scan, max of 1 (ms) | peak memory, MiB (working set / private) | added by the case | first reason a store was not verified |
|---|---|---|---|---|---|---|---|---|
| boxes: 10,000 in one store | 80,822 x 1 | 1,594 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 5 | 70 / 52 | 2 / 1 | every store verified |
| boxes: one superbox of 2 million empty boxes | 16,774,093 x 1 | 25,928 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 533 | 486 / 470 | 419 / 419 | a JUMBF (C2PA) box: more than 10000 boxes |
| boxes: 100 stores of 10,000 | 80,822 x 100 | 109,269 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_VERIFIED | 329 | 77 / 60 | 10 / 9 | every store verified |
| CBOR: 100,000 items in one store | 100,886 x 1 | 1,573 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 21 | 68 / 50 | 0 / 0 | every store verified |
| CBOR: 100 stores of 100,000 items | 100,886 x 100 | 107,169 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_VERIFIED | 1,940 | 78 / 60 | 10 / 9 | every store verified |
| CBOR: indefinite text of 16 million empty chunks | 16,774,101 x 1 | 17,805 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 5,080 | 1,996 / 2,006 | 1,929 / 1,955 | every store verified |
| CBOR: nesting 64 deep | 1,045 x 1 | 1,355 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 4 | 68 / 51 | 0 / 0 | every store verified |
| JSON: 8 million values in one box | 16,774,102 x 1 | 17,814 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 915 | 221 / 211 | 153 / 160 | every store verified |
| text: 1 MiB in one string | 1,047,562 x 1 | 2,493 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 30 | 70 / 52 | 3 / 2 | every store verified |
| text: 16 stores of 1 MiB | 1,047,562 x 16 | 32,248 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 459 | 86 / 68 | 18 / 17 | every store verified |
| SVG: 10,000 elements, 1 MiB of values | 1,160,945 x 1 | 5,528 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 76 | 74 / 57 | 7 / 6 | every store verified |
| SVG: 50 stores of 10,000 elements | 411,020 x 50 | 114,119 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 1,473 | 92 / 74 | 24 / 24 | a JUMBF (C2PA) box: too large to read |
| JPEG: 16 MiB of fill bytes | 16,774,273 x 1 | 17,893 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 1,388 | 99 / 85 | 32 / 35 | every store verified |
| JPEG: 8 million stuffed FF00 pairs | 16,774,273 x 1 | 17,900 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 911 | 100 / 86 | 32 / 35 | every store verified |
| JPEG: 4 million empty COM segments | 16,774,273 x 1 | 17,908 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 1,344 | 100 / 86 | 32 / 35 | every store verified |
| JPEG: 16 MiB of entropy data like markup | 16,774,273 x 1 | 34,157 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 506 | 99 / 86 | 32 / 35 | every store verified |
| PNG: 1.4 million empty chunks | 16,774,198 x 1 | 34,183 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 752 | 99 / 85 | 32 / 35 | every store verified |
| PNG: one 16 MiB IDAT | 16,774,188 x 1 | 17,906 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 300 | 115 / 98 | 48 / 47 | every store verified |
| all limits at once: 7 stores | 99,986 x 7 | 38,569 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 566 | 98 / 80 | 31 / 30 | every store verified |
