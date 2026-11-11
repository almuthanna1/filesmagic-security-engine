| case | store bytes | PDF bytes | verdict | attachment rule | unified scan, max of 3 (ms) | peak memory, MiB (working set / private) | added by the case | first reason a store was not verified |
|---|---|---|---|---|---|---|---|---|
| boxes: 10,000 in one store | 80,822 x 1 | 1,594 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 5 | 69 / 51 | 2 / 1 | every store verified |
| boxes: one superbox of 2 million empty boxes | 16,774,093 x 1 | 25,928 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 15 | 134 / 120 | 66 / 69 | a JUMBF (C2PA) box: more than 10000 boxes in the manifest stores of this file |
| boxes: 100 stores of 10,000 | 80,822 x 100 | 109,269 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 46 | 86 / 68 | 19 / 17 | a JUMBF (C2PA) box: more than 10000 boxes in the manifest stores of this file |
| CBOR: 100,000 items in one store | 100,886 x 1 | 1,573 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 33 | 68 / 50 | 0 / 0 | every store verified |
| CBOR: 100 stores of 100,000 items | 100,886 x 100 | 107,169 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 78 | 89 / 71 | 21 / 21 | a JUMBF (C2PA) box: c2pa.test: more than 100000 CBOR or JSON items in the manifest stores of this file |
| CBOR: indefinite text of 16 million empty chunks | 16,774,101 x 1 | 17,805 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 56 | 135 / 122 | 68 / 71 | a JUMBF (C2PA) box: c2pa.test: more than 100000 CBOR or JSON items in the manifest stores of this file |
| CBOR: nesting 64 deep | 1,045 x 1 | 1,355 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 9 | 68 / 50 | 0 / 0 | every store verified |
| JSON: 8 million values in one box | 16,774,102 x 1 | 17,814 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 21 | 132 / 118 | 64 / 67 | a JUMBF (C2PA) box: c2pa.test: more than 1048576 bytes of JSON in the manifest stores of this file |
| text: 1 MiB in one string | 1,047,562 x 1 | 2,493 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 31 | 72 / 55 | 5 / 4 | every store verified |
| text: 16 stores of 1 MiB | 1,047,562 x 16 | 32,248 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 49 | 117 / 100 | 49 / 49 | a JUMBF (C2PA) box: more than 1048576 characters of text in the manifest stores of this file |
| SVG: 10,000 elements, 1 MiB of values | 1,160,945 x 1 | 5,528 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 163 | 79 / 61 | 11 / 11 | every store verified |
| SVG: 50 stores of 10,000 elements | 411,020 x 50 | 114,119 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 113 | 150 / 133 | 82 / 82 | a JUMBF (C2PA) box: c2pa.thumbnail.claim: markup with more than 10000 elements in the manifest stores of this |
| JPEG: 16 MiB of fill bytes | 16,774,273 x 1 | 17,893 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 308 | 132 / 118 | 64 / 67 | every store verified |
| JPEG: 8 million stuffed FF00 pairs | 16,774,273 x 1 | 17,900 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 381 | 131 / 117 | 64 / 67 | every store verified |
| JPEG: 4 million empty COM segments | 16,774,273 x 1 | 17,908 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 76 | 133 / 118 | 64 / 67 | a JUMBF (C2PA) box: c2pa.thumbnail.claim: JPEG with more than 100000 markers and chunks in the pictures of thi |
| JPEG: 16 MiB of entropy data like markup | 16,774,273 x 1 | 34,157 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 526 | 132 / 118 | 64 / 67 | every store verified |
| PNG: 1.4 million empty chunks | 16,774,198 x 1 | 34,183 | SUSPICIOUS | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 81 | 132 / 118 | 64 / 67 | a JUMBF (C2PA) box: c2pa.thumbnail.claim: PNG with more than 100000 markers and chunks in the pictures of this |
| PNG: one 16 MiB IDAT | 16,774,188 x 1 | 17,906 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 309 | 148 / 130 | 80 / 79 | every store verified |
| all limits at once: 7 stores | 99,986 x 7 | 38,569 | SAFE | ENGINE_PDF_ATTACHMENTS_VERIFIED | 574 | 133 / 115 | 65 / 64 | every store verified |
