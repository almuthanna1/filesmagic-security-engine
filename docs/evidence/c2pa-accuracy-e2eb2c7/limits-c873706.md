| case | store bytes | PDF bytes | verdict | unified scan, max of 1 (ms) | the C2PA check on the first store |
|---|---|---|---|---|---|
| boxes: 10,000 in one store | 80,822 x 1 | 1,594 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 23 | verified |
| boxes: one superbox of 2 million empty boxes | 16,774,093 x 1 | 25,928 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 1,324 | not verified: more than 10000 boxes |
| boxes: 100 stores of 10,000 | 80,822 x 100 | 109,269 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_VERIFIED | 626 | verified |
| CBOR: 100,000 items in one store | 100,886 x 1 | 1,573 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 30 | verified |
| CBOR: 100 stores of 100,000 items | 100,886 x 100 | 107,169 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_VERIFIED | 2,510 | verified |
| CBOR: indefinite text of 16 million empty chunks | 16,774,101 x 1 | 17,805 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 5,519 | verified |
| CBOR: nesting 64 deep | 1,045 x 1 | 1,355 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 3 | verified |
| JSON: 8 million values in one box | 16,774,102 x 1 | 17,814 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 972 | verified |
| text: 1 MiB in one string | 1,047,562 x 1 | 2,493 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 40 | verified |
| text: 16 stores of 1 MiB | 1,047,562 x 16 | 32,248 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 505 | verified |
| SVG: 10,000 elements, 1 MiB of values | 1,160,945 x 1 | 5,528 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 75 | verified |
| SVG: 50 stores of 10,000 elements | 411,020 x 50 | 114,119 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 1,556 | verified |
| JPEG: 16 MiB of fill bytes | 16,774,273 x 1 | 17,893 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 1,324 | verified |
| JPEG: 8 million stuffed FF00 pairs | 16,774,273 x 1 | 17,900 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 946 | verified |
| JPEG: 4 million empty COM segments | 16,774,273 x 1 | 17,908 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 1,575 | verified |
| JPEG: 16 MiB of entropy data like markup | 16,774,273 x 1 | 34,157 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 502 | verified |
| PNG: 1.4 million empty chunks | 16,774,198 x 1 | 34,183 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 764 | verified |
| PNG: one 16 MiB IDAT | 16,774,188 x 1 | 17,906 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 305 | verified |
