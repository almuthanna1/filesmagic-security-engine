| case | store bytes | PDF bytes | verdict | unified scan, max of 3 (ms) | the C2PA check on the first store |
|---|---|---|---|---|---|
| boxes: 10,000 in one store | 80,822 x 1 | 1,594 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 7 | verified |
| boxes: one superbox of 2 million empty boxes | 16,774,093 x 1 | 25,928 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 14 | not verified: more than 10000 boxes in the manifest stores of this file |
| boxes: 100 stores of 10,000 | 80,822 x 100 | 109,269 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 46 | verified |
| CBOR: 100,000 items in one store | 100,886 x 1 | 1,573 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 33 | verified |
| CBOR: 100 stores of 100,000 items | 100,886 x 100 | 107,169 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 113 | verified |
| CBOR: indefinite text of 16 million empty chunks | 16,774,101 x 1 | 17,805 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 50 | not verified: c2pa.test: more than 100000 CBOR or JSON items in the manifest stores of this file |
| CBOR: nesting 64 deep | 1,045 x 1 | 1,355 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 4 | verified |
| JSON: 8 million values in one box | 16,774,102 x 1 | 17,814 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 18 | not verified: c2pa.test: more than 1048576 bytes of JSON in the manifest stores of this file |
| text: 1 MiB in one string | 1,047,562 x 1 | 2,493 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 31 | verified |
| text: 16 stores of 1 MiB | 1,047,562 x 16 | 32,248 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 48 | verified |
| SVG: 10,000 elements, 1 MiB of values | 1,160,945 x 1 | 5,528 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 86 | verified |
| SVG: 50 stores of 10,000 elements | 411,020 x 50 | 114,119 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 108 | verified |
| JPEG: 16 MiB of fill bytes | 16,774,273 x 1 | 17,893 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 328 | verified |
| JPEG: 8 million stuffed FF00 pairs | 16,774,273 x 1 | 17,900 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 376 | verified |
| JPEG: 4 million empty COM segments | 16,774,273 x 1 | 17,908 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 79 | not verified: c2pa.thumbnail.claim: JPEG with more than 100000 markers and chunks in the pictures of thi |
| JPEG: 16 MiB of entropy data like markup | 16,774,273 x 1 | 34,157 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 525 | verified |
| PNG: 1.4 million empty chunks | 16,774,198 x 1 | 34,183 | SUSPICIOUS ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 64 | not verified: c2pa.thumbnail.claim: PNG with more than 100000 markers and chunks in the pictures of this |
| PNG: one 16 MiB IDAT | 16,774,188 x 1 | 17,906 | SAFE ENGINE_PDF_ATTACHMENTS_VERIFIED | 310 | verified |
