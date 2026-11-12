# Third-party software in the Security Engine

The Security Engine's own code and YARA rules (`app/rules/filesmagic.yar`, `app/engine/rules/pdf.yar`)
are FilesMagic's, under [LICENSE](LICENSE). The production image installs exactly the packages pinned
in [`requirements.txt`](requirements.txt), from PyPI, on `python:3.11-slim` (Debian). Licenses below
are from each package's own metadata at the pinned version.

| Package | Version | License |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| cffi | 2.1.1 | MIT-0 |
| click | 8.5.0 | BSD-3-Clause |
| colorclass | 2.2.2 | MIT |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause (bundles OpenSSL, Apache-2.0) |
| defusedxml | 0.7.1 | PSF-2.0 |
| easygui | 0.98.3 | BSD |
| fastapi | 0.142.4 | MIT |
| h11 | 0.16.0 | MIT |
| httptools | 0.8.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| msoffcrypto-tool | 6.0.0 | MIT |
| olefile | 0.47 | BSD-2-Clause |
| oletools | 0.60.2 | BSD-2-Clause |
| opentelemetry-api | 1.45.1 | Apache-2.0 |
| **pcodedmp** | 1.2.6 | **GPL-3.0** (see below) |
| pycparser | 3.1 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic_core | 2.46.5 | MIT |
| pyparsing | 3.3.3 | MIT |
| pypdf | 7.0.1 | BSD-3-Clause |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| PyYAML | 6.0.3 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| uvicorn | 0.54.0 | BSD-3-Clause |
| watchfiles | 1.3.0 | MIT |
| websockets | 17.2 | BSD-3-Clause |
| win_unicode_console | 0.5 | MIT (Windows only; not in the production image) |
| yara-x | 1.21.0 | BSD-3-Clause |

## pcodedmp (GPL-3.0)

`pcodedmp` is a dependency of `oletools`, which imports it only inside `VBA_Parser.extract_pcode`,
the VBA-stomping check. The engine does not import or modify it.

- **Hosted service (how FilesMagic uses it):** the image is built and run by Render for FilesMagic's own
  service and is not given to anyone. GPL-3.0's obligations attach to conveying (distributing) a
  covered work; running it as a network service is not conveying, and GPL-3.0, unlike AGPL-3.0, has no
  network-use clause. Nothing is owed.
- **If the image, or the engine bundled with its dependencies, is ever distributed** (for example to a
  customer to run themselves): distribute `pcodedmp` under GPL-3.0 with its source and license text, and
  have the combined work reviewed, or build without it (`oletools` then skips the P-code check, which
  changes detection and would need re-validation).
- Publishing this repository's source does not distribute `pcodedmp`: it is not vendored here, only
  named in `requirements.txt`.
