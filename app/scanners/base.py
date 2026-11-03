"""Contract every scanner (YARA-X, Office analysis, PDF analysis) implements."""

from typing import Protocol

from app.models import Finding


class ScanError(RuntimeError):
    """Raised by a scanner when a file could not be analysed. The message is safe to return.

    Subclass it per scanner and list, in `malformed_causes`, the parser exceptions that mean
    "the input itself is malformed". The worker classifies a ScanError by how it was raised:

      - no ``__cause__``                -> the scanner's own structure/limit check (invalid_structure)
      - ``__cause__`` in malformed_causes -> a parser rejecting hostile/broken input (malformed_input)
      - any other ``__cause__``         -> a possible scanner bug (unexpected)

    Keeping the malformed-input causes here, next to the scanner that knows them, is what lets a
    new scanner (e.g. the planned custom detector) be classified correctly without editing the
    worker. A plain exception that is not a ScanError is always treated as unexpected.
    """

    malformed_causes: tuple[type[BaseException], ...] = ()


class Scanner(Protocol):
    name: str

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        """Analyse the file and return findings; an empty list means nothing was found.

        Return None if the scanner does not handle this file format at all (e.g. the
        Office scanner given a PDF). That is neither a clean result nor a failure; a
        file that no scanner handles is UNABLE_TO_SCAN.

        Raise an exception if the file could not be analysed. The caller records
        that as a failed scan, so a broken scanner can never produce a SAFE verdict.
        """
        ...
