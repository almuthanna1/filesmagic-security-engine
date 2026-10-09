"""Contract every scanner (YARA-X, Office analysis, PDF analysis) implements."""

from typing import Protocol

from app.models import Finding


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
