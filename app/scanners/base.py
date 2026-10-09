"""Contract every scanner (YARA-X, Office analysis, PDF analysis) implements."""

from typing import Protocol

from app.models import Finding


class Scanner(Protocol):
    name: str

    def scan(self, filename: str, data: bytes) -> list[Finding]:
        """Analyse the file and return findings; an empty list means nothing was found.

        Raise an exception if the file could not be analysed. The caller records
        that as a failed scan, so a broken scanner can never produce a SAFE verdict.
        """
        ...
