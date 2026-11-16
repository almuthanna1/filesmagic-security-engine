"""Writes manifest.json for the benign corpus: SHA-256, size, producer, ground truth, and the
structural features actually present in each file (read from the bytes, not from the file name).

    python -m evaluation.benign_corpus.manifest
"""

import hashlib
import json
import re
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
PRODUCERS = {"word": "Microsoft Word 16", "excel": "Microsoft Excel 16", "ppt": "Microsoft PowerPoint 16",
             "powerpoint": "Microsoft PowerPoint 16", "libreoffice": "LibreOffice (headless)", "edge": "Microsoft Edge (headless print)"}
PDF_FEATURES = {"JavaScript": rb"/JavaScript|/JS\b", "OpenAction": rb"/OpenAction", "AA": rb"/AA\b", "AcroForm": rb"/AcroForm",
                "EmbeddedFile": rb"/EmbeddedFile", "Launch": rb"/Launch", "URI": rb"/URI\b", "Outlines": rb"/Outlines", "ObjStm": rb"/ObjStm"}


def features(path: Path) -> list[str]:
    data = path.read_bytes()
    if path.suffix == ".pdf":  # not is_zipfile(): a hybrid PDF carries a whole ODF (ZIP) inside
        return [name for name, pattern in PDF_FEATURES.items() if re.search(pattern, data)]
    z = zipfile.ZipFile(path)
    names, found = z.namelist(), set()
    for n in names:
        if "/embeddings/" in n:
            found.add("embedded object")
        if "externalLink" in n:
            found.add("external workbook link part")
        if "pivotCache" in n:
            found.add("pivot cache")
        if "vbaProject" in n:
            found.add("VBA project")
        if n.endswith(".rels"):
            for m in re.finditer(rb'<Relationship [^>]*>', z.read(n)):
                rel = m.group()
                if b'TargetMode="External"' in rel:
                    kind = re.search(rb'Type="[^"]*/([^"/]+)"', rel).group(1).decode()
                    target = re.search(rb'Target="([^"]*)"', rel).group(1).decode()
                    found.add(f"external {kind} -> {target}")
    return sorted(found)


def main() -> None:
    rows = []
    for f in sorted((HERE / "files").iterdir()):
        producer = PRODUCERS[f.stem.split("-")[2]]  # <format>-<nn>-<producer>-...
        rows.append({"file": f.name, "format": f.suffix[1:], "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                     "size_bytes": f.stat().st_size, "producer": producer,
                     "ground_truth": "known-benign (authored here from neutral text by build.ps1; no macros)",
                     "features": features(f)})
    (HERE / "manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
    for r in rows:
        print(f"{r['file']:45} {r['producer']:28} {'; '.join(r['features'])[:110]}")


if __name__ == "__main__":
    main()
