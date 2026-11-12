// Linux ELF malware signatures for the custom engine (compiled by EngineSignatures,
// app.engine, scanner name "yara-x-engine"). These are HIGH only when the pattern is a
// documented, specific indicator of malicious construction, never a generic executable trait.
// Entropy, "it is an ELF", ordinary libraries and ordinary syscalls are NOT here; a bare native
// executable is left to the reference rule Native_Executable (MEDIUM -> SUSPICIOUS). Correlation
// (app.engine.correlate) only lets a match here stand as MALICIOUS when the bounded ELF parser
// (app.engine.elf) confirmed a genuine, loadable ELF, and records the structural corroboration.
//
// Validated against inert, in-memory fixtures (tests/elf_fixtures.py, tests/test_elf.py) and, in
// Linux CI, against real benign system binaries for false positives (tests/test_elf_linux.py).
// Authoring/validating signatures for specific malware families against genuine samples is done
// only in the offline research VM (docs/genuine-malware-evaluation-plan.md).

rule ELF_UPX_Tampered_Header
{
    meta:
        description = "ELF carries the UPX decompression stub but its 'UPX!' header magic is absent: a documented way malware blocks 'upx -d' and signature tools while staying self-unpacking. FP risk: a file embedding the UPX banner as data without being packed (covered by tests)."
        category = "packer-evasion"
        severity = "HIGH"
    strings:
        $banner = "This file is packed with the UPX executable packer"
        $stub = "PROT_EXEC|PROT_WRITE failed"   // UPX runtime loader message
        $magic = "UPX!"
    condition:
        uint32(0) == 0x464C457F and ($banner or $stub) and not $magic
}

rule ELF_Inert_Marker_Pipeline
{
    meta:
        description = "Inert research marker that validates the ELF detection pipeline end to end (YARA HIGH + structural corroboration -> MALICIOUS). Matches only the test fixtures' marker (tests/elf_fixtures.py), never real files; carried in the engine rules so the same compiler and scanner exercise the correlation path as for production rules."
        category = "test-marker"
        severity = "HIGH"
    strings:
        $m = "FILESMAGIC-INERT-ELF-MALWARE-MARKER-v1"
    condition:
        uint32(0) == 0x464C457F and $m
}
