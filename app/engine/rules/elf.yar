// Linux ELF signatures for the custom engine (compiled by EngineSignatures, app.engine, scanner
// name "yara-x-engine"). HIGH is reserved for validated malicious evidence; no rule here is HIGH
// yet, because none has been validated against genuine samples. Evasion-shaped
// packing (ELF_UPX_Tampered_Header) is MEDIUM: legitimate software also modifies packer headers
// to protect itself, so it is suspicious, not proof, and never makes a file MALICIOUS by itself.
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
        description = "ELF carries the UPX decompression stub but its 'UPX!' header magic is absent: a documented way malware blocks 'upx -d' and signature tools while staying self-unpacking. Commercial protectors and a banner embedded as data look the same, so this is suspicious, not proof of malice."
        category = "packer-evasion"
        severity = "MEDIUM"
    strings:
        $banner = "This file is packed with the UPX executable packer"
        $stub = "PROT_EXEC|PROT_WRITE failed"   // UPX runtime loader message
        $magic = "UPX!"
    condition:
        uint32(0) == 0x464C457F and ($banner or $stub) and not $magic
}
