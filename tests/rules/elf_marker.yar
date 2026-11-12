// TEST-ONLY rule. Never copy into app/rules or app/engine/rules: tests/test_elf.py fails if the
// marker or a HIGH ELF rule appears in a production-loadable rule file.

rule ELF_Inert_Marker_Pipeline
{
    meta:
        description = "Inert research marker that validates the ELF detection pipeline end to end (YARA HIGH + structural corroboration -> MALICIOUS). Matches only the test fixtures' marker (tests/elf_fixtures.py), never real files. Test-only: this file is outside app/, is not in the production image, and no production scanner loads it."
        category = "test-marker"
        severity = "HIGH"
    strings:
        $m = "FILESMAGIC-INERT-ELF-MALWARE-MARKER-v1"
    condition:
        uint32(0) == 0x464C457F and $m
}
