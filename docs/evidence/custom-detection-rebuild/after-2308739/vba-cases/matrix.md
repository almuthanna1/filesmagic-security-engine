# VBA case matrix

| Case | Tests | Expected | After | Baseline b6774be | Rules changed (non-INFO) |
|---|---|---|---|---|---|
| v01-autoopen-calls-shell | automatic entry reaches Shell through a call | MALICIOUS | MALICIOUS | MALICIOUS | none |
| v02-qualified-call-to-shell | Module.Procedure call across modules (module names without olevba's .bas extension) | MALICIOUS | MALICIOUS | MALICIOUS | +vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH |
| v03-entry-and-unrelated-shell | no call path, kept HIGH: P-code may differ from source (never lowered on source alone) | MALICIOUS | MALICIOUS | MALICIOUS | none |
| v04-benign-formatting | harmless macro: macros present is never SAFE | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS | -office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW |
| v05-vbhide-constant-only | olevba listed vbHide as execution; a constant is no operation | SUSPICIOUS | SUSPICIOUS | MALICIOUS | -office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH; -office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM |
| v06-application-run-macro | olevba listed Run as execution; Application.Run starts a macro | SUSPICIOUS | SUSPICIOUS | MALICIOUS | -office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH; -office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM |
| v07-shell32-folder-api | olevba listed shell32 as execution; the declared API decides | SUSPICIOUS | SUSPICIOUS | MALICIOUS | -office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH; -office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM |
| v08-user-shell-procedure | a user procedure named Shell shadows the built-in: only possible | SUSPICIOUS | SUSPICIOUS | MALICIOUS | +office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW; -office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH; -office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM; -vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH |
| v09-strreverse-progid-run | obfuscated ProgID folded statically, method resolved on the object | MALICIOUS | MALICIOUS | MALICIOUS | +office:OFFICE_MACRO_OBFUSCATION:LOW; +vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH; -office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW |
| v10-callbyname-run | dynamic method call with a constant name | MALICIOUS | MALICIOUS | MALICIOUS | +vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH; -office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW |
| v11-xmlhttp-download | download on open | MALICIOUS | MALICIOUS | MALICIOUS | -office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW |
| v12-run-key-persistence | persistence through the Run key | MALICIOUS | MALICIOUS | MALICIOUS | +vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH |
| v13-click-handler-shell | user-triggered entry with execution (trigger kind recorded as user action) | MALICIOUS | MALICIOUS | MALICIOUS | none |
| v14-obj-run-unknown-object | Run on an object of unknown type: possible only | SUSPICIOUS | SUSPICIOUS | MALICIOUS | +office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS:LOW; -office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH; -office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM |
| v15-plain-helper-no-entry | Shell without any entry point: dangerous capability (MEDIUM), not automatic | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS | none |
| v16-legacy-doc | legacy .doc with a Macros storage | MALICIOUS | MALICIOUS | MALICIOUS | none |
