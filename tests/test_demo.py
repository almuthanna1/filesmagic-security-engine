from evaluation import demo


def test_the_capstone_demonstrations_still_reach_their_verdicts(capsys):
    got = {name: demo.show(name, data) for _, files in demo.DEMOS.values() for name, data in files}
    assert got == {
        "auto-js-unrelated-attachment.pdf": "SUSPICIOUS", "auto-js-exports-attachment.pdf": "MALICIOUS",
        "v04-benign-formatting.docm": "SUSPICIOUS", "v01-autoopen-calls-shell.docm": "MALICIOUS",
        "v09-strreverse-progid-run.docm": "MALICIOUS",
        "hyperlink.docx": "SAFE", "external-template.docx": "SUSPICIOUS", "ddeauto-field.docx": "MALICIOUS",
    }
