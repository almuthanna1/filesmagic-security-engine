import pytest

from app.engine.file_paths import local_drive_path

LOCAL = [
    r"file:///C:\tmp\fm-benign\chart.png",  # what Word writes for "Link to File"
    "file:///c:/Users/x/report.xlsx", "file:C:/x/y.png", "file:/C:/x/y.png", "file://localhost/C:/x/y.png",
    "FILE:///D:/Shared Docs/a.dotx", "file:///C:/My%20Documents/a.png", r"C:\Templates\committee.dotx", "C:/x.png",
]
NOT_LOCAL = [
    r"\\server\share\x.png", "//server/share/x.png", "file://server/share/x.png", "file:////server/share/x.png",
    r"file:\\server\share\x.png", r"file:///\\server\share\x.png", "file:///%5C%5Cserver%5Cshare%5Cx.png",
    r"\\?\C:\x.png", r"\\.\C:\x.png", "file://C:/x.png", "file:///C|/x.png", "file:///C%3A/x.png",
    "file:///C:/a%2541.png",  # %25 decodes to %, leaving "%41": double encoding
    "file:///C:/%FF.png", "file:///C:/x%00.png", "file:///C:/x.png:stream", "file:///C:/x/D:/y",
    "file:///C://server/share", r"C:\\server\share", " file:///C:/x.png", "file:///C:/x.png ",
    "C:x.png", "/tmp/x.png", "../x.png", "x.png", "file:///tmp/x.png", "http://example.com/x.png",
    "https://example.com/C:/x.png", "smb://server/share", "", "file:",
]


@pytest.mark.parametrize("target", LOCAL)
def test_unambiguous_drive_paths_are_local(target):
    assert local_drive_path(target)


@pytest.mark.parametrize("target", NOT_LOCAL)
def test_hosts_and_ambiguous_forms_are_not_local(target):
    assert not local_drive_path(target)
