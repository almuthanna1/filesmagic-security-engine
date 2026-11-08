"""Does an Office relationship target name a local drive path? (custom engine)

The Office scanner gives every file: target OFFICE_EXTERNAL_NETWORK_PATH, because a UNC path or a
file URI with a host makes Windows contact that host and can send the user's credentials. A drive
path names no host. This test accepts only unambiguous drive paths, the DOS forms of RFC 8089
Appendix E.2, and nothing else:

    C:\\dir\\f, C:/dir/f                   no scheme
    file:C:/dir/f                          E.2, no authority
    file:/C:/dir/f                         E.2
    file:///C:/dir/f, file:///C:\\dir\\f    E.2, empty authority (Word writes backslashes)
    file://localhost/C:/dir/f              section 2: "localhost" is the local machine

Everything else is not local, so its finding stands: UNC (\\\\host\\share, //host/share,
file:////host/share as in E.3.2, file://host/share), device paths (\\\\?\\, \\\\.\\), file://C:/f
(is "C:" an authority or a drive?), the historic file:///C|/f (E.2.2), a drive letter written
percent-encoded, a percent-decoded path that still has escapes (double encoding) or is not UTF-8,
control characters, a second colon (another drive or an NTFS stream), a separator straight after the
drive (C://host), surrounding whitespace, relative and rooted paths. Rejecting is always safe:
it only means the reference finding is not superseded.
"""

import re
from urllib.parse import unquote_to_bytes

_DRIVE_PATH = re.compile(r"(?:file:(?://(?:localhost)?/|/)?)?[A-Za-z]:[\\/](.*)", re.IGNORECASE | re.DOTALL)
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f:|]")


def local_drive_path(target: str) -> bool:
    """True only for an unambiguous local drive path (see the module docstring)."""
    match = _DRIVE_PATH.fullmatch(target)
    if not match or target != target.strip():
        return False
    rest = match.group(1)
    try:
        path = unquote_to_bytes(rest).decode("utf-8") if target.lower().startswith("file:") else rest
    except UnicodeDecodeError:
        return False
    return not (_ESCAPE.search(path) or _UNSAFE.search(path) or path.startswith(("/", "\\")))
