"""evaluation/vm/trusted_tree.sh, the interpreter-tree check of guest_checks.sh (Linux: GNU find,
readlink -f). Regression: the Phase 6 check at 6ffd413 counted every symlink as writable (a link's
mode is always 777), so 1053 root-owned links inside /opt/filesmagic made it STOP."""

import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="GNU find/readlink: Linux only")
SCRIPTS = Path(__file__).resolve().parent.parent / "evaluation/vm"


def check(root: Path) -> subprocess.CompletedProcess:
    me = pwd.getpwuid(os.getuid()).pw_name
    return subprocess.run(["bash", str(SCRIPTS / "trusted_tree.sh"), str(root), me],
                          capture_output=True, text=True, timeout=60)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "trusted"
    (root / "lib").mkdir(parents=True)
    (root / "lib/libpython3.11.so.1.0").write_bytes(b"inert")
    (root / "lib/libpython3.11.so").symlink_to("libpython3.11.so.1.0")  # relative, inside
    (root / "bin").mkdir()
    (root / "bin/python").symlink_to(root / "lib/libpython3.11.so.1.0")  # absolute, inside
    (root / "lib/dir-link").symlink_to("..")  # resolves to the root itself
    for p in [root, *root.rglob("*")]:
        if not p.is_symlink():
            p.chmod(0o755 if p.is_dir() else 0o644)
    return root


def test_links_inside_the_tree_are_trusted_whatever_their_mode(tree):
    r = check(tree)
    assert r.returncode == 0, r.stdout
    assert "SUMMARY 0 problem(s)" in r.stdout and "3 symlinks resolved" in r.stdout


@pytest.mark.parametrize("make, problem", [
    (lambda t, out: (t / "lib/gone").symlink_to("missing.so"), "dangling or looping link"),
    (lambda t, out: ((t / "a").symlink_to("b"), (t / "b").symlink_to("a")), "dangling or looping link"),
    (lambda t, out: (t / "lib/etc").symlink_to("/etc/passwd"), "link leaves"),
    (lambda t, out: (t / "lib/up").symlink_to("../../outside.so"), "link leaves"),
    (lambda t, out: (t / "lib/via").symlink_to(out), "link leaves"),  # a directory link out of the tree
    (lambda t, out: (t / "lib/libpython3.11.so.1.0").chmod(0o664), "group- or other-writable"),
    (lambda t, out: (t / "bin").chmod(0o777), "group- or other-writable"),
])
def test_escaping_dangling_or_writable_entries_are_rejected(tree, make, problem):
    outside = tree.parent / "outside.so"
    outside.write_bytes(b"inert")
    make(tree, tree.parent)
    r = check(tree)
    assert r.returncode == 1 and f"PROBLEM {problem}" in r.stdout, r.stdout


def test_a_root_that_is_a_link_or_missing_is_rejected(tree, tmp_path):
    (tmp_path / "alias").symlink_to(tree)
    assert check(tmp_path / "alias").returncode == 1
    assert check(tmp_path / "missing").returncode == 1


def test_guest_checks_uses_it_on_the_interpreter_tree():
    text = (SCRIPTS / "guest_checks.sh").read_text()
    assert 'trusted_tree.sh" /opt/filesmagic root' in text
    assert "-perm /022 -print 2>/dev/null | wc -l" not in text  # the check that counted symlinks
