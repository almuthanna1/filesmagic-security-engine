"""tests/processes.alive: a process is reported ended only when that is shown, never when it
cannot be observed. Fake /proc entries and a fake kill(), so this runs on every platform (on
Windows os.kill(pid, 0) would terminate the process). The same function on real processes:
tests/test_worker_linux.py."""

import errno

import pytest

from tests.processes import alive

PID = 4242


def stat(tmp_path, state: str, comm: str = "sleep"):
    (tmp_path / str(PID)).mkdir()
    (tmp_path / str(PID) / "stat").write_text(f"{PID} ({comm}) {state} 1 1 1 0 -1 4194560 0 0\n")
    return tmp_path


class Denied:
    """A /proc whose stat entries raise `error` when read (default: refused, as under the VM's
    AppArmor profile)."""

    def __init__(self, error: OSError = PermissionError(errno.EACCES, "Permission denied")):
        self.error = error

    def __truediv__(self, _):
        return self

    def read_text(self):
        raise self.error


def kill_raising(error):
    def kill(pid, sig):
        assert (pid, sig) == (PID, 0)  # only ever signal 0: nothing is sent
        if error:
            raise error
    return kill


def never_called(pid, sig):
    raise AssertionError("kill() used although /proc was readable")


@pytest.mark.parametrize("state, expected", [("S", True), ("R", True), ("D", True), ("T", True), ("Z", False)])
def test_a_readable_stat_decides(tmp_path, state, expected):
    assert alive(PID, stat(tmp_path, state), kill=never_called) is expected


def test_a_command_name_with_parentheses_and_spaces_is_parsed(tmp_path):
    assert alive(PID, stat(tmp_path, "S", comm="a) Z (b"), kill=never_called) is True


def test_no_proc_entry_means_ended(tmp_path):
    assert alive(PID, tmp_path, kill=never_called) is False


def test_a_reused_pid_running_something_else_is_not_reported_ended(tmp_path):
    # The original is gone, but another process now has its PID: the answer is "not ended", so
    # the test can only fail, never pass wrongly.
    assert alive(PID, stat(tmp_path, "S", comm="unrelated"), kill=never_called) is True


@pytest.mark.parametrize("error, expected", [
    (ProcessLookupError(errno.ESRCH, "No such process"), False),  # no process has the PID: ended
    (PermissionError(errno.EPERM, "Operation not permitted"), True),  # exists, not ours to signal
    (PermissionError(errno.EACCES, "Permission denied"), True),  # an LSM refused the signal
    (None, True),  # signal 0 accepted: exists (running, or a zombie the fallback cannot tell)
])
def test_the_fallback_reports_ended_only_on_esrch(error, expected):
    assert alive(PID, Denied(), kill=kill_raising(error)) is expected


def test_any_other_error_is_raised_not_guessed():
    with pytest.raises(OSError, match="Invalid argument"):
        alive(PID, Denied(), kill=kill_raising(OSError(errno.EINVAL, "Invalid argument")))
    with pytest.raises(IsADirectoryError):  # /proc unreadable for a reason other than refusal
        alive(PID, Denied(IsADirectoryError(errno.EISDIR, "Is a directory")), kill=never_called)
