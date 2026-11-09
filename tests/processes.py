"""Has a process ended? Used by the worker-cleanup tests (tests/test_worker_linux.py), which assert
that a worker's grandchildren are gone within a deadline. Linux only (/proc, kill(2)).

The answer is "ended" only when that is shown; a process this test cannot observe is never
reported as ended.

1. /proc/<pid>/stat, the primary observation. No such entry: no process has that PID, so the one
   watched has ended (a PID is reused only after its process is fully reaped). State Z: it has
   exited and waits to be reaped. A reused PID, whatever runs under it, still implies the
   original ended, so neither case can report a living original as ended. Any other state:
   running.
2. Only if that read is refused (PermissionError: under the evaluation VM's AppArmor profile,
   /proc/<pid>/stat of a process whose entry is owned by root, final run 1 at d80a46d), kill(pid,
   0) is the fallback:
   - ESRCH (ProcessLookupError): no process has that PID: ended. The kernel looks the PID up
     before any permission check, AppArmor's included, so this answer does not depend on access.
   - success, or EPERM/EACCES (PermissionError): some process has that PID. It may be the one
     watched, still running, or a zombie (the fallback cannot tell, and a zombie also accepts
     signal 0), or an unrelated process that reused the PID. All count as not ended: the test
     waits, and fails at its deadline if the PID never disappears. Conservative by design.
   Any other error is raised.
"""

import os
from pathlib import Path


def alive(pid: int, proc: Path = Path("/proc"), kill=os.kill) -> bool:
    """True unless the process with this PID is shown to have ended (see the module docstring)."""
    try:
        state = (proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    except PermissionError:
        try:
            kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    return state != "Z"
