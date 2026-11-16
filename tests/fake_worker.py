"""Misbehaving stand-ins for app.worker, run as `python -m tests.fake_worker <mode> [arg]`."""

import json
import os
import subprocess
import sys
import time

mode = sys.argv[1]
sys.stdin.buffer.read()
if mode == "sleep":
    time.sleep(60)
elif mode == "crash":
    sys.exit(1)
elif mode == "flood":
    while True:
        sys.stdout.buffer.write(b"x" * 65536)
elif mode == "garbage":
    sys.stdout.write("not json")
elif mode == "segv":  # a real native crash, like a memory-safety bug in a parser
    import ctypes

    ctypes.string_at(0)
elif mode in ("spawn-sleep", "spawn-exit"):  # leaves a grandchild behind; argv[2] receives its PID
    child = subprocess.Popen(["sleep", "60"])
    with open(sys.argv[2], "w") as f:
        f.write(str(child.pid))
    if mode == "spawn-sleep":
        time.sleep(60)
elif mode == "env":
    sys.stdout.write(json.dumps(sorted(os.environ)))
