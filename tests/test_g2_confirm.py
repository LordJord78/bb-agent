"""Stage-2 G2 typed-confirmation test, driven through a real pseudo-terminal.

Proves: with active_testing_allowed=true and BB_DRY_RUN=0, the active stage
still refuses to send traffic unless the operator types the exact program name
on the tty. A wrong or empty answer aborts cleanly and writes no output; the
correct name proceeds. The network is stubbed by a fake `httpx` on PATH, so the
"proceeds" case sends nothing real.

Uses pty.fork so the stage's read from /dev/tty is genuinely exercised — the
answer cannot be supplied via stdin, an env var, or a flag.
"""

import os
import pty
import select
import shutil
import signal
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = "g2test"


def _setup():
    (ROOT / "targets" / PROG).mkdir(parents=True, exist_ok=True)
    (ROOT / "targets" / PROG / "scope.yaml").write_text(
        "program: g2test\n"
        "in_scope:\n  - '*.example.com'\n  - example.com\n"
        "out_of_scope: []\n"
        "rate_limit_rps: 2\n"
        "automation_allowed: true\n"
        "active_testing_allowed: true\n"
    )
    recon = ROOT / "recon" / PROG
    recon.mkdir(parents=True, exist_ok=True)
    (recon / "hosts.txt").write_text("www.example.com\napi.example.com\n")
    # Remove any output from a previous case.
    for f in ("probed.jsonl", "alive.txt", "hosts.scoped"):
        (recon / f).unlink(missing_ok=True)
    # Fake httpx so the "proceeds" case touches no network.
    fakebin = Path(tempfile.mkdtemp(prefix="g2fakebin-"))
    httpx = fakebin / "httpx"
    httpx.write_text('#!/usr/bin/env bash\n'
                     'echo \'{"url":"https://www.example.com","host":"www.example.com","status_code":200,"title":"x","tech":[],"cdn":false}\'\n')
    httpx.chmod(0o755)
    return fakebin


def _teardown(fakebin):
    shutil.rmtree(ROOT / "targets" / PROG, ignore_errors=True)
    shutil.rmtree(ROOT / "recon" / PROG, ignore_errors=True)
    shutil.rmtree(fakebin, ignore_errors=True)


def _run_probe(answer: str, fakebin: Path):
    """Run stage2-probe under a pty, type `answer`, return (exit_code, output)."""
    env = dict(os.environ)
    env["PATH"] = f"{fakebin}:{env.get('PATH', '')}"
    env["BB_DRY_RUN"] = "0"
    env["BB_INFERENCE_BACKEND"] = "claude"

    pid, fd = pty.fork()
    if pid == 0:  # child: becomes the stage, with the pty as its controlling tty
        os.chdir(str(ROOT))
        os.execve(str(ROOT / "bin" / "stage2-probe"), ["stage2-probe", PROG], env)
        os._exit(127)  # unreachable

    # parent
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(30)
    out = b""
    try:
        os.write(fd, (answer + "\n").encode())
        while True:
            r, _, _ = select.select([fd], [], [], 10)
            if not r:
                break
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
    except TimeoutError:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("stage hung waiting on the tty prompt")
    finally:
        signal.alarm(0)
        os.close(fd)
    return code, out.decode(errors="replace")


def test_wrong_answer_aborts_without_traffic():
    fakebin = _setup()
    try:
        code, out = _run_probe("not-the-program", fakebin)
        assert code == 4, f"expected abort exit 4, got {code}\n{out}"
        assert "NOT confirmed" in out
        assert not (ROOT / "recon" / PROG / "probed.jsonl").exists(), "probe ran despite wrong answer"
    finally:
        _teardown(fakebin)


def test_empty_answer_aborts_without_traffic():
    fakebin = _setup()
    try:
        code, out = _run_probe("", fakebin)
        assert code == 4, f"expected abort exit 4, got {code}\n{out}"
        assert not (ROOT / "recon" / PROG / "probed.jsonl").exists(), "probe ran despite empty answer"
    finally:
        _teardown(fakebin)


def test_correct_program_name_proceeds():
    fakebin = _setup()
    try:
        code, out = _run_probe(PROG, fakebin)
        assert code == 0, f"expected success exit 0, got {code}\n{out}"
        probed = ROOT / "recon" / PROG / "probed.jsonl"
        assert probed.exists() and probed.stat().st_size > 0, "probe did not run after correct confirmation"
    finally:
        _teardown(fakebin)


def _run():
    passed = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {t.__name__}: {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"pass  {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    raise SystemExit(_run())
