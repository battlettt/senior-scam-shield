import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

from senior_scam_shield import analyze
from senior_scam_shield.cli import main
from senior_scam_shield.samples import get_sample, sample_names


class FakeStdin(io.StringIO):
    def isatty(self):
        return False


def run(argv, stdin=""):
    saved = sys.stdin
    sys.stdin = FakeStdin(stdin)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = saved
    return code, out.getvalue(), err.getvalue()


def test_reads_from_stdin():
    _, _, text = get_sample("sms-scam")
    code, out, _ = run([], text)
    assert code == 0 and "VERDICT:  LIKELY SCAM" in out


def test_reads_from_file_and_channel_flag():
    _, _, text = get_sample("call-legit")
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "msg.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        code, out, _ = run([path, "--channel", "call"])
    assert code == 0 and "VERDICT:  LOOKS SAFE" in out and "A phone call" in out


def test_empty_input_is_a_friendly_error():
    code, out, err = run([], "   ")
    assert code == 2 and out == "" and "--demo" in err


def test_demo_verdicts_match_cli_exactly():
    for name in sample_names():
        channel, _, text = get_sample(name)
        _, demo_out, _ = run(["--demo", name])
        _, stdin_out, _ = run(["--channel", channel], text)
        expected = analyze(text, channel).verdict
        assert f"VERDICT:  {expected}" in demo_out and f"VERDICT:  {expected}" in stdin_out
        assert demo_out.split("########\n\n", 1)[1].rstrip() == stdin_out.rstrip(), name


def test_demo_all_and_list():
    code, out, _ = run(["--demo"])
    assert code == 0 and out.count("SENIOR SCAM SHIELD REPORT") == len(sample_names())
    code, out, _ = run(["--list-demos"])
    assert out.split() == sample_names()
    assert run(["--demo", "nope"])[0] == 2


def test_share_only():
    _, out, _ = run(["--demo", "email-scam", "--share-only"])
    assert "SHARE SHEET" in out and "WHY" not in out


def test_save_and_html_write_only_requested_files():
    _, _, text = get_sample("email-scam")
    with tempfile.TemporaryDirectory() as folder:
        txt, page = os.path.join(folder, "r.txt"), os.path.join(folder, "r.html")
        code, _, _ = run(["--save", txt, "--html", page], text)
        assert code == 0 and sorted(os.listdir(folder)) == ["r.html", "r.txt"]
        with open(page, encoding="utf-8") as handle:
            assert "LIKELY SCAM" in handle.read()
