"""Local-only safety: no network, no files, no live links, no storage code."""

import ast
import builtins
import io
import os
import re
import socket
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

from senior_scam_shield import analyze
from senior_scam_shield.cli import main
from senior_scam_shield.report import render_html, render_share_sheet, render_text
from senior_scam_shield.samples import get_sample, sample_names
from senior_scam_shield.urls import looks_like_email, looks_like_url, strip_edges
from tests.test_adversarial import PAIRS, make_twin

PACKAGE = Path(__file__).resolve().parent.parent / "senior_scam_shield"


def all_messages():
    for name in sample_names():
        channel, _, text = get_sample(name)
        yield channel, text
    for _, channel, legit, replacements in PAIRS:
        yield channel, legit
        yield channel, make_twin(legit, replacements)


def render_all(analysis):
    return render_text(analysis) + render_share_sheet(analysis) + render_html(analysis)


class NetworkBlocked(Exception):
    pass


def run_with_sockets_blocked(work):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise NetworkBlocked("network used during analysis")

    saved = (socket.socket, socket.create_connection, socket.getaddrinfo)
    socket.socket = socket.create_connection = socket.getaddrinfo = refuse
    try:
        work()
    finally:
        socket.socket, socket.create_connection, socket.getaddrinfo = saved
    return attempts


def test_analysis_works_with_sockets_blocked():
    def work():
        for channel, text in all_messages():
            render_all(analyze(text, channel))
    assert run_with_sockets_blocked(work) == []


def test_cli_demo_works_with_sockets_blocked():
    def work():
        with redirect_stdout(io.StringIO()):
            assert main(["--demo"]) == 0
    assert run_with_sockets_blocked(work) == []


def test_no_files_written_per_analysis_run():
    writes = []
    real_open = builtins.open

    def watching_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wax+"):
            writes.append(file)
        return real_open(file, mode, *args, **kwargs)

    with tempfile.TemporaryDirectory() as folder:
        before = os.getcwd()
        os.chdir(folder)
        builtins.open = watching_open
        try:
            for channel, text in all_messages():
                render_all(analyze(text, channel))
            with redirect_stdout(io.StringIO()):
                main(["--demo"])
        finally:
            builtins.open = real_open
            os.chdir(before)
        assert os.listdir(folder) == []
    assert writes == []


def live_links_in(text):
    """Tokens a person or a mail app could click."""
    found = []
    for raw in re.findall(r"\S+", text):
        token = strip_edges(raw)
        if looks_like_url(token) or looks_like_email(token):
            found.append(token)
    found += re.findall(r"(?i)\b(?:https?|ftp)://", text)
    found += re.findall(r"(?i)\bwww\.", text)
    found += re.findall(r"(?i)\b[a-z0-9-]+\.(?:com|net|org|gov|info|top|ly|ru|xyz|help)\b", text)
    return found


def test_output_contains_no_live_links():
    for channel, text in all_messages():
        output = render_all(analyze(text, channel))
        assert live_links_in(output) == [], live_links_in(output)[:5]


def test_output_defangs_links_from_every_place_they_appear():
    raw = ("From: Chase <alerts@chase-help.example.com>\nSubject: visit chase-help.example.com\n\n"
           '<a href="http://203.0.113.9/login">www.chase.com</a> and https://bit.ly/x')
    output = render_all(analyze(raw))
    assert live_links_in(output) == []
    assert "203[.]0[.]113[.]9" in output and "hxxp" in output


BANNED_IMPORTS = {"socket", "http", "urllib.request", "requests", "ftplib", "smtplib",
                  "telnetlib", "ssl", "asyncio", "logging", "sqlite3", "shelve",
                  "pickle", "dbm", "tempfile", "shutil", "subprocess", "webbrowser"}
WRITE_CALLS = {"open", "write_text", "write_bytes", "mkdir", "makedirs", "dump"}


def module_trees():
    for path in sorted(PACKAGE.glob("*.py")):
        yield path.name, ast.parse(path.read_text(encoding="utf-8"))


def test_source_has_no_network_or_storage_imports():
    for name, tree in module_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert module not in BANNED_IMPORTS and module.split(".")[0] not in {
                    "socket", "http", "requests", "logging", "sqlite3", "pickle"}, (name, module)


def test_only_the_cli_reads_or_writes_files():
    for name, tree in module_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if called in WRITE_CALLS:
                    assert name == "cli.py", (name, called)


def test_cli_writes_only_inside_save_report():
    tree = ast.parse((PACKAGE / "cli.py").read_text(encoding="utf-8"))
    for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
                modes = [a.value for a in node.args[1:] if isinstance(a, ast.Constant)]
                if function.name != "save_report":
                    assert not any("w" in m or "a" in m for m in modes), function.name


def test_source_has_no_network_strings():
    pattern = re.compile(r"urlopen|create_connection|getaddrinfo|socket\.|\.connect\(|print\(.*raw")
    for path in PACKAGE.glob("*.py"):
        assert not pattern.search(path.read_text(encoding="utf-8")), path.name
