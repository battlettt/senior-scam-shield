"""Command line: paste a message (stdin or file), get a report.

Nothing is written to disk unless you ask for it with --save or --html.
"""

import argparse
import sys

from .report import render_html, render_share_sheet, render_text
from .samples import get_sample, sample_names
from .verdict import analyze


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m senior_scam_shield",
        description="Check a text message, email, or phone call transcript for scam signs. "
                    "Works offline. Nothing you paste is sent or stored.",
    )
    parser.add_argument("file", nargs="?", help="file with the message (default: read from stdin)")
    parser.add_argument("--channel", choices=("auto", "sms", "email", "call"), default="auto",
                        help="what kind of message it is (default: auto-detect)")
    parser.add_argument("--demo", nargs="?", const="all", metavar="NAME",
                        help="run built-in samples (all, or one name from --list-demos)")
    parser.add_argument("--list-demos", action="store_true", help="list built-in samples")
    parser.add_argument("--share-only", action="store_true", help="print only the share sheet")
    parser.add_argument("--save", metavar="PATH", help="also save the text report to this file")
    parser.add_argument("--html", metavar="PATH", help="also save a printable HTML report to this file")
    return parser


def read_input(path):
    if path and path != "-":
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    if sys.stdin.isatty():
        print("Paste the message below. When done, press Ctrl-D "
              "(on Windows: Ctrl-Z, then Enter).\n", file=sys.stderr)
    return sys.stdin.read()


def save_report(path, content):
    """The only place a file is written, and only when the user asks."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"Saved: {path}", file=sys.stderr)


def report_for(analysis, share_only):
    return render_share_sheet(analysis) + "\n" if share_only else render_text(analysis)


def run_demo(name, share_only):
    names = sample_names() if name == "all" else [name]
    for sample in names:
        if sample not in sample_names():
            print(f"Unknown demo '{sample}'. Try: {', '.join(sample_names())}", file=sys.stderr)
            return 2
        channel, _expected, text = get_sample(sample)
        print(f"\n######## DEMO: {sample} ########\n")
        print(report_for(analyze(text, channel), share_only))
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list_demos:
        print("\n".join(sample_names()))
        return 0
    if args.demo:
        return run_demo(args.demo, args.share_only)
    text = read_input(args.file)
    if not text.strip():
        print("No message was given. Paste a message, or try --demo.", file=sys.stderr)
        return 2
    analysis = analyze(text, None if args.channel == "auto" else args.channel)
    print(report_for(analysis, args.share_only), end="")
    if args.save:
        save_report(args.save, render_text(analysis))
    if args.html:
        save_report(args.html, render_html(analysis))
    return 0
