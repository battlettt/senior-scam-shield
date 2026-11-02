"""Senior-first reports: plain text, a printable HTML page, and a share sheet.

Order is always: verdict, confidence, reasons, what to do, share sheet.
Every link, website name, and email address is defanged before output.
"""

import html
import textwrap

from .models import severity_label
from .urls import defang_text
from .verdict import LIKELY_SCAM, LOOKS_SAFE, SUSPICIOUS

WIDTH = 64
INDENT = "   "

VERDICT_MEANING = {
    LIKELY_SCAM: "This message is very likely a scam. Do not act on it.",
    SUSPICIOUS: "This message has warning signs. Check it before you do anything.",
    LOOKS_SAFE: "We did not find scam signs. That is not a promise.",
}
CONFIDENCE_MEANING = {
    "High": "We are quite sure.",
    "Medium": "We are fairly sure, but not completely.",
    "Low": "We are not sure.",
}
CHANNEL_NAMES = {"sms": "A text message", "email": "An email", "call": "A phone call"}
MAX_SHARED_REASONS = 3


def wrap(text, indent=INDENT, first=None):
    first = indent if first is None else first
    return textwrap.fill(defang_text(" ".join(text.split())), WIDTH, initial_indent=first,
                         subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False)


def heading(title, char="="):
    return f"{char * WIDTH}\n  {title}\n{char * WIDTH}"


def excerpt(analysis, limit=160):
    """The start of the message, cut between words so no link is cut in half."""
    body = " ".join(analysis.message.body.split())
    if len(body) <= limit:
        return body
    return body[:limit].rsplit(" ", 1)[0].rstrip() + " ..."


def reason_blocks(analysis):
    """(label, reason, explain, evidence) for each signal, most serious first."""
    return [(severity_label(s.weight), s.reason, s.explain, s.evidence) for s in analysis.signals]


# ----- plain text ----------------------------------------------------------

def text_reasons(analysis):
    blocks = reason_blocks(analysis)
    if not blocks:
        return [wrap("We did not find any warning signs.")]
    lines = []
    for number, (label, reason, explain, evidence) in enumerate(blocks, 1):
        lines.append(wrap(f"{number}. [{label}] {reason}", indent="      ", first=INDENT))
        lines.append(wrap(explain, indent="      "))
        if evidence:
            lines.append(wrap(f"What we found: {evidence}", indent="      "))
        lines.append("")
    return lines[:-1]


def text_steps(analysis):
    return [wrap(f"* {step}", indent="     ", first=INDENT) for step in analysis.next_steps]


def render_share_sheet(analysis):
    m = analysis.message
    lines = [heading("SHARE SHEET - for a family member or friend I trust"), ""]
    lines.append(wrap("Hello. I received this and checked it with Senior Scam Shield. "
                      "Can you help me look at it?"))
    lines += ["", "  WHAT I RECEIVED", ""]
    lines.append(wrap(f"{CHANNEL_NAMES[m.channel]}, from: {m.sender or 'unknown sender'}"))
    if analysis.claimed_brand:
        lines.append(wrap(f"It says it is from: {analysis.claimed_brand}"))
    if m.subject:
        lines.append(wrap(f"Subject: {m.subject}"))
    lines.append(wrap(f'It starts: "{excerpt(analysis)}"'))
    lines += ["", "  WHAT THE TOOL FOUND", ""]
    lines.append(wrap(f"{analysis.verdict} (how sure: {analysis.confidence})"))
    for signal in analysis.signals[:MAX_SHARED_REASONS]:
        lines.append(wrap(f"- {signal.reason}", indent="     ", first=INDENT))
    if not analysis.signals:
        lines.append(wrap("- No warning signs found."))
    lines += ["", "  WHAT TO DO", ""]
    for step in analysis.next_steps[:3]:
        lines.append(wrap(f"- {step}", indent="     ", first=INDENT))
    lines += ["", wrap("Note: sender names and numbers can be faked. This check ran "
                       "only on my own device. Nothing was sent anywhere.")]
    return defang_text("\n".join(lines))


def render_text(analysis, include_share_sheet=True):
    lines = [heading("SENIOR SCAM SHIELD REPORT"), ""]
    lines.append(f"  VERDICT:  {analysis.verdict}")
    lines += ["", wrap(VERDICT_MEANING[analysis.verdict]), ""]
    lines.append(f"  HOW SURE WE ARE:  {analysis.confidence}")
    lines += ["", wrap(CONFIDENCE_MEANING[analysis.confidence])]
    for note in analysis.uncertainty:
        lines.append(wrap(f"- {note}", indent="     ", first=INDENT))
    lines += ["", heading("WHY  (most serious first)", "-"), ""]
    lines += text_reasons(analysis)
    lines += ["", heading("WHAT TO DO NOW", "-"), ""]
    lines += text_steps(analysis)
    text = defang_text("\n".join(lines)) + "\n"
    if include_share_sheet:
        text += "\n\n" + render_share_sheet(analysis) + "\n"
    return text


# ----- printable HTML ------------------------------------------------------

CSS = """
body { font-family: Georgia, 'Times New Roman', serif; font-size: 22px;
       line-height: 1.6; max-width: 46em; margin: 1.5em auto; padding: 0 1em;
       color: #111; background: #fff; }
h1 { font-size: 1.6em; margin-bottom: 0.2em; }
h2 { font-size: 1.3em; border-bottom: 3px solid #111; margin-top: 1.6em; }
.verdict { font-size: 1.8em; font-weight: bold; border: 5px solid #111;
           padding: 0.4em 0.6em; margin: 0.6em 0; }
.LIKELY-SCAM { border-color: #b00020; color: #b00020; }
.SUSPICIOUS { border-color: #8a5a00; color: #8a5a00; }
.LOOKS-SAFE { border-color: #1b5e20; color: #1b5e20; }
.label { font-weight: bold; }
li { margin-bottom: 0.8em; }
.found { font-style: italic; }
.share { border: 3px dashed #111; padding: 0.2em 1em 1em; margin-top: 2em;
         page-break-before: always; }
@media print { body { font-size: 16pt; margin: 0; max-width: none; }
               .share { page-break-before: always; } }
"""


def esc(text):
    return html.escape(defang_text(text))


def html_reasons(analysis):
    if not analysis.signals:
        return "<p>We did not find any warning signs.</p>"
    items = []
    for label, reason, explain, evidence in reason_blocks(analysis):
        found = f'<br><span class="found">What we found: {esc(evidence)}</span>' if evidence else ""
        items.append(f'<li><span class="label">[{esc(label)}]</span> {esc(reason)}'
                     f"<br>{esc(explain)}{found}</li>")
    return "<ol>\n" + "\n".join(items) + "\n</ol>"


def render_html(analysis):
    """A self-contained page: no scripts, no links, no outside files."""
    css_class = analysis.verdict.replace(" ", "-")
    notes = "".join(f"<li>{esc(note)}</li>" for note in analysis.uncertainty)
    steps = "".join(f"<li>{esc(step)}</li>" for step in analysis.next_steps)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Senior Scam Shield report</title>
<style>{CSS}</style>
</head>
<body>
<h1>Senior Scam Shield report</h1>
<h2>Verdict</h2>
<div class="verdict {css_class}">{esc(analysis.verdict)}</div>
<p>{esc(VERDICT_MEANING[analysis.verdict])}</p>
<h2>How sure we are: {esc(analysis.confidence)}</h2>
<p>{esc(CONFIDENCE_MEANING[analysis.confidence])}</p>
<ul>{notes}</ul>
<h2>Why (most serious first)</h2>
{html_reasons(analysis)}
<h2>What to do now</h2>
<ul>{steps}</ul>
<div class="share">
<h2>Share sheet</h2>
<pre style="font-size:0.85em; white-space:pre-wrap;">{html.escape(render_share_sheet(analysis))}</pre>
</div>
</body>
</html>
"""
