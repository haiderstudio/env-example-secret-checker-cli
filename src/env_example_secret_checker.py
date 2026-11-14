#!/usr/bin/env python3
"""Check .env.example files for secret-looking values.

Run: python3 src/env_example_secret_checker.py .env.example
     python3 src/env_example_secret_checker.py project/
     python3 src/env_example_secret_checker.py --stdin < .env.example

An example file is meant to hold placeholders, but people
paste a real key into it "just to test" and commit it — and
because the file is named .example, nobody scans it. This
tool reads only the committed example file, checks every
value in it, and reports each line that looks like a real
secret, with the file and the line number. It exits 1 when
any line looks like a real secret, so it can fail a CI run.
A file whose values are all placeholders exits 0.

It never reads a real .env file. A folder walk checks only
files whose name ends in .env.example, and a real .env
passed on the command line is refused outright. A real
.env file sitting next to the example is never opened,
even when it holds a real key.

Values are never printed. A finding names the key, the
file, and the line, and says why the value looks real —
the value itself stays out of the report, so the report
is safe to paste into a CI log or an issue.

A value counts as a placeholder when it is empty, or it
is one of the usual placeholder words (your-key-here,
changeme, xxx, and friends), or it is wrapped in angle
brackets or ${...}, or it starts with a word like your-,
insert-, replace-, or demo-. A value counts as a real
secret when it matches a known key format (an AWS key,
a GitHub token, a Slack token, a Google API key, a
Stripe key, an OpenAI key, an Anthropic key, a JWT, or
a private key block), or when it is a long random-looking
string in a secret-named key, or a long random-looking
string anywhere. A short value that matches no known
format is left alone: the tool cannot tell a short real
password from a word, so it only flags what it can
prove looks real. A password hidden inside a database
URL is checked the same way, after the placeholder
test.

It never rewrites a file, never touches the network, and
reads only the files and folders you point it at.
"""

import argparse
import fnmatch
import json
import math
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

__version__ = "1.0.0"

EXAMPLE_SUFFIX = ".env.example"

# Known secret formats: (id, pattern, human reason).
# The patterns match the shape of a real key, never a
# placeholder — placeholders are filtered out first.
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"),
     "looks like a real AWS access key"),
    ("github-token", re.compile(
        r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
     "looks like a real GitHub token"),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
     "looks like a real Slack token"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}"),
     "looks like a real Google API key"),
    ("stripe-key", re.compile(
        r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
     "looks like a real Stripe key"),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
     "looks like a real Anthropic API key"),
    ("openai-key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
     "looks like a real OpenAI API key"),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."
        r"[A-Za-z0-9_-]{10,}"),
     "looks like a real JWT"),
    ("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "looks like a real private key"),
]

PLACEHOLDER_WORDS = {
    "changeme", "change-me", "change_me", "xxx", "xxxx",
    "placeholder", "example", "dummy", "sample", "test",
    "none", "null", "todo", "fixme", "your-key-here",
    "your_key_here", "your-api-key", "your_api_key",
    "your-api-key-here", "your_api_key_here",
    "your-secret-here", "your_secret_here",
    "your-password-here", "your_password_here",
    "your-token-here", "your_token_here",
    "your-value-here", "your_value_here",
    "your-secret-key-here", "your_secret_key_here",
    "your-access-key", "your_access_key",
    "your-access-key-here", "your_access_key_here",
    "replace-me", "replace_me", "your-key", "your_key",
    "yourkey", "yourkeyhere", "your-secret", "your_secret",
    "your-password", "your_password", "your-token",
    "your_token", "your-value", "your_value",
    "insert-your-key-here", "enter-your-key-here",
    "123456", "password", "secret",
}

PLACEHOLDER_PREFIXES = (
    "your-", "your_", "my-", "my_", "insert-", "insert_",
    "enter-", "enter_", "replace-", "replace_", "sample-",
    "sample_", "demo-", "demo_", "fake-", "fake_",
    "dummy-", "dummy_", "example-", "example_", "change-",
    "change_", "test-", "test_", "placeholder-",
    "placeholder_",
)

PLACEHOLDER_SUBSTRINGS = (
    "your-key", "your_key", "yourkey", "your-secret",
    "your_secret", "your-password", "your_password",
    "your-token", "your_token", "changeme", "change-me",
    "change_me", "placeholder", "insecure",
)

SECRET_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|"
    r"API[-_]?KEY|ACCESS[-_]?KEY)", re.IGNORECASE)

HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
RANDOM_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")


def shannon_entropy(text):
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(value):
    """True when a value is clearly a placeholder, not a secret."""
    v = value.strip().lower()
    if v == "":
        return True
    if v in PLACEHOLDER_WORDS:
        return True
    if len(v) >= 2 and (
            (v.startswith("<") and v.endswith(">"))
            or (v.startswith("${") and v.endswith("}"))
            or (v.startswith("[") and v.endswith("]"))):
        return True
    if v.startswith(PLACEHOLDER_PREFIXES):
        return True
    for word in PLACEHOLDER_SUBSTRINGS:
        if word in v:
            return True
    if re.fullmatch(r"x+", v) or re.fullmatch(r"\*+", v):
        return True
    if len(v) >= 8 and (
            v in "abcdefghijklmnopqrstuvwxyz"
            or v in "0123456789"
            or v in "abcdefghijklmnopqrstuvwxyz0123456789"
            or v in "0123456789abcdefghijklmnopqrstuvwxyz"):
        return True
    return False


def _check_url_password(value):
    """Flag a real-looking password inside a URL, or None.

    Only the password part of scheme://user:password@host is
    judged, and only when it is long or high-entropy enough
    to look real. A placeholder password passes.
    """
    if "://" not in value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    password = parts.password
    if not password:
        return None
    if is_placeholder(password):
        return None
    if len(password) >= 12 and shannon_entropy(password) >= 3.8:
        return "has a real-looking password inside a URL"
    for _id, pattern, _reason in SECRET_PATTERNS:
        if pattern.search(password):
            return "has a real-looking password inside a URL"
    return None


def check_value(key, value):
    """Return a reason the value looks like a real secret, or None.

    Placeholders pass. Known key formats are flagged at any
    length. A long random-looking value is flagged when its
    key name says secret, or when it is long enough to be a
    token on its own. A short value that matches no known
    format passes — the tool cannot tell a short real
    password from a word.
    """
    if value is None or value == "":
        return None
    if is_placeholder(value):
        return None
    for _id, pattern, reason in SECRET_PATTERNS:
        if pattern.search(value):
            return reason
    url_reason = _check_url_password(value)
    if url_reason:
        return url_reason
    if len(value) >= 16 and SECRET_NAME_RE.search(key or ""):
        if shannon_entropy(value) >= 4.0:
            return ("has a long random-looking value in a "
                    "secret-named key")
    if len(value) >= 32 and RANDOM_CHARS_RE.match(value):
        if HEX_RE.match(value) or shannon_entropy(value) >= 4.3:
            return "has a long random-looking value"
    return None


def parse_line(line):
    """Split one line into (key, value) or (None, None) to skip.

    Blank lines, comments, and lines with no '=' carry no
    value and are skipped. An 'export ' prefix is allowed.
    A quoted value keeps what is inside the quotes; an
    unquoted value loses a trailing ' # comment'. The
    value is returned unstripped of its quotes' content
    only — surrounding spaces are removed.
    """
    stripped = line.strip()
    if stripped == "" or stripped.startswith("#"):
        return None, None
    if stripped.startswith("export "):
        stripped = stripped[len("export "):].strip()
    if "=" not in stripped:
        return None, None
    key, raw = stripped.split("=", 1)
    key = key.strip()
    if key == "":
        return None, None
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        if end != -1:
            return key, raw[1:end]
        return key, raw[1:]
    if raw.startswith("#"):
        return key, ""
    if " #" in raw:
        raw = raw.split(" #", 1)[0].rstrip()
    return key, raw


def check_text(text):
    """Check one document's text.

    Returns a list of findings, each {"line": int, "key": str,
    "reason": str}, in document order. The value is never
    included in a finding, so a report is safe to share.
    """
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        key, value = parse_line(line)
        if key is None:
            continue
        reason = check_value(key, value)
        if reason:
            findings.append({"line": number, "key": key,
                             "reason": reason})
    return findings


def check_file(path):
    """Check one file. Returns (findings, error)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [], "not valid UTF-8"
    except OSError as exc:
        return [], str(exc)
    return check_text(text), None


def _is_real_env_file(path):
    """True when a path names a real env file, not an example.

    A file called .env, or ending in .env, is a real env
    file. A file ending in .env.example is the example and
    is safe to check.
    """
    name = Path(path).name
    if name.endswith(EXAMPLE_SUFFIX):
        return False
    return (name == ".env" or name.startswith(".env")
            or name.endswith(".env"))


def _is_example_file(path):
    return Path(path).name.endswith(EXAMPLE_SUFFIX)


def collect_files(paths, recursive=True, exclude=None):
    """Expand CLI paths into a sorted list of example files.

    A file given directly is always checked, whatever its
    name — except a real .env file, which is refused. A
    folder is walked for files ending in .env.example only;
    a real .env sitting in that folder is never opened.
    .git folders are never walked, and directory links are
    never followed.
    """
    exclude = exclude or []
    found = []
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            if _is_real_env_file(path):
                raise ValueError(
                    "refusing to read a real .env file: %s "
                    "(check .env.example files only)" % raw)
            found.append(str(path))
        elif path.is_dir():
            root = str(path)
            for dirpath, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = [
                    d for d in dirs
                    if d != ".git"
                    and not any(fnmatch.fnmatch(d, pat) for pat in exclude)
                ]
                for name in files:
                    candidate = Path(dirpath) / name
                    if not _is_example_file(candidate):
                        continue
                    if any(
                        fnmatch.fnmatch(str(candidate), pat)
                        or fnmatch.fnmatch(name, pat)
                        for pat in exclude
                    ):
                        continue
                    found.append(str(candidate))
                if not recursive:
                    break
        else:
            raise FileNotFoundError("no such file or folder: %s" % raw)
    seen = set()
    unique = []
    for item in found:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return sorted(unique)


def format_finding(path, finding):
    """One human-readable line for one suspect value.

    The value is never printed — only the key, the line,
    and the reason.
    """
    return ("FAIL %s: %s line %d %s — replace it with a "
            "placeholder" % (path, finding["key"],
                             finding["line"], finding["reason"]))


def run(paths, recursive=True, exclude=None, as_json=False):
    """Check paths, print the report, return the exit code."""
    try:
        files = collect_files(paths, recursive=recursive, exclude=exclude)
    except (FileNotFoundError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if not files:
        print("error: no .env.example files found", file=sys.stderr)
        return 2
    results = []
    findings = 0
    files_with_findings = 0
    for path in files:
        bad, error = check_file(path)
        count = len(bad) + (1 if error else 0)
        if count:
            findings += count
            files_with_findings += 1
        results.append({"path": path, "findings": bad, "error": error})
    if as_json:
        print(json.dumps(
            {"files": results, "checked": len(files),
             "findings": findings},
            indent=2))
    else:
        for result in results:
            if result["error"]:
                print("FAIL %s: %s" % (result["path"], result["error"]))
            for finding in result["findings"]:
                print(format_finding(result["path"], finding))
        if findings:
            print("Checked %d file(s), %d suspect value(s) in %d "
                  "file(s)." % (len(files), findings,
                                files_with_findings))
        else:
            print("OK — %d file(s) checked, every value in the "
                  "example file is a placeholder." % len(files))
    return 1 if findings else 0


def run_stdin(as_json=False):
    """Check one example document read from standard input."""
    text = sys.stdin.read()
    bad = check_text(text)
    findings = len(bad)
    if as_json:
        print(json.dumps(
            {"files": [{"path": "<stdin>", "findings": bad,
                        "error": None}],
             "checked": 1, "findings": findings},
            indent=2))
    else:
        for finding in bad:
            print(format_finding("<stdin>", finding))
        if findings:
            print("Checked 1 file(s), %d suspect value(s) in 1 "
                  "file(s)." % findings)
        else:
            print("OK — 1 file(s) checked, every value in the "
                  "example file is a placeholder.")
    return 1 if findings else 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="env_example_secret_checker",
        description="Check .env.example files for secret-looking "
                    "values, fail CI when one is found. Never reads "
                    "a real .env file.")
    parser.add_argument("paths", nargs="*",
                        help=".env.example files or folders to walk")
    parser.add_argument("--no-recursive", action="store_true",
                        help="do not walk into subfolders")
    parser.add_argument("--exclude", action="append", default=[],
                        help="skip files or folders matching this pattern "
                             "(repeatable)")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON")
    parser.add_argument("--stdin", action="store_true",
                        help="check one .env.example document from "
                             "standard input")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    args = parser.parse_args(argv)
    if args.stdin:
        if args.paths:
            parser.error("--stdin takes no file or folder arguments")
        return run_stdin(as_json=args.json)
    if not args.paths:
        parser.error("give at least one .env.example file or folder")
    return run(args.paths, recursive=not args.no_recursive,
               exclude=args.exclude, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
