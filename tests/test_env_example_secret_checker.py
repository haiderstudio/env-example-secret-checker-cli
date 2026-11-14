#!/usr/bin/env python3
"""Tests for env_example_secret_checker — stdlib unittest only.

Every secret-looking value in this file is FAKE, made up
for testing: the AWS key is the one from the AWS docs,
the GitHub token is twenty A letters, the Stripe key is
the one from the Stripe docs, the JWT is the jwt.io
example, and every random-looking string was invented
here. No real secret appears anywhere in this file.
"""

import ast
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import env_example_secret_checker as checker

REPO = Path(__file__).resolve().parent.parent

FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_GITHUB = "ghp_AAAAAAAAAAAAAAAAAAAA"
FAKE_STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
FAKE_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
FAKE_HEX32 = "9f86d081884c7d659a2feaa0c55ad015"
FAKE_RANDOM32 = "X7kQ2mZ9pL4vN8wR3tY6uB1aD5eF0kL2"
FAKE_RANDOM19 = "aB3$dF7!kL9@mN2#pQ5"


def run_cli(argv):
    """Run main(argv), capture stdout/stderr, return (code, out, err)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = checker.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def write(tmp, name, text, encoding="utf-8"):
    path = Path(tmp) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding=encoding)
    return str(path)


def findings_of(text):
    return checker.check_text(text)


class TestPlaceholdersPass(unittest.TestCase):
    def test_your_key_here_passes(self):
        self.assertEqual(findings_of("API_KEY=your-key-here"), [])

    def test_changeme_passes(self):
        self.assertEqual(findings_of("SECRET_KEY=changeme"), [])

    def test_xxx_passes(self):
        self.assertEqual(findings_of("GITHUB_TOKEN=xxx"), [])

    def test_angle_bracket_placeholder_passes(self):
        self.assertEqual(findings_of("API_KEY=<your-api-key>"), [])

    def test_dollar_brace_placeholder_passes(self):
        self.assertEqual(findings_of("API_KEY=${API_KEY}"), [])

    def test_empty_value_passes(self):
        self.assertEqual(findings_of("DATABASE_PASSWORD="), [])

    def test_uppercase_placeholder_passes(self):
        self.assertEqual(findings_of(
            "AWS_ACCESS_KEY_ID=YOUR_KEY_HERE"), [])

    def test_your_secret_key_here_passes(self):
        self.assertEqual(findings_of(
            "AWS_SECRET_ACCESS_KEY=your-secret-key-here"), [])

    def test_quoted_placeholder_passes(self):
        self.assertEqual(findings_of(
            'API_KEY="your-api-key-here"'), [])

    def test_single_quoted_placeholder_passes(self):
        self.assertEqual(findings_of(
            "API_KEY='your-api-key-here'"), [])

    def test_django_insecure_marker_passes(self):
        self.assertEqual(findings_of(
            "SECRET_KEY=django-insecure-xxxxxxxxxxxxxxxxxxxx"), [])

    def test_alphabet_sequence_passes(self):
        self.assertEqual(findings_of(
            "API_KEY=abcdefghijklmnopqrstuvwxyz012345"), [])

    def test_run_of_x_passes(self):
        self.assertEqual(findings_of("API_KEY=xxxxxxxxxxxxxxxxxxxx"), [])

    def test_change_me_please_passes(self):
        self.assertEqual(findings_of("SECRET_KEY=change-me-please"), [])

    def test_plain_words_pass(self):
        self.assertEqual(findings_of("PASSWORD=password"), [])
        self.assertEqual(findings_of("API_KEY=test"), [])
        self.assertEqual(findings_of("TOKEN=123456"), [])

    def test_stripe_placeholder_shape_passes(self):
        self.assertEqual(findings_of("STRIPE_KEY=sk-your-key-here"), [])

    def test_replace_me_passes(self):
        self.assertEqual(findings_of("API_KEY=replace-me"), [])


class TestKnownPatternsFlagged(unittest.TestCase):
    def test_aws_key_flagged(self):
        bad = findings_of("AWS_ACCESS_KEY_ID=" + FAKE_AWS)
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["line"], 1)
        self.assertEqual(bad[0]["key"], "AWS_ACCESS_KEY_ID")
        self.assertIn("AWS access key", bad[0]["reason"])

    def test_aws_key_inside_longer_value_flagged(self):
        bad = findings_of("KEY=prefix-" + FAKE_AWS + "-suffix")
        self.assertEqual(len(bad), 1)

    def test_github_pat_flagged(self):
        bad = findings_of("GITHUB_TOKEN=" + FAKE_GITHUB)
        self.assertEqual(len(bad), 1)
        self.assertIn("GitHub token", bad[0]["reason"])

    def test_github_oauth_flagged(self):
        bad = findings_of("TOKEN=gho_" + "B" * 36)
        self.assertEqual(len(bad), 1)

    def test_github_fine_grained_pat_flagged(self):
        bad = findings_of("TOKEN=github_pat_" + "11ABCDEFG0" + "a" * 59)
        self.assertEqual(len(bad), 1)

    def test_slack_token_flagged(self):
        bad = findings_of("SLACK_TOKEN=xoxb-123456789012-abcdefghij")
        self.assertEqual(len(bad), 1)
        self.assertIn("Slack token", bad[0]["reason"])

    def test_google_api_key_flagged(self):
        bad = findings_of(
            "GOOGLE_API_KEY=AIzaSyD6xK8vN2pQ4rT7wY1uI3oP5aS9dF0gH2j")
        self.assertEqual(len(bad), 1)
        self.assertIn("Google API key", bad[0]["reason"])

    def test_stripe_live_key_flagged(self):
        bad = findings_of("STRIPE_SECRET_KEY=" + FAKE_STRIPE)
        self.assertEqual(len(bad), 1)
        self.assertIn("Stripe key", bad[0]["reason"])

    def test_stripe_test_key_flagged(self):
        bad = findings_of(
            "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc")
        self.assertEqual(len(bad), 1)

    def test_openai_key_flagged(self):
        bad = findings_of("OPENAI_API_KEY=sk-abcdefghijklmnopqrst")
        self.assertEqual(len(bad), 1)
        self.assertIn("OpenAI", bad[0]["reason"])

    def test_openai_project_key_flagged(self):
        bad = findings_of(
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst")
        self.assertEqual(len(bad), 1)

    def test_anthropic_key_flagged(self):
        bad = findings_of(
            "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrst")
        self.assertEqual(len(bad), 1)
        self.assertIn("Anthropic", bad[0]["reason"])

    def test_jwt_flagged(self):
        bad = findings_of("JWT_SECRET=" + FAKE_JWT)
        self.assertEqual(len(bad), 1)
        self.assertIn("JWT", bad[0]["reason"])

    def test_private_key_block_flagged(self):
        bad = findings_of(
            "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----")
        self.assertEqual(len(bad), 1)
        self.assertIn("private key", bad[0]["reason"])

    def test_lowercase_key_name_flagged(self):
        bad = findings_of("aws_access_key_id=" + FAKE_AWS)
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["key"], "aws_access_key_id")


class TestRandomLookingValues(unittest.TestCase):
    def test_long_random_in_secret_named_key_flagged(self):
        bad = findings_of("SECRET_KEY=" + FAKE_RANDOM19)
        self.assertEqual(len(bad), 1)
        self.assertIn("secret-named key", bad[0]["reason"])

    def test_hex32_flagged(self):
        bad = findings_of("SESSION_SECRET=" + FAKE_HEX32)
        self.assertEqual(len(bad), 1)
        self.assertIn("long random-looking value", bad[0]["reason"])

    def test_random32_in_plain_key_flagged(self):
        bad = findings_of("APP_NAME=" + FAKE_RANDOM32)
        self.assertEqual(len(bad), 1)

    def test_short_password_passes(self):
        self.assertEqual(findings_of("PASSWORD=hunter2"), [])

    def test_wordy_passphrase_passes(self):
        self.assertEqual(findings_of(
            "PASSWORD=correct-horse-battery-staple"), [])

    def test_wordy_secret_value_passes(self):
        self.assertEqual(findings_of(
            "SECRET=mysecretpassword12345"), [])

    def test_short_mixed_value_in_secret_key_passes(self):
        self.assertEqual(findings_of("SECRET=Ab3$xY9!qW2"), [])

    def test_long_hyphenated_words_pass(self):
        self.assertEqual(findings_of(
            "API_KEY=this-is-a-secret-value"), [])

    def test_short_value_with_no_pattern_passes(self):
        self.assertEqual(findings_of("TOKEN=abc"), [])
        self.assertEqual(findings_of("API_KEY=localhost"), [])


class TestParsing(unittest.TestCase):
    def test_comment_lines_skipped(self):
        text = "# API_KEY=" + FAKE_AWS + "\nAPI_KEY=your-key-here\n"
        self.assertEqual(findings_of(text), [])

    def test_comment_with_fake_key_skipped(self):
        text = "# pasted " + FAKE_AWS + " here by mistake\n"
        self.assertEqual(findings_of(text), [])

    def test_blank_lines_skipped(self):
        text = "\n\nAPI_KEY=your-key-here\n\n"
        self.assertEqual(findings_of(text), [])

    def test_bare_key_skipped(self):
        self.assertEqual(findings_of("EXTRA_KEY"), [])

    def test_key_without_value_passes(self):
        self.assertEqual(findings_of("DATABASE_PASSWORD="), [])

    def test_export_prefix_checked(self):
        bad = findings_of("export API_KEY=" + FAKE_AWS)
        self.assertEqual(len(bad), 1)

    def test_export_prefix_placeholder_passes(self):
        self.assertEqual(findings_of(
            'export API_KEY="your-api-key-here"'), [])

    def test_inline_comment_stripped(self):
        bad = findings_of(
            "API_KEY=" + FAKE_AWS + " # the real key")
        self.assertEqual(len(bad), 1)

    def test_inline_comment_after_placeholder_passes(self):
        self.assertEqual(findings_of(
            "API_KEY=your-key-here # fill this in"), [])

    def test_quoted_value_flagged(self):
        bad = findings_of('API_KEY="' + FAKE_AWS + '"')
        self.assertEqual(len(bad), 1)

    def test_single_quoted_value_flagged(self):
        bad = findings_of("API_KEY='" + FAKE_AWS + "'")
        self.assertEqual(len(bad), 1)

    def test_quoted_value_with_trailing_comment(self):
        bad = findings_of(
            'API_KEY="' + FAKE_AWS + '" # do not commit')
        self.assertEqual(len(bad), 1)

    def test_spaces_around_equals(self):
        bad = findings_of("API_KEY = " + FAKE_AWS)
        self.assertEqual(len(bad), 1)

    def test_value_with_equals_inside_passes(self):
        self.assertEqual(findings_of("KEY=abc=def"), [])

    def test_crlf_line_endings(self):
        bad = findings_of("API_KEY=" + FAKE_AWS + "\r\n"
                          "OTHER=your-key-here\r\n")
        self.assertEqual(len(bad), 1)

    def test_unclosed_quote_checked(self):
        bad = findings_of('API_KEY="' + FAKE_AWS)
        self.assertEqual(len(bad), 1)

    def test_duplicate_keys_each_checked(self):
        text = ("API_KEY=your-key-here\n"
                "API_KEY=" + FAKE_AWS + "\n")
        bad = findings_of(text)
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["line"], 2)

    def test_findings_in_document_order_with_lines(self):
        text = ("APP_NAME=my-app\n"
                "AWS_ACCESS_KEY_ID=" + FAKE_AWS + "\n"
                "DEBUG=false\n"
                "GITHUB_TOKEN=" + FAKE_GITHUB + "\n")
        bad = findings_of(text)
        self.assertEqual([b["line"] for b in bad], [2, 4])
        self.assertEqual([b["key"] for b in bad],
                         ["AWS_ACCESS_KEY_ID", "GITHUB_TOKEN"])

    def test_finding_never_contains_the_value(self):
        bad = findings_of("API_KEY=" + FAKE_AWS)
        self.assertNotIn("value", bad[0])
        self.assertNotIn(FAKE_AWS, str(bad))

    def test_empty_document_passes(self):
        self.assertEqual(findings_of(""), [])
        self.assertEqual(findings_of("\n\n# nothing here\n"), [])


class TestUrls(unittest.TestCase):
    def test_url_with_placeholder_password_passes(self):
        text = ("DATABASE_URL=postgres://user:password"
                "@localhost:5432/myapp\n")
        self.assertEqual(findings_of(text), [])

    def test_url_with_real_password_flagged(self):
        text = ("DATABASE_URL=postgres://app:S3cretP@ssw0rd!2026"
                "@db.internal:5432/myapp\n")
        bad = findings_of(text)
        self.assertEqual(len(bad), 1)
        self.assertIn("password inside a URL", bad[0]["reason"])

    def test_url_with_short_password_passes(self):
        text = ("DATABASE_URL=postgres://app:hunter2"
                "@db.internal:5432/myapp\n")
        self.assertEqual(findings_of(text), [])

    def test_url_with_no_password_passes(self):
        self.assertEqual(findings_of(
            "REDIS_URL=redis://localhost:6379/0"), [])

    def test_url_with_placeholder_host_passes(self):
        self.assertEqual(findings_of(
            "DATABASE_URL=postgres://user:pass@example.com/db"), [])


class TestCli(unittest.TestCase):
    def test_clean_file_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "API_KEY=your-key-here\n")
            code, out, _ = run_cli([path])
            self.assertEqual(code, 0)
            self.assertIn("OK —", out)

    def test_flagged_file_exit_1_with_file_and_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "APP_NAME=my-app\nAPI_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([path])
            self.assertEqual(code, 1)
            self.assertIn("API_KEY line 2", out)
            self.assertIn("AWS access key", out)
            self.assertIn("1 suspect value(s)", out)

    def test_output_never_contains_the_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([path])
            self.assertEqual(code, 1)
            self.assertNotIn(FAKE_AWS, out)

    def test_folder_walk_finds_multiple_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, ".env.example", "API_KEY=your-key-here\n")
            write(tmp, "api/.env.example",
                  "API_KEY=" + FAKE_AWS + "\n")
            write(tmp, "web/.env.example",
                  "TOKEN=" + FAKE_GITHUB + "\n")
            write(tmp, "notes.txt", "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([tmp])
            self.assertEqual(code, 1)
            self.assertIn("Checked 3 file(s)", out)
            self.assertIn("2 suspect value(s)", out)
            self.assertNotIn("notes.txt", out)

    def test_folder_walk_skips_nested_with_no_recursive(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, ".env.example", "API_KEY=your-key-here\n")
            write(tmp, "api/.env.example",
                  "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([tmp, "--no-recursive"])
            self.assertEqual(code, 0)
            self.assertIn("1 file(s) checked", out)

    def test_exclude_skips_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, ".env.example", "API_KEY=your-key-here\n")
            write(tmp, "vendor/.env.example",
                  "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([tmp, "--exclude", "vendor"])
            self.assertEqual(code, 0)
            self.assertIn("1 file(s) checked", out)

    def test_git_folder_skipped_in_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, ".env.example", "API_KEY=your-key-here\n")
            write(tmp, ".git/.env.example",
                  "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([tmp])
            self.assertEqual(code, 0)
            self.assertIn("1 file(s) checked", out)

    def test_real_env_file_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env", "API_KEY=" + FAKE_AWS + "\n")
            code, _, err = run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("refusing to read a real .env file", err)

    def test_real_env_local_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.local",
                         "API_KEY=" + FAKE_AWS + "\n")
            code, _, err = run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("refusing to read a real .env file", err)

    def test_real_env_never_read_in_folder_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, ".env", "API_KEY=" + FAKE_AWS + "\n")
            write(tmp, ".env.example", "API_KEY=your-key-here\n")
            code, out, _ = run_cli([tmp])
            self.assertEqual(code, 0)
            self.assertIn("1 file(s) checked", out)

    def test_direct_file_checked_whatever_its_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, "weird.txt", "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([path])
            self.assertEqual(code, 1)
            self.assertIn("AWS access key", out)

    def test_duplicate_paths_checked_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli([path, path])
            self.assertEqual(code, 1)
            self.assertIn("Checked 1 file(s)", out)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli(["--json", path])
            self.assertEqual(code, 1)
            data = json.loads(out)
            self.assertEqual(data["checked"], 1)
            self.assertEqual(data["findings"], 1)
            self.assertEqual(data["files"][0]["findings"][0]["key"],
                             "API_KEY")
            self.assertEqual(data["files"][0]["findings"][0]["line"], 1)
            self.assertNotIn(FAKE_AWS, out)

    def test_stdin_clean(self):
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("API_KEY=your-key-here\n")
            code, out, _ = run_cli(["--stdin"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(code, 0)
        self.assertIn("OK —", out)

    def test_stdin_dirty(self):
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("API_KEY=" + FAKE_AWS + "\n")
            code, out, _ = run_cli(["--stdin"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(code, 1)
        self.assertIn("FAIL <stdin>: API_KEY line 1", out)
        self.assertNotIn(FAKE_AWS, out)

    def test_stdin_with_paths_is_usage_error(self):
        code, _, err = run_cli(["--stdin", "x.env.example"])
        self.assertEqual(code, 2)
        self.assertIn("--stdin takes no file", err)

    def test_no_paths_is_usage_error(self):
        code, _, err = run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("at least one .env.example file", err)

    def test_missing_path_exit_2(self):
        code, _, err = run_cli(["/nonexistent/.env.example"])
        self.assertEqual(code, 2)
        self.assertIn("no such file or folder", err)

    def test_empty_folder_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli([tmp])
            self.assertEqual(code, 2)
            self.assertIn("no .env.example files found", err)

    def test_bad_flag_exit_2(self):
        code, _, _ = run_cli(["--nope"])
        self.assertEqual(code, 2)

    def test_version(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("env_example_secret_checker 1.0.0", out)

    def test_non_utf8_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         b"API_KEY=a\xffbc\n")
            code, out, _ = run_cli([path])
            self.assertEqual(code, 1)
            self.assertIn("not valid UTF-8", out)

    def test_input_files_left_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = "API_KEY=" + FAKE_AWS + "\n"
            path = write(tmp, ".env.example", text)
            before = Path(path).read_text()
            run_cli([path])
            self.assertEqual(Path(path).read_text(), before)

    def test_cli_runs_from_another_folder(self):
        # CWD-robustness: the tool must work from /tmp and from /,
        # not only from the repo root.
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, ".env.example",
                         "API_KEY=your-key-here\n")
            for cwd in ("/tmp", "/"):
                result = subprocess.run(
                    [sys.executable,
                     str(REPO / "src/env_example_secret_checker.py"),
                     path],
                    cwd=cwd, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, cwd)
                self.assertIn("OK —", result.stdout)

    def test_cli_runs_under_fake_home(self):
        # A test that only passes because a local path exists
        # is not a passing test: HOME must not matter.
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = str(Path(tmp) / "fakehome")
            os.makedirs(fake_home)
            path = write(tmp, ".env.example",
                         "API_KEY=" + FAKE_AWS + "\n")
            env = dict(os.environ, HOME=fake_home)
            result = subprocess.run(
                [sys.executable,
                 str(REPO / "src/env_example_secret_checker.py"),
                 path],
                cwd="/tmp", capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 1)
            self.assertIn("AWS access key", result.stdout)


class TestExamples(unittest.TestCase):
    def test_run_example_output_matches_sample(self):
        result = subprocess.run(
            ["sh", "examples/run-example.sh"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        expected = (REPO / "examples/sample-output.md").read_text()
        self.assertEqual(result.stdout, expected)

    def test_readme_quotes_match_real_runs(self):
        readme = (REPO / "README.md").read_text()
        clean = subprocess.run(
            [sys.executable, "src/env_example_secret_checker.py",
             "examples/clean.env.example"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(clean.returncode, 0)
        self.assertIn(clean.stdout.strip(), readme)
        flagged = subprocess.run(
            [sys.executable, "src/env_example_secret_checker.py",
             "examples/flagged.env.example"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(flagged.returncode, 1)
        self.assertIn(flagged.stdout.strip(), readme)
        folder = subprocess.run(
            [sys.executable, "src/env_example_secret_checker.py",
             "examples/"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(folder.returncode, 1)
        self.assertIn("Checked 3 file(s), 7 suspect value(s) in 1 "
                      "file(s).", folder.stdout)
        self.assertIn("Checked 3 file(s), 7 suspect value(s) in 1 "
                      "file(s).", readme)
        edge = subprocess.run(
            [sys.executable, "src/env_example_secret_checker.py",
             "examples/edge.env.example"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(edge.returncode, 0)
        self.assertIn(edge.stdout.strip(), readme)
        js = subprocess.run(
            [sys.executable, "src/env_example_secret_checker.py",
             "--json", "examples/flagged.env.example"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(js.returncode, 1)
        self.assertIn(js.stdout.strip(), readme)


class TestHygiene(unittest.TestCase):
    def _repo_files(self, skip_tests=True, skip_examples=True):
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs
                       if d not in (".git", "__pycache__")
                       and not (skip_tests and d == "tests")
                       and not (skip_examples and d == "examples")]
            for name in files:
                if name.endswith(".pyc"):
                    continue
                yield Path(root) / name

    def test_no_placeholder_text(self):
        banned = ["TODO", "coming soon", "lorem", "FIXME", "XXX"]
        hits = []
        for path in self._repo_files(skip_tests=True,
                                     skip_examples=False):
            text = path.read_text(errors="ignore")
            for word in banned:
                if word in text:
                    hits.append("%s: %s" % (path.name, word))
        self.assertEqual(hits, [])

    def test_no_absolute_paths(self):
        hits = []
        for path in self._repo_files(skip_tests=True,
                                     skip_examples=False):
            text = path.read_text(errors="ignore")
            for marker in ("/home/", "/Users/", "C:\\"):
                if marker in text:
                    hits.append("%s: %s" % (path.name, marker))
        self.assertEqual(hits, [])

    def test_no_real_secrets_outside_tests_and_examples(self):
        # The source holds key SHAPES (regexes), never key
        # values; the tests and examples hold fake values
        # only, so they are excluded from this scan.
        patterns = [
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
            re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
            re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
            re.compile(r"AIza[0-9A-Za-z_-]{35}"),
            re.compile(r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
            re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ"),
        ]
        hits = []
        for path in self._repo_files():
            text = path.read_text(errors="ignore")
            for pattern in patterns:
                if pattern.search(text):
                    hits.append("%s: %s" % (path.name, pattern.pattern))
        self.assertEqual(hits, [])

    def test_stdlib_imports_only(self):
        stdlib = set(sys.stdlib_module_names)
        for target in (REPO / "src/env_example_secret_checker.py",
                       REPO / "tests/test_env_example_secret_checker.py"):
            tree = ast.parse(target.read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0]
                                    for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertFalse(
                imported - stdlib - {"env_example_secret_checker"},
                (target.name, imported))
            self.assertNotIn("yaml", imported)

    def test_no_network_use_in_src(self):
        src = (REPO / "src/env_example_secret_checker.py").read_text()
        for marker in ("urllib.request", "requests", "socket",
                       "http.client", "urlopen", "urlretrieve"):
            self.assertNotIn(marker, src, marker)

    def test_gitignore_lists_env_first(self):
        lines = (REPO / ".gitignore").read_text().splitlines()
        self.assertEqual(lines[0], ".env")

    def test_ci_runs_this_test_file(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text()
        self.assertIn("tests/test_env_example_secret_checker.py", ci)
        self.assertIn("ubuntu-latest", ci)
        self.assertIn("3.12", ci)
        self.assertIn("actions/checkout", ci)
        self.assertIn("setup-python", ci)
        self.assertIn("push", ci)
        self.assertIn("pull_request", ci)

    def test_readme_names_the_neighbouring_repos(self):
        readme = (REPO / "README.md").read_text()
        self.assertIn("secret-scan-skill", readme)
        self.assertIn("env-example-sync-cli", readme)
        self.assertIn("never reads a real", readme)


if __name__ == "__main__":
    unittest.main()
