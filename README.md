# env-example-secret-checker-cli

Check `.env.example` files for secret-looking values, fail CI when one is found — it never reads a real `.env`.

[![CI](https://github.com/haiderstudio/env-example-secret-checker-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/haiderstudio/env-example-secret-checker-cli/actions/workflows/ci.yml) [![Licence: MIT](https://img.shields.io/badge/Licence-MIT-yellow.svg)](LICENSE)

## What it does

`env_example_secret_checker` reads only the committed
example file, checks every value in it, and reports each
line that looks like a real secret, with the file and the
line number. It exits 1 when any line looks like a real
secret, so it can fail a CI run. A file whose values are
all placeholders exits 0.

- An example file is meant to hold placeholders, but
  people paste a real key into it "just to test" and
  commit it — and because the file is named `.example`,
  nobody scans it. This catches it before the file
  ships.
- A value counts as a placeholder when it is empty, or
  it is one of the usual placeholder words
  (`your-key-here`, `changeme`, `xxx`, and friends), or
  it is wrapped in angle brackets or `${...}`, or it
  starts with a word like `your-`, `insert-`,
  `replace-`, or `demo-`.
- A value counts as a real secret when it matches a
  known key format — an AWS access key, a GitHub
  token, a Slack token, a Google API key, a Stripe
  key, an OpenAI key, an Anthropic key, a JWT, or a
  private key block — or when it is a long
  random-looking string in a secret-named key, or a
  long random-looking string anywhere. A password
  hidden inside a database URL is checked the same
  way, after the placeholder test.
- A short value that matches no known format is left
  alone: the tool cannot tell a short real password
  from a word, so it only flags what it can prove
  looks real. `PASSWORD=hunter2` passes, and so does
  a wordy passphrase — a 32-character random string
  does not.
- Values are never printed. A finding names the key,
  the file, and the line, and says why the value looks
  real — the value itself stays out of the report, so
  the report is safe to paste into a CI log or an
  issue.
- A file given directly on the command line is always
  checked, whatever its name. A folder is walked for
  files ending in `.env.example` only, recursively by
  default (`--no-recursive` stops at the top level).
  `.git` folders are never walked, and directory links
  are never followed.
- `--json` prints the result as JSON, and `--stdin`
  checks one example document read from standard
  input.
- Comment lines are never checked, blank lines are
  skipped, and a key with no value is not a secret.
  `export KEY=value`, single- and double-quoted
  values, spaces around `=`, and inline ` # comments`
  are all handled.

## Who it is for

Anyone who commits an `.env.example` file — which is
every project with a README that says "copy
`.env.example` to `.env`". One pasted key in that file
is a credential in git history, and the usual secret
scanners skip the file because it is only an example.
This is the gate that stops it at the pull request.

## What it does NOT do

- It never reads a real `.env` file. A real `.env`
  passed on the command line is refused outright, and
  a real `.env` sitting next to the example in a
  folder walk is never opened — even when it holds a
  real key. Only `.env.example` files are ever read.
  This is deliberate: a tool that reads real env
  files in CI is a leak waiting to happen.
- It does not scan code or diffs for leaked keys.
  That is repo #12, secret-scan-skill, which scans
  diffs and code — this checks the example file's own
  secret-looking values, a different check.
- It does not check whether the example matches what
  the code uses. That is repo #3,
  env-example-sync-cli, which checks the example
  matches code use — the example file's own
  secret-looking values are this repo's different
  check.
- It does not check `.env` file format, duplicate
  keys, or missing variables. That is repo #40,
  dotenv-format-checker-cli, and repo #3,
  env-example-sync-cli — format and sync are
  different jobs on the same files.
- It does not rotate, revoke, or delete a key it
  finds. If a real key was committed, rotate it
  first — removing it from the file does not un-leak
  it.
- It never rewrites a file, and it never touches the
  network.

## How this differs

- A fresh search of GitHub on Nov 13, 2026 found 0
  results for `"env-example-secret-checker-cli"` and
  4 results for `env example secret checker`, all
  0-star tools. None of them does the example-only
  check with a CI gate:
  - spinov001-art/python-env-checker audits secrets
    in the real `.env` only (`secrets .env`); its
    example handling is a missing-variable compare,
    not a secret check on example values.
  - 0xelitesystem/env-var-checker does flag leaked
    secrets in `.env.example`, but it is a
    browser-only paste-and-click page — no CLI, no
    exit code, nothing a CI run can call.
  - rayhanlimon/envdoctor is a Node CLI with a CI
    recipe, but its secret scan runs on the real
    `.env` entries only — the example entries are
    never passed through its secret scanner, and it
    refuses to run without a real `.env` present.
  - bobby404-K/fast-env-guard is a Node runtime
    validator library with an `.env.example` sync
    checker; it has no CLI and checks sync, not
    secret values in the example.
- So the narrow slice stands: the committed example
  file only, per-line reporting, a CI exit code, and
  a hard refusal to ever read a real `.env`.

## Install

```sh
git clone https://github.com/haiderstudio/env-example-secret-checker-cli.git
cd env-example-secret-checker-cli
```

There is nothing else to install: Python 3.10 or newer,
standard library only, no dependencies.

## Usage

Check one example file:

```sh
python3 src/env_example_secret_checker.py .env.example
```

A file whose values are all placeholders passes:

```sh
$ python3 src/env_example_secret_checker.py examples/clean.env.example
OK — 1 file(s) checked, every value in the example file is a placeholder.
```

A file with a pasted real-looking key fails, with the
key and line for each one — the value itself is never
shown:

```sh
$ python3 src/env_example_secret_checker.py examples/flagged.env.example
FAIL examples/flagged.env.example: AWS_ACCESS_KEY_ID line 4 looks like a real AWS access key — replace it with a placeholder
FAIL examples/flagged.env.example: GITHUB_TOKEN line 5 looks like a real GitHub token — replace it with a placeholder
FAIL examples/flagged.env.example: STRIPE_SECRET_KEY line 6 looks like a real Stripe key — replace it with a placeholder
FAIL examples/flagged.env.example: DATABASE_URL line 7 has a real-looking password inside a URL — replace it with a placeholder
FAIL examples/flagged.env.example: JWT_SECRET line 8 looks like a real JWT — replace it with a placeholder
FAIL examples/flagged.env.example: API_KEY line 9 has a long random-looking value in a secret-named key — replace it with a placeholder
FAIL examples/flagged.env.example: SESSION_SECRET line 10 has a long random-looking value — replace it with a placeholder
Checked 1 file(s), 7 suspect value(s) in 1 file(s).
```

Check a whole folder (`.env.example` files only — a
real `.env` in the same folder is never opened):

```sh
$ python3 src/env_example_secret_checker.py examples/
FAIL examples/flagged.env.example: AWS_ACCESS_KEY_ID line 4 looks like a real AWS access key — replace it with a placeholder
FAIL examples/flagged.env.example: GITHUB_TOKEN line 5 looks like a real GitHub token — replace it with a placeholder
FAIL examples/flagged.env.example: STRIPE_SECRET_KEY line 6 looks like a real Stripe key — replace it with a placeholder
FAIL examples/flagged.env.example: DATABASE_URL line 7 has a real-looking password inside a URL — replace it with a placeholder
FAIL examples/flagged.env.example: JWT_SECRET line 8 looks like a real JWT — replace it with a placeholder
FAIL examples/flagged.env.example: API_KEY line 9 has a long random-looking value in a secret-named key — replace it with a placeholder
FAIL examples/flagged.env.example: SESSION_SECRET line 10 has a long random-looking value — replace it with a placeholder
Checked 3 file(s), 7 suspect value(s) in 1 file(s).
```

Check one document from standard input:

```sh
$ python3 src/env_example_secret_checker.py --stdin < examples/flagged.env.example
FAIL <stdin>: AWS_ACCESS_KEY_ID line 4 looks like a real AWS access key — replace it with a placeholder
FAIL <stdin>: GITHUB_TOKEN line 5 looks like a real GitHub token — replace it with a placeholder
FAIL <stdin>: STRIPE_SECRET_KEY line 6 looks like a real Stripe key — replace it with a placeholder
FAIL <stdin>: DATABASE_URL line 7 has a real-looking password inside a URL — replace it with a placeholder
FAIL <stdin>: JWT_SECRET line 8 looks like a real JWT — replace it with a placeholder
FAIL <stdin>: API_KEY line 9 has a long random-looking value in a secret-named key — replace it with a placeholder
FAIL <stdin>: SESSION_SECRET line 10 has a long random-looking value — replace it with a placeholder
Checked 1 file(s), 7 suspect value(s) in 1 file(s).
```

Machine-readable output:

```sh
$ python3 src/env_example_secret_checker.py --json examples/flagged.env.example
{
  "files": [
    {
      "path": "examples/flagged.env.example",
      "findings": [
        {
          "line": 4,
          "key": "AWS_ACCESS_KEY_ID",
          "reason": "looks like a real AWS access key"
        },
        {
          "line": 5,
          "key": "GITHUB_TOKEN",
          "reason": "looks like a real GitHub token"
        },
        {
          "line": 6,
          "key": "STRIPE_SECRET_KEY",
          "reason": "looks like a real Stripe key"
        },
        {
          "line": 7,
          "key": "DATABASE_URL",
          "reason": "has a real-looking password inside a URL"
        },
        {
          "line": 8,
          "key": "JWT_SECRET",
          "reason": "looks like a real JWT"
        },
        {
          "line": 9,
          "key": "API_KEY",
          "reason": "has a long random-looking value in a secret-named key"
        },
        {
          "line": 10,
          "key": "SESSION_SECRET",
          "reason": "has a long random-looking value"
        }
      ],
      "error": null
    }
  ],
  "checked": 1,
  "findings": 7
}
```

Exit codes: 0 when every value is a placeholder, 1
when any value looks like a real secret or a file
cannot be read, 2 for a usage error (a missing path,
a bad flag, no `.env.example` files found, or a real
`.env` file passed on the command line).

## Examples

A real `.env` is refused outright — the tool will not
read it, even to check it:

```sh
$ python3 src/env_example_secret_checker.py .env
error: refusing to read a real .env file: .env (check .env.example files only)
```

Comments, quotes, `export`, and inline comments are
handled — `examples/edge.env.example` has a fake key
in a comment, a quoted placeholder, a short password,
an empty value, and a bare key, and it passes:

```sh
$ python3 src/env_example_secret_checker.py examples/edge.env.example
OK — 1 file(s) checked, every value in the example file is a placeholder.
```

A short password passes, a long random string does
not — the tool only flags what it can prove looks
real:

```sh
$ printf 'PASSWORD=hunter2\n' > /tmp/short.env.example
$ python3 src/env_example_secret_checker.py /tmp/short.env.example
OK — 1 file(s) checked, every value in the example file is a placeholder.
$ printf 'API_KEY=X7kQ2mZ9pL4vN8wR3tY6uB1aD5eF0kL2mN4pQ\n' > /tmp/long.env.example
$ python3 src/env_example_secret_checker.py /tmp/long.env.example
FAIL /tmp/long.env.example: API_KEY line 1 has a long random-looking value in a secret-named key — replace it with a placeholder
Checked 1 file(s), 1 suspect value(s) in 1 file(s).
```

Run every bundled example at once with `sh
examples/run-example.sh` — the output is saved in
[examples/sample-output.md](examples/sample-output.md).

## How it is tested

```sh
python3 tests/test_env_example_secret_checker.py
```

The tests cover placeholders (your-key-here,
changeme, xxx, angle-bracket and `${...}` wrappers,
empty values, uppercase placeholders, quoted
placeholders, django-insecure markers, alphabet
sequences, runs of x, change-me-please, plain words,
Stripe-shaped placeholders, replace-me), known
secret formats (AWS keys, GitHub classic, OAuth,
and fine-grained tokens, Slack tokens, Google API
keys, Stripe live and test keys, OpenAI keys with
and without the proj prefix, Anthropic keys, JWTs,
private key blocks, lowercase key names, a known
key inside a longer value), random-looking values
(long random strings in secret-named keys, 32-char
hex, 32-char random strings in plain keys, short
passwords passing, wordy passphrases passing, wordy
secret values passing, short mixed values in secret
keys passing, long hyphenated words passing, short
values with no pattern passing), parsing (comment
lines skipped including a comment holding a fake
key, blank lines, bare keys, keys without values,
export prefixes, inline comments stripped, quoted
values flagged, quoted values with trailing
comments, spaces around `=`, values holding `=`,
CRLF endings, unclosed quotes, duplicate keys
checked line by line, findings in document order
with lines, findings never holding the value, empty
documents), URLs (placeholder passwords, real
passwords, short passwords, no password,
placeholder hosts), the CLI (exit 0/1/2, folder
walking for several example files, nested folders,
`--no-recursive`, `--exclude`, `.git` skipped, a
real `.env` refused, `.env.local` refused, a real
`.env` never read in a folder walk, a direct file
checked whatever its name, duplicate paths checked
once, `--json` output with no values, `--stdin`,
bad flags, missing paths, empty folders, `--version`,
a non-UTF-8 file reported, input files left
unchanged, the tool run from `/tmp` and from `/`,
the tool run under a fake HOME), the bundled
examples (sample output compared byte-for-byte
against a fresh run, and the README-quoted outputs
checked against it), and hygiene checks (no
placeholder text, no absolute paths, no real
secrets outside the tests and examples, stdlib
imports only, no network use in the source, `.env`
first in `.gitignore`, CI file runs the test file,
README names the neighbouring repos).

## Contributing

Small, focused improvements are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT — see [LICENSE](LICENSE).

## Original work

This tool was written from scratch for this repo. The
idea of scanning for leaked secrets is not new, and
the known-pattern technique follows the same approach
as repo #12, secret-scan-skill — but no existing tool
does this one job, checking the committed example
file only, as a tested command-line gate that refuses
to read a real `.env`, as the search above shows —
and every line of code here is original, built on
nothing but Python's standard library. All key-like
values in the tests and examples are fake, made up
for testing, and the tool never prints a value it
flags.
