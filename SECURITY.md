# Security Policy

This tool runs locally, collects no data, sends nothing anywhere, and needs no API key or secret. It only reads `.env.example` files you point it at, and it never rewrites a file and never changes anything. It writes nothing except the report on standard output (and usage errors on standard error). It never fetches a URL: remote addresses are skipped, not opened.

It never reads a real `.env` file — a real `.env` passed on the command line is refused, and a real `.env` in a walked folder is never opened. It never prints a value it flags, so a report is safe to paste into a CI log or an issue.

If you find a case where the tool reads a real `.env` file, prints a flagged value, or reports a pass for an example file holding a real-looking secret, please open an issue describing the exact commands and input. Do not include any real secret in the report.
