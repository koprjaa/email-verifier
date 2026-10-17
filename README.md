# email-verifier

Checks whether email addresses exist, one by one or in bulk.

[![Rust CI](https://github.com/koprjaa/email-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/koprjaa/email-verifier/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-A31F34?style=flat-square)](LICENSE)

## What it does

Checks address syntax, disposable domains, DNS MX records and SMTP recipient responses. Catch-all detection flags domains that accept arbitrary recipients. SMTP probes do not send messages.

The browser accepts CSV and TXT uploads and exports results as CSV. JSON results include verification steps; `is_valid` is `true`, `false`, or `null` when inconclusive.

## Install

Install stable Rust, then build from the repository directory:

```sh
cargo build --release
```

Review `config.json` before starting. Replace its `sender_emails` entries with addresses you control. Set `helo_hostname` if you need a specific SMTP greeting name. Verification needs DNS access and outbound SMTP connections on port 25 by default.

No environment variables are required. `FLASK_RUN_HOST` and `FLASK_RUN_PORT` override the default bind address and port. Optionally set `EMAIL_VERIFIER_TOKEN` to require an access token for API requests.

## Use

Run from the repository directory:

```sh
cargo run --release
```

Open http://127.0.0.1:5001. Upload a CSV, select its email column, and start verification. Use TXT for a list without column delimiters. Uploads are limited to 10 MiB, including multipart framing. Download completed results from the browser; stopping preserves the current batch's completed work.

To check one address:

```sh
curl -X POST http://127.0.0.1:5001/verify_single \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com"}'
```

If authentication is enabled, enter the token in the browser or send the `X-Auth-Token` header.

Paths are relative to the working directory: `config.json`, `data/disposable_domains.txt`, `uploads/` and `results/`. The server creates the last two directories.

## License

[MIT](LICENSE)
