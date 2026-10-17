# email-verifier

Verify email addresses using DNS MX lookups and SMTP recipient probes, with catch-all detection and a web interface for bulk CSV and TXT uploads.

![rust](https://img.shields.io/badge/rust-stable-DEA584?style=flat-square&logo=rust&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-A31F34?style=flat-square)
[![Rust CI](https://github.com/koprjaa/email-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/koprjaa/email-verifier/actions/workflows/ci.yml)


## Install and run

Install stable Rust, then run from the project directory:

```sh
cargo install --path .
email-verifier
```

Or build and run directly:

```sh
cargo build --release
cargo run --release
```

Open **http://127.0.0.1:5001**. Paths are relative to the process working directory: `config.json`, `data/disposable_domains.txt`, `uploads/`, and `results/`. Cargo installation installs the executable; keep the configuration and blocklist alongside the working directory you use to run it. The server creates its upload and result directories.

The executable starts the server and has no command-line options. Extra arguments are ignored, as with the original entry point. Startup failures exit with code 1. Ctrl+C gracefully shuts down HTTP and removes old uploads/results, retaining the current job's files.

## Use

Verify an address:

```sh
curl -X POST http://127.0.0.1:5001/verify_single \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com"}'
```

The JSON result contains these fields:

```json
{
  "email": "test@example.com",
  "is_valid": false,
  "status_code": "invalid_mailbox",
  "message": "User unknown",
  "is_catchall": false,
  "mx_record": "mx.example.com",
  "smtp_code_internal": 550,
  "verification_steps": []
}
```

`is_valid` is `true`, `false`, or `null` (inconclusive). `verification_steps` contains timestamped stage records, each with `timestamp`, `status`, `action`, `details`, and a string or null `code`. The original email text is preserved in results and SMTP recipient commands; a validated, lowercased IDNA domain is used for DNS.

Upload a CSV or TXT file in the browser. Select the email column for CSV, then start verification. You can stop after the current batch and download its completed results. The interface polls every two seconds and uses text nodes to display untrusted email addresses, headers, and server messages.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Browser interface |
| `/verify_single` | POST | JSON body with `email` |
| `/load_csv` | POST | Multipart `file`, CSV extension |
| `/load_txt` | POST | Multipart `file`, TXT extension |
| `/select_column` | POST | JSON `column` for CSV; `{}` for TXT |
| `/start_verification` | GET | Start/restart the prepared list; `confirm` is ignored |
| `/stop_verification` | POST | Request stop and wait up to five seconds |
| `/status` | GET | Progress counters and recent job log |
| `/download_results` | GET | Current result CSV as an attachment |
| `/cleanup` | POST | Delete upload/result files and reset the finished job |

Uploads are limited to **10 MiB including multipart framing**. Encoding detection tries UTF-8 with optional BOM, Windows-1250, then ISO-8859-2. CSV delimiter detection chooses the first present delimiter from comma, semicolon, tab, and pipe in the first line. Single-column CSV is unsupported; use TXT instead. CSV values are stripped and deduplicated in first-occurrence order, preserving case. Email column suggestions recognize `email`, `e-mail`, `mail`, and `emailaddress` after removing spaces and underscores, falling back to the first column. TXT extraction preserves the original separator priority and prefix-matching behavior.

Results are saved to `results/verification_results_YYYYmmddHHMMSS.csv`. The format is UTF-8 with BOM, comma separated, CRLF terminated, and uses this exact column order:

```text
email,status,error_details,domain_type,smtp_response_full,mx_servers,verification_duration_ms,raw_status_code,is_catchall_domain,smtp_internal_code
```

CSV status is `valid`, `catchall`, `invalid`, or `unknown`. Boolean text is `True`/`False`; absent fields are empty. The original result structure does not populate duration or domain type: those columns remain empty and `unknown`, respectively. JSON is returned over HTTP; this project has no XLSX or XML output.

## Configuration

The existing **flat** `config.json` format is retained. These are the effective defaults when a setting is absent (the shipped configuration overrides several):

| Key | Default | Effect |
| --- | --- | --- |
| `smtp_timeout` | `10` | Seconds for connect and each SMTP operation |
| `dns_timeout` | `5` | Resolver timeout in seconds |
| `dns_servers` | System resolvers | DNS server IP addresses |
| `catchall_test` | `true` | Takes precedence over `check_catchall` |
| `check_catchall` | `true` | Fallback catch-all setting |
| `check_disposable` | `true` | Enable local disposable-domain filter |
| `connect_port` | `25` | Main SMTP recipient probe port |
| `retry_attempts` | `2` | Total attempts, starting at attempt 1 |
| `retry_delay` | `5` | Retry delay is this value times `2^attempt` |
| `max_concurrent_domains` | `5` | Maximum simultaneous SMTP sessions |
| `ui_batch_size` | `20` | Concurrent addresses in a UI batch |
| `helo_hostname` | Machine hostname | SMTP EHLO/HELO name |
| `sender_email_override` | Unset | Force the envelope sender |
| `sender_emails` | `{}` | Provider-to-sender mapping; `default` selects fallback |
| `disposable_domains_file_path` | `data/disposable_domains.txt` | Blocklist path |

If no default sender is configured, it is `verifier@<helo_hostname>`. Czech reputation-sensitive providers prefer a sender at the same provider, then Gmail, Outlook, and Yahoo. Alternative senders are tried in configuration insertion order on reputation-related MAIL FROM refusals.

The optional `verifier/default_verifier_config.json` remains supported. It can supply `helo_hostname`, `default_sender_email`, `sender_emails_by_domain`, `dns_servers`, and `dns_resolver_tries` (default 2). Application-level values take precedence. No such internal configuration file was shipped by the original project.

The original `timeout`, `max_workers`, `rate_limit_delay`, and `batch_size` settings remain without effect because they were unused by the application execution path. There is no extra global deadline or rate-limit sleep. The nested `server`/`smtp`/`dns`/`catchall` example previously shown in the README never controlled the application.

Environment variables:

| Variable | Default | Effect |
| --- | --- | --- |
| `FLASK_RUN_HOST` | `127.0.0.1` | HTTP bind address |
| `FLASK_RUN_PORT` | `5001` | HTTP port; `0` requests an ephemeral port |
| `FLASK_DEBUG` | `0` | Accepted for compatibility; no debugger or reloader |
| `EMAIL_VERIFIER_TOKEN` | Unset | Require `X-Auth-Token` or `?token=` on API requests |

Root and `/static/` paths are exempt from token authentication, as before. There are no bundled static routes and no cross-origin allowance. Enter a configured token in the browser's access-token field; it is held only in the page's memory. No `.env` loader is used.

The shipped blocklist has 28 domains. Exact domains and the final two labels of a subdomain are checked, matching the original rule. A missing/unreadable list logs a warning and disables that stage. It is a starter list; update it for your deployment.

## Verification behavior

MX records are sorted by preference and hostname and cached until a new bulk run. Every resolved A and AAAA address must pass the public-IP guard. SMTP connects to the first checked IP directly, preventing a second hostname resolution from bypassing the guard. There are no HTTP clients, User-Agent strings, proxy settings, or Tor configuration in the original project.

SMTP uses EHLO with HELO fallback, MAIL FROM, RCPT TO, RSET, and QUIT. Success codes are 250, 251, and 252; EHLO also accepts 220. MAIL/RCPT 421, 450, 451, and 452 request a whole-address retry. Other recipient replies are invalid; connection and unexpected transaction errors move to the next MX. Exhausting the MX list yields `is_valid: null` and `unreachable_all_mx`. Retry traces start over, as in the original.

Catch-all detection probes two generated addresses on **port 25**, regardless of `connect_port`, and caches the result. The original 22 known freemail domains skip that stage. One successful probe is enough; Microsoft 550 replies containing case-sensitive `Access denied` also count as inconclusive catch-all. Catch-all failures never replace the main recipient result.

The classifier intentionally retains its unusual rules: 552/553/554 count as temporary in the generic error classifier; 554 counts as reputation-related; `temporary` is a substring pattern, so `temporarily unavailable` does not match it. A 550 recipient refusal remains invalid even if its text sounds temporary, matching the original explicit RCPT decision.

## Changes from the Python version

This is a native Rust replacement, with no Python runtime or subprocess bridge. Behavioral differences and compatibility limits are explicit:

1. **Concurrency fixes.** Verification traces belong to each address instead of a shared mutable list. Bulk runs have independent caches and unique run IDs. One Tokio runtime replaces per-request/per-thread event loops. The SMTP semaphore covers complete sessions, including catch-all probes; the original released it immediately after connect and did not limit catch-all connections. This enforces the intended connection cap and can reduce throughput.
2. **Stop/cleanup fixes.** Completed work in the current batch is saved when stopping; the original discarded it. A job remains `stopping` after the five-second HTTP wait until its worker finishes, rather than falsely reporting `stopped`. Cleanup and restart are rejected while a worker is active, preventing file deletion and stale-worker state races. Upload transitions are serialized. Download containment checks compare canonical path components, fixing the old string-prefix check that also accepted a sibling directory with a matching prefix.
3. **CSV save fix.** Every save rewrites a complete snapshot. The original incremental saves appended every prior row again, causing duplicates before its final rewrite. Short CSV rows now treat missing cells as empty instead of calling `.strip()` on `None` and failing the upload. Result schemas, BOM, quoting, delimiter, column order, and CRLF are retained.
4. **English interface and logs.** Czech UI text, API error messages, and job log messages are translated. The browser interface is rewritten without CDN dependencies, shows complete JSON results/status, supports drag/drop and tokens, and uses the real `/download_results` endpoint instead of the broken `/download` link. CSV column names and machine status codes are retained except DNS errors below. Browser alerts, styling, simulated upload progress, and the old catch-all summary display are replaced by textual results. The status API retains its original field set.
5. **HTTP runtime.** Axum replaces Flask/Werkzeug. Framework-generated errors for malformed JSON/multipart, unsupported methods, missing routes, and body limits have Axum status/body formats. JSON uses compact UTF-8 serialization and insertion order rather than Flask's escaped, sorted pretty-printing; object values/schema are preserved. Incidental server, date, cache, ETag, conditional/range download, and debug-response headers differ. Downloads send `text/csv; charset=utf-8` with an attachment filename. There is no Flask debugger, development reloader, automatic OPTIONS handler, or Flask static-file service. `FLASK_DEBUG` does not enable these. Errors and startup logs use the original timestamp/thread/level format, but all Rust worker logs use `MainThread`; Python tracebacks, source logger names, library diagnostics and some stage/log detail strings differ.
6. **Syntax/Unicode.** Native validation replaces `email-validator`: common unquoted mailbox syntax, length limits, dot rules, IDNA domains, and reserved-domain checks are implemented, but it is not a full port of that library's Unicode category, normalization, and diagnostic rules. Rare Unicode local parts, Unicode separators, normalization-dependent length checks, IDNA profiles and detailed syntax error wording can differ. Domain DNS queries use ASCII IDNA names. The default EHLO name uses the operating-system hostname rather than Python's `socket.getfqdn()`; configure `helo_hostname` for identical wire text. No SMTPUTF8 capability negotiation is implemented, so use ASCII envelope addresses for predictable interoperability.
7. **DNS backend.** Hickory replaces c-ares. DNS errors use `dns_resolver_failure` with the native resolver message rather than c-ares-dependent `dns_error_code_<message>` strings. Successful queries retain MX ordering, positive application caching, configured servers, timeout and attempt settings; wire query scheduling, system search rules, DNS caching internals and failure timing can differ. The redundant second lookup used only for logging was removed: logs show the exact pinned connection IP. The native public-IP policy also refuses IPv6 outside global unicast, 6to4, documentation and special-purpose blocks; edge assignments may differ across Python `ipaddress` versions.
8. **SMTP backend.** Explicit plaintext sessions replace `aiosmtplib`; they do not opportunistically issue STARTTLS when a server advertises it. The old source described plaintext but library defaults could upgrade. SMTP reply handling now reaches the intended MAIL reputation retry and RCPT temporary/permanent classifications directly, instead of library exceptions bypassing them and returning `unknown_smtp_error`. EHLO/HELO explicitly sends the configured hostname. UTF-8 decoding of invalid reply bytes uses replacement characters. Replies are limited to 64 KiB and have bounded read/write waits; malformed or oversized replies become inconclusive connection failures. Protocol exception wording and detailed traces differ. No SMTP DATA is sent.
9. **Configuration and file handling.** Invalid numeric settings, zero concurrency/batch/timeouts, out-of-range/fractional ports, and SMTP settings containing line breaks fail startup clearly instead of hanging or failing later. A non-object `config.json` falls back to defaults. Internal configuration is located relative to the working directory, since there is no Python module install location. Entire uploaded files are decoded before parsing; malformed later bytes therefore affect encoding selection earlier. Filenames use NFKD ASCII sanitization, collapsed whitespace and platform-specific reserved-device protection. Uploads are bounded and buffered in memory instead of copied in 8192-byte chunks; old chunk progress logs are absent. No empty orphan upload is left for an empty-file request. Startup does not create the parent directory of a missing blocklist.
10. **Process/API packaging.** Python classes/exceptions are replaced by Rust modules and structured results, and are not a Python import API. Exit cleanup runs on graceful Ctrl+C; force-kill does not execute it. In-progress job state remains memory-only, and the server still has one bulk job rather than a persistent queue. No new network rate delay was introduced. Retry exponential multiplication is capped at exponent 30 to avoid overflow with pathological attempt counts.

These limits mean ordinary API workflows and file formats are covered, but byte-for-byte equivalence of all external-library errors and every Unicode address is not claimed.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Tests never query live DNS or SMTP hosts. The full pipeline uses deterministic DNS/SMTP replacements; HTTP tests run the router in memory; protocol tests use loopback SMTP fixtures. They cover each original classification/blocklist test, pinned-IP behavior for both recipient and catch-all probes, retries, cache resets, independent traces, CSV bytes, upload encodings, authentication, the 10 MiB limit, CLI startup/exit codes, bulk progress, cleanup and stopping. Test servers explicitly clear inherited nonblocking mode, shut down their write half and drain input for Windows compatibility. `.gitattributes` preserves fixture bytes on checkout.

CI runs formatting, Clippy, tests and a release build on Ubuntu and Windows. See [REPORT.md](REPORT.md) for locally executed results and the migration inventory.

Direct dependencies are limited to the HTTP/runtime layer (`axum`, `tokio`), JSON/data representation (`serde`, `serde_json`), CSV (`csv`), legacy encodings (`encoding_rs`), TXT extraction (`regex`), local timestamps (`chrono`), DNS (`hickory-resolver`), machine hostname (`hostname`), international domains (`idna`), Unicode filename/domain normalization (`unicode-normalization`), and catch-all randomness (`rand`). Test-only `tower` and `http-body-util` exercise the router without real HTTP requests. `Cargo.lock` pins transitive versions.

## License

[MIT](LICENSE)
