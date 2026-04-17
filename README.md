# email-verifier

**Async SMTP email verification with catch-all detection, DNS caching, and a Flask bulk-upload UI.**

![python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-A31F34?style=flat-square)
![status](https://img.shields.io/badge/status-active-22863A?style=flat-square)
![flask](https://img.shields.io/badge/flask-3.0-000?style=flat-square&logo=flask&logoColor=white)
![aiosmtplib](https://img.shields.io/badge/aiosmtplib-2.0-222?style=flat-square)
![aiodns](https://img.shields.io/badge/aiodns-3.1-222?style=flat-square)
![pandas](https://img.shields.io/badge/pandas-2.2-150458?style=flat-square&logo=pandas&logoColor=white)

## The problem

Most email verification services charge per check. Most open-source tools stop at syntax + MX lookup, which says nothing about whether the mailbox actually exists. Gmail and catch-all domains silently accept anything.

This project does it the hard way: real SMTP connections, `RCPT TO` probing, and a reputation layer for Czech providers (`seznam.cz`, `centrum.cz`, `post.cz`, `email.cz`) that routinely tarpit unknown senders.

## What you get

A Flask web app on port **5001** with:

- **REST API** — `POST /verify_single` for one address, CSV upload endpoint for bulk
- **Bulk pipeline** — upload thousands of rows, watch progress update live, download timestamped CSV result
- **Five-stage verification** per address:
  1. RFC 5322 syntax (`email-validator`)
  2. Disposable domain filter (external blocklist at `data/disposable_domains.txt`)
  3. DNS MX lookup with caching (`aiodns`)
  4. Catch-all probe (optional) — detects domains that accept any recipient
  5. SMTP `RCPT TO` over async connections (`aiosmtplib`) on ports 25 and 587
- **Retry + backoff** — configurable attempts with exponential delay on 4xx SMTP errors (421, 450, 451, 452)
- **Rate limiting** — semaphore (default 5 concurrent domains) + jittered 2s base delay + 15s DNS / 10s SMTP timeouts
- **Result classes** — `valid`, `invalid`, `probable`, `unknown`, `catchall`

## Architecture

```
┌──────────────┐    ┌───────────────────┐    ┌─────────────────────┐
│  Flask UI /  │───▶│  EmailVerifier    │───▶│  Async engine       │
│  REST API    │    │  (global instance)│    │  • aiodns DNS       │
│  (Flask 3.0) │    │                   │    │  • aiosmtplib SMTP  │
└──────────────┘    └───────────────────┘    │  • backoff retry    │
                            │                │  • asyncio.Semaphore│
                            ▼                └─────────────────────┘
                    ┌───────────────────┐
                    │  results/*.csv    │
                    │  (timestamped)    │
                    └───────────────────┘
```

## Install and run

```bash
uv venv
uv pip install -r requirements.txt
python run.py
# → http://localhost:5001
```

## Config

Everything lives in `config.json`:

```jsonc
{
  "server": { "host": "0.0.0.0", "port": 5001 },
  "smtp": {
    "ports": [25, 587],
    "timeout": 10,
    "retry_attempts": 2,
    "retry_delay_base": 5,
    "base_delay": 2.0
  },
  "dns": { "timeout": 15, "servers": ["8.8.8.8", "1.1.1.1"] },
  "catchall": { "enabled": true, "test_address": "nonexistent-..." }
}
```

No `.env` required. The disposable blocklist at `data/disposable_domains.txt` is optional — if missing, a warning is logged and that stage is skipped.

## Example — single verification

```bash
curl -X POST http://localhost:5001/verify_single \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

```json
{
  "email": "test@example.com",
  "status": "invalid",
  "steps": {
    "syntax": "ok",
    "disposable": "ok",
    "mx": ["mx.example.com"],
    "catchall": false,
    "smtp_rcpt": "550 mailbox unavailable"
  }
}
```

## Example — bulk upload

Upload a CSV with an `email` column via the UI. Output lands in `results/verification_<timestamp>.csv` with per-address status, MX, catch-all flag, and the full SMTP dialogue for auditing.

## Known limits

- **IPv4 SMTP egress required** — many residential ISPs block outbound port 25. Runs best on a VPS or cloud instance.
- **No queue** — a crash mid-bulk loses in-flight state. OK for thousands, not millions.
- **Not 100% conclusive** — catch-all domains and greylist tarpits return `probable` / `unknown`. Treat those as signals, not verdicts.

## License

[MIT](LICENSE)
