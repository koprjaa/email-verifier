# email-verifier

Verifies email addresses over real SMTP connections. It detects catch-all domains, caches DNS lookups, and ships a Flask interface for bulk CSV upload.

![python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-A31F34?style=flat-square)
![status](https://img.shields.io/badge/status-active-22863A?style=flat-square)

## What it does

Most verification services charge per check. Most open source tools stop at syntax and an MX lookup, which says nothing about whether the mailbox exists. Gmail and catch-all domains accept any recipient without an error.

This project opens an SMTP connection, probes with `RCPT TO`, and adds a reputation layer for the Czech providers `seznam.cz`, `centrum.cz`, `post.cz`, and `email.cz`, which delay unknown senders.

Each address passes five stages:

1. RFC 5322 syntax check with `email-validator`.
2. Disposable domain filter against `data/disposable_domains.txt`.
3. DNS MX lookup with a cache, using `aiodns`.
4. Catch-all probe. This finds domains that accept any recipient. The stage is optional.
5. SMTP `RCPT TO` over async connections with `aiosmtplib`, on ports 25 and 587.

## Install

```bash
uv venv
uv pip install -r requirements.txt
python run.py
```

The application listens on `http://localhost:5001`.

## Use

Verify one address:

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

For bulk work, upload a CSV with an `email` column through the web interface. Progress updates while the run proceeds. The result goes to `results/verification_<timestamp>.csv` with the status, the MX record, the catch-all flag, and the full SMTP dialogue for each address.

## Configure

All settings live in `config.json`. No `.env` file is needed.

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

The disposable blocklist is optional. If the file is missing, the application logs a warning and skips that stage.

## How it works

```
Flask UI  ->  VerificationService  ->  aiodns DNS lookup
              (state per job)          aiosmtplib SMTP probe
                    |                  backoff retry
                    v                  asyncio.Semaphore
              results/*.csv
```

## Limits

- The host needs outbound IPv4 port 25. Many residential providers block it. A virtual server works better.
- There is no job queue. A crash during a bulk run loses the in-flight state. This suits thousands of addresses, not millions.
- The result is not always conclusive. Catch-all domains and greylisting return `probable` or `unknown`. Treat those as signals, not as verdicts.
- No tests.

## License

[MIT](LICENSE)
