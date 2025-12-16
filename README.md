# Email Verifier

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10-blue)
![Flask](https://img.shields.io/badge/flask-3.0.2-green)

## Overview

Email verification web application that validates email addresses using SMTP and DNS checks. Implements bulk verification with concurrent processing, catch-all domain detection, and disposable email filtering. Built as a Flask application with an async verification engine.

## Motivation

Email verification is unreliable when done purely through syntax or DNS checks. Many domains accept all emails (catch-all), making verification ambiguous. This project implements SMTP-based verification to determine actual mailbox existence. The architecture separates concerns between web interface, business logic, and verification engine to demonstrate production-ready code organization.

## What This Project Does

Verifies email addresses through multiple stages:
1. Syntax validation using email-validator
2. Disposable domain checking against a configurable list
3. DNS MX record resolution with caching
4. Catch-all domain detection via test emails
5. SMTP connection and RCPT TO verification
6. Result classification (valid, invalid, probable, unknown)

Supports single email verification via API and bulk verification via CSV/TXT file upload. Results are exported as CSV with detailed verification steps.

## Architecture

Three-layer architecture:

**Web Layer (`app/routes/`)**
- Flask blueprints for HTTP endpoints
- Synchronous request handling
- Creates new asyncio event loops per request for async verification

**Service Layer (`app/services/`)**
- `VerificationService`: Orchestrates verification, manages background threads for bulk operations
- `FileService`: Handles file uploads, encoding detection, CSV parsing
- `StateService`: Manages verification state and CSV result generation

**Verification Engine (`verifier/`)**
- `EmailVerifier`: Async core engine using aiodns and aiosmtplib
- Implements semaphore-based concurrency limiting per domain
- Caches MX records and catch-all test results
- Custom exception hierarchy for error classification

**State Management (`app/models/`)**
- `VerificationState`: Thread-safe state container using RLock
- Stores verification progress, results, and statistics
- Accessed by both Flask routes and background verification threads

Bulk verification runs in a separate thread to avoid blocking Flask. Each request creates its own asyncio event loop because Flask is synchronous. State is shared between threads using locks.

## Tech Stack

**Backend**
- Flask 3.0.2: Web framework
- aiosmtplib 2.0.2: Async SMTP client
- aiodns 3.1.1: Async DNS resolver
- email-validator 2.1.1: Syntax validation
- dnspython 2.6.1: DNS utilities

**Data Processing**
- pandas 2.2.2: CSV parsing and manipulation
- charset-normalizer: Encoding detection

**Concurrency**
- asyncio: Async I/O for verification operations
- threading: Background thread for bulk verification
- asyncio.Semaphore: Domain-level concurrency limiting

**Configuration**
- JSON-based configuration with environment variable overrides
- Configurable sender emails per domain for reputation management

## Data Sources

**Disposable Domains**
- Loaded from `data/disposable_domains.txt` (not included in repository)
- File format: one domain per line, comments start with #
- Falls back to empty set if file missing

**MX Records**
- Resolved via DNS queries using system or configured DNS servers
- Cached per EmailVerifier instance to reduce DNS lookups

**Catch-all Detection**
- Sends test emails to random addresses on target domain
- Tests on ports 25 and 587
- Special handling for Microsoft domains due to ambiguous responses

**Known Freemail Domains**
- Hardcoded list of major providers (Gmail, Yahoo, Outlook, etc.)
- Used to skip catch-all tests on freemail domains

## Key Design Decisions

**Async Verification with Sync Flask**
Flask is synchronous, but SMTP/DNS operations benefit from async I/O. Each request creates a new event loop. This avoids blocking but requires careful loop management. Bulk operations run in a background thread with its own event loop.

**Semaphore-Based Concurrency Limiting**
Limits concurrent connections per domain, not globally. Prevents overwhelming individual mail servers while allowing parallel verification across domains. Default: 5 concurrent domains.

**Catch-all Domain Detection**
Catch-all domains accept all emails, making verification ambiguous. The system sends test emails to random addresses. If accepted, the domain is marked catch-all and results are classified as "probable" rather than "valid".

**Sender Email Configuration**
Different domains require different sender addresses for reputation. Configurable per-domain sender emails prevent reputation-based rejections. Default sender falls back to verifier@{hostname}.

**Thread-Safe State Management**
VerificationState uses RLock for re-entrant locking. Allows nested lock acquisition and safe access from multiple threads. State updates are atomic within lock context.

**MX Record Caching**
DNS lookups are expensive. MX records are cached per EmailVerifier instance. Cache is protected by asyncio.Lock for thread-safe access.

**Encoding Detection**
CSV files may use various encodings. The system tries multiple encodings (UTF-8, CP1250, ISO-8859-2) and delimiters (comma, semicolon, tab) before parsing.

**Separate Event Loops**
Flask requests cannot share an event loop. Each request creates and closes its own loop. This is necessary because Flask's threading model conflicts with asyncio's event loop model.

## Limitations

**Verification Accuracy**
- Catch-all domains cannot be definitively verified. Results are marked "probable".
- Some mail servers reject verification attempts as spam, leading to false negatives.
- Rate limiting may cause timeouts or rejections.
- Microsoft domains often return ambiguous responses, treated as catch-all.

**Concurrency**
- Single EmailVerifier instance shared across requests. Bulk operations may contend for semaphore slots.
- Event loop creation per request adds overhead. Not suitable for high-throughput scenarios.
- Background thread for bulk verification is single-threaded. No parallel batch processing.

**State Management**
- VerificationState is in-memory. No persistence across application restarts.
- No distributed state. Cannot scale horizontally without shared state solution.
- State cleanup relies on atexit handlers. May not run on abnormal termination.

**File Handling**
- Uploaded files stored on filesystem. No size limits beyond Flask's MAX_CONTENT_LENGTH.
- No file validation beyond extension checking.
- Results directory grows unbounded without manual cleanup.

**Configuration**
- Disposable domains file must be provided separately. Not included in repository.
- No validation of config.json structure. Invalid config may cause runtime errors.
- Environment variables override config.json but type checking is minimal.

**Error Handling**
- SMTP errors are caught and classified, but network failures may result in "unknown" status.
- DNS failures are retried but may still fail if DNS servers are unreachable.
- No automatic retry for bulk verification failures. Manual restart required.

**Security**
- No authentication or authorization. All endpoints are public.
- File uploads use secure_filename but no content scanning.
- No rate limiting on API endpoints beyond SMTP-level limits.

**Scalability**
- Designed for single-instance deployment. No database or message queue.
- Thread-based bulk processing limits throughput.
- No horizontal scaling support.

## How to Run

**Prerequisites**
- Python 3.10+
- Virtual environment (recommended)

**Setup**
```bash
git clone <repository-url>
cd email-verifier
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

**Configuration**
Create `config.json` in project root (see `config.json.example` if provided). Optional: set environment variables:
- `FLASK_RUN_HOST`: Server host (default: 0.0.0.0)
- `FLASK_RUN_PORT`: Server port (default: 5001)
- `FLASK_DEBUG`: Debug mode (default: 1)

**Optional: Disposable Domains**
Create `data/disposable_domains.txt` with one domain per line. Application works without this file but disposable checking will be disabled.

**Run**
```bash
python run.py
```

Application starts on `http://localhost:5001` (or configured port).

## Example Usage

**Single Email Verification (API)**
```bash
curl -X POST http://localhost:5001/verify_single \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'
```

**Bulk Verification (Web UI)**
1. Open `http://localhost:5001`
2. Upload CSV file with email column
3. Select email column
4. Start verification
5. Download results CSV when complete

**Status Check (API)**
```bash
curl http://localhost:5001/status
```

Returns current verification state, statistics, and recent log entries.

## Future Improvements

**Architecture**
- Replace thread-based bulk processing with task queue (Celery, RQ)
- Add database for state persistence and result storage
- Implement proper async Flask (Quart) or separate API server
- Add Redis for distributed caching and state

**Verification**
- Implement greylisting detection and retry logic
- Add SPF/DKIM/DMARC validation
- Support for additional SMTP ports (465, 587 with TLS)
- Improve catch-all detection accuracy

**Scalability**
- Horizontal scaling with shared state backend
- API rate limiting middleware
- Batch processing with message queues
- Result pagination for large datasets

**User Experience**
- Authentication and user accounts
- Progress WebSocket updates instead of polling
- Export formats beyond CSV (JSON, Excel)
- Email verification history

**Reliability**
- Comprehensive error recovery
- Automatic retry with exponential backoff
- Health check endpoints
- Monitoring and metrics integration

## Author

Jan Alexandr Kopřiva  
jan.alexandr.kopriva@gmail.com

## License

MIT License
