// Project: email-verifier
// File: tests/smtp.rs
// Description: Real SMTP protocol exercised against loopback fixtures only.
// Author: Jan Alexandr Kopřiva
// License: MIT

use email_verifier::{network::smtp_session, verifier::Settings};
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener},
    thread,
    time::Duration,
};
fn server(script: Vec<(&'static str, &'static str)>) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"220 mock SMTP\r\n").unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for (expected, response) in script {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, format!("{expected}\r\n"));
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
        stream.shutdown(Shutdown::Write).unwrap();
        let mut rest = vec![];
        reader.read_to_end(&mut rest).unwrap();
    });
    (port, task)
}
fn settings() -> Settings {
    Settings::from_value(&json!({"helo_hostname":"probe.example.com","sender_emails":{"default":"sender@example.com"},"smtp_timeout":1})).unwrap()
}
#[tokio::test]
async fn multiline_ehlo_and_reset_failure_preserve_verdict() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250-mock\r\n250 PIPELINING\r\n"),
        ("MAIL FROM:<sender@example.com>", "250 OK\r\n"),
        ("RCPT TO:<a@example.com>", "250 Accepted\r\n"),
        ("RSET", "500 Reset failed\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "a@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        false,
    )
    .await
    .unwrap();
    assert!(r.valid);
    assert_eq!(r.code, 250);
    task.join().unwrap();
}
#[tokio::test]
async fn ehlo_falls_back_and_invalid_recipient_is_reported() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "500 No EHLO\r\n"),
        ("HELO probe.example.com", "250 Hello\r\n"),
        ("MAIL FROM:<sender@example.com>", "250 OK\r\n"),
        ("RCPT TO:<a@example.com>", "550 User unknown\r\n"),
        ("RSET", "250 OK\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "a@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        false,
    )
    .await
    .unwrap();
    assert!(!r.valid);
    assert_eq!(r.message, "User unknown");
    task.join().unwrap();
}
#[tokio::test]
async fn temporary_recipient_failure_is_retryable() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250 Hello\r\n"),
        ("MAIL FROM:<sender@example.com>", "250 OK\r\n"),
        ("RCPT TO:<a@example.com>", "450 Busy\r\n"),
        ("RSET", "250 OK\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "a@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        false,
    )
    .await
    .unwrap_err();
    assert!(r.retryable);
    assert_eq!(r.status, "rcpt_to_temp_fail");
    task.join().unwrap();
}
#[tokio::test]
async fn catchall_uses_no_reset_and_accepts_252() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250 Hello\r\n"),
        ("MAIL FROM:<sender@example.com>", "250 OK\r\n"),
        (
            "RCPT TO:<random@example.com>",
            "252 Cannot verify but accepting\r\n",
        ),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "random@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        true,
    )
    .await
    .unwrap();
    assert!(r.valid);
    task.join().unwrap();
}
#[tokio::test]
async fn reputation_failure_tries_alternative_sender() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250 Hello\r\n"),
        ("MAIL FROM:<sender@example.com>", "554 Sender blocked\r\n"),
        ("MAIL FROM:<alt@gmail.com>", "250 OK\r\n"),
        ("RCPT TO:<a@example.com>", "251 Forwarded\r\n"),
        ("RSET", "250 OK\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let mut s = settings();
    s.ordered_senders
        .push(("gmail.com".into(), "alt@gmail.com".into()));
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "a@example.com",
        "example.com",
        &s,
        &mut vec![],
        false,
    )
    .await
    .unwrap();
    assert!(r.valid);
    task.join().unwrap();
}

#[tokio::test]
async fn semaphore_limits_full_smtp_sessions() {
    use email_verifier::network::{Network, RealNetwork};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let observed = maximum.clone();
    let task = thread::spawn(move || {
        let mut workers = vec![];
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let active = active.clone();
            let maximum = maximum.clone();
            workers.push(thread::spawn(move || {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(count, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                stream.write_all(b"220 mock\r\n").unwrap();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "QUIT\r\n" {
                        active.fetch_sub(1, Ordering::SeqCst);
                        stream.write_all(b"221 Bye\r\n").unwrap();
                        break;
                    }
                    if line.starts_with("RCPT") {
                        thread::sleep(Duration::from_millis(20));
                    }
                    stream.write_all(b"250 OK\r\n").unwrap();
                }
                stream.shutdown(Shutdown::Write).unwrap();
                let mut rest = vec![];
                reader.read_to_end(&mut rest).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let mut s = settings();
    s.max_concurrent_domains = 1;
    let network = RealNetwork::new(&s).unwrap();
    let ip = "127.0.0.1".parse().unwrap();
    let mut first = vec![];
    let mut second = vec![];
    let (a, b) = tokio::join!(
        network.smtp(
            ip,
            port,
            "a@example.com",
            "example.com",
            &s,
            &mut first,
            false
        ),
        network.smtp(
            ip,
            port,
            "b@example.com",
            "example.com",
            &s,
            &mut second,
            true
        )
    );
    assert!(a.unwrap().valid && b.unwrap().valid);
    task.join().unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_multiline_and_reply_separators_are_refused() {
    for response in [
        "250Xinvalid\r\n",
        "250-first\r\n550 last\r\n",
        "999 Invalid\r\n",
    ] {
        let (port, task) = server(vec![
            ("EHLO probe.example.com", response),
            ("QUIT", "221 Bye\r\n"),
        ]);
        let result = smtp_session(
            "127.0.0.1".parse().unwrap(),
            port,
            "a@example.com",
            "example.com",
            &settings(),
            &mut vec![],
            false,
        )
        .await;
        assert_eq!(result.unwrap_err().status, "unknown_smtp_error");
        task.join().unwrap();
    }
}

#[tokio::test]
async fn greeting_timeout_and_oversized_reply_are_bounded() {
    for oversized in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            if oversized {
                let _ = stream.write_all(&vec![b'x'; 65537]);
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        });
        let mut s = settings();
        s.smtp_timeout = 0.02;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            smtp_session(
                "127.0.0.1".parse().unwrap(),
                port,
                "a@example.com",
                "example.com",
                &s,
                &mut vec![],
                false,
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        task.join().unwrap();
    }
}

#[tokio::test]
async fn public_smtp_entry_rejects_injection_and_invalid_timeout_before_connecting() {
    let mut s = settings();
    let result = smtp_session(
        "127.0.0.1".parse().unwrap(),
        1,
        "a@example.com\r\nQUIT",
        "example.com",
        &s,
        &mut vec![],
        false,
    )
    .await;
    assert_eq!(result.unwrap_err().status, "smtp_invalid_input");
    s.smtp_timeout = f64::INFINITY;
    let result = smtp_session(
        "127.0.0.1".parse().unwrap(),
        1,
        "a@example.com",
        "example.com",
        &s,
        &mut vec![],
        false,
    )
    .await;
    assert_eq!(result.unwrap_err().status, "smtp_timeout");
}

#[tokio::test]
async fn saved_python_smtp_dialogues_keep_documented_verdicts() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/smtp-reference.json")).unwrap();
    for case in cases {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let phase = case["phase"].as_str().unwrap().to_string();
        let response = case["response"].as_str().unwrap().to_string();
        let task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.write_all(b"220 mock\r\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let reply = if line.starts_with(&phase) {
                    format!("{response}\r\n")
                } else if line.starts_with("QUIT") {
                    "221 Bye\r\n".into()
                } else {
                    "250 OK\r\n".into()
                };
                if stream.write_all(reply.as_bytes()).is_err() || line.starts_with("QUIT") {
                    break;
                }
            }
        });
        let result = smtp_session(
            "127.0.0.1".parse().unwrap(),
            port,
            "a@example.com",
            "example.com",
            &settings(),
            &mut vec![],
            false,
        )
        .await;
        let actual = match result {
            Ok(r) => json!({"valid":r.valid,"status":r.status,"message":r.message,"code":r.code}),
            Err(e) => json!({"error":e.status,"message":e.message,"retryable":e.retryable}),
        };
        task.join().unwrap();
        assert_eq!(actual, case["rust"], "{case}");
    }
}

#[tokio::test]
async fn policy_and_unusual_temporary_recipient_refusals_carry_no_verdict() {
    for (reply, status) in [
        (
            "550 5.7.1 Client host blocked using zen.spamhaus.org\r\n",
            "rcpt_policy_reject",
        ),
        ("553 5.7.1 Relaying denied\r\n", "rcpt_policy_reject"),
        ("455 4.5.5 Try later\r\n", "rcpt_temp_reject"),
        ("550 5.1.1 User unknown\r\n", "invalid_mailbox"),
    ] {
        let (port, task) = server(vec![
            ("EHLO probe.example.com", "250 mock\r\n"),
            ("MAIL FROM:<sender@example.com>", "250 OK\r\n"),
            ("RCPT TO:<a@example.com>", reply),
            ("RSET", "250 OK\r\n"),
            ("QUIT", "221 Bye\r\n"),
        ]);
        let r = smtp_session(
            "127.0.0.1".parse().unwrap(),
            port,
            "a@example.com",
            "example.com",
            &settings(),
            &mut vec![],
            false,
        )
        .await
        .unwrap();
        assert!(!r.valid);
        assert_eq!(r.status, status, "{reply}");
        task.join().unwrap();
    }
}
#[tokio::test]
async fn non_ascii_local_part_is_sent_only_when_the_server_advertises_smtputf8() {
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250-mock\r\n250 SMTPUTF8\r\n"),
        ("MAIL FROM:<sender@example.com> SMTPUTF8", "250 OK\r\n"),
        ("RCPT TO:<řehoř@example.com>", "250 Accepted\r\n"),
        ("RSET", "250 OK\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "řehoř@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        false,
    )
    .await
    .unwrap();
    assert!(r.valid);
    task.join().unwrap();
    let (port, task) = server(vec![
        ("EHLO probe.example.com", "250-mock\r\n250 PIPELINING\r\n"),
        ("QUIT", "221 Bye\r\n"),
    ]);
    let r = smtp_session(
        "127.0.0.1".parse().unwrap(),
        port,
        "řehoř@example.com",
        "example.com",
        &settings(),
        &mut vec![],
        false,
    )
    .await
    .unwrap();
    assert!(!r.valid);
    assert_eq!(r.status, "smtputf8_unsupported");
    task.join().unwrap();
}
