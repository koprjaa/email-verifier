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
