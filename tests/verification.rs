// Project: email-verifier
// File: tests/verification.rs
// Description: Offline pipeline tests, retry outcomes, cache behavior and concurrency isolation.
// Author: Jan Alexandr Kopřiva
// Based on email-verifier by Jan Alexandr Kopřiva
// License: MIT

mod support;
use email_verifier::{
    network::{ProbeError, Reply},
    verifier::Verifier,
};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Duration};
use support::*;
#[tokio::test]
async fn valid_and_invalid_smtp_results() {
    let mock = MockNetwork::new();
    mock.replies.lock().unwrap().push_back(Ok(Reply {
        valid: false,
        status: "invalid_mailbox".into(),
        message: "No such user".into(),
        code: 550,
    }));
    let v = verifier(mock.clone(), json!({}));
    let r = v.verify("a@example.com").await;
    assert_eq!(r.is_valid, Some(false));
    assert_eq!(r.smtp_code_internal, Some(550));
    assert_eq!(v.verify("b@example.com").await.is_valid, Some(true));
    assert_eq!(mock.mx_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn syntax_and_disposable_never_touch_network() {
    let mock = MockNetwork::new();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/disposable_domains.txt");
    let v = verifier(
        mock.clone(),
        json!({"check_disposable":true,"disposable_domains_file_path":path}),
    );
    assert_eq!(v.verify("bad").await.status_code, "syntax_error");
    assert_eq!(
        v.verify("a@mailinator.com").await.status_code,
        "disposable_domain"
    );
    assert_eq!(mock.mx_calls.load(Ordering::SeqCst), 0);
    assert!(mock.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn recipient_and_catchall_probes_connect_only_checked_ips() {
    for catchall in [true, false] {
        let mock = MockNetwork::new();
        let v = verifier(mock.clone(), json!({"catchall_test":catchall}));
        assert_eq!(v.verify("a@example.com").await.is_valid, Some(true));
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), if catchall { 3 } else { 1 });
        assert!(calls.iter().all(|c| c.0.to_string() == "8.8.8.8"));
        assert_eq!(
            calls.iter().filter(|c| c.3).count(),
            if catchall { 2 } else { 0 }
        );
    }
}
#[tokio::test]
async fn one_private_address_blocks_every_probe() {
    let mock = MockNetwork::new();
    mock.ips.lock().unwrap().push("127.0.0.1".parse().unwrap());
    let v = verifier(mock.clone(), json!({"catchall_test":true}));
    let r = v.verify("a@example.com").await;
    assert_eq!(r.is_valid, None);
    assert_eq!(r.status_code, "unreachable_all_mx");
    assert!(mock.calls.lock().unwrap().is_empty());
    assert!(r
        .verification_steps
        .iter()
        .any(|s| s.details.contains("SSRF protection")));
}
#[tokio::test]
async fn retries_reset_trace_and_honor_total_attempt_count() {
    let mock = MockNetwork::new();
    mock.replies.lock().unwrap().extend((0..2).map(|_| {
        Err(ProbeError {
            status: "rcpt_to_temp_fail".into(),
            message: "RCPT TO temp error: 450 Busy".into(),
            retryable: true,
        })
    }));
    let v = verifier(mock.clone(), json!({"retry_attempts":2}));
    let r = v.verify("a@example.com").await;
    assert_eq!(r.is_valid, None);
    assert_eq!(r.status_code, "rcpt_to_temp_fail");
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
    assert!(r.verification_steps[0].details.ends_with("Attempt: 2"));
}
#[tokio::test]
async fn successful_retry_and_nonretryable_timeout() {
    let mock = MockNetwork::new();
    mock.replies.lock().unwrap().push_back(Err(ProbeError {
        status: "mail_from_temp_fail".into(),
        message: "try again later".into(),
        retryable: true,
    }));
    let v = verifier(mock.clone(), json!({}));
    assert_eq!(v.verify("a@example.com").await.is_valid, Some(true));
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
    mock.replies.lock().unwrap().push_back(Err(ProbeError::new(
        "smtp_timeout",
        "SMTP response timeout",
    )));
    assert_eq!(
        v.verify("a@example.com").await.status_code,
        "unreachable_all_mx"
    );
    assert_eq!(mock.calls.lock().unwrap().len(), 3);
}
#[tokio::test]
async fn dns_failures_return_false() {
    let mock = MockNetwork::new();
    *mock.mx_error.lock().unwrap() = Some(ProbeError::new("dns_resolver_failure", "DNS failed"));
    let r = verifier(mock.clone(), json!({}))
        .verify("a@example.com")
        .await;
    assert_eq!(r.is_valid, Some(false));
    assert_eq!(r.message, "DNS failed");
    assert!(mock.calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn catchall_result_is_cached_and_freemail_skipped() {
    let mock = MockNetwork::new();
    *mock.catchall_accept.lock().unwrap() = true;
    let v = verifier(mock.clone(), json!({"catchall_test":true}));
    assert!(v.verify("a@example.com").await.is_catchall);
    assert!(v.verify("b@example.com").await.is_catchall);
    assert!(!v.verify("a@gmail.com").await.is_catchall);
    assert_eq!(mock.calls.lock().unwrap().iter().filter(|c| c.3).count(), 2);
    let run = std::sync::Arc::new(v.for_run());
    assert!(run.verify("c@example.com").await.is_catchall);
    assert_eq!(mock.calls.lock().unwrap().iter().filter(|c| c.3).count(), 4);
}
#[tokio::test]
async fn concurrent_traces_do_not_contain_other_recipients() {
    let mock = MockNetwork::new();
    *mock.delay.lock().unwrap() = Duration::from_millis(10);
    let v = verifier(mock, json!({}));
    let emails = vec!["one@example.com".into(), "two@example.com".into()];
    let results = v.batch(&emails).await;
    assert_eq!(results.len(), 2);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.email, emails[i]);
        assert!(r
            .verification_steps
            .iter()
            .all(|s| !s.details.contains(&emails[1 - i])));
    }
}
#[test]
fn separate_runs_have_separate_caches() {
    let v = verifier(MockNetwork::new(), json!({}));
    let run: Verifier = v.for_run();
    assert!(!std::sync::Arc::ptr_eq(&v.cache, &run.cache));
}
#[test]
fn fixture_directory_is_isolated() {
    let dir = Directory::new();
    assert!(dir.0.exists());
}

#[tokio::test]
async fn exponential_retry_delay_is_applied() {
    let mock = MockNetwork::new();
    mock.replies.lock().unwrap().extend((0..2).map(|_| {
        Err(ProbeError {
            status: "rcpt_to_temp_fail".into(),
            message: "Busy".into(),
            retryable: true,
        })
    }));
    let v = verifier(mock.clone(), json!({"retry_attempts":3,"retry_delay":0.01}));
    let started = std::time::Instant::now();
    assert_eq!(v.verify("a@example.com").await.is_valid, Some(true));
    assert!(started.elapsed() >= Duration::from_millis(60));
    assert_eq!(mock.calls.lock().unwrap().len(), 3);
}
