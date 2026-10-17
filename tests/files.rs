// Project: email-verifier
// File: tests/files.rs
// Description: Encoding, extraction and byte-level CSV regression tests.
// Author: Jan Alexandr Kopřiva
// Based on email-verifier by Jan Alexandr Kopřiva
// License: MIT

use email_verifier::{
    files::*,
    verifier::{validate_syntax, Settings, VerificationResult},
};
use serde_json::json;
#[test]
fn csv_fixture_preserves_order_and_deduplicates() {
    let text = include_str!("fixtures/addresses.csv");
    let (d, h) = csv_headers(text).unwrap();
    assert_eq!(d, b';');
    assert_eq!(suggest_column(&h), Some("Email Address".into()));
    assert_eq!(
        csv_emails(text, d, "Email Address").unwrap(),
        ["one@example.com", "two@example.com"]
    );
    assert!(csv_emails(text, d, "missing").is_err());
}
#[test]
fn encoding_detection() {
    assert_eq!(
        decode(b"\xef\xbb\xbfemail,name\n").unwrap(),
        ("email,name\n".into(), "utf-8-sig")
    );
    assert_eq!(
        decode(&[0x8e, 0x6c, 0x75, 0x9d]).unwrap(),
        ("Žluť".into(), "cp1250")
    );
}
#[test]
fn delimiter_priority_and_single_column_behavior() {
    assert_eq!(csv_headers("email;name,other\na;b,c\n").unwrap().0, b',');
    assert!(csv_headers("email\na@example.com\n").is_err());
    for separator in [',', ';', '\t', '|'] {
        assert_eq!(
            csv_headers(&format!("a{separator}b\n")).unwrap().1,
            ["a", "b"]
        );
    }
}
#[test]
fn missing_cells_and_duplicate_headers_are_safe() {
    assert_eq!(
        csv_emails("email,name\na@example.com,x\n\ny\n", b',', "name").unwrap(),
        ["x"]
    );
    assert_eq!(
        csv_emails("email,email\na@example.com,b@example.com\n", b',', "email").unwrap(),
        ["b@example.com"]
    );
}
#[test]
fn txt_fixture_and_prefix_behavior() {
    assert_eq!(
        txt_emails(include_str!("fixtures/addresses.txt")),
        ["one@example.com", "two@example.com", "three@example.com"]
    );
    assert_eq!(
        txt_emails("one@example.com trailing; two@example.com"),
        ["one@example.com trailing", "two@example.com"]
    );
    assert_eq!(
        txt_emails("Prefix one@example.com;two@example.com"),
        ["two@example.com"]
    );
}
#[test]
fn filenames_cannot_escape_upload_folder() {
    assert_eq!(secure_filename("../../žluť file.csv"), "zlut_file.csv");
    assert!(!secure_filename("a\\b/evil.csv").contains(['\\', '/']));
}
#[test]
fn csv_bom_column_order_crlf_and_quoting() {
    let r:VerificationResult=serde_json::from_value(json!({"email":"a@example.com","is_valid":true,"status_code":"valid","message":"Accepted, yes","is_catchall":false,"mx_record":"mx.example.com","smtp_code_internal":250,"verification_steps":[]})).unwrap();
    let bytes = result_csv(&[r]).unwrap();
    assert_eq!(bytes, include_bytes!("fixtures/results.csv"));
}
#[test]
fn configuration_defaults_and_precedence() {
    let s=Settings::from_value(&json!({"helo_hostname":"probe.example.com","catchall_test":false,"check_catchall":true,"batch_size":100})).unwrap();
    assert!(!s.catchall);
    assert_eq!(s.ui_batch_size, 20);
    assert_eq!(s.smtp_timeout, 10.);
    assert_eq!(s.connect_port, 25);
    assert_eq!(s.retry_attempts, 2);
    assert_eq!(s.default_sender, "verifier@probe.example.com");
    assert!(Settings::from_value(&json!({"ui_batch_size":0})).is_err());
    assert!(Settings::from_value(&json!({"helo_hostname":"x\r\nMAIL FROM:<a>"})).is_err());
}
#[test]
fn syntax_idna_and_injection() {
    assert_eq!(validate_syntax("a@EXAMPLE.COM").unwrap(), "example.com");
    assert!(validate_syntax("a@háčky.cz").unwrap().starts_with("xn--"));
    for s in [
        "bad",
        "@example.com",
        "a@",
        "a..b@example.com",
        "a@localhost",
        "a@example.test",
        "a@-example.com",
        "a@example.com\r\nQUIT",
    ] {
        assert!(validate_syntax(s).is_err(), "{s}");
    }
}

#[test]
fn invalid_integer_settings_are_rejected() {
    for value in [
        json!({"connect_port":65536}),
        json!({"connect_port":25.5}),
        json!({"max_concurrent_domains":-1}),
        json!({"ui_batch_size":"20"}),
    ] {
        assert!(Settings::from_value(&value).is_err());
    }
}
