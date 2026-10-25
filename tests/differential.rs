// Project: email-verifier
// File: tests/differential.rs
// Description: Replay Python reference outputs without requiring the replaced runtime.
// Author: Jan Alexandr Kopřiva
// License: AGPL-3.0-or-later
use email_verifier::{files, verifier::validate_syntax};
use serde_json::{json, Value};
#[test]
fn saved_python_reference_cases() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python-reference.json")).unwrap();
    for case in cases {
        let expected = &case["expected"];
        let text = case["text"].as_str().unwrap_or("");
        let actual = match case["op"].as_str().unwrap() {
            "headers" => json!(files::csv_headers(text).unwrap().1),
            "txt" => json!(files::txt_emails(text)),
            "decode" => {
                let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
                let (text, encoding) = files::decode(&bytes).unwrap();
                json!([text, encoding])
            }
            "csv" => json!(files::csv_emails(text, b',', "email").unwrap()),
            "syntax" => match validate_syntax(text) {
                Ok(domain) => json!({"domain":domain}),
                Err(e) => json!({"error":e}),
            },
            "ip" if text == "::ffff:8.8.8.8" => {
                assert!(!email_verifier::classify::is_blocked_ip(text));
                continue;
            }
            "ip" => json!(email_verifier::classify::is_blocked_ip(text)),
            _ => panic!("unknown reference case"),
        };
        if case["op"] == "syntax" && expected.get("error").is_some() {
            assert!(actual.get("error").is_some(), "{case}: {actual}");
        } else {
            assert_eq!(&actual, expected, "{case}");
        }
    }
}
#[test]
fn extreme_configuration_is_rejected_without_panicking() {
    use email_verifier::verifier::Settings;
    for value in [
        json!({"smtp_timeout":1e300}),
        json!({"dns_timeout":1e300}),
        json!({"retry_delay":1e300}),
        json!({"max_concurrent_domains":u64::MAX}),
    ] {
        assert!(Settings::from_value(&value).is_err(), "{value}");
    }
    assert!(Settings::from_value(
        &json!({"max_concurrent_domains":tokio::sync::Semaphore::MAX_PERMITS})
    )
    .is_ok());
}

#[test]
fn deterministic_csv_corpus_matches_python() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/csv-reference.json")).unwrap();
    for case in cases {
        assert_eq!(
            json!(files::csv_emails(case["text"].as_str().unwrap(), b',', "email").unwrap()),
            case["expected"],
            "{case}"
        );
    }
}
