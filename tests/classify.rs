// Project: email-verifier
// File: tests/classify.rs
// Description: Equivalents of every original classification and shipped-list test.
// Author: Jan Alexandr Kopřiva
// License: MIT

use email_verifier::classify::*;
use std::collections::{HashMap, HashSet};
fn disposable() -> HashSet<String> {
    ["mailinator.com", "10minutemail.com", "guerrillamail.com"]
        .map(str::to_string)
        .into_iter()
        .collect()
}
fn senders() -> HashMap<String, String> {
    [
        ("seznam.cz".into(), "probe@seznam.cz".into()),
        ("gmail.com".into(), "probe@gmail.com".into()),
    ]
    .into_iter()
    .collect()
}
const DEFAULT: &str = "default@example.com";
#[test]
fn an_address_that_is_not_publicly_routable_is_refused() {
    for ip in [
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "100.127.255.254",
    ] {
        assert!(is_blocked_ip(ip), "{ip}");
    }
}
#[test]
fn a_public_address_is_allowed() {
    for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
        assert!(!is_blocked_ip(ip), "{ip}");
    }
}
#[test]
fn an_address_that_will_not_parse_is_refused() {
    for ip in ["", "not an ip", "999.999.999.999", "10.0.0"] {
        assert!(is_blocked_ip(ip));
    }
}
#[test]
fn the_edges_of_the_cgnat_range() {
    assert!(!is_blocked_ip("100.63.255.255"));
    assert!(is_blocked_ip("100.64.0.0"));
    assert!(is_blocked_ip("100.127.255.255"));
    assert!(!is_blocked_ip("100.128.0.0"));
}
#[test]
fn a_listed_domain_is_disposable() {
    assert!(is_disposable_domain("mailinator.com", &disposable()));
}
#[test]
fn the_check_ignores_case() {
    assert!(is_disposable_domain("MailInator.COM", &disposable()));
}
#[test]
fn a_subdomain_of_a_listed_domain_is_disposable() {
    assert!(is_disposable_domain("mail.mailinator.com", &disposable()));
}
#[test]
fn a_domain_that_merely_ends_in_a_listed_name_is_not_matched() {
    assert!(!is_disposable_domain("notmailinator.com", &disposable()));
}
#[test]
fn an_ordinary_domain_is_not_disposable() {
    for domain in ["gmail.com", "seznam.cz", "example.co.uk"] {
        assert!(!is_disposable_domain(domain, &disposable()));
    }
}
#[test]
fn an_empty_blocklist_matches_nothing() {
    assert!(!is_disposable_domain("mailinator.com", &HashSet::new()));
}
#[test]
fn every_listed_code_reads_as_temporary() {
    for code in TEMPORARY_ERROR_CODES {
        assert!(is_temporary_error(*code, ""));
    }
}
#[test]
fn a_permanent_refusal_is_not_temporary() {
    for code in [250, 500, 501, 550, 551] {
        assert!(!is_temporary_error(code, ""));
    }
}
#[test]
fn the_permanent_looking_codes_are_temporary_on_purpose() {
    for code in [552, 553, 554] {
        assert!(is_temporary_error(code, ""));
    }
}
#[test]
fn a_busy_message_reads_as_temporary_whatever_the_code() {
    for message in [
        "Try again later",
        "Service temporary failure",
        "Server busy",
        "Rate limit exceeded",
        "Mailbox quota exceeded",
        "System overloaded",
        "Connection throttled",
    ] {
        assert!(is_temporary_error(550, message));
    }
}
#[test]
fn the_message_match_is_a_substring_not_a_word() {
    assert!(!is_temporary_error(550, "Service temporarily unavailable"));
    assert!(is_temporary_error(450, "Service temporarily unavailable"));
}
#[test]
fn the_message_match_ignores_case() {
    assert!(is_temporary_error(550, "TRY AGAIN LATER"));
}
#[test]
fn a_plain_rejection_is_not_temporary() {
    for message in ["", "User unknown", "No such user here"] {
        assert!(!is_temporary_error(550, message));
    }
}
#[test]
fn a_554_is_about_the_sender() {
    assert!(is_reputation_error(554, ""));
}
#[test]
fn a_sender_complaint_is_recognized() {
    for message in [
        "Your IP has poor reputation",
        "Sender reputation is low",
        "Message rejected as spam",
        "Your address is blocked",
        "Host is blacklisted",
        "Message rejected",
    ] {
        assert!(is_reputation_error(550, message));
    }
}
#[test]
fn a_recipient_problem_is_not_a_reputation_error() {
    for message in ["", "User unknown", "Mailbox full"] {
        assert!(!is_reputation_error(550, message));
    }
}
#[test]
fn an_override_wins_over_everything() {
    assert_eq!(
        choose_sender("seznam.cz", &senders(), DEFAULT, Some("forced@x.cz")),
        "forced@x.cz"
    );
}
#[test]
fn a_sensitive_domain_gets_a_sender_at_the_same_provider() {
    assert_eq!(
        choose_sender("seznam.cz", &senders(), DEFAULT, None),
        "probe@seznam.cz"
    );
}
#[test]
fn a_sensitive_domain_without_a_matching_sender_falls_back_to_a_trusted_one() {
    assert_eq!(
        choose_sender("post.cz", &senders(), DEFAULT, None),
        "probe@gmail.com"
    );
}
#[test]
fn a_sensitive_domain_with_no_usable_sender_falls_back_to_the_default() {
    assert_eq!(
        choose_sender("post.cz", &HashMap::new(), DEFAULT, None),
        DEFAULT
    );
}
#[test]
fn an_ordinary_domain_uses_its_own_sender_when_there_is_one() {
    assert_eq!(
        choose_sender("gmail.com", &senders(), DEFAULT, None),
        "probe@gmail.com"
    );
}
#[test]
fn an_ordinary_domain_otherwise_uses_the_default() {
    assert_eq!(
        choose_sender("example.com", &senders(), DEFAULT, None),
        DEFAULT
    );
}
#[test]
fn the_domain_lookup_ignores_case() {
    assert_eq!(
        choose_sender("SEZNAM.CZ", &senders(), DEFAULT, None),
        "probe@seznam.cz"
    );
}
#[test]
fn every_sensitive_domain_is_handled() {
    for domain in REPUTATION_SENSITIVE_DOMAINS {
        assert!(
            choose_sender(domain, &senders(), DEFAULT, None) == "probe@gmail.com"
                || *domain == "seznam.cz"
        );
    }
}
#[test]
fn the_verifier_connects_to_a_checked_address_not_a_name() {
    let public = "8.8.8.8".parse().unwrap();
    assert_eq!(
        checked_ips("mx.example.com", vec![public]).unwrap(),
        vec![public]
    );
    assert!(checked_ips("mx.example.com", vec![public, "127.0.0.1".parse().unwrap()]).is_err());
    assert!(checked_ips("mx.example.com", vec![]).is_err());
}
fn shipped() -> HashSet<String> {
    include_str!("../data/disposable_domains.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}
#[test]
fn the_blocklist_is_shipped() {
    assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data/disposable_domains.txt")
        .exists());
}
#[test]
fn the_blocklist_is_not_empty() {
    assert!(shipped().len() >= 20);
}
#[test]
fn the_blocklist_catches_the_obvious_providers() {
    for domain in ["mailinator.com", "guerrillamail.com", "yopmail.com"] {
        assert!(shipped().contains(domain));
    }
}
#[test]
fn the_blocklist_does_not_list_a_real_mail_provider() {
    for domain in ["gmail.com", "seznam.cz", "outlook.com", "protonmail.com"] {
        assert!(!shipped().contains(domain));
    }
}
#[test]
fn every_entry_looks_like_a_bare_domain() {
    for domain in shipped() {
        assert!(!domain.contains(['@', '/']) && domain.contains('.'));
        assert_eq!(domain, domain.trim().to_lowercase());
    }
}
#[test]
fn the_shipped_list_works_through_the_public_check() {
    assert!(is_disposable_domain("mailinator.com", &shipped()));
    assert!(is_disposable_domain("throwaway.mailinator.com", &shipped()));
    assert!(!is_disposable_domain("gmail.com", &shipped()));
}
#[test]
fn ipv4_mapped_and_reserved_ipv6_are_refused() {
    for ip in [
        "::ffff:127.0.0.1",
        "::ffff:10.1.1.1",
        "2001:db8::1",
        "fc00::1",
        "ff02::1",
        "2002::1",
        "198.18.1.1",
        "240.1.1.1",
    ] {
        assert!(is_blocked_ip(ip), "{ip}");
    }
    assert!(!is_blocked_ip("::ffff:8.8.8.8"));
}
