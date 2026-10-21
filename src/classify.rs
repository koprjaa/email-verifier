// Project: email-verifier
// File: classify.rs
// Description: Network-independent address and SMTP policy decisions.
// Author: Jan Alexandr Kopřiva
// License: MIT

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
pub const TEMPORARY_ERROR_CODES: &[u16] =
    &[421, 450, 451, 452, 454, 458, 459, 471, 472, 552, 553, 554];
pub const REPUTATION_SENSITIVE_DOMAINS: &[&str] =
    &["centrum.cz", "post.cz", "seznam.cz", "email.cz"];
pub fn is_temporary_error(code: u16, message: &str) -> bool {
    TEMPORARY_ERROR_CODES.contains(&code)
        || [
            "temporary",
            "try again",
            "later",
            "busy",
            "overloaded",
            "rate limit",
            "throttled",
            "quota",
            "limit exceeded",
        ]
        .iter()
        .any(|p| message.to_lowercase().contains(p))
}
pub fn is_reputation_error(code: u16, message: &str) -> bool {
    code == 554
        || [
            "poor reputation",
            "reputation",
            "spam",
            "blocked",
            "blacklisted",
            "rejected",
        ]
        .iter()
        .any(|p| message.to_lowercase().contains(p))
}
/// Statuses of a reply that says nothing about the mailbox itself.
pub fn is_unknown_status(status: &str) -> bool {
    [
        "smtputf8_unsupported",
        "rcpt_temp_reject",
        "rcpt_policy_reject",
    ]
    .contains(&status)
}
/// A permanent RCPT refusal caused by policy or reputation (5.7.x, blocklists), not by the mailbox.
pub fn is_rcpt_policy_rejection(code: u16, message: &str) -> bool {
    if !(500..600).contains(&code) {
        return false;
    }
    let lower = message.to_lowercase();
    let status = |prefix: &str| lower.split_whitespace().any(|t| t.starts_with(prefix));
    if status("5.1.") {
        return false;
    }
    status("5.7.")
        || [
            "reputation",
            "blocked",
            "blacklist",
            "blocklist",
            "spamhaus",
            "spam",
        ]
        .iter()
        .any(|p| lower.contains(p))
}
pub fn is_disposable_domain(domain: &str, domains: &HashSet<String>) -> bool {
    let domain = domain.to_lowercase();
    let parts: Vec<_> = domain.split('.').collect();
    domains.contains(&domain)
        || (parts.len() > 2 && domains.contains(&parts[parts.len() - 2..].join(".")))
}
pub fn choose_sender(
    domain: &str,
    senders: &HashMap<String, String>,
    default: &str,
    override_sender: Option<&str>,
) -> String {
    if let Some(sender) = override_sender.filter(|s| !s.is_empty()) {
        return sender.to_string();
    }
    let domain = domain.to_lowercase();
    if REPUTATION_SENSITIVE_DOMAINS.contains(&domain.as_str()) {
        for name in [domain.as_str(), "gmail.com", "outlook.com", "yahoo.com"] {
            if let Some(sender) = senders.get(name) {
                return sender.clone();
            }
        }
    }
    senders
        .get(&domain)
        .map(String::as_str)
        .unwrap_or(default)
        .to_string()
}
pub fn is_blocked_ip(value: &str) -> bool {
    match value.parse::<IpAddr>() {
        Err(_) => true,
        Ok(IpAddr::V4(ip)) => {
            let n = u32::from(ip);
            [
                ("0.0.0.0", 8),
                ("10.0.0.0", 8),
                ("100.64.0.0", 10),
                ("127.0.0.0", 8),
                ("169.254.0.0", 16),
                ("172.16.0.0", 12),
                ("192.0.0.0", 24),
                ("192.0.2.0", 24),
                ("192.168.0.0", 16),
                ("198.18.0.0", 15),
                ("198.51.100.0", 24),
                ("203.0.113.0", 24),
                ("224.0.0.0", 3),
            ]
            .iter()
            .any(|(base, bits)| {
                if n == u32::from(std::net::Ipv4Addr::new(192, 0, 0, 9))
                    || n == u32::from(std::net::Ipv4Addr::new(192, 0, 0, 10))
                {
                    return false;
                }
                let base = u32::from(base.parse::<std::net::Ipv4Addr>().expect("constant IP"));
                n >> (32 - bits) == base >> (32 - bits)
            })
        }
        Ok(IpAddr::V6(ip)) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_blocked_ip(&v4.to_string());
            }
            let n = u128::from(ip);
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || n >> 121 == 0b1111110
                || n >> 118 == 0b1111111010
                || n >> 96 == 0x20010db8
                || n >> 32 == 0
                || n >> 125 != 1
                || (n >> 105 == 0x2001 << 7 && !protocol_exception(n))
                || n >> 112 == 0x2002
        }
    }
}

/// Globally reachable parts of 2001::/23, the IETF protocol assignments block.
fn protocol_exception(n: u128) -> bool {
    use std::net::Ipv6Addr;
    [
        (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1), 128),
        (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2), 128),
        (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3), 128),
        (Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 4, 0x112, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28),
    ]
    .iter()
    .any(|(net, bits)| n >> (128 - bits) == u128::from(*net) >> (128 - bits))
}

pub fn checked_ips(host: &str, ips: Vec<IpAddr>) -> Result<Vec<IpAddr>, String> {
    if ips.is_empty() {
        return Err(format!(
            "Could not resolve MX host {host} to a public IP address."
        ));
    }
    for ip in &ips {
        if is_blocked_ip(&ip.to_string()) {
            return Err(format!("Refusing to connect to MX host {host}: resolved IP {ip} is in a private/reserved range (SSRF protection)."));
        }
    }
    Ok(ips)
}
