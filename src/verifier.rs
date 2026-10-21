// Project: email-verifier
// File: verifier.rs
// Description: Isolated verification traces, DNS caches, catch-all tests and retry orchestration.
// Author: Jan Alexandr Kopřiva
// License: MIT

use crate::{
    classify,
    network::{Network, ProbeError, Reply},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, OnceCell};
#[derive(Clone, Debug)]
pub struct Settings {
    pub smtp_timeout: f64,
    pub dns_timeout: f64,
    pub dns_tries: usize,
    pub dns_servers: Vec<String>,
    pub catchall: bool,
    pub check_disposable: bool,
    pub connect_port: u16,
    pub max_concurrent_domains: usize,
    pub retry_attempts: usize,
    pub retry_delay: f64,
    pub helo_hostname: String,
    pub default_sender: String,
    pub senders: HashMap<String, String>,
    pub ordered_senders: Vec<(String, String)>,
    pub sender_override: Option<String>,
    pub disposable_path: String,
    pub ui_batch_size: usize,
}
impl Settings {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let internal = std::fs::read_to_string("verifier/default_verifier_config.json")
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let number = |key: &str, default: f64| -> Result<f64, String> {
            let n = v
                .get(key)
                .map(|v| v.as_f64().ok_or_else(|| format!("Invalid setting: {key}")))
                .transpose()?
                .unwrap_or(default);
            if !n.is_finite()
                || n < 0.0
                || (["smtp_timeout", "dns_timeout", "retry_delay"].contains(&key) && n > 86400.0)
            {
                Err(format!("Invalid setting: {key}"))
            } else {
                Ok(n)
            }
        };
        let helo = v["helo_hostname"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or(internal["helo_hostname"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                hostname::get()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        let mapping = v["sender_emails"].as_object();
        let mut ordered_senders: Vec<(String, String)> = mapping
            .into_iter()
            .flat_map(|m| m.iter())
            .filter(|(k, _)| k.as_str() != "default")
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        if ordered_senders.is_empty() {
            ordered_senders = internal["sender_emails_by_domain"]
                .as_object()
                .into_iter()
                .flat_map(|m| m.iter())
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
        }
        for (key, max) in [
            ("connect_port", 65535_u64),
            (
                "max_concurrent_domains",
                tokio::sync::Semaphore::MAX_PERMITS as u64,
            ),
            ("retry_attempts", usize::MAX as u64),
            ("ui_batch_size", usize::MAX as u64),
        ] {
            if v.get(key)
                .is_some_and(|value| value.as_u64().is_none_or(|n| n > max))
            {
                return Err(format!("Invalid integer setting: {key}"));
            }
        }
        let s = Self {
            smtp_timeout: number("smtp_timeout", 10.)?,
            dns_timeout: number("dns_timeout", 5.)?,
            dns_tries: internal["dns_resolver_tries"].as_u64().unwrap_or(2) as usize,
            dns_servers: v
                .get("dns_servers")
                .or(internal.get("dns_servers"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            catchall: v["catchall_test"]
                .as_bool()
                .or(v["check_catchall"].as_bool())
                .unwrap_or(true),
            check_disposable: v["check_disposable"].as_bool().unwrap_or(true),
            connect_port: v["connect_port"].as_u64().unwrap_or(25) as u16,
            max_concurrent_domains: v["max_concurrent_domains"].as_u64().unwrap_or(5) as usize,
            retry_attempts: v["retry_attempts"].as_u64().unwrap_or(2) as usize,
            retry_delay: number("retry_delay", 5.)?,
            default_sender: v["sender_emails"]["default"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or(internal["default_sender_email"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("verifier@{helo}")),
            helo_hostname: helo,
            senders: ordered_senders.iter().cloned().collect(),
            ordered_senders,
            sender_override: v["sender_email_override"].as_str().map(str::to_string),
            disposable_path: v["disposable_domains_file_path"]
                .as_str()
                .unwrap_or("data/disposable_domains.txt")
                .into(),
            ui_batch_size: v["ui_batch_size"].as_u64().unwrap_or(20) as usize,
        };
        if s.max_concurrent_domains == 0
            || s.ui_batch_size == 0
            || s.connect_port == 0
            || s.smtp_timeout == 0.
            || s.dns_timeout == 0.
        {
            return Err("Concurrency, batch size, port and timeouts must be positive".into());
        }
        if s.helo_hostname.contains(['\r', '\n'])
            || s.default_sender.contains(['\r', '\n'])
            || s.sender_override
                .as_deref()
                .is_some_and(|s| s.contains(['\r', '\n']))
            || s.senders.values().any(|s| s.contains(['\r', '\n']))
        {
            return Err("SMTP settings must not contain line breaks".into());
        }
        Ok(s)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub timestamp: String,
    pub status: String,
    pub action: String,
    pub details: String,
    pub code: Option<String>,
}
impl Step {
    pub fn add(
        steps: &mut Vec<Self>,
        status: &str,
        action: &str,
        details: impl Into<String>,
        code: Option<u16>,
    ) {
        let details = details.into();
        crate::log(
            "DEBUG",
            &format!(
                "Step: {action} - {details} (Status: {status}, Code: {})",
                code.map(|c| c.to_string()).unwrap_or_else(|| "None".into())
            ),
        );
        steps.push(Self {
            timestamp: crate::timestamp(),
            status: status.into(),
            action: action.into(),
            details,
            code: code.map(|c| c.to_string()),
        });
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub email: String,
    pub is_valid: Option<bool>,
    pub status_code: String,
    pub message: String,
    pub is_catchall: bool,
    pub mx_record: Option<String>,
    pub smtp_code_internal: Option<u16>,
    pub verification_steps: Vec<Step>,
}
impl VerificationResult {
    fn new(email: &str, attempt: usize) -> Self {
        let mut r = Self {
            email: email.into(),
            is_valid: Some(false),
            status_code: "unknown_error".into(),
            message: "Unknown error".into(),
            is_catchall: false,
            mx_record: None,
            smtp_code_internal: None,
            verification_steps: vec![],
        };
        Step::add(
            &mut r.verification_steps,
            "info",
            "Verification start",
            format!("Email: {email}, Attempt: {attempt}"),
            None,
        );
        r
    }
    fn outcome(&mut self, valid: Option<bool>, status: &str, message: &str) {
        self.is_valid = valid;
        self.status_code = status.into();
        self.message = message.into();
    }
}
type MxRecords = Vec<(u16, String)>;
#[derive(Default)]
pub struct RunCache {
    // one cell per domain: concurrent addresses of a domain wait for a single lookup
    mx: Mutex<HashMap<String, Arc<OnceCell<MxRecords>>>>,
    catchall: Mutex<HashMap<String, Arc<OnceCell<bool>>>>,
}
pub struct Verifier {
    pub settings: Settings,
    pub network: Arc<dyn Network>,
    disposable: HashSet<String>,
    pub cache: Arc<RunCache>,
}
impl Verifier {
    pub fn new(settings: Settings, network: Arc<dyn Network>) -> Self {
        if let Some(parent) = std::path::Path::new(&settings.disposable_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            if let Err(e) = std::fs::create_dir_all(parent) {
                crate::log(
                    "ERROR",
                    &format!("Could not create disposable list directory: {e}"),
                );
            }
        }
        let disposable = if settings.check_disposable {
            match std::fs::read_to_string(&settings.disposable_path) {
                Ok(s) => s
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                    .map(str::to_lowercase)
                    .collect(),
                Err(_) => {
                    crate::log("WARNING",&format!("Disposable domains file '{}' not found. The disposable check is off and no address will be rejected for it.",settings.disposable_path));
                    HashSet::new()
                }
            }
        } else {
            HashSet::new()
        };
        crate::log(
            "INFO",
            &format!(
                "EmailVerifier init. HELO: {}, Catch-all: {}, Disposable check: {}",
                settings.helo_hostname,
                if settings.catchall { "True" } else { "False" },
                if settings.check_disposable {
                    "True"
                } else {
                    "False"
                }
            ),
        );
        Self {
            settings,
            network,
            disposable,
            cache: Arc::new(RunCache::default()),
        }
    }
    pub fn for_run(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            network: self.network.clone(),
            disposable: self.disposable.clone(),
            cache: Arc::new(RunCache::default()),
        }
    }
    async fn probe(
        &self,
        email: &str,
        domain: &str,
        host: &str,
        port: u16,
        steps: &mut Vec<Step>,
        catchall: bool,
    ) -> Result<Reply, ProbeError> {
        let ips = self.network.ips(host).await?;
        let ips = classify::checked_ips(host, ips).map_err(|message| {
            Step::add(
                steps,
                "error",
                &format!("SSRF check (Port {port})"),
                &message,
                None,
            );
            ProbeError::new("mx_host_blocked", message)
        })?;
        let mut last = None;
        for ip in ips.iter().take(4) {
            Step::add(
                steps,
                "info",
                &format!("SMTP Connect (Port {port})"),
                format!("Attempting connect to {host} (IP: {ip})"),
                None,
            );
            match self
                .network
                .smtp(*ip, port, email, domain, &self.settings, steps, catchall)
                .await
            {
                // the next address of the same host may still answer
                Err(e) if ["smtp_timeout", "smtp_connect_error"].contains(&e.status.as_str()) => {
                    last = Some(e)
                }
                other => return other,
            }
        }
        Err(last.expect("at least one address"))
    }
    async fn catchall(&self, domain: &str, mx: &[(u16, String)], steps: &mut Vec<Step>) -> bool {
        const FREEMAIL: &[&str] = &[
            "gmail.com",
            "googlemail.com",
            "yahoo.com",
            "yahoodns.net",
            "aol.com",
            "hotmail.com",
            "outlook.com",
            "live.com",
            "msn.com",
            "seznam.cz",
            "email.cz",
            "post.cz",
            "centrum.cz",
            "gmx.com",
            "gmx.net",
            "mail.com",
            "mail.ru",
            "yandex.ru",
            "protonmail.com",
            "icloud.com",
            "me.com",
            "mac.com",
        ];
        if !self.settings.catchall {
            Step::add(steps, "info", "Catch-all Test", "Skipped (config).", None);
            return false;
        }
        if FREEMAIL.contains(&domain) {
            Step::add(
                steps,
                "info",
                "Catch-all Test",
                format!("Skipped ('{domain}' is known freemail)."),
                None,
            );
            return false;
        }
        let cell = self
            .cache
            .catchall
            .lock()
            .await
            .entry(domain.to_string())
            .or_default()
            .clone();
        let mut ran = false;
        let tested = cell
            .get_or_try_init(|| async {
                ran = true;
                self.catchall_test(domain, mx, steps).await
            })
            .await;
        match tested {
            Ok(value) => {
                if !ran {
                    Step::add(
                        steps,
                        "info",
                        "Catch-all Test (Cache)",
                        format!(
                            "Result for '{domain}' from cache: {}",
                            if *value { "True" } else { "False" }
                        ),
                        None,
                    );
                }
                *value
            }
            // nothing answered, so nothing is known and nothing is cached
            Err(()) => false,
        }
    }
    async fn catchall_test(
        &self,
        domain: &str,
        mx: &[(u16, String)],
        steps: &mut Vec<Step>,
    ) -> Result<bool, ()> {
        Step::add(
            steps,
            "info",
            "Catch-all Test",
            format!("Starting test for '{domain}'."),
            None,
        );
        let mut successful = 0;
        let mut inconclusive = 0;
        let mut answered = 0_usize;
        let ts = chrono::Local::now().timestamp();
        for i in 0..2 {
            let email = format!("catchall-probe-{ts}-{}-{i}@{domain}", rand::random::<u16>());
            let mut accepted = false;
            for (_, host) in mx {
                let mut probe_steps = vec![];
                let outcome = self
                    .probe(&email, domain, host, 25, &mut probe_steps, true)
                    .await;
                answered += usize::from(outcome.is_ok());
                match outcome {
                    Ok(r)
                        if is_microsoft(domain, host)
                            && r.code == 550
                            && r.message.contains("Access denied") =>
                    {
                        inconclusive += 1;
                        accepted = true;
                        Step::add(steps,"warning","Catch-all Test (Microsoft)","Microsoft domain detected - Access denied response treated as inconclusive.",None);
                        break;
                    }
                    Ok(r) if r.valid => {
                        successful += 1;
                        accepted = true;
                        Step::add(
                            steps,
                            "warning",
                            "Catch-all Test (Attempt)",
                            format!("Test email '{email}' accepted on {host}:25."),
                            None,
                        );
                        break;
                    }
                    _ => {}
                }
            }
            if !accepted {
                Step::add(
                    steps,
                    "info",
                    "Catch-all Test (Attempt)",
                    format!("Test email '{email}' not accepted."),
                    None,
                );
            }
        }
        let result = successful > 0 || inconclusive > 0;
        if successful == 0 && inconclusive > 0 {
            Step::add(steps,"warning","Catch-all Test (Result)",format!("Domain '{domain}' is likely catch-all (Microsoft domain with inconclusive results)."),None);
        } else if !result {
            Step::add(
                steps,
                "info",
                "Catch-all Test (Result)",
                format!("Domain '{domain}' is not catch-all. Successful: {successful}/2."),
                None,
            );
        }
        if answered == 0 {
            return Err(());
        }
        Ok(result)
    }
    pub async fn verify(&self, email: &str) -> VerificationResult {
        let mut attempt = 1;
        'retry: loop {
            let mut r = VerificationResult::new(email, attempt);
            let domain = match validate_syntax(email) {
                Ok(d) => {
                    Step::add(
                        &mut r.verification_steps,
                        "success",
                        "Syntax check",
                        format!("Email '{email}' syntax valid."),
                        None,
                    );
                    d
                }
                Err(e) => {
                    Step::add(
                        &mut r.verification_steps,
                        "error",
                        "Syntax check",
                        format!("Invalid email format '{email}': {e}"),
                        None,
                    );
                    r.outcome(Some(false), "syntax_error", &e);
                    return r;
                }
            };
            // DNS and SMTP speak punycode; the local part stays as written
            let unicode = domain.clone();
            let domain = idna::domain_to_ascii(&domain).unwrap_or(domain);
            let rcpt = match email.rsplit_once('@') {
                Some((local, _)) => format!("{local}@{domain}"),
                None => email.to_string(),
            };
            if self.settings.check_disposable
                && (classify::is_disposable_domain(&unicode, &self.disposable)
                    || classify::is_disposable_domain(&domain, &self.disposable))
            {
                Step::add(
                    &mut r.verification_steps,
                    "warning",
                    "Domain check",
                    format!("Domain '{domain}' is disposable."),
                    None,
                );
                r.outcome(Some(false), "disposable_domain", "Domain is disposable.");
                return r;
            }
            Step::add(
                &mut r.verification_steps,
                "info",
                "DNS MX query",
                format!("Getting MX for {domain}"),
                None,
            );
            let cell = self
                .cache
                .mx
                .lock()
                .await
                .entry(domain.clone())
                .or_default()
                .clone();
            let mut looked_up = false;
            let found = cell
                .get_or_try_init(|| async {
                    looked_up = true;
                    match self.network.mx(&domain).await {
                        Ok(mut mx) if !mx.is_empty() => {
                            mx.sort();
                            Ok(mx)
                        }
                        Ok(_) => Err(ProbeError::new(
                            "dns_resolver_failure",
                            format!("Unexpected error during DNS MX query for {domain}: No MX records found for {domain}."),
                        )),
                        Err(e) => Err(e),
                    }
                })
                .await;
            let mx = match found {
                Ok(mx) if looked_up => {
                    Step::add(
                        &mut r.verification_steps,
                        "success",
                        "DNS MX query",
                        format!("Found MX: {mx:?}"),
                        None,
                    );
                    mx.clone()
                }
                Ok(mx) => {
                    Step::add(
                        &mut r.verification_steps,
                        "info",
                        "DNS MX query",
                        format!("Using cached MX records for {domain}"),
                        None,
                    );
                    mx.clone()
                }
                Err(e) => {
                    Step::add(
                        &mut r.verification_steps,
                        "error",
                        "DNS MX query",
                        &e.message,
                        None,
                    );
                    r.outcome(Some(false), &e.status, &e.message);
                    return r;
                }
            };
            r.is_catchall = self.catchall(&domain, &mx, &mut r.verification_steps).await;
            for (_, host) in &mx {
                r.mx_record = Some(host.clone());
                match self
                    .probe(
                        &rcpt,
                        &domain,
                        host,
                        self.settings.connect_port,
                        &mut r.verification_steps,
                        false,
                    )
                    .await
                {
                    Ok(reply) => {
                        r.smtp_code_internal = Some(reply.code);
                        let verdict = if reply.valid {
                            Some(true)
                        } else if classify::is_unknown_status(&reply.status) {
                            None
                        } else {
                            Some(false)
                        };
                        r.outcome(verdict, &reply.status, &reply.message);
                        return r;
                    }
                    Err(e) => {
                        crate::log(
                            "WARNING",
                            &format!("Verifier error for {email} on {host}: {}", e.message),
                        );
                        if (e.retryable || classify::is_temporary_error(0, &e.message))
                            && attempt < self.settings.retry_attempts
                        {
                            let delay = (self.settings.retry_delay
                                * 2_f64.powi(attempt.min(30) as i32))
                            .min(86400.0);
                            Step::add(
                                &mut r.verification_steps,
                                "warning",
                                if e.retryable {
                                    "Rate Limit Retry"
                                } else {
                                    "Temporary Error Retry"
                                },
                                format!(
                                    "Attempt {attempt}/{}. Waiting {delay:.1}s for {email}.",
                                    self.settings.retry_attempts
                                ),
                                None,
                            );
                            tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                            attempt += 1;
                            continue 'retry;
                        }
                        if e.retryable {
                            r.outcome(None, &e.status, &e.message);
                            return r;
                        }
                    }
                }
            }
            Step::add(
                &mut r.verification_steps,
                "error",
                "SMTP Verification",
                "Failed to verify on any MX.",
                None,
            );
            r.outcome(
                None,
                "unreachable_all_mx",
                "Cannot connect to any MX or all returned temp error.",
            );
            return r;
        }
    }
    pub async fn batch(self: &Arc<Self>, emails: &[String]) -> Vec<VerificationResult> {
        let mut handles = vec![];
        for email in emails {
            let v = self.clone();
            let email = email.clone();
            handles.push(tokio::spawn(async move { v.verify(&email).await }));
        }
        let mut results = vec![];
        for (i, handle) in handles.into_iter().enumerate() {
            results.push(handle.await.unwrap_or_else(|e| {
                let mut r = VerificationResult::new(&emails[i], 1);
                r.outcome(
                    None,
                    "internal_verifier_error",
                    &format!("Verifier error: {e}"),
                );
                r
            }));
        }
        results
    }
}
pub fn is_microsoft(domain: &str, host: &str) -> bool {
    [
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "office365.com",
        "microsoft.com",
    ]
    .contains(&domain)
        || [
            ".mail.protection.outlook.com",
            ".outlook.com",
            ".hotmail.com",
        ]
        .iter()
        .any(|p| host.ends_with(p))
}
pub fn validate_syntax(email: &str) -> Result<String, String> {
    use unicode_normalization::UnicodeNormalization;
    if email.contains(['\r', '\n']) {
        return Err("The email address contains invalid characters.".into());
    }
    let (local, domain) = email
        .rsplit_once('@')
        .ok_or("An email address must have an @-sign.")?;
    if local.is_empty() {
        return Err("There must be something before the @-sign.".into());
    }
    if domain.is_empty() {
        return Err("There must be something after the @-sign.".into());
    }
    if local.starts_with('.') {
        return Err("An email address cannot start with a period.".into());
    }
    if local.ends_with('.') {
        return Err("An email address cannot have a period immediately before the @-sign.".into());
    }
    if local.contains("..") || domain.contains("..") {
        return Err("An email address cannot have two periods in a row.".into());
    }
    if local.starts_with('"') && local.ends_with('"') {
        return Err("Quoting the part before the @-sign is not allowed here.".into());
    }
    if local
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "@(),:;<>[\\]\"".contains(c))
    {
        return Err("The email address contains invalid characters before the @-sign.".into());
    }
    static UNSAFE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{C}\p{Z}]|^\p{M}").expect("constant Unicode categories")
    });
    for part in [local, domain] {
        if let Some(m) = UNSAFE.find(part) {
            let c = m.as_str().chars().next().expect("nonempty match");
            let name = match c {
                '\u{200b}' => "ZERO WIDTH SPACE".into(),
                '\u{202e}' => "RIGHT-TO-LEFT OVERRIDE".into(),
                '\u{ad}' => "SOFT HYPHEN".into(),
                _ => format!("U+{:04X}", c as u32),
            };
            return Err(format!(
                "The email address contains unsafe characters: {name}."
            ));
        }
    }
    if local.starts_with('"') && local.ends_with('"') {
        return Err("Quoting the part before the @-sign is not allowed here.".into());
    }
    if domain.ends_with('.') {
        return Err("An email address cannot end with a period.".into());
    }
    if domain.contains(".-") || domain.contains("-.") {
        return Err(
            "An email address cannot have a period and a hyphen next to each other.".into(),
        );
    }
    if domain.split('.').any(|label| {
        label.as_bytes().get(2..4) == Some(b"--") && !label.to_ascii_lowercase().starts_with("xn--")
    }) {
        return Err("An email address cannot have two letters followed by two dashes immediately after the @-sign or after a period, except Punycode.".into());
    }
    let domain: String = domain.nfc().collect::<String>().to_lowercase();
    let ascii = idna::domain_to_ascii(&domain)
        .map_err(|_| "The part after the @-sign contains invalid characters.")?;
    if !ascii.contains('.') {
        return Err("The part after the @-sign is not valid. It should have a period.".into());
    }
    if ascii
        .split('.')
        .any(|label| label.as_bytes().get(2..4) == Some(b"--") && !label.starts_with("xn--"))
    {
        return Err("The part after the @-sign contains an invalid hyphen label.".into());
    }
    if ascii.len() > 253
        || format!("{}@{ascii}", local.nfc().collect::<String>()).len() > 254
        || ascii.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || s.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-')
        })
    {
        return Err("The part after the @-sign is not valid.".into());
    }
    if ["test", "invalid", "localhost", "local", "onion", "arpa"]
        .iter()
        .any(|s| ascii == *s || ascii.ends_with(&format!(".{s}")))
    {
        return Err("The part after the @-sign is a special-use or reserved name that cannot be used with email.".into());
    }
    if !ascii
        .rsplit('.')
        .next()
        .unwrap_or("")
        .chars()
        .any(|c| c.is_ascii_alphabetic())
    {
        return Err(
            "The part after the @-sign is not valid. It is not within a valid top-level domain."
                .into(),
        );
    }
    let (unicode, result) = idna::domain_to_unicode(&ascii);
    result.map_err(|_| "The part after the @-sign contains invalid characters.")?;
    static DOMAIN_SYMBOL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{S}\p{P}]").expect("constant Unicode categories")
    });
    if unicode
        .chars()
        .any(|c| DOMAIN_SYMBOL.is_match(&c.to_string()) && !".-·͵׳״・".contains(c))
    {
        return Err("The part after the @-sign contains invalid IDNA characters.".into());
    }
    static GREEK: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^\p{Greek}$").expect("constant script"));
    static HEBREW: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^\p{Hebrew}$").expect("constant script"));
    static JAPANESE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{Hiragana}\p{Katakana}\p{Han}]").expect("constant scripts")
    });
    // UTS-46 accepts characters whose IDNA2008 validity depends on their neighbors.
    for label in unicode.split('.') {
        let chars: Vec<_> = label.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            let previous = i.checked_sub(1).and_then(|i| chars.get(i));
            let next = chars.get(i + 1);
            let valid = match c {
                '·' => previous == Some(&'l') && next == Some(&'l'),
                '͵' => next.is_some_and(|c| GREEK.is_match(&c.to_string())),
                '׳' | '״' => previous.is_some_and(|c| HEBREW.is_match(&c.to_string())),
                '・' => JAPANESE.is_match(label),
                _ => true,
            };
            if !valid {
                return Err(
                    "The part after the @-sign contains invalid contextual IDNA characters.".into(),
                );
            }
        }
        if chars.iter().any(|c| ('\u{660}'..='\u{669}').contains(c))
            && chars.iter().any(|c| ('\u{6f0}'..='\u{6f9}').contains(c))
        {
            return Err("The part after the @-sign mixes incompatible Arabic digits.".into());
        }
    }
    Ok(unicode)
}
