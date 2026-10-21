// Project: email-verifier
// File: tests/support/mod.rs
// Description: Deterministic network replacement and isolated working directories.
// Author: Jan Alexandr Kopřiva
// License: MIT

use email_verifier::{
    network::{NetFuture, Network, ProbeError, Reply},
    verifier::{Settings, Step, Verifier},
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
#[derive(Default)]
pub struct MockNetwork {
    pub calls: Mutex<Vec<(IpAddr, u16, String, bool)>>,
    pub replies: Mutex<VecDeque<Result<Reply, ProbeError>>>,
    pub mx_calls: AtomicUsize,
    pub ips: Mutex<Vec<IpAddr>>,
    pub delay: Mutex<Duration>,
    pub mx_error: Mutex<Option<ProbeError>>,
    pub catchall_accept: Mutex<bool>,
    pub catchall_reply: Mutex<Option<Reply>>,
    pub catchall_down: Mutex<bool>,
}
impl MockNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ips: Mutex::new(vec!["8.8.8.8".parse().unwrap()]),
            ..Self::default()
        })
    }
}
impl Network for MockNetwork {
    fn mx<'a>(&'a self, _domain: &'a str) -> NetFuture<'a, Vec<(u16, String)>> {
        Box::pin(async move {
            self.mx_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(e) = self.mx_error.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(vec![(10, "mx.example.com".into())])
        })
    }
    fn ips<'a>(&'a self, _host: &'a str) -> NetFuture<'a, Vec<IpAddr>> {
        Box::pin(async move { Ok(self.ips.lock().unwrap().clone()) })
    }
    #[allow(clippy::too_many_arguments)]
    fn smtp<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        email: &'a str,
        _domain: &'a str,
        _settings: &'a Settings,
        steps: &'a mut Vec<Step>,
        catchall: bool,
    ) -> NetFuture<'a, Reply> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((ip, port, email.into(), catchall));
            let delay = *self.delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            Step::add(
                steps,
                "info",
                "RCPT TO",
                format!("Recipient: {email}"),
                Some(250),
            );
            if catchall {
                if *self.catchall_down.lock().unwrap() {
                    return Err(ProbeError::new("smtp_connect_error", "down"));
                }
                if let Some(reply) = self.catchall_reply.lock().unwrap().clone() {
                    return Ok(reply);
                }
                let valid = *self.catchall_accept.lock().unwrap();
                return Ok(Reply {
                    valid,
                    status: if valid { "valid" } else { "invalid_mailbox" }.into(),
                    message: "catchall reply".into(),
                    code: if valid { 250 } else { 550 },
                });
            }
            self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(Reply {
                    valid: true,
                    status: "valid".into(),
                    message: "Accepted".into(),
                    code: 250,
                })
            })
        })
    }
}
pub fn verifier(mock: Arc<MockNetwork>, extra: Value) -> Arc<Verifier> {
    let mut config = json!({"helo_hostname":"probe.example.com","check_disposable":false,"catchall_test":false,"retry_delay":0});
    for (k, v) in extra.as_object().unwrap() {
        config[k] = v.clone();
    }
    Arc::new(Verifier::new(Settings::from_value(&config).unwrap(), mock))
}
static COUNTER: AtomicUsize = AtomicUsize::new(0);
pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-work")
            .join(format!(
                "{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
