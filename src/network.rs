// Project: email-verifier
// File: network.rs
// Description: DNS lookups and bounded plaintext SMTP sessions to pinned IP addresses.
// Author: Jan Alexandr Kopřiva
// License: MIT

use crate::verifier::{Settings, Step};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Semaphore,
};
pub type NetFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProbeError>> + Send + 'a>>;
#[derive(Debug, Clone)]
pub struct ProbeError {
    pub status: String,
    pub message: String,
    pub retryable: bool,
}
impl ProbeError {
    pub fn new(status: &str, message: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            message: message.into(),
            retryable: false,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Reply {
    pub valid: bool,
    pub status: String,
    pub message: String,
    pub code: u16,
}
pub trait Network: Send + Sync {
    fn mx<'a>(&'a self, domain: &'a str) -> NetFuture<'a, Vec<(u16, String)>>;
    fn ips<'a>(&'a self, host: &'a str) -> NetFuture<'a, Vec<IpAddr>>;
    #[allow(clippy::too_many_arguments)]
    fn smtp<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        email: &'a str,
        domain: &'a str,
        settings: &'a Settings,
        steps: &'a mut Vec<Step>,
        catchall: bool,
    ) -> NetFuture<'a, Reply>;
}
pub struct RealNetwork {
    resolver: TokioAsyncResolver,
    semaphore: Arc<Semaphore>,
}
impl RealNetwork {
    pub fn new(settings: &Settings) -> Result<Self, String> {
        let (mut config, mut opts) = hickory_resolver::system_conf::read_system_conf()
            .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
        if !settings.dns_servers.is_empty() {
            config = ResolverConfig::new();
            for server in &settings.dns_servers {
                let ip = server
                    .parse()
                    .map_err(|_| format!("Invalid DNS server: {server}"))?;
                for protocol in [Protocol::Udp, Protocol::Tcp] {
                    config
                        .add_name_server(NameServerConfig::new(SocketAddr::new(ip, 53), protocol));
                }
            }
        }
        opts.timeout =
            Duration::try_from_secs_f64(settings.dns_timeout).map_err(|_| "Invalid DNS timeout")?;
        if settings.max_concurrent_domains == 0
            || settings.max_concurrent_domains > Semaphore::MAX_PERMITS
        {
            return Err("Invalid SMTP concurrency limit".into());
        }
        opts.attempts = settings.dns_tries;
        opts.cache_size = 0;
        Ok(Self {
            resolver: TokioAsyncResolver::tokio(config, opts),
            semaphore: Arc::new(Semaphore::new(settings.max_concurrent_domains)),
        })
    }
}
impl Network for RealNetwork {
    fn mx<'a>(&'a self, domain: &'a str) -> NetFuture<'a, Vec<(u16, String)>> {
        Box::pin(async move {
            let response = self.resolver.mx_lookup(domain).await.map_err(|e| {
                ProbeError::new(
                    "dns_resolver_failure",
                    format!("DNS error (MX) for {domain}: {e}"),
                )
            })?;
            let mut records: Vec<_> = response
                .iter()
                .map(|r| {
                    (
                        r.preference(),
                        r.exchange().to_utf8().trim_end_matches('.').to_string(),
                    )
                })
                .collect();
            records.sort();
            if records.is_empty() {
                return Err(ProbeError::new("dns_resolver_failure",format!("Unexpected error during DNS MX query for {domain}: No MX records found for {domain}.")));
            }
            Ok(records)
        })
    }
    fn ips<'a>(&'a self, host: &'a str) -> NetFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            let mut ips = vec![];
            if let Ok(answer) = self.resolver.ipv4_lookup(host).await {
                ips.extend(answer.iter().map(|a| IpAddr::V4(a.0)));
            }
            if let Ok(answer) = self.resolver.ipv6_lookup(host).await {
                ips.extend(answer.iter().map(|a| IpAddr::V6(a.0)));
            }
            Ok(ips)
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn smtp<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        email: &'a str,
        domain: &'a str,
        settings: &'a Settings,
        steps: &'a mut Vec<Step>,
        catchall: bool,
    ) -> NetFuture<'a, Reply> {
        Box::pin(async move {
            // The permit covers the full conversation, including catch-all probes.
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|e| ProbeError::new("smtp_connect_error", e.to_string()))?;
            smtp_session(ip, port, email, domain, settings, steps, catchall).await
        })
    }
}
struct Session {
    io: BufReader<TcpStream>,
    timeout: Duration,
}
impl Session {
    async fn reply(&mut self) -> Result<(u16, String), ProbeError> {
        let timeout = self.timeout;
        tokio::time::timeout(timeout, async {
            let mut messages = vec![];
            let mut total = 0;
            let mut first_code = None;
            loop {
                let mut bytes = Vec::new();
                let n = (&mut self.io)
                    .take((65537 - total) as u64)
                    .read_until(b'\n', &mut bytes)
                    .await
                    .map_err(io_error)?;
                total += n;
                if n == 0 || total > 65536 {
                    return Err(ProbeError::new(
                        "unknown_smtp_error",
                        "SMTP response closed or too long",
                    ));
                }
                let line = String::from_utf8_lossy(&bytes);
                let code = line
                    .get(..3)
                    .and_then(|s| s.parse::<u16>().ok())
                    .ok_or_else(|| {
                        ProbeError::new("unknown_smtp_error", "Malformed SMTP response")
                    })?;
                if !(100..=599).contains(&code)
                    || !matches!(
                        line.as_bytes().get(3),
                        Some(b' ' | b'-' | b'\r' | b'\n') | None
                    )
                    || first_code.is_some_and(|first| first != code)
                {
                    return Err(ProbeError::new(
                        "unknown_smtp_error",
                        "Malformed SMTP response",
                    ));
                }
                first_code = Some(code);
                messages.push(
                    line.get(4..)
                        .unwrap_or("")
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                );
                if line.as_bytes().get(3) != Some(&b'-') {
                    return Ok((code, messages.join("\n")));
                }
            }
        })
        .await
        .map_err(|_| ProbeError::new("smtp_timeout", "SMTP response timeout"))?
    }
    async fn command(&mut self, command: &str) -> Result<(u16, String), ProbeError> {
        tokio::time::timeout(
            self.timeout,
            self.io
                .get_mut()
                .write_all(format!("{command}\r\n").as_bytes()),
        )
        .await
        .map_err(|_| ProbeError::new("smtp_timeout", "SMTP write timeout"))?
        .map_err(io_error)?;
        self.reply().await
    }
}
fn io_error(e: std::io::Error) -> ProbeError {
    ProbeError::new("smtp_connect_error", e.to_string())
}
fn success(code: u16) -> bool {
    [250, 251, 252].contains(&code)
}
fn trace(steps: &mut Vec<Step>, action: &str, code: u16, message: &str) {
    Step::add(
        steps,
        "info",
        action,
        format!("Resp: {code} {message}"),
        Some(code),
    );
}
#[allow(clippy::too_many_arguments)]
pub async fn smtp_session(
    ip: IpAddr,
    port: u16,
    email: &str,
    domain: &str,
    settings: &Settings,
    steps: &mut Vec<Step>,
    catchall: bool,
) -> Result<Reply, ProbeError> {
    let timeout = Duration::try_from_secs_f64(settings.smtp_timeout)
        .map_err(|_| ProbeError::new("smtp_timeout", "Invalid SMTP timeout"))?;
    if email.contains(['\r', '\n'])
        || settings.helo_hostname.contains(['\r', '\n'])
        || settings.default_sender.contains(['\r', '\n'])
        || settings
            .sender_override
            .as_deref()
            .is_some_and(|s| s.contains(['\r', '\n']))
        || settings
            .senders
            .values()
            .chain(settings.ordered_senders.iter().map(|(_, s)| s))
            .any(|s| s.contains(['\r', '\n']))
    {
        return Err(ProbeError::new(
            "smtp_invalid_input",
            "SMTP input must not contain line breaks",
        ));
    }
    if !email.is_ascii() {
        return Err(ProbeError::new(
            "smtp_encoding_error",
            "SMTPUTF8 envelopes are not supported",
        ));
    }
    let stream = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .map_err(|_| ProbeError::new("smtp_timeout", format!("Timeout on {ip}:{port}")))?
        .map_err(io_error)?;
    let mut session = Session {
        io: BufReader::new(stream),
        timeout,
    };
    let result=async {
        let (code,message)=session.reply().await?;
        if code!=220 {return Err(ProbeError::new("smtp_connect_error",format!("{code} {message}")));}
        let (mut code,mut message)=session.command(&format!("EHLO {}",settings.helo_hostname)).await?;
        if !success(code) && code!=220 {(code,message)=session.command(&format!("HELO {}",settings.helo_hostname)).await?;}
        trace(steps,"EHLO/HELO",code,&message);
        if !success(code) && code!=220 {return Err(ProbeError::new("ehlo_failed",format!("EHLO/HELO failed: {code} {message}")));}
        let sender=crate::classify::choose_sender(domain,&settings.senders,&settings.default_sender,settings.sender_override.as_deref());
        Step::add(steps,"info","MAIL FROM",format!("Sender: {sender}"),None);
        (code,message)=session.command(&format!("MAIL FROM:<{sender}>" )).await?;
        trace(steps,"MAIL FROM",code,&message);
        if !catchall && crate::classify::is_reputation_error(code,&message) {
            Step::add(steps,"warning","MAIL FROM","Reputation-based rejection detected. Will retry with different sender if available.",None);
            if let Some((_,alt))=settings.ordered_senders.iter().find(|(d,s)|d!=domain&&s!=&sender) {
                Step::add(steps,"info","MAIL FROM",format!("Retrying with alternative sender: {alt}"),None);
                (code,message)=session.command(&format!("MAIL FROM:<{alt}>" )).await?;
                trace(steps,"MAIL FROM",code,&message);
            }
        }
        if !success(code) {return Err(ProbeError{status:if [421,450,451,452].contains(&code){"mail_from_temp_fail"}else{"mail_from_perm_fail"}.into(),message:format!("MAIL FROM {} error: {code} {message}",if [421,450,451,452].contains(&code){"temp"}else{"perm"}),retryable:[421,450,451,452].contains(&code)});}
        Step::add(steps,"info","RCPT TO",format!("Recipient: {email}"),None);
        (code,message)=session.command(&format!("RCPT TO:<{email}>" )).await?;
        trace(steps,"RCPT TO",code,&message);
        if !catchall {let _=session.command("RSET").await;}
        if [421,450,451,452].contains(&code) {return Err(ProbeError{status:"rcpt_to_temp_fail".into(),message:format!("RCPT TO temp error: {code} {message}"),retryable:true});}
        Ok(Reply{valid:success(code),status:if success(code){"valid"}else{"invalid_mailbox"}.into(),message,code})
    }.await;
    let _ = session.command("QUIT").await;
    let _ = session.io.get_mut().shutdown().await;
    result
}
