// Project: email-verifier
// File: tests/cli.rs
// Description: Process-level startup, environment and exit-code checks without external network.
// Author: Jan Alexandr Kopřiva
// Based on email-verifier by Jan Alexandr Kopřiva
// License: MIT

use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::Duration,
};
fn directory(name: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-work")
        .join(format!("cli-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("config.json"),
        b"{\"check_disposable\":false,\"helo_hostname\":\"probe.example.com\"}",
    )
    .unwrap();
    path
}
#[test]
fn invalid_port_exits_one() {
    let dir = directory("invalid-port");
    let output = Command::new(env!("CARGO_BIN_EXE_email-verifier"))
        .current_dir(&dir)
        .env("FLASK_RUN_PORT", "bad")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERROR"));
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn no_argument_parser_and_environment_controls_bind() {
    let dir = directory("startup");
    let mut child = Command::new(env!("CARGO_BIN_EXE_email-verifier"))
        .current_dir(&dir)
        .args(["--ignored", "value"])
        .env("FLASK_RUN_HOST", "127.0.0.1")
        .env("FLASK_RUN_PORT", "0")
        .env("FLASK_DEBUG", "1")
        .env_remove("EMAIL_VERIFIER_TOKEN")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if let Some((_, address)) = line.split_once("Running on http://") {
                let _ = tx.send(address.to_string());
                break;
            }
        }
    });
    let address = rx.recv_timeout(Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();
    reader.join().unwrap();
    assert!(address.unwrap().starts_with("127.0.0.1:"));
    std::fs::remove_dir_all(dir).unwrap();
}
