// Project: email-verifier
// File: lib.rs
// Description: Public modules for email verification and the web application.
// Author: Jan Alexandr Kopřiva
// License: MIT

pub mod classify;
pub mod files;
pub mod network;
pub mod verifier;
pub mod web;

pub fn log(level: &str, message: &str) {
    eprintln!(
        "{} - MainThread - {} - {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"),
        level,
        message
    );
}

pub fn timestamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.6f")
        .to_string()
}
