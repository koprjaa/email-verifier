// Project: email-verifier
// File: main.rs
// Description: HTTP server entry point using the original environment variables.
// Author: Jan Alexandr Kopřiva
// Based on email-verifier by Jan Alexandr Kopřiva
// License: MIT

use email_verifier::{
    files,
    network::RealNetwork,
    verifier::{Settings, Verifier},
    web::{router, App},
};
use std::{path::Path, sync::Arc};
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        email_verifier::log("ERROR", &e);
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let config = files::read_config(Path::new("config.json"));
    let settings = Settings::from_value(&config)?;
    let network = Arc::new(RealNetwork::new(&settings)?);
    let verifier = Arc::new(Verifier::new(settings, network));
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let app = App::new(verifier, root, std::env::var("EMAIL_VERIFIER_TOKEN").ok())
        .map_err(|e| e.to_string())?;
    email_verifier::log(
        "INFO",
        "Global EmailVerifier instance created and configured.",
    );
    if app.token.is_some() {
        email_verifier::log(
            "INFO",
            "EMAIL_VERIFIER_TOKEN set: shared-token auth enabled.",
        );
    }
    let host = std::env::var("FLASK_RUN_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("FLASK_RUN_PORT")
        .unwrap_or_else(|_| "5001".into())
        .parse::<u16>()
        .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .map_err(|e| e.to_string())?;
    email_verifier::log(
        "INFO",
        &format!(
            "Running on http://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        ),
    );
    axum::serve(listener, router(app.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())?;
    app.cleanup_unused().await.map_err(|e| e.to_string())
}
