// Project: email-verifier
// File: web.rs
// Description: HTTP endpoints, synchronized run state, bulk jobs and file lifecycle.
// Author: Jan Alexandr Kopřiva
// License: AGPL-3.0-or-later
use crate::{
    files,
    verifier::{VerificationResult, Verifier},
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, DefaultBodyLimit, Multipart, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Notify};
type ApiResponse = (StatusCode, Json<Value>);
fn ok(v: Value) -> ApiResponse {
    (StatusCode::OK, Json(v))
}
fn error(code: StatusCode, message: impl Into<String>) -> ApiResponse {
    (code, Json(json!({"error":message.into()})))
}
fn bad(message: impl Into<String>) -> ApiResponse {
    error(StatusCode::BAD_REQUEST, message)
}
fn now() -> f64 {
    chrono::Local::now().timestamp_millis() as f64 / 1000.
}
#[derive(Debug)]
pub struct Job {
    pub status: String,
    pub error: Option<String>,
    pub uploaded: Option<PathBuf>,
    pub text: String,
    pub file_type: String,
    pub encoding: String,
    pub delimiter: u8,
    pub selected_column: Option<String>,
    pub emails: Vec<String>,
    pub results: Vec<VerificationResult>,
    pub processed: usize,
    pub valid: usize,
    pub invalid: usize,
    pub probable: usize,
    pub unknown: usize,
    pub current_batch: usize,
    pub total_batches: usize,
    pub start_time: Option<String>,
    pub last_activity: Option<f64>,
    pub result_path: Option<PathBuf>,
    pub stop: bool,
    pub run_id: u64,
    pub active: bool,
    pub logs: Vec<Value>,
    pub catchall_domains: serde_json::Map<String, Value>,
}
impl Default for Job {
    fn default() -> Self {
        Self {
            status: "idle".into(),
            error: None,
            uploaded: None,
            text: String::new(),
            file_type: "csv".into(),
            encoding: String::new(),
            delimiter: b',',
            selected_column: None,
            emails: vec![],
            results: vec![],
            processed: 0,
            valid: 0,
            invalid: 0,
            probable: 0,
            unknown: 0,
            current_batch: 0,
            total_batches: 0,
            start_time: None,
            last_activity: None,
            result_path: None,
            stop: false,
            run_id: 0,
            active: false,
            logs: vec![],
            catchall_domains: serde_json::Map::new(),
        }
    }
}
impl Job {
    fn add_log(&mut self, status: &str, action: impl Into<String>, details: impl Into<String>) {
        self.logs.push(json!({"timestamp":crate::timestamp(),"status":status,"action":action.into(),"details":details.into()}));
        if self.logs.len() > 1000 {
            self.logs.drain(..self.logs.len() - 1000);
        }
    }
    fn process(&mut self, results: Vec<VerificationResult>) {
        for r in results {
            self.processed += 1;
            match r.is_valid {
                Some(true) if r.is_catchall => {
                    self.probable += 1;
                    let domain = r.email.rsplit('@').next().unwrap_or("");
                    let count = self
                        .catchall_domains
                        .get(domain)
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        + 1;
                    self.catchall_domains.insert(domain.into(), json!(count));
                }
                Some(true) => self.valid += 1,
                Some(false) => self.invalid += 1,
                None => self.unknown += 1,
            }
            self.add_log(
                if r.is_valid == Some(true) {
                    "success"
                } else if r.is_catchall {
                    "warning"
                } else {
                    "error"
                },
                format!("Verified email: {}", r.email),
                format!("Result: {}", r.status_code),
            );
            if self.logs.len() > 100 {
                self.logs.drain(..self.logs.len() - 50);
            }
            self.results.push(r);
        }
    }
}
pub struct App {
    pub verifier: Arc<Verifier>,
    pub job: Mutex<Job>,
    pub root: PathBuf,
    pub token: Option<String>,
    finished: Notify,
}
impl App {
    pub fn new(
        verifier: Arc<Verifier>,
        root: PathBuf,
        token: Option<String>,
    ) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(root.join("uploads"))?;
        std::fs::create_dir_all(root.join("results"))?;
        Ok(Arc::new(Self {
            verifier,
            job: Mutex::new(Job::default()),
            root,
            token: token.filter(|s| !s.is_empty()),
            finished: Notify::new(),
        }))
    }
    async fn save(&self, job: &mut Job) -> Result<(), String> {
        if job.results.is_empty() {
            return Ok(());
        }
        let path = job
            .result_path
            .get_or_insert_with(|| {
                PathBuf::from("results").join(format!(
                    "verification_results_{}.csv",
                    chrono::Local::now().format("%Y%m%d%H%M%S")
                ))
            })
            .clone();
        let results = job.results.clone();
        let destination = self.root.join(&path);
        // CSV serialization and disk I/O must not occupy an async worker.
        tokio::task::spawn_blocking(move || {
            let bytes = files::result_csv(&results).map_err(|e| e.to_string())?;
            std::fs::write(destination, bytes).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
        crate::log(
            "INFO",
            &format!("Results saved to {} (final save)", path.display()),
        );
        job.add_log(
            "success",
            "Saving results",
            format!(
                "Results saved to {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        );
        Ok(())
    }
    pub async fn cleanup_unused(&self) -> std::io::Result<()> {
        let job = self.job.lock().await;
        for folder in ["uploads", "results"] {
            let mut entries = tokio::fs::read_dir(self.root.join(folder)).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let relative = path.strip_prefix(&self.root).unwrap_or(&path);
                if job.uploaded.as_deref() != Some(relative)
                    && job.result_path.as_deref() != Some(relative)
                    && entry.file_type().await?.is_file()
                {
                    tokio::fs::remove_file(path).await?;
                }
            }
        }
        Ok(())
    }
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/verify_single", post(verify_single))
        .route("/load_csv", post(load_csv))
        .route("/load_txt", post(load_txt))
        .route("/select_column", post(select_column))
        .route("/start_verification", get(start))
        .route("/stop_verification", post(stop))
        .route("/status", get(status))
        .route("/download_results", get(download))
        .route("/cleanup", post(cleanup))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), authorize))
        .with_state(app)
}
async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}
fn constant_time_equal(a: &str, b: &str) -> bool {
    let mut diff = a.len() ^ b.len();
    for (a, b) in a.bytes().zip(b.bytes()) {
        diff |= (a ^ b) as usize;
    }
    diff == 0
}
async fn authorize(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    if request.uri().path() != "/" && !request.uri().path().starts_with("/static/") {
        if let Some(token) = &app.token {
            let params =
                axum::extract::Query::<std::collections::HashMap<String, String>>::try_from_uri(
                    request.uri(),
                )
                .ok();
            let supplied = request
                .headers()
                .get("X-Auth-Token")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    params
                        .as_ref()
                        .and_then(|p| p.get("token").map(String::as_str))
                });
            if !supplied.is_some_and(|s| constant_time_equal(s, token)) {
                return error(StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
        }
    }
    next.run(request).await
}
async fn verify_single(State(app): State<Arc<App>>, Json(data): Json<Value>) -> ApiResponse {
    let Some(email) = data["email"].as_str().filter(|s| !s.is_empty()) else {
        return bad("Missing email in request");
    };
    crate::log(
        "INFO",
        &format!("API /verify_single: Received request to verify email: {email}"),
    );
    ok(serde_json::to_value(app.verifier.verify(email).await).expect("serializable result"))
}
async fn load_csv(State(app): State<Arc<App>>, multipart: Multipart) -> ApiResponse {
    upload(app, multipart, "csv").await
}
async fn load_txt(State(app): State<Arc<App>>, multipart: Multipart) -> ApiResponse {
    upload(app, multipart, "txt").await
}
async fn upload(app: Arc<App>, mut multipart: Multipart, kind: &str) -> ApiResponse {
    crate::log("INFO", &"=".repeat(50));
    crate::log(
        "INFO",
        &format!(
            "API /load_{kind}: Starting {} upload process",
            kind.to_uppercase()
        ),
    );
    let mut job = app.job.lock().await;
    if job.active || !["idle", "error", "completed", "stopped"].contains(&job.status.as_str()) {
        return bad("Another operation is already in progress.");
    }
    *job = Job::default();
    job.status = format!("loading_{kind}");
    job.last_activity = Some(now());
    drop(job);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        // A slow client must not hold the job mutex while sending its body.
        let field = tokio::time::timeout_at(deadline, multipart.next_field()).await;
        let mut job = app.job.lock().await;
        let field = match field {
            Err(_) => {
                job.status = "error".into();
                return error(StatusCode::REQUEST_TIMEOUT, "Upload timed out");
            }
            Ok(result) => result,
        };
        let field = match field {
            Ok(Some(f)) => f,
            Ok(None) => {
                job.status = "error".into();
                return bad("No file provided");
            }
            Err(e) => {
                job.status = "error".into();
                return error(e.status(), e.to_string());
            }
        };
        if field.name() != Some("file") {
            drop(job);
            continue;
        }
        let filename = field.file_name().unwrap_or("").to_string();
        if filename.is_empty() {
            job.status = "error".into();
            return bad("No file selected");
        }
        if !filename.to_lowercase().ends_with(&format!(".{kind}")) {
            job.status = "error".into();
            return bad(format!("Only {} files are allowed", kind.to_uppercase()));
        }
        drop(job);
        let bytes = tokio::time::timeout_at(deadline, field.bytes()).await;
        let mut job = app.job.lock().await;
        let bytes = match bytes {
            Err(_) => {
                job.status = "error".into();
                return error(StatusCode::REQUEST_TIMEOUT, "Upload timed out");
            }
            Ok(result) => result,
        };
        let bytes = match bytes {
            Ok(b) => b,
            Err(e) => {
                job.status = "error".into();
                return error(e.status(), e.to_string());
            }
        };
        if bytes.is_empty() {
            job.status = "error".into();
            job.error = Some("Uploaded file is empty".into());
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error processing {}.", kind.to_uppercase()),
            );
        }
        let path = PathBuf::from("uploads").join(format!(
            "{}_{}",
            chrono::Local::now().format("%Y%m%d%H%M%S"),
            files::secure_filename(&filename)
        ));
        if let Err(e) = tokio::fs::write(app.root.join(&path), &bytes).await {
            job.status = "error".into();
            job.error = Some(e.to_string());
            return error(StatusCode::INTERNAL_SERVER_ERROR, "Error saving upload");
        }
        let decode_bytes = bytes.clone();
        let decoded = tokio::task::spawn_blocking(move || files::decode(&decode_bytes))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
        let (text, encoding) = match decoded {
            Ok(t) => t,
            Err(e) => {
                job.status = "error".into();
                let _ = tokio::fs::remove_file(app.root.join(path)).await;
                return bad(e);
            }
        };
        if kind == "csv" {
            let header_text = text.clone();
            let parsed = tokio::task::spawn_blocking(move || files::csv_headers(&header_text))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            let (delimiter, headers) = match parsed {
                Ok(h) => h,
                Err(e) => {
                    job.status = "error".into();
                    let _ = tokio::fs::remove_file(app.root.join(path)).await;
                    return bad(e);
                }
            };
            job.delimiter = delimiter;
            job.status = "selecting_column".into();
            job.text = text;
            job.uploaded = Some(path);
            job.encoding = encoding.into();
            return ok(
                json!({"status":"select_column","suggested_email_column":files::suggest_column(&headers),"columns":headers}),
            );
        }
        let txt = text.clone();
        let emails = match tokio::task::spawn_blocking(move || files::txt_emails(&txt)).await {
            Ok(emails) => emails,
            Err(e) => {
                job.status = "error".into();
                return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
            }
        };
        if emails.is_empty() {
            job.status = "error".into();
            let _ = tokio::fs::remove_file(app.root.join(path)).await;
            return bad("No valid email addresses found in the file");
        }
        job.file_type = "txt".into();
        job.status = "ready".into();
        job.text = text;
        job.uploaded = Some(path);
        job.encoding = encoding.into();
        job.emails = emails;
        return ok(
            json!({"status":"ready","total_emails":job.emails.len(),"sample_emails":job.emails.iter().take(5).collect::<Vec<_>>(),"file_info":{"filename":filename,"encoding":encoding,"size_bytes":bytes.len()}}),
        );
    }
}
async fn select_column(
    State(app): State<Arc<App>>,
    data: Result<Json<Value>, JsonRejection>,
) -> ApiResponse {
    let mut job = app.job.lock().await;
    if !["selecting_column", "ready"].contains(&job.status.as_str()) {
        return bad("Invalid state for column selection.");
    }
    job.last_activity = Some(now());
    let exists = match &job.uploaded {
        Some(path) => tokio::fs::try_exists(app.root.join(path))
            .await
            .unwrap_or(false),
        None => false,
    };
    if !exists {
        return bad("Upload a file first");
    }
    if job.file_type != "txt" {
        let data = match data {
            Ok(Json(v)) => v,
            Err(e) => return error(e.status(), e.body_text()),
        };
        let Some(column) = data["column"].as_str().filter(|s| !s.is_empty()) else {
            return bad("No column selected");
        };
        let csv_text = job.text.clone();
        let delimiter = job.delimiter;
        let csv_column = column.to_string();
        let parsed = tokio::task::spawn_blocking(move || {
            files::csv_emails(&csv_text, delimiter, &csv_column)
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        match parsed {
            Ok(emails) => {
                job.emails = emails;
                job.selected_column = Some(column.into());
            }
            Err(e) => {
                job.error = Some(e);
                job.status = "error".into();
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error extracting emails from CSV.",
                );
            }
        }
    }
    if job.emails.is_empty() {
        job.status = "error".into();
        return bad("No valid email addresses found.");
    }
    job.status = "ready_to_verify".into();
    ok(json!({"status":"ready","total_emails":job.emails.len()}))
}
async fn start(State(app): State<Arc<App>>) -> ApiResponse {
    let mut job = app.job.lock().await;
    if job.active
        || !["ready_to_verify", "stopped", "completed", "error", "idle"]
            .contains(&job.status.as_str())
    {
        return bad("Verification already running or not ready");
    }
    if job.emails.is_empty() {
        return bad("No emails to verify");
    }
    let run_id = (chrono::Local::now().timestamp_millis() as u64).max(job.run_id + 1);
    let emails = job.emails.clone();
    let uploaded = job.uploaded.clone();
    let text = job.text.clone();
    let encoding = job.encoding.clone();
    let delimiter = job.delimiter;
    let file_type = job.file_type.clone();
    let selected_column = job.selected_column.clone();
    *job = Job {
        status: "verifying".into(),
        run_id,
        active: true,
        emails: emails.clone(),
        uploaded,
        text,
        encoding,
        delimiter,
        file_type,
        selected_column,
        start_time: Some(crate::timestamp()),
        last_activity: Some(now()),
        total_batches: emails.len().div_ceil(app.verifier.settings.ui_batch_size),
        ..Job::default()
    };
    job.add_log("info", "Starting verification", format!("Run ID: {run_id}"));
    drop(job);
    let worker_app = app.clone();
    tokio::spawn(async move {
        run_bulk(worker_app, run_id, emails).await;
    });
    ok(json!({"status":"verifying","message":"Verification started.","run_id":run_id}))
}
async fn run_bulk(app: Arc<App>, run_id: u64, emails: Vec<String>) {
    let verifier = Arc::new(app.verifier.for_run());
    for (i, batch) in emails.chunks(verifier.settings.ui_batch_size).enumerate() {
        {
            let mut job = app.job.lock().await;
            if job.run_id != run_id || job.stop {
                break;
            }
            job.current_batch = i + 1;
            job.last_activity = Some(now());
        }
        let results = verifier.batch(batch).await;
        let mut job = app.job.lock().await;
        if job.run_id != run_id {
            break;
        }
        // Completed work is retained when a stop arrives during the batch.
        job.process(results);
        if let Err(e) = app.save(&mut job).await {
            job.error = Some(e);
            job.status = "error".into();
            break;
        }
        if job.stop {
            break;
        }
    }
    let mut job = app.job.lock().await;
    if job.run_id == run_id {
        if job.status != "error" {
            job.status = if job.stop { "stopped" } else { "completed" }.into();
        }
        if let Err(e) = app.save(&mut job).await {
            job.error = Some(e);
            job.status = "error".into();
        }
        job.active = false;
    }
    app.finished.notify_waiters();
}
async fn stop(State(app): State<Arc<App>>) -> ApiResponse {
    let notified = app.finished.notified();
    {
        let mut job = app.job.lock().await;
        if !job.active {
            return ok(
                json!({"status":job.status,"message":"No verification process is currently running","has_results":job.result_path.is_some()}),
            );
        }
        job.stop = true;
        job.status = "stopping".into();
        job.add_log(
            "info",
            "Stop requested",
            "Verification will stop after the current batch finishes.",
        );
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), notified).await;
    let job = app.job.lock().await;
    ok(
        json!({"status":job.status,"message":if job.active{"Verification stop requested"}else{"Verification process stopped"},"filepath":job.result_path,"has_results":job.result_path.is_some()}),
    )
}
async fn status(State(app): State<Arc<App>>) -> ApiResponse {
    let job = app.job.lock().await;
    let total_emails = if job.status == "ready" {
        0
    } else {
        job.emails.len()
    };
    let logs = &job.logs[job
        .logs
        .len()
        .saturating_sub(app.verifier.settings.ui_batch_size)..];
    ok(
        json!({"status":job.status,"error_message":job.error,"total_emails":total_emails,"processed_emails":job.processed,"valid_emails":job.valid,"invalid_emails":job.invalid,"probable_emails":job.probable,"unknown_emails":job.unknown,"current_batch":job.current_batch,"total_batches":job.total_batches,"start_time":job.start_time,"last_activity_time":job.last_activity,"result_filepath":job.result_path,"has_results":job.result_path.is_some(),"verification_log_batch":logs}),
    )
}
async fn download(State(app): State<Arc<App>>) -> Response {
    let job = app.job.lock().await;
    let Some(path) = &job.result_path else {
        return error(StatusCode::NOT_FOUND, "No results file available").into_response();
    };
    let full = app.root.join(path);
    let Ok(resolved) = tokio::fs::canonicalize(&full).await else {
        return error(StatusCode::NOT_FOUND, "Results file not found").into_response();
    };
    let Ok(folder) = tokio::fs::canonicalize(app.root.join("results")).await else {
        return error(StatusCode::FORBIDDEN, "Invalid file path").into_response();
    };
    if !resolved.starts_with(folder) {
        return error(StatusCode::FORBIDDEN, "Invalid file path").into_response();
    }
    match tokio::fs::read(full).await {
        Ok(bytes) => Response::builder()
            .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
            .header(
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename={}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
            )
            .body(Body::from(bytes))
            .expect("valid download response"),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error downloading results.",
        )
        .into_response(),
    }
}
async fn cleanup(State(app): State<Arc<App>>) -> ApiResponse {
    let mut job = app.job.lock().await;
    if job.active || job.status.starts_with("loading_") {
        return bad("Cannot clean files while an operation is running");
    }
    for folder in ["uploads", "results"] {
        let result: std::io::Result<()> = async {
            let mut entries = tokio::fs::read_dir(app.root.join(folder)).await?;
            while let Some(entry) = entries.next_entry().await? {
                if entry.file_type().await?.is_file() {
                    tokio::fs::remove_file(entry.path()).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error during cleanup: {e}"),
            );
        }
    }
    *job = Job::default();
    ok(json!({"status":"success","message":"Cleanup completed"}))
}
