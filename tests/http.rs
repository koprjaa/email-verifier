// Project: email-verifier
// File: tests/http.rs
// Description: Offline HTTP integration tests for authentication, upload, jobs and downloads.
// Author: Jan Alexandr Kopřiva
// License: MIT

mod support;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use email_verifier::web::{router, App};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use support::*;
use tower::ServiceExt;
fn app(token: Option<&str>, extra: Value) -> (Directory, Arc<App>, Router) {
    let dir = Directory::new();
    let app = App::new(
        verifier(MockNetwork::new(), extra),
        dir.0.clone(),
        token.map(str::to_string),
    )
    .unwrap();
    let router = router(app.clone());
    (dir, app, router)
}
async fn request(router: &Router, path: &str, method: &str, body: Value) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .method(method)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
    )
}
async fn upload(router: &Router, path: &str, filename: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let mut body=format!("--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n").into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n--fixture--\r\n");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .method("POST")
                .header(
                    header::CONTENT_TYPE,
                    "multipart/form-data; boundary=fixture",
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn wait_completed(router: &Router) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, v) = request(router, "/status", "GET", Value::Null).await;
            if ["completed", "stopped", "error"].contains(&v["status"].as_str().unwrap()) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn index_status_and_single_validation() {
    let (_dir, _app, r) = app(None, json!({}));
    let response = r
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains("Email Verifier"));
    let (_, v) = request(&r, "/status", "GET", Value::Null).await;
    assert_eq!(v["status"], "idle");
    assert_eq!(v["total_emails"], 0);
    assert_eq!(
        request(&r, "/verify_single", "POST", json!({})).await.0,
        400
    );
    let (_, v) = request(&r, "/verify_single", "POST", json!({"email":"bad"})).await;
    assert_eq!(v["status_code"], "syntax_error");
    assert_eq!(
        request(&r, "/verify_single", "POST", json!({"email":7}))
            .await
            .0,
        400
    );
}
#[tokio::test]
async fn token_auth_header_query_and_no_cors() {
    let (_dir, _app, r) = app(Some("fixture-token"), json!({}));
    assert_eq!(request(&r, "/status", "GET", Value::Null).await.0, 401);
    assert_eq!(
        request(&r, "/status?token=wrong", "GET", Value::Null)
            .await
            .0,
        401
    );
    assert_eq!(
        request(&r, "/status?token=fixture%2Dtoken", "GET", Value::Null)
            .await
            .0,
        200
    );
    let response = r
        .clone()
        .oneshot(
            Request::builder()
                .uri("/status")
                .header("X-Auth-Token", "fixture-token")
                .header("Origin", "https://foreign.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response
        .headers()
        .contains_key("access-control-allow-origin"));
    assert_eq!(
        r.clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        200
    );
}
#[tokio::test]
async fn csv_to_bulk_to_byte_exact_download_and_cleanup() {
    let (dir, _app, r) = app(None, json!({"ui_batch_size":1}));
    let (status, v) = upload(
        &r,
        "/load_csv",
        "addresses.csv",
        include_bytes!("fixtures/addresses.csv"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(v["suggested_email_column"], "Email Address");
    assert_eq!(
        request(
            &r,
            "/select_column",
            "POST",
            json!({"column":"Email Address"})
        )
        .await
        .1["total_emails"],
        2
    );
    let (status, v) = request(&r, "/start_verification?confirm=true", "GET", Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(v["status"], "verifying");
    let v = wait_completed(&r).await;
    assert_eq!(v["status"], "completed");
    assert_eq!(v["processed_emails"], 2);
    assert_eq!(v["valid_emails"], 2);
    assert_eq!(v["total_batches"], 2);
    let response = r
        .clone()
        .oneshot(
            Request::builder()
                .uri("/download_results")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("attachment; filename=verification_results_"));
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(bytes.starts_with(&[239, 187, 191]));
    assert_eq!(csv::Reader::from_reader(&bytes[3..]).records().count(), 2);
    assert_eq!(
        std::fs::read(dir.0.join(v["result_filepath"].as_str().unwrap())).unwrap(),
        bytes
    );
    assert_eq!(
        request(&r, "/cleanup", "POST", json!({})).await.1["status"],
        "success"
    );
    assert_eq!(std::fs::read_dir(dir.0.join("results")).unwrap().count(), 0);
    assert_eq!(
        request(&r, "/status", "GET", Value::Null).await.1["status"],
        "idle"
    );
}
#[tokio::test]
async fn txt_workflow_and_upload_state_guards() {
    let (_dir, _app, r) = app(None, json!({}));
    assert_eq!(
        request(&r, "/select_column", "POST", json!({})).await.0,
        400
    );
    assert_eq!(
        request(&r, "/start_verification", "GET", Value::Null)
            .await
            .0,
        400
    );
    assert_eq!(
        request(&r, "/download_results", "GET", Value::Null).await.0,
        404
    );
    let (status, v) = upload(
        &r,
        "/load_txt",
        "addresses.txt",
        include_bytes!("fixtures/addresses.txt"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(v["total_emails"], 3);
    assert_eq!(v["file_info"]["encoding"], "utf-8-sig");
    assert_eq!(
        upload(&r, "/load_txt", "addresses.txt", b"x@y.com").await.0,
        400
    );
    assert_eq!(
        request(&r, "/select_column", "POST", json!({})).await.1["total_emails"],
        3
    );
    assert_eq!(
        request(&r, "/stop_verification", "POST", json!({})).await.1["message"],
        "No verification process is currently running"
    );
}
#[tokio::test]
async fn upload_errors_and_missing_columns() {
    let (_dir, _app, r) = app(None, json!({}));
    assert_eq!(upload(&r, "/load_csv", "wrong.txt", b"a,b").await.0, 400);
    assert_eq!(upload(&r, "/load_csv", "empty.csv", b"").await.0, 500);
    assert_eq!(
        upload(&r, "/load_txt", "empty.txt", b"no addresses")
            .await
            .0,
        400
    );
    assert_eq!(
        upload(&r, "/load_csv", "ok.csv", b"email,name\na@example.com,A\n")
            .await
            .0,
        200
    );
    assert_eq!(
        request(&r, "/select_column", "POST", json!({})).await.0,
        400
    );
    assert_eq!(
        request(&r, "/select_column", "POST", json!({"column":"missing"}))
            .await
            .0,
        500
    );
}
#[tokio::test]
async fn single_column_csv_is_accepted() {
    let (_dir, _app, r) = app(None, json!({}));
    let (status, body) = upload(&r, "/load_csv", "single.csv", b"email\na@example.com").await;
    assert_eq!(
        (status, body["columns"].clone()),
        (StatusCode::OK, json!(["email"]))
    );
}
#[tokio::test]
async fn stop_retains_finished_batch_and_cleanup_cannot_race() {
    let dir = Directory::new();
    let mock = MockNetwork::new();
    *mock.delay.lock().unwrap() = Duration::from_millis(80);
    let app = App::new(
        verifier(mock.clone(), json!({"ui_batch_size":1})),
        dir.0.clone(),
        None,
    )
    .unwrap();
    let r = router(app.clone());
    upload(&r, "/load_txt", "a.txt", b"a@example.com\nb@example.com").await;
    request(&r, "/select_column", "POST", json!({})).await;
    request(&r, "/start_verification", "GET", Value::Null).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while mock.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(request(&r, "/cleanup", "POST", json!({})).await.0, 400);
    assert_eq!(
        request(&r, "/start_verification", "GET", Value::Null)
            .await
            .0,
        400
    );
    let (_, v) = request(&r, "/stop_verification", "POST", json!({})).await;
    assert_eq!(v["status"], "stopped");
    let v = wait_completed(&r).await;
    assert_eq!(v["processed_emails"], 1);
    assert_eq!(v["has_results"], true);
    assert!(!app.job.lock().await.active);
}
#[tokio::test]
async fn unused_cleanup_retains_current_files() {
    let (dir, app, _r) = app(None, json!({}));
    std::fs::write(dir.0.join("uploads/old.csv"), b"old").unwrap();
    std::fs::write(dir.0.join("results/current.csv"), b"current").unwrap();
    app.job.lock().await.result_path = Some("results/current.csv".into());
    app.cleanup_unused().await.unwrap();
    assert!(!dir.0.join("uploads/old.csv").exists());
    assert!(dir.0.join("results/current.csv").exists());
}
#[tokio::test]
async fn csv_incremental_snapshots_do_not_duplicate_rows() {
    let (_dir, app, r) = app(None, json!({"ui_batch_size":1}));
    upload(
        &r,
        "/load_txt",
        "a.txt",
        b"a@example.com\nb@example.com\nc@example.com",
    )
    .await;
    request(&r, "/select_column", "POST", json!({})).await;
    request(&r, "/start_verification", "GET", Value::Null).await;
    wait_completed(&r).await;
    assert_eq!(app.job.lock().await.results.len(), 3);
    let response = r
        .oneshot(
            Request::builder()
                .uri("/download_results")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(csv::Reader::from_reader(&bytes[3..]).records().count(), 3);
}

#[tokio::test]
async fn oversized_upload_is_rejected() {
    let (_dir, _app, r) = app(None, json!({}));
    let bytes = vec![b'x'; 10 * 1024 * 1024];
    assert_eq!(
        upload(&r, "/load_csv", "large.csv", &bytes).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn download_refuses_sibling_directory_with_matching_prefix() {
    let (dir, app, r) = app(None, json!({}));
    std::fs::create_dir(dir.0.join("results-other")).unwrap();
    std::fs::write(dir.0.join("results-other/escape.csv"), b"private").unwrap();
    app.job.lock().await.result_path = Some("results-other/escape.csv".into());
    assert_eq!(
        request(&r, "/download_results", "GET", Value::Null).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn txt_column_confirmation_does_not_require_json() {
    let (_dir, _app, r) = app(None, json!({}));
    assert_eq!(
        upload(&r, "/load_txt", "a.txt", b"a@example.com").await.0,
        200
    );
    let response = r
        .oneshot(
            Request::builder()
                .uri("/select_column")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["total_emails"],
        1
    );
}

#[tokio::test]
async fn saved_http_reference_scenarios() {
    let (_dir, _app, r) = app(None, json!({}));
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/http-reference.json")).unwrap();
    for case in cases {
        let path = case["path"].as_str().unwrap();
        if path == "/select_column" {
            continue;
        }
        let (status, value) = request(
            &r,
            path,
            case["method"].as_str().unwrap(),
            case["body"].clone(),
        )
        .await;
        let expected_status = if path == "/verify_single"
            && (case["body"].is_array() || case["body"]["email"].is_number())
        {
            400
        } else {
            case["python_status"].as_u64().unwrap() as u16
        };
        assert_eq!(status.as_u16(), expected_status, "{case}");
        if let Some(expected) = case["python"].as_object() {
            for (key, expected) in expected {
                if key != "error" && key != "verification_steps" {
                    assert_eq!(&value[key], expected, "{case}: {key}");
                }
            }
        }
    }
}

#[tokio::test]
async fn slow_upload_does_not_lock_status_or_allow_cleanup() {
    use tokio::io::AsyncWriteExt;
    let (_dir, app, r) = app(None, json!({}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = r.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(b"POST /load_txt HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: 1000\r\n\r\n--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"slow.txt\"\r\n\r\na@example.com").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(job) = app.job.try_lock() {
                if job.status == "loading_txt" {
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (_, value) = tokio::time::timeout(
        Duration::from_secs(1),
        request(&r, "/status", "GET", Value::Null),
    )
    .await
    .unwrap();
    assert_eq!(value["status"], "loading_txt");
    assert_eq!(request(&r, "/cleanup", "POST", json!({})).await.0, 400);
    assert_eq!(
        upload(&r, "/load_txt", "new.txt", b"b@example.com").await.0,
        400
    );
    drop(client);
    server.abort();
}
