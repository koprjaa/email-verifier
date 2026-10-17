// Project: email-verifier
// File: files.rs
// Description: Encoding detection, ordered address extraction and result CSV serialization.
// Author: Jan Alexandr Kopřiva
// License: MIT

use crate::verifier::VerificationResult;
use serde_json::Value;
use std::collections::HashSet;

pub fn decode(bytes: &[u8]) -> Result<(String, &'static str), String> {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return Ok((
            s.strip_prefix('\u{feff}').unwrap_or(s).to_string(),
            "utf-8-sig",
        ));
    }
    for (enc, name) in [
        (encoding_rs::WINDOWS_1250, "cp1250"),
        (encoding_rs::ISO_8859_2, "iso-8859-2"),
    ] {
        let (text, _, bad) = enc.decode(bytes);
        if !bad {
            return Ok((text.into_owned(), name));
        }
    }
    Err("Could not read file with a supported encoding".into())
}
pub fn csv_headers(text: &str) -> Result<(u8, Vec<String>), String> {
    let line = text.lines().next().unwrap_or("").trim();
    let delimiter = b",;\t|"
        .iter()
        .copied()
        .find(|c| line.contains(*c as char))
        .ok_or("Could not read CSV headers. Check the encoding and column delimiter.")?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .map(str::to_string)
        .collect();
    Ok((delimiter, headers))
}
pub fn suggest_column(headers: &[String]) -> Option<String> {
    headers
        .iter()
        .find(|s| {
            ["email", "e-mail", "mail", "emailaddress"]
                .contains(&s.to_lowercase().replace([' ', '_'], "").as_str())
        })
        .or(headers.first())
        .cloned()
}
pub fn unique(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect()
}
pub fn csv_emails(text: &str, delimiter: u8, column: &str) -> Result<Vec<String>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(text.as_bytes());
    // DictReader uses the last duplicate header.
    let index = reader
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .enumerate()
        .filter(|(_, h)| *h == column)
        .map(|(i, _)| i)
        .last()
        .ok_or_else(|| format!("Column '{column}' not found in CSV"))?;
    let mut items = vec![];
    for row in reader.records() {
        items.push(
            row.map_err(|e| e.to_string())?
                .get(index)
                .unwrap_or("")
                .trim()
                .to_string(),
        );
    }
    Ok(unique(items))
}
pub fn txt_emails(text: &str) -> Vec<String> {
    let pattern = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        .expect("constant regex");
    let mut emails = vec![];
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(sep) = [',', ';', '|', '\t']
            .into_iter()
            .find(|c| line.contains(*c))
        {
            for part in line.split(sep).map(str::trim) {
                if pattern.find(part).is_some_and(|m| m.start() == 0) {
                    emails.push(part.to_string());
                }
            }
        } else {
            emails.extend(pattern.find_iter(line).map(|m| m.as_str().to_string()));
        }
    }
    unique(emails)
}
pub fn secure_filename(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let normalized: String = name
        .nfkd()
        .filter(char::is_ascii)
        .map(|c| {
            if c == '/' || (cfg!(windows) && c == '\\') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let filename = normalized
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .collect::<String>()
        .trim_matches(['.', '_'])
        .to_string();
    if cfg!(windows) {
        let base = filename
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL"].contains(&base.as_str())
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && base.as_bytes()[3].is_ascii_digit())
        {
            return format!("_{filename}");
        }
    }
    filename
}
pub const CSV_COLUMNS: [&str; 10] = [
    "email",
    "status",
    "error_details",
    "domain_type",
    "smtp_response_full",
    "mx_servers",
    "verification_duration_ms",
    "raw_status_code",
    "is_catchall_domain",
    "smtp_internal_code",
];
pub fn result_csv(results: &[VerificationResult]) -> Result<Vec<u8>, csv::Error> {
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(vec![0xef, 0xbb, 0xbf]);
    writer.write_record(CSV_COLUMNS)?;
    for r in results {
        let status = match r.is_valid {
            Some(true) if r.is_catchall => "catchall",
            Some(true) => "valid",
            Some(false) => "invalid",
            None => "unknown",
        };
        let smtp = r
            .smtp_code_internal
            .map(|c| format!("{c}: {}", r.message))
            .unwrap_or_default();
        writer.write_record([
            r.email.as_str(),
            status,
            r.message.as_str(),
            "unknown",
            smtp.as_str(),
            r.mx_record.as_deref().unwrap_or(""),
            "",
            r.status_code.as_str(),
            if r.is_catchall { "True" } else { "False" },
            &r.smtp_code_internal
                .map(|c| c.to_string())
                .unwrap_or_default(),
        ])?;
    }
    writer.flush()?;
    writer.into_inner().map_err(|e| e.into_error().into())
}
pub fn read_config(path: &std::path::Path) -> Value {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str::<Value>(&s) {
            Ok(v) if v.is_object() => v,
            _ => {
                crate::log(
                    "ERROR",
                    "Error parsing main config.json, using default parameters",
                );
                serde_json::json!({})
            }
        },
        Err(_) => {
            crate::log(
                "WARNING",
                "Main config.json not found in root. Using default parameters.",
            );
            serde_json::json!({})
        }
    }
}
