// Project: email-verifier
// File: files.rs
// Description: Encoding detection, ordered address extraction and result CSV serialization.
// Author: Jan Alexandr Kopřiva
// License: MIT

use crate::verifier::VerificationResult;
use serde_json::Value;
use std::{collections::HashSet, sync::LazyLock};

fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
fn strip(s: &str) -> &str {
    s.trim_matches(python_space)
}

pub fn decode(bytes: &[u8]) -> Result<(String, &'static str), String> {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return Ok((
            s.strip_prefix('\u{feff}').unwrap_or(s).to_string(),
            "utf-8-sig",
        ));
    }
    // WHATWG maps undefined CP1250 bytes to controls; Python rejects them.
    let undefined = [0x81, 0x83, 0x88, 0x90, 0x98];
    let (enc, name) = if bytes.iter().any(|b| undefined.contains(b)) {
        (encoding_rs::ISO_8859_2, "iso-8859-2")
    } else {
        (encoding_rs::WINDOWS_1250, "cp1250")
    };
    let (text, _) = enc.decode_without_bom_handling(bytes);
    Ok((text.into_owned(), name))
}

fn normalized_csv(text: &str) -> String {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    // The CSV crate consumes a BOM itself; decoding has already consumed one.
    if text.starts_with('\u{feff}') {
        format!("\u{feff}{text}")
    } else {
        text
    }
}

pub fn csv_headers(text: &str) -> Result<(u8, Vec<String>), String> {
    let line = text.split(['\r', '\n']).next().unwrap_or("").trim();
    let delimiter = b",;\t|"
        .iter()
        .copied()
        .find(|c| line.contains(*c as char))
        // a single column has no delimiter; the comma is as good as any
        .or((!line.is_empty()).then_some(b','))
        .ok_or("Could not read CSV headers. Check the encoding and column delimiter.")?;
    let text = normalized_csv(text);
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
    let text = normalized_csv(text);
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
                .trim_matches(python_space)
                .to_string(),
        );
    }
    Ok(unique(items))
}
pub fn txt_emails(text: &str) -> Vec<String> {
    static PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
            .expect("constant regex")
    });
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^[\p{L}\p{N}_]$").expect("constant Unicode categories")
    });
    // Python's word boundaries exclude combining marks and join controls.
    let matches = |part: &str| {
        let mut shadow = String::new();
        let mut offsets = Vec::new();
        for (offset, c) in part.char_indices() {
            let mapped = if !c.is_ascii() && !WORD.is_match(&c.to_string()) {
                '\0'
            } else {
                c
            };
            shadow.push(mapped);
            offsets.extend(std::iter::repeat_n(offset, mapped.len_utf8()));
        }
        offsets.push(part.len());
        PATTERN
            .find_iter(&shadow)
            .map(|m| {
                let start = offsets[m.start()];
                (start, part[start..offsets[m.end()]].to_string())
            })
            .collect::<Vec<_>>()
    };
    let mut emails = vec![];
    for line in text
        .split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ])
        .map(strip)
        .filter(|s| !s.is_empty())
    {
        if let Some(sep) = [',', ';', '|', '\t']
            .into_iter()
            .find(|c| line.contains(*c))
        {
            for part in line.split(sep).map(strip) {
                if matches(part).first().is_some_and(|(start, _)| *start == 0) {
                    emails.push(part.to_string());
                }
            }
        } else {
            emails.extend(matches(line).into_iter().map(|(_, email)| email));
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
        .split(python_space)
        .filter(|s| !s.is_empty())
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
            .filter(|c| *c != 0)
            .map(|c| {
                if r.message.is_empty() {
                    format!("Code: {c}")
                } else {
                    format!("{c}: {}", r.message)
                }
            })
            .unwrap_or_default();
        let message = if r.message.is_empty() {
            format!("Status: {}", r.status_code)
        } else {
            r.message.clone()
        };
        writer.write_record([
            r.email.as_str(),
            status,
            message.as_str(),
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
