use reqwest::{self, StatusCode, Url};
use serde::Deserialize;
use std::fs::File;

pub fn file_towrite(file_path: &str, content: &str) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    use std::io::Write;
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub struct ScanResults {
    pub subdomains: Option<Vec<String>>,
    pub certificates: Option<Vec<certificate>>,
    pub paths: Option<Vec<String>>,
}

pub struct Wordlist {
    pub directories: Vec<&'static str>,
}

impl Wordlist {
    pub fn paths() -> Self {
        Self {
            directories: vec![
                "/api",
                "/admin",
                "/login",
                "/register",
                "/dashboard",
                "/config",
                "/.env",
                "/.git",
                "/.htaccess",
                "/download",
                "/health",
                "/status",
                "/metrics",
                "/robots.txt",
                "/sitemap.xml",
                "/uploads",
                "/upload",
                "/images",
                "/css",
                "/api/v1",
                "/api/v2",
                "/docs",
                "/search",
                "/auth",
                "/contact",
                "/about",
            ],
        }
    }
}

#[derive(Debug, Deserialize)]
struct ctlogsresponse {
    rows: Vec<certificate>,
}

#[derive(Debug, Deserialize)]
pub struct certificate {
    pub not_before: String,
    pub not_after: String,
    pub serial_hex: String,
    pub issuer: String,
    pub key_algo: String,
    pub san_count: u32,
}

pub fn clear_url(url: &str) -> String {
    let url = url.trim();
    let url = url.trim_start_matches("http://");
    let url = url.trim_start_matches("https://");
    let url = url.trim_start_matches("www.");
    let url = url.trim_end_matches("/");
    url.to_string()
}

pub async fn subdomain_scan(url: &str) -> reqwest::Result<Vec<String>> {
    let endpoint = format!("https://crt.name/v1/search?apex={}", clear_url(url));
    let response = reqwest::get(endpoint).await?;
    let text = response.text().await?;
    println!("{}", text);
    Ok(vec![text])
}

pub async fn webcert_scan(url: &str) -> reqwest::Result<Vec<certificate>> {
    let domain = clear_url(url);
    let endpoint = format!("https://ctlogs.dev/search?q={}&output=json", domain);
    let response = reqwest::get(endpoint).await?;
    let data: ctlogsresponse = response.error_for_status()?.json().await?;
    Ok(data.rows)
}

pub async fn directory_scan(url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let base = Url::parse(url)?;
    let wordlist = Wordlist::paths();
    let mut results = Vec::new();
    for path in wordlist.directories {
        let target = base.join(path)?;
        let response = reqwest::get(target.clone()).await?;
        let result = format!("{} -> {}", target, response.status().as_u16());
        println!("{}", result);
        results.push(result);
    }
    Ok(results)
}

pub async fn upload_scan(upload: &str, results: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let mut message = String::new();
    for line in results.lines() {
        if message.len() + line.len() + 1 > 1900 {
            let res = client
                .post(upload)
                .json(&serde_json::json!({
                    "content": message
                }))
                .send()
                .await?;
            match res.status() {
                StatusCode::NO_CONTENT => println!("[+] Sent"),
                status => println!("Status: {}", status),
            }
            message.clear();
        }
        message.push_str(line);
        message.push('\n');
    }
    if !message.is_empty() {
        let res = client
            .post(upload)
            .json(&serde_json::json!({
                "content": message
            }))
            .send()
            .await?;
        match res.status() {
            StatusCode::NO_CONTENT => println!("[+] Sent"),
            status => println!("Status: {}", status),
        }
    }
    Ok(())
}
