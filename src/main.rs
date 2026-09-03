mod cli;
mod utils;

use clap::Parser;
use cli::Args;

use crate::utils::directory_scan;
use crate::utils::subdomain_scan;
use crate::utils::upload_scan;
use crate::utils::webcert_scan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let specific_scan = args.directory || args.subdomains || args.webcert;

    println!("WebBooper - A Rust-based web scanning tool");

    if args.info {
        println!("Open-source Rust tool made to boop URLs and find suspicious little clues");
    }

    if args.url.is_some() {
        println!("[/]Scanning URL: {}", args.url.as_ref().unwrap());
    }

    let mut results = String::new();

    if specific_scan {
        if args.subdomains {
            println!("[/]Scanning for subdomains only...");
            let subdomains = subdomain_scan(args.url.as_ref().unwrap()).await?;
            for subdomain in subdomains {
                println!("{}", subdomain);
                results.push_str(&format!("{}\n", subdomain));
            }
        }
    }

    if args.webcert {
        println!("[+] Retreiving web certificate");
        let certificates = webcert_scan(args.url.as_ref().unwrap()).await?;
        println!("[+] Found {} certificates\n", certificates.len());
        for cert in &certificates {
            println!("Issued: {}", cert.not_before);
            println!("Expires: {}", cert.not_after);
            println!("Serial: {}", cert.serial_hex);
            println!("Issuer: {}", cert.issuer);
            println!("Key Algorithm: {}", cert.key_algo);
            println!("SAN Count: {}", cert.san_count);
            println!("---------------------------");
            results.push_str(&format!(
                    "Issued: {}\nExpires: {}\nSerial: {}\nIssuer: {}\nKey Algorithm: {}\nSAN Count: {}\n---------------------------\n",
                    cert.not_before,
                    cert.not_after,
                    cert.serial_hex,
                    cert.issuer,
                    cert.key_algo,
                    cert.san_count
                ));
        }
    }

    if args.directory {
        println!("[+] Scanning directory");
        let directories = directory_scan(args.url.as_ref().unwrap()).await?;
        results.push_str("[+] DIRECTORY SCAN\n");
        results.push_str("--------------------------------\n");
        for directory in directories {
            println!("{}", directory);
            results.push_str(&format!("{}\n", directory));
        }
        results.push('\n');
    }

    if !specific_scan {
        println!("[+] No specific scan selected");
        println!("[+] Starting full scan...");
        println!("\n[+] Directory scan");
        let directories = directory_scan(args.url.as_ref().unwrap()).await?;
        results.push_str("[+] DIRECTORY SCAN\n");
        results.push_str("--------------------------------\n");

        for directory in directories {
            println!("{}", directory);
            results.push_str(&format!("{}\n", directory));
        }
        println!("\n[+] Subdomain scan");
        let subdomains = subdomain_scan(args.url.as_ref().unwrap()).await?;
        results.push_str("--------------------------------\n");
        results.push_str("[+] SUBDOMAIN SCAN\n");
        results.push_str("--------------------------------\n");
        for subdomain in subdomains {
            println!("{}", subdomain);
            results.push_str(&format!("{}\n", subdomain));
        }

        results.push('\n');

        println!("\n[+] Web certificate scan");
        let certificates = webcert_scan(args.url.as_ref().unwrap()).await?;
        println!("[+] Found {} certificates\n", certificates.len());
        for (number, cert) in certificates.iter().enumerate() {
            println!("Certificate #{}", number + 1);
            println!("Issued: {}", cert.not_before);
            println!("Expires: {}", cert.not_after);
            println!("Serial: {}", cert.serial_hex);
            println!("Issuer: {}", cert.issuer);
            println!("Key Algorithm: {}", cert.key_algo);
            println!("SAN Count: {}", cert.san_count);
            println!("---------------------------");
            results.push_str(&format!(
                "Certificate #{}\nIssued: {}\nExpires: {}\nSerial: {}\nIssuer: {}\nKey Algorithm: {}\nSAN Count: {}\n---------------------------\n",
                number + 1,
                cert.not_before,
                cert.not_after,
                cert.serial_hex,
                cert.issuer,
                cert.key_algo,
                cert.san_count
            ));
        }
    }

    if let Some(output) = args.output.as_deref() {
        println!("[+] Saving results to: {}", output);
        utils::file_towrite(output, &results)?;
    }
    if let Some(upload) = args.upload.as_deref() {
        println!("[+] Uploading scan results");
        upload_scan(upload, &results).await?;
    }
    Ok(())
}
