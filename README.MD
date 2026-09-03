# WebBooper

## What it does
Boops websites with 3 common reconnaissance techniques:
- Web certificate information
- Directory enumeration
- Subdomain discovery

It's mainly a project for learning Rust, web requests, and building security tooling.

# Usage
Run WebBooper with a target URL:

```bash
webbooper -u https://example.com
This will run all aspects of the scan 

Specific scan arguments include:

Directory scan only:
webbooper -u https://example.com --directory
Uses a list of common paths located in utils.rs.

Subdomain scan only:
webbooper -u https://example.com --subdomains
Uses the crt.sh API to retrieve subdomains registered to the hostname.

Web certificate scan only:
webbooper -u https://example.com --webcert
Retrieves web certificate information from CTlogs.


webbooper -u https://example.com -o results.txt
*Output to file*

webbooper -u https://example.com --upload <webhook>
Allows the results to be sent to a webhook or other server that accepts the request.
Note: Due to the amount of data a scan can return, webhook uploads can be unstable.
