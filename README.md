# CyberRecon

CyberRecon is a command-line OSINT (Open Source Intelligence) tool for domain and host reconnaissance. It chains multiple analysis modules (DNS, certificates, email discovery, headers, SSL, port scan, and others), writes structured JSON under `results/`, and runs an optional configuration check before each scan.

## Features

- Eleven modules selectable individually or as a full run (`-m` / `--modules`).
- Module definitions and `--list-modules` categories stored in [`modules.json`](modules.json); each module exposes a standard **`run(target, logger)`** entrypoint while internal helpers remain callable for testing or reuse.
- Pre-scan configuration validation via `modules/config_checker.py`.
- Logging to `results/` with a per-target log file when a target is set.
- UTF-8 handling for logs and outputs.
- HTTP requests go through `modules/http_client.py`, a `requests`-compatible client backed by [curl_cffi](https://github.com/lexiforest/curl_cffi) that impersonates a real browser's TLS handshake (JA3/JA4) instead of Python's stock `ssl`/OpenSSL fingerprint.
- Google dorking (`dorking` module) resolves each dork through [SerpApi](https://serpapi.com/) when `serpapi_api_key` is configured; otherwise it scrapes Google directly, falling back through DuckDuckGo, Bing, and Startpage when a request is blocked or fails. Bot-check/captcha pages served by any of these engines are detected and treated as a failed lookup rather than a false "0 results".

## Requirements

- Python 3.9+ recommended (3.7+ may work).
- Network access for APIs and external lookups.
- **Nmap** on the system PATH for the port-scanning module (`scan`).

## Installation

```bash
git clone https://github.com/GuyGuy-59/cyberrecon.git
cd cyberrecon
pip install -r requirements.txt
```

Install Nmap:

| Platform | Command |
|----------|---------|
| Ubuntu / Debian | `sudo apt install nmap` |
| Fedora / RHEL | `sudo dnf install nmap` |
| macOS | `brew install nmap` |
| Windows | `choco install nmap` or installer from [nmap.org](https://nmap.org/) |

## Configuration

Copy the example config and add your API keys:

```bash
cp modules/config.py.example modules/config.py
```

Edit `modules/config.py`. Typical keys include Hunter.io, WhatCMS, Wappalyzer, BreachDirectory; Shodan and Censys are optional for IoT-related features. `serpapi_api_key` is optional and used only by the `dorking` module — leave it empty (`""`) to keep the default scraping-based search, or set it to route dorks through [SerpApi](https://serpapi.com/) instead. The configuration checker reports missing or invalid keys before a run (unless you skip it).

`header_default` (User-Agent) and `tls_impersonate` (browser TLS fingerprint used by `modules/http_client.py`, e.g. `"chrome131"`, `"firefox135"`, `"safari184"`) should be kept in sync — a User-Agent claiming one browser while the TLS handshake fingerprints as another is itself a detection signal for fingerprint-correlating WAFs.

## Usage

```bash
# Full scan (all modules)
python cyberrecon.py example.com

# Specific modules
python cyberrecon.py example.com -m dns ssl headers

# List modules (grouped by category, with short descriptions)
python cyberrecon.py --list-modules
# or
python cyberrecon.py -L

# Skip configuration check
python cyberrecon.py example.com --skip-config-check

# Verbose logging
python cyberrecon.py example.com -v
```

| Option | Short | Description |
|--------|-------|-------------|
| `--modules` | `-m` | Space-separated module names (see below). Default: all. |
| `--list-modules` | `-L` | Print modules and exit. |
| `--skip-config-check` | | Do not run the interactive configuration check. |
| `--verbose` | `-v` | Debug-level logging. |

### Module IDs

| ID | Role |
|----|------|
| `dorking` | Google dorking (SerpApi if configured, otherwise Google/DuckDuckGo/Bing/Startpage scraping) |
| `browse` | robots.txt, `.well-known`, and directory probing (`run` → `scan_robots` and follow-on steps) |
| `scan` | Port scan (Nmap) |
| `ip` | IP / geolocation context |
| `headers` | HTTP security headers (incl. observatory-style checks) |
| `iot` | Shodan / urlscan / Censys where configured |
| `crtsh` | Subdomains via certificate transparency |
| `ssl` | SSL/TLS analysis |
| `site` | CMS / stack / WAF-oriented checks |
| `dns` | DNS records and related tests |
| `email` | Email enumeration and related lookups |

Categories shown by `--list-modules` come from `modules.json` (`categories`).

## Module manifest

[`modules.json`](modules.json) holds:

- **`modules`**: for each module id, `display_name`, Python `package`, and entrypoint **`function`** (conventionally **`run`**).
- **`categories`**: sections for `--list-modules` (each item: `id` + `description`).

Every id under `modules` must appear exactly once across `categories`, and vice versa, or the tool raises an error when listing modules.

The main script imports the module and calls `function(target, logger)`. Modules that need a resolved IPv4 address (for example `scan`, `ip`, `iot`) return a sentinel (`SKIP_RESOLUTION_FAILED`) when DNS resolution fails; the CLI reports those runs as skipped.

## Shared utilities

- **`modules/common_utils.py`**: paths under the configured `result` directory (`result_path`), timestamps (`scan_timestamp` / `scan_timestamp_long`), JSON metadata helpers (`base_scan_meta` / `base_scan_meta_long` with `target` and `scan_date`), and `save_json_result` / `save_json_file`.
- **`modules/run_utils.py`**: `run_safe` and `run_safe_steps` to run sub-steps without aborting the whole module on a single failure (used in DNS, browse, site analysis, and similar).
- **`modules/http_client.py`**: `requests`-compatible `get` / `post` / `head` / `Session` / exceptions, backed by `curl_cffi`. Every module imports it as `from . import http_client as requests` instead of importing `requests` directly, so the TLS handshake (JA3/JA4) matches the `tls_impersonate` browser configured in `modules/config.py` for every outbound request.

## Output

- **Directory**: `results/` (configurable via `result` in `modules/config.py`).
- **Per target**: e.g. `results/example.com/` with JSON from each module (filenames vary by module).
- **Logs**: e.g. `results/cyberrecon_example_com.log` for a given target (paths built with the same `result` root as artifacts).
- **JSON metadata**: most exports include **`target`** and **`scan_date`** (minute precision, or with seconds where `base_scan_meta_long` is used). Older keys such as standalone `timestamp` or `analysis_date` may have been merged into this pattern in recent versions; adjust any external parsers accordingly.

## Project layout

```
cyberrecon/
├── cyberrecon.py       # CLI entry point
├── modules.json        # Module registry and list-modules categories
├── requirements.txt
├── LICENSE
├── README.md
├── modules/
│   ├── config.py           # Your configuration (from .example)
│   ├── config.py.example
│   ├── config_checker.py
│   ├── common_utils.py     # Paths, timestamps, JSON helpers
│   ├── run_utils.py        # run_safe / run_safe_steps
│   ├── http_client.py      # curl_cffi-backed HTTP client (TLS/JA3-JA4 impersonation)
│   ├── browseUrl.py
│   ├── crtsh.py
│   ├── dns_info.py
│   ├── dorking.py
│   ├── email_search.py
│   ├── headers_info.py
│   ├── IoT.py
│   ├── ip_tools.py
│   ├── scan.py
│   ├── site_analysis.py
│   └── ssl_info.py
├── wordlists/
│   └── dorks.txt
└── results/            # Created at runtime
```

## Troubleshooting

- **`ModuleNotFoundError`**: run `pip install -r requirements.txt` from the project root.
- **API errors**: verify keys and quotas in `modules/config.py`; confirm outbound HTTPS access.
- **Nmap not found**: install Nmap and ensure `nmap` is on `PATH`.
- **Permission errors on `results/`**: ensure the process can create and write `results/` (e.g. `chmod` / ownership).
- **Requests still getting blocked by a WAF**: check that `tls_impersonate` in `modules/config.py` matches a target curl_cffi supports (see `curl_cffi.requests.impersonate.BrowserType`) and that it agrees with the browser family/version in `header_default`'s User-Agent.

## Security and legal use

Use CyberRecon only on systems and domains you are authorized to test. You are responsible for complying with applicable laws and with third-party terms of service for APIs and data sources. The software is provided as-is; see [LICENSE](LICENSE).

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Third-party services and projects used by the modules include (non-exhaustive): SSL Labs, Security Headers, Mozilla HTTP Observatory, Hunter.io, WhatCMS, Wappalyzer, Shodan, Censys, crt.sh, urlscan.io, SerpApi, and DuckDuckGo/Bing/Startpage (dorking fallback), depending on configuration and module selection.
