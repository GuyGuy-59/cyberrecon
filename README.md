# CyberRecon

CyberRecon is a command-line OSINT (Open Source Intelligence) tool for domain and host reconnaissance. It chains multiple analysis modules (DNS, certificates, email discovery, headers, SSL, port scan, and others), writes structured JSON under `results/`, and runs an optional configuration check before each scan.

## Features

- Eleven modules selectable individually or as a full run (`-m` / `--modules`).
- Module definitions and `--list-modules` categories stored in [`modules.json`](modules.json) (add or adjust modules without editing the main script logic beyond wiring).
- Pre-scan configuration validation via `modules/config_checker.py`.
- Logging to `results/` with a per-target log file when a target is set.
- UTF-8 handling for logs and outputs.

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

Edit `modules/config.py`. Typical keys include Hunter.io, WhatCMS, Wappalyzer, BreachDirectory; Shodan and Censys are optional for IoT-related features. The configuration checker reports missing or invalid keys before a run (unless you skip it).

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
| `dorking` | Google dorking |
| `browse` | robots.txt / URL exploration (entrypoint: `scan_robots`) |
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

- **`modules`**: for each module id, `display_name`, Python `package`, and entrypoint `function`.
- **`categories`**: sections for `--list-modules` (each item: `id` + `description`).

Every id under `modules` must appear exactly once across `categories`, and vice versa, or the tool raises an error when listing modules.

## Output

- **Directory**: `results/` (configurable via `result` in `modules/config.py`).
- **Per target**: e.g. `results/example.com/` with JSON from each module (names vary by module).
- **Logs**: e.g. `results/cyberrecon_example_com.log` for a given target.

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

## Security and legal use

Use CyberRecon only on systems and domains you are authorized to test. You are responsible for complying with applicable laws and with third-party terms of service for APIs and data sources. The software is provided as-is; see [LICENSE](LICENSE).

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Third-party services and projects used by the modules include (non-exhaustive): SSL Labs, Security Headers, Mozilla HTTP Observatory, Hunter.io, WhatCMS, Wappalyzer, Shodan, Censys, crt.sh, and urlscan.io, depending on configuration and module selection.
