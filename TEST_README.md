# CyberRecon Test Suite

## Description
The `cyberrecon_test.py` script is a comprehensive testing tool for the cyberrecon OSINT tool. It allows testing individually or collectively all optimized modules of the tool.

## Usage

### Basic syntax
```bash
python cyberrecon_test.py [OPTIONS]
```

### Available options

#### `--test` (required)
Specifies the type of test to perform:
- `config` : Configuration test
- `network` : Network connectivity test
- `dorking` : Dorking module test
- `browse` : BrowseUrl module test
- `scan` : Scan module test
- `ip` : IP tools module test
- `headers` : Headers info module test
- `iot` : IoT module test
- `crtsh` : crt.sh module test
- `ssl` : SSL info module test
- `site` : Site analysis module test
- `dns` : DNS info module test
- `email` : Email search module test
- `all` : Test all modules (default)

#### `--target` (optional)
Specifies the target for tests (default: `example.com`)
```bash
python cyberrecon_test.py --test dns --target google.com
```

#### `--verbose` or `-v` (optional)
Enables verbose logging for more details
```bash
python cyberrecon_test.py --test all --verbose
```

## Usage examples

### Configuration test
```bash
python cyberrecon_test.py --test config
```

### Specific module test
```bash
python cyberrecon_test.py --test dns --target google.com
```

### All modules test
```bash
python cyberrecon_test.py --test all --target example.com
```

### Test with verbose logging
```bash
python cyberrecon_test.py --test site --target github.com --verbose
```

## Tested Modules

### 1. Configuration (`config`)
- Configuration parameters verification
- Paths and API keys validation

### 2. Network Connectivity (`network`)
- DNS resolution testing
- Internet connectivity verification

### 3. Dorking (`dorking`)
- Google Dorking search testing
- Parallel processing verification

### 4. Browse URL (`browse`)
- robots.txt scan testing
- .well-known scan testing
- Directory brute-force testing

### 5. Scan (`scan`)
- Nmap scan testing
- Port detection verification

### 6. IP Tools (`ip`)
- IP geolocation testing
- SpamCop verification testing

### 7. Headers Info (`headers`)
- Security headers analysis testing
- Security scores verification

### 8. IoT (`iot`)
- Shodan search testing
- urlscan.io testing
- Censys testing

### 9. crt.sh (`crtsh`)
- Subdomain enumeration testing
- IP resolution verification

### 10. SSL Info (`ssl`)
- SSL Labs analysis testing
- TLS analysis testing

### 11. Site Analysis (`site`)
- CMS detection testing
- Technology detection testing
- WAF detection testing

### 12. DNS Info (`dns`)
- DNS enumeration testing
- Email security testing (SPF, DKIM, DMARC)
- Zone transfer testing

### 13. Email Search (`email`)
- Email enumeration testing
- Breach verification testing

## Test Results

### Output format
- **✓** : Test passed
- **✗** : Test failed
- **⚠️** : Warning (e.g., missing API key)

### Result files
Results are saved in the `results/` directory with:
- Structured JSON files
- Complete metadata
- Scan timestamps

### Test summary
At the end of each test, a summary is displayed with:
- Number of passed/failed tests
- Execution time
- Error details

## Error Handling

### Missing API keys
Some modules require API keys. If a key is missing:
- Test is marked as "skipped"
- Warning message is displayed
- Test continues with other modules

### Network errors
- Automatic retry with exponential backoff
- Configurable timeouts
- Graceful error handling

### Configuration errors
- Parameter validation
- Explicit error messages
- Correction suggestions

## Required Configuration

### Python Dependencies
- requests
- dnslib
- dns
- beautifulsoup4
- nmap3
- concurrent.futures

### API Keys (optional)
- WhatCMS API key
- Wappalyzer API key
- Shodan API key
- Censys API key
- Hunter.io API key

### Permissions
- Read/write access to `results/` directory
- Network access for external requests
- Permissions for Nmap scans (if applicable)

## Troubleshooting

### Common errors
1. **ModuleNotFoundError**: Check dependency installation
2. **PermissionError**: Check permissions on results/ directory
3. **ConnectionError**: Check network connectivity
4. **APIError**: Check API keys in config.py

### Debug logs
Use the `--verbose` option for more details:
```bash
python cyberrecon_test.py --test all --verbose
```

## Support

For more information or to report issues:
- Check test logs
- Consult module documentation
- Check configuration in `config.py`
