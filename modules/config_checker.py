#!/usr/bin/env python3
"""
Configuration checker module for cyberrecon
Verifies that all required components are properly configured before running scans
"""

import sys
import os
import socket
import subprocess
from .config import *

def check_api_key(key_name, key_value, required=True):
    """Check if an API key is configured"""
    if key_value and key_value != "":
        return True, f"✓ {key_name}: Configured"
    else:
        status = "✗" if required else "⚠️"
        message = f"{status} {key_name}: {'Not configured' if required else 'Optional'}"
        return not required, message

def check_dependencies():
    """Check if all required Python dependencies are installed"""
    required_modules = [
        'requests', 'dnslib', 'dns', 'beautifulsoup4', 
        'nmap3', 'concurrent.futures', 'json', 'os', 'time'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            if module == 'concurrent.futures':
                import concurrent.futures
            else:
                __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        return False, f"✗ Missing dependencies: {', '.join(missing_modules)}"
    else:
        return True, "✓ All Python dependencies installed"

def check_nmap():
    """Check if Nmap is installed and accessible"""
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, "✓ Nmap is installed and accessible"
        else:
            return False, "✗ Nmap is installed but not working properly"
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False, "✗ Nmap is not installed or not in PATH"

def check_network_connectivity():
    """Check basic network connectivity"""
    test_domains = ["google.com", "github.com", "stackoverflow.com"]
    working_domains = 0
    
    for domain in test_domains:
        try:
            socket.gethostbyname(domain)
            working_domains += 1
        except socket.gaierror:
            pass
    
    if working_domains >= 2:
        return True, f"✓ Network connectivity OK ({working_domains}/3 domains reachable)"
    else:
        return False, f"✗ Network connectivity issues ({working_domains}/3 domains reachable)"

def check_directories():
    """Check if required directories exist and are writable"""
    directories_to_check = [
        (result, "Results directory"),
        ("wordlists", "Wordlists directory"),
        ("modules", "Modules directory")
    ]
    
    issues = []
    for directory, name in directories_to_check:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
                issues.append(f"✓ {name}: Created")
            except Exception as e:
                issues.append(f"✗ {name}: Cannot create - {e}")
        else:
            if os.access(directory, os.W_OK):
                issues.append(f"✓ {name}: Exists and writable")
            else:
                issues.append(f"✗ {name}: Exists but not writable")
    
    return len([i for i in issues if i.startswith("✗")]) == 0, issues

def check_configuration():
    """Comprehensive configuration check"""
    print("=== CyberRecon Configuration Check ===")
    print()
    
    all_checks_passed = True
    results = []
    
    # Check API keys
    print("API Keys:")
    api_checks = [
        ("Shodan API", shodan_api_key, False),
        ("Email Hunter API", email_hunter_api_key, True),
        ("WhatCMS API", whatcms_api_key, True),
        ("Wappalyzer API", wappalyzer_api_key, True),
        ("Censys API", censys_api_id and censys_secret, False),
        ("BreachDirectory API", breachdirectory_api_key, True)
    ]
    
    for key_name, key_value, required in api_checks:
        passed, message = check_api_key(key_name, key_value, required)
        print(f"  {message}")
        if not passed and required:
            all_checks_passed = False
        results.append(("API Keys", passed or not required))
    
    print()
    
    # Check dependencies
    print("Dependencies:")
    deps_passed, deps_message = check_dependencies()
    print(f"  {deps_message}")
    all_checks_passed = all_checks_passed and deps_passed
    results.append(("Dependencies", deps_passed))
    
    # Check Nmap
    print()
    print("External Tools:")
    nmap_passed, nmap_message = check_nmap()
    print(f"  {nmap_message}")
    all_checks_passed = all_checks_passed and nmap_passed
    results.append(("Nmap", nmap_passed))
    
    # Check network
    print()
    print("Network:")
    net_passed, net_message = check_network_connectivity()
    print(f"  {net_message}")
    all_checks_passed = all_checks_passed and net_passed
    results.append(("Network", net_passed))
    
    # Check directories
    print()
    print("Directories:")
    dirs_passed, dir_messages = check_directories()
    for message in dir_messages:
        print(f"  {message}")
    all_checks_passed = all_checks_passed and dirs_passed
    results.append(("Directories", dirs_passed))
    
    # Check configuration parameters
    print()
    print("Configuration Parameters:")
    config_issues = []
    
    if timeout < 0:
        config_issues.append("✗ Timeout must be positive")
    else:
        print(f"  ✓ Timeout: {timeout}s")
    
    if num_threads < 1:
        config_issues.append("✗ Number of threads must be at least 1")
    else:
        print(f"  ✓ Threads: {num_threads}")
    
    if not dns_resolver:
        config_issues.append("✗ DNS resolver not configured")
    else:
        print(f"  ✓ DNS Resolver: {dns_resolver}")
    
    if config_issues:
        for issue in config_issues:
            print(f"  {issue}")
        all_checks_passed = False
    else:
        print("  ✓ All configuration parameters valid")
    
    results.append(("Configuration", len(config_issues) == 0))
    
    # Summary
    print()
    print("=== Summary ===")
    passed_checks = sum(1 for _, passed in results if passed)
    total_checks = len(results)
    
    print(f"Checks passed: {passed_checks}/{total_checks}")
    
    if all_checks_passed:
        print("🎉 All checks passed! CyberRecon is ready to use.")
        return 0
    elif passed_checks >= total_checks * 0.8:
        print("⚠️  Most checks passed. Some modules may not work optimally.")
        return 1
    else:
        print("❌ Several checks failed. Please fix the issues before using CyberRecon.")
        return 2

def main():
    """Main function for standalone execution"""
    return check_configuration()

if __name__ == '__main__':
    sys.exit(main())
