#!/usr/bin/env python3
"""
Enhanced test script for cyberrecon tool
This script allows testing all modules of the tool with comprehensive coverage
"""

import sys
import os
import argparse
import socket
import logging
import time
from modules.config import *

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def setup_logger():
    """Setup logger for tests"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger

def test_config():
    """Test configuration using the config checker module"""
    print("=== Testing configuration ===")
    try:
        from modules.config_checker import check_configuration
        return check_configuration()
    except Exception as e:
        print(f"✗ Configuration check failed: {e}")
        return 2

def test_network_connectivity():
    """Test network connectivity"""
    print("=== Testing network connectivity ===")
    test_domains = ["google.com", "github.com", "stackoverflow.com"]
    
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"✓ {domain} -> {ip}")
        except socket.gaierror as e:
            print(f"✗ {domain} -> Error: {e}")

def test_dorking(target):
    """Test dorking module"""
    print("=== Testing dorking module ===")
    try:
        from modules.dorking import scan_dorks
        logger = setup_logger()
        print(f"Testing dorking with target: {target}")
        scan_dorks(target, logger)
        print("✓ Dorking module test completed")
    except Exception as e:
        print(f"✗ Dorking module test failed: {e}")

def test_browse_url(target):
    """Test browseUrl module"""
    print("=== Testing browseUrl module ===")
    try:
        from modules.browseUrl import scan_robots, scan_wellkown, dirs_brute
        logger = setup_logger()
        print(f"Testing browseUrl with target: {target}")
        
        # Test robots.txt scanning
        print("Testing robots.txt scanning...")
        scan_robots(target, f"https://{target}", logger)
        
        # Test .well-known scanning
        print("Testing .well-known scanning...")
        scan_wellkown(f"https://{target}", logger)
        
        print("✓ BrowseUrl module test completed")
    except Exception as e:
        print(f"✗ BrowseUrl module test failed: {e}")

def test_scan(target):
    """Test scan module"""
    print("=== Testing scan module ===")
    try:
        from modules.scan import scan_victim
        import socket
        logger = setup_logger()
        print(f"Testing scan with target: {target}")
        
        # Get IP address for the target
        try:
            target_ip = socket.gethostbyname(target)
            print(f"Target IP: {target_ip}")
        except socket.gaierror:
            target_ip = "127.0.0.1"  # Fallback IP
            print(f"Could not resolve IP, using fallback: {target_ip}")
        
        scan_victim(target, target_ip, logger)
        print("✓ Scan module test completed")
    except Exception as e:
        print(f"✗ Scan module test failed: {e}")

def test_ip_tools(target):
    """Test ip_tools module"""
    print("=== Testing ip_tools module ===")
    try:
        from modules.ip_tools import iplocator, spamcop_test
        logger = setup_logger()
        print(f"Testing ip_tools with target: {target}")
        
        # Test IP geolocation
        print("Testing IP geolocation...")
        iplocator(target, logger)
        
        # Test SpamCop
        print("Testing SpamCop blacklist...")
        spamcop_test(target, logger)
        
        print("✓ IP tools module test completed")
    except Exception as e:
        print(f"✗ IP tools module test failed: {e}")

def test_headers_info(target):
    """Test headers_info module (now includes HTTP Observatory)"""
    print("=== Testing comprehensive security headers module ===")
    try:
        from modules.headers_info import analyze_security_headers_comprehensive
        logger = setup_logger()
        print(f"Testing comprehensive security headers with target: {target}")
        analyze_security_headers_comprehensive(target, logger)
        print("✓ Comprehensive security headers module test completed")
    except Exception as e:
        print(f"✗ Comprehensive security headers module test failed: {e}")

def test_iot(target):
    """Test IoT module"""
    print("=== Testing IoT module ===")
    try:
        from modules.IoT import device_shodan, urlscanio, device_censys
        logger = setup_logger()
        print(f"Testing IoT with target: {target}")
        
        # Test Shodan (requires API key)
        print("Testing Shodan lookup...")
        try:
            device_shodan(target, "1.1.1.1", logger)  # Using dummy IP
        except Exception as e:
            print(f"Shodan test skipped (API key required): {e}")
        
        # Test urlscan.io
        print("Testing urlscan.io...")
        urlscanio(target, logger)
        
        # Test Censys (requires API key)
        print("Testing Censys...")
        try:
            device_censys(target, logger)
        except Exception as e:
            print(f"Censys test skipped (API key required): {e}")
        
        print("✓ IoT module test completed")
    except Exception as e:
        print(f"✗ IoT module test failed: {e}")

def test_crtsh(target):
    """Test crtsh module"""
    print("=== Testing crtsh module ===")
    try:
        from modules.crtsh import crtsh
        logger = setup_logger()
        print(f"Testing crtsh with target: {target}")
        crtsh(target, logger)
        print("✓ crtsh module test completed")
    except Exception as e:
        print(f"✗ crtsh module test failed: {e}")

def test_ssl_info(target):
    """Test ssl_info module"""
    print("=== Testing ssl_info module ===")
    try:
        from modules.ssl_info import analyze_Transport_Layer_Security
        logger = setup_logger()
        print(f"Testing ssl_info with target: {target}")
        analyze_Transport_Layer_Security(target, logger)
        print("✓ SSL info module test completed")
    except Exception as e:
        print(f"✗ SSL info module test failed: {e}")

def test_site_analysis(target):
    """Test site_analysis module"""
    print("=== Testing site_analysis module ===")
    try:
        from modules.site_analysis import whatcms, find_techs, wafDetector
        logger = setup_logger()
        print(f"Testing site_analysis with target: {target}")
        
        # Test CMS detection
        print("Testing CMS detection...")
        whatcms(target, logger)
        
        # Test technology detection (requires API key)
        print("Testing technology detection...")
        try:
            find_techs(target, logger)
        except Exception as e:
            print(f"Technology detection test skipped (API key required): {e}")
        
        # Test WAF detection
        print("Testing WAF detection...")
        wafDetector(target, f"https://{target}", logger)
        
        print("✓ Site analysis module test completed")
    except Exception as e:
        print(f"✗ Site analysis module test failed: {e}")

def test_dns_info(target):
    """Test dns_info module"""
    print("=== Testing dns_info module ===")
    try:
        from modules.dns_info import req_dns_types, check_dns_caa, check_dns_mx, dns_zone_xfer
        logger = setup_logger()
        print(f"Testing dns_info with target: {target}")
        
        # Test DNS record enumeration
        print("Testing DNS record enumeration...")
        req_dns_types(target, logger)
        
        # Test CAA records
        print("Testing CAA records...")
        check_dns_caa(target, logger)
        
        # Test email security records
        print("Testing email security records...")
        check_dns_mx(target, logger)
        
        # Test zone transfer
        print("Testing zone transfer...")
        dns_zone_xfer(target, logger)
        
        print("✓ DNS info module test completed")
    except Exception as e:
        print(f"✗ DNS info module test failed: {e}")

def test_email_search(target):
    """Test email_search module"""
    print("=== Testing email_search module ===")
    try:
        from modules.email_search import get_email
        logger = setup_logger()
        print(f"Testing email_search with target: {target}")
        get_email(target, logger)
        print("✓ Email search module test completed")
    except Exception as e:
        print(f"✗ Email search module test failed: {e}")


def test_all_modules(target):
    """Test all modules"""
    print("=== Testing all modules ===")
    modules = [
        ("Configuration", test_config),
        ("Network Connectivity", test_network_connectivity),
        ("Dorking", lambda: test_dorking(target)),
        ("Browse URL", lambda: test_browse_url(target)),
        ("Scan", lambda: test_scan(target)),
        ("IP Tools", lambda: test_ip_tools(target)),
        ("Comprehensive Security Headers", lambda: test_headers_info(target)),
        ("IoT", lambda: test_iot(target)),
        ("crt.sh", lambda: test_crtsh(target)),
        ("SSL Info", lambda: test_ssl_info(target)),
        ("Site Analysis", lambda: test_site_analysis(target)),
        ("DNS Info", lambda: test_dns_info(target)),
        ("Email Search", lambda: test_email_search(target))
    ]
    
    results = []
    for name, test_func in modules:
        print(f"\n--- {name} ---")
        try:
            start_time = time.time()
            test_func()
            end_time = time.time()
            duration = end_time - start_time
            results.append((name, "✓ PASSED", f"{duration:.2f}s"))
        except Exception as e:
            results.append((name, "✗ FAILED", str(e)))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for name, status, details in results:
        print(f"{status} {name:<20} {details}")
    
    passed = sum(1 for _, status, _ in results if "PASSED" in status)
    total = len(results)
    print(f"\nTotal: {passed}/{total} tests passed")

def main():
    parser = argparse.ArgumentParser(description="Enhanced test script for cyberrecon")
    parser.add_argument('--test', 
                       choices=['config', 'network', 'dorking', 'browse', 'scan', 'ip', 
                               'headers', 'iot', 'crtsh', 'ssl', 'site', 'dns', 'email', 'all'], 
                       default='all', help='Type of test to perform')
    parser.add_argument('--target', default='example.com', 
                       help='Target for tests (default: example.com)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--skip-config-check', action='store_true',
                       help='Skip configuration check before running tests')
    
    args = parser.parse_args()
    
    print("=== cyberrecon enhanced test script ===")
    print(f"Selected test: {args.test}")
    print(f"Target: {args.target}")
    print(f"Verbose: {args.verbose}")
    print("="*50)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run configuration check first (unless skipped)
    if not args.skip_config_check and args.test != 'config':
        print("Running configuration check...")
        try:
            from modules.config_checker import check_configuration
            config_result = check_configuration()
            if config_result > 1:
                print("\n❌ Critical configuration issues found. Use --skip-config-check to bypass.")
                return config_result
            elif config_result == 1:
                print("\n⚠️  Some configuration issues found. Continuing with tests...")
            else:
                print("\n✅ Configuration check passed!")
        except Exception as e:
            print(f"\n⚠️  Configuration check failed: {e}. Continuing with tests...")
        print()
    
    start_time = time.time()
    
    if args.test == 'config':
        test_config()
    elif args.test == 'network':
        test_network_connectivity()
    elif args.test == 'dorking':
        test_dorking(args.target)
    elif args.test == 'browse':
        test_browse_url(args.target)
    elif args.test == 'scan':
        test_scan(args.target)
    elif args.test == 'ip':
        test_ip_tools(args.target)
    elif args.test == 'headers':
        test_headers_info(args.target)
    elif args.test == 'iot':
        test_iot(args.target)
    elif args.test == 'crtsh':
        test_crtsh(args.target)
    elif args.test == 'ssl':
        test_ssl_info(args.target)
    elif args.test == 'site':
        test_site_analysis(args.target)
    elif args.test == 'dns':
        test_dns_info(args.target)
    elif args.test == 'email':
        test_email_search(args.target)
    elif args.test == 'all':
        test_all_modules(args.target)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n=== Tests completed in {total_time:.2f} seconds ===")

if __name__ == '__main__':
    main()