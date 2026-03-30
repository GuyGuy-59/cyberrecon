import requests
import json
import socket
import time
from .config import *
from .common_utils import base_scan_meta, save_json_result
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

def parse_jsondata(jsondata, target_domain):
    """Enhanced JSON parsing with better error handling and filtering"""
    subdomains = defaultdict(set)
    
    if not jsondata:
        return subdomains
    
    for entry in jsondata:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get('name_value') or ''
        for name in name_value.split('\n'):
            name = name.strip()
            if not name or name == target_domain:
                continue
            if '.' not in name or len(name) < 3:
                continue
            key = 'wildcard' if '*' in name else 'regular'
            subdomains[key].add(name)
    return subdomains

def request_crtsh(domain, logger, max_retries=3):
    """Enhanced crt.sh request with retry mechanism and better error handling"""
    url = f"https://crt.sh/?q={domain}&output=json"
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Requesting crt.sh data for {domain} (attempt {attempt + 1})")
            response = requests.get(
                url, 
                headers=header_default, 
                timeout=30,
                allow_redirects=True
            )
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ Retrieved {len(data)} certificates for {domain}")
            return data
            
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to get crt.sh data for {domain} after {max_retries} attempts: {e}")
                return None
            else:
                logger.warning(f"Attempt {attempt + 1} failed for {domain}, retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response for {domain}: {e}")
            return None
    
    return None

def log_subdomain_address(subdomain, logger):
    """Enhanced subdomain IP resolution with better error handling"""
    try:
        ip_address = socket.gethostbyname(subdomain)
        return subdomain, ip_address
    except socket.gaierror:
        return subdomain, None
    except Exception as e:
        logger.warning(f"Error resolving {subdomain}: {e}")
        return subdomain, None

def process_domain(domain, logger):
    """Enhanced domain processing with better error handling"""
    jsondata = request_crtsh(domain, logger)
    return parse_jsondata(jsondata, domain) if jsondata else defaultdict(set)

def save_subdomain_results(victim, subdomains, subdomain_ips, logger):
    """Save subdomain results to file"""
    results_data = {
        **base_scan_meta(victim),
        'total_regular_subdomains': len(subdomains['regular']),
        'total_wildcard_subdomains': len(subdomains['wildcard']),
        'regular_subdomains': list(subdomains['regular']),
        'wildcard_subdomains': list(subdomains['wildcard']),
        'subdomain_ips': subdomain_ips,
    }
    save_json_result(
        victim,
        "crtsh_subdomains.json",
        results_data,
        logger,
        "crt.sh subdomain results",
        indent=2,
    )

def crtsh(victim, logger):
    """Enhanced crt.sh subdomain enumeration with better error handling and progress tracking"""
    logger.info(f"Starting crt.sh subdomain enumeration for: {victim}")
    
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Get initial subdomains
            logger.info("Fetching initial subdomain data...")
            initial_future = executor.submit(process_domain, victim, logger)
            subdomains = initial_future.result()
            
            if not subdomains['regular'] and not subdomains['wildcard']:
                logger.info(f"No subdomains found for {victim}")
                return
            
            logger.info(f"Found {len(subdomains['regular'])} regular and {len(subdomains['wildcard'])} wildcard subdomains")
            
            # Process wildcard subdomains
            if subdomains['wildcard']:
                logger.info("Processing wildcard subdomains...")
                wildcard_futures = [
                    executor.submit(process_domain, wildcardsubdomain.replace('*.', '%25.'), logger)
                    for wildcardsubdomain in subdomains['wildcard']
                ]
                
                for future in as_completed(wildcard_futures):
                    try:
                        result = future.result()
                        for subdomain_type, subdomains_set in result.items():
                            subdomains[subdomain_type].update(subdomains_set)
                    except Exception as e:
                        logger.warning(f"Error processing wildcard subdomain: {e}")
            
            # Resolve IP addresses for all subdomains
            all_subdomains = subdomains['regular'].union(subdomains['wildcard'])
            logger.info(f"Resolving IP addresses for {len(all_subdomains)} subdomains...")
            
            address_futures = [
                executor.submit(log_subdomain_address, subdomain, logger) 
                for subdomain in all_subdomains
            ]
            
            subdomain_ips = {}
            resolved_count = 0
            
            for future in as_completed(address_futures):
                try:
                    subdomain, ip = future.result()
                    if ip:
                        subdomain_ips[subdomain] = ip
                        resolved_count += 1
                except Exception as e:
                    logger.warning(f"Error resolving subdomain: {e}")
            
            logger.info(f"Resolved {resolved_count}/{len(all_subdomains)} subdomains")
        
        # Save results
        save_subdomain_results(victim, subdomains, subdomain_ips, logger)
        
        # Display results
        logger.info(f"\n--- Subdomain Enumeration Results for {victim} ---")
        logger.info(f"Regular subdomains: {len(subdomains['regular'])}")
        logger.info(f"Wildcard subdomains: {len(subdomains['wildcard'])}")
        logger.info(f"Resolved IPs: {len(subdomain_ips)}")
        
        # Show some examples
        if subdomains['regular']:
            logger.info("\nSample regular subdomains:")
            for subdomain in sorted(subdomains['regular'])[:10]:
                ip = subdomain_ips.get(subdomain, "IP not found")
                logger.info(f"  - {subdomain}: {ip}")
        
        if subdomains['wildcard']:
            logger.info("\nSample wildcard subdomains:")
            for subdomain in sorted(subdomains['wildcard'])[:5]:
                logger.info(f"  - {subdomain}")
        
    except Exception as e:
        logger.error(f"Error in crt.sh enumeration: {e}")


def run(victim, logger):
    """Entry point: certificate transparency subdomain enumeration."""
    return crtsh(victim, logger)
