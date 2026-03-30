import dns.resolver
import requests
import time
from .config import *
from .common_utils import (
    SKIP_RESOLUTION_FAILED,
    base_scan_meta,
    resolve_host_to_ip,
    save_json_result,
)
def perform_request(url, logger, timeout=10, max_retries=3):
    """Enhanced request function with retry mechanism and better error handling"""
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url, 
                stream=False, 
                allow_redirects=True, 
                verify=False, 
                headers=header_default,
                timeout=timeout
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                logger.error(f"Request failed after {max_retries} attempts: {e}")
                return None
            else:
                logger.warning(f"Request attempt {attempt + 1} failed, retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
    return None

def iplocator(victim_ip, logger):
    """Enhanced IP location lookup with multiple sources and better data formatting"""
    logger.info(f"Looking up IP location for: {victim_ip}")
    
    # Try multiple IP geolocation services
    services = [
        {
            "name": "ipinfo.io",
            "url": f"https://ipinfo.io/{victim_ip}/json",
            "parser": parse_ipinfo_response
        },
        {
            "name": "ip-api.com",
            "url": f"http://ip-api.com/json/{victim_ip}",
            "parser": parse_ipapi_response
        }
    ]
    
    results = []
    
    for service in services:
        logger.info(f"Querying {service['name']}...")
        result = perform_request(service['url'], logger)
        
        if result:
            try:
                data = result.json()
                parsed_data = service['parser'](data)
                results.append({
                    'service': service['name'],
                    'data': parsed_data
                })
                logger.info(f"✓ {service['name']} lookup successful")
            except Exception as e:
                logger.warning(f"Failed to parse {service['name']} response: {e}")
        else:
            logger.warning(f"✗ {service['name']} lookup failed")
    
    # Save results to file
    if results:
        save_ip_results(victim_ip, results, logger)
        
        # Display results
        for result in results:
            logger.info(f"\n--- {result['service'].upper()} Results ---")
            for key, value in result['data'].items():
                logger.info(f"{key}: {value}")
    else:
        logger.error("All IP location services failed")

    if not results:
        return False

def parse_ipinfo_response(data):
    """Parse ipinfo.io response"""
    return {
        "IP": data.get('ip', 'Unknown'),
        "City": data.get('city', 'Unknown'),
        "Region": data.get('region', 'Unknown'),
        "Country": data.get('country', 'Unknown'),
        "Location": data.get('loc', 'Unknown'),
        "Organization": data.get('org', 'Unknown'),
        "Postal": data.get('postal', 'Unknown'),
        "Timezone": data.get('timezone', 'Unknown')
    }

def parse_ipapi_response(data):
    """Parse ip-api.com response"""
    return {
        "IP": data.get('query', 'Unknown'),
        "City": data.get('city', 'Unknown'),
        "Region": data.get('regionName', 'Unknown'),
        "Country": data.get('country', 'Unknown'),
        "Location": f"{data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}",
        "Organization": data.get('org', 'Unknown'),
        "ISP": data.get('isp', 'Unknown'),
        "Timezone": data.get('timezone', 'Unknown'),
        "Status": data.get('status', 'Unknown')
    }

def save_ip_results(victim_ip, results, logger):
    """Save IP lookup results to file"""
    save_json_result(
        victim_ip,
        "ip_location_results.json",
        {**base_scan_meta(victim_ip), "results": results},
        logger,
        "IP location results",
        indent=2,
    )

def revert_ip(victim_ip):
    """Reverse IP address for DNS lookups"""
    return '.'.join(victim_ip.split('.')[::-1])

def spamcop_test(victim_ip, logger):
    """Enhanced SpamCop blacklist check with better error handling"""
    logger.info(f"Checking {victim_ip} against SpamCop blacklist...")
    
    reversed_victim_ip = revert_ip(victim_ip)
    query = f"{reversed_victim_ip}.bl.spamcop.net"
    
    try:
        # Set timeout for DNS query
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        answers = resolver.resolve(query, 'A')
        
        if answers:
            logger.warning(f"⚠️  {victim_ip} IS LISTED in SpamCop blacklist")
            for answer in answers:
                logger.info(f"Blacklist entry: {answer}")
            return True
        else:
            logger.info(f"✓ {victim_ip} is NOT listed in SpamCop blacklist")
            return False
            
    except dns.resolver.NXDOMAIN:
        logger.info(f"✓ {victim_ip} is NOT listed in SpamCop blacklist")
        return False
    except dns.resolver.Timeout:
        logger.error(f"DNS query timeout for {victim_ip}")
        return None
    except dns.exception.DNSException as e:
        logger.error(f"DNS query failed for {victim_ip}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during SpamCop check: {e}")
        return None


def run(victim, logger):
    """Entry point: geolocation, SpamCop, and related IP intelligence."""
    target_ip = resolve_host_to_ip(victim, logger)
    if not target_ip:
        return SKIP_RESOLUTION_FAILED
    iplocator(target_ip, logger)
    spamcop_test(target_ip, logger)
