import ssl
import socket
import requests
import time
import json
from .config import *
from .common_utils import (
    base_scan_meta_long,
    result_path,
    save_json_file,
    save_json_result,
)
from collections import OrderedDict
from bs4 import BeautifulSoup

def scanssl(victim, logger, max_wait_time=300):
    """Enhanced SSL Labs analysis with better error handling and progress tracking"""
    logger.info(f"Starting SSL Labs analysis for: {victim}")
    
    ssl_file = result_path(victim, f"ssl_{victim}.json")
    url = f'https://api.ssllabs.com/api/v3/analyze?host={victim}&ignoreMismatch=on&all=done'
    logger.info(f"Requesting SSL Labs analysis: {url}")
    
    start_time = time.time()
    attempts = 0
    
    while time.time() - start_time < max_wait_time:
        try:
            attempts += 1
            response = requests.get(url, headers=header_default, timeout=30)
            response.raise_for_status()
            
            j = response.json()
            status = j.get('status')
            
            logger.info(f"SSL Labs status: {status} (attempt {attempts})")
            
            if status == 'READY':
                logger.info('✓ SSL Labs analysis completed')
                break
            elif status == 'ERROR':
                error_msg = j.get('statusMessage', 'Unknown error')
                logger.error(f"SSL Labs analysis failed: {error_msg}")
                return None
            else:
                logger.info('SSL Labs analysis in progress, waiting...')
                time.sleep(15)
                
        except requests.RequestException as e:
            logger.error(f"Error requesting SSL Labs analysis: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing SSL Labs response: {e}")
            return None
    
    if time.time() - start_time >= max_wait_time:
        logger.error("SSL Labs analysis timed out")
        return None

    save_json_file(ssl_file, j, logger, "SSL Labs raw response")

    data = {
        **base_scan_meta_long(victim),
        'hostname': victim,
        'serverName': victim,
        'grade': 'Unknown',
        'hasWarnings': False,
        'isExceptional': False,
        'heartbleed': False,
        'vulnBeast': False,
        'poodle': False,
        'freak': False,
        'logjam': False,
        'supportsRc4': False,
        'TLS': [],
        'endpoints': [],
    }

    # Get first endpoint and its details
    if not j.get('endpoints'):
        logger.warning("No endpoints found in SSL Labs response")
        return data
        
    endpoint = j['endpoints'][0]
    details = endpoint.get('details', {})

    # Update data with endpoint info
    data.update({
        'grade': endpoint.get('grade', 'Unknown'),
        'serverName': endpoint.get('serverName', victim),
        'hasWarnings': endpoint.get('hasWarnings', False),
        'isExceptional': endpoint.get('isExceptional', False),
        'heartbleed': details.get('heartbleed', False),
        'vulnBeast': details.get('vulnBeast', False),
        'poodle': details.get('poodle', False),
        'freak': details.get('freak', False),
        'logjam': details.get('logjam', False),
        'supportsRc4': details.get('supportsRc4', False),
        'TLS': [p['version'] for p in details.get('protocols', [])],
        'endpoints': j.get('endpoints', [])
    })

    return data


def requests_analyze_TLS(victim, logger):
    """Enhanced TLS analysis with better error handling and multiple domain testing"""
    logger.info(f"Starting TLS analysis for: {victim}")
    
    data = {
        **base_scan_meta_long(victim),
        'domains_tested': [],
        'results': {},
    }
    
    base_url = "https://tls.imirhil.fr/https/"
    domains = [victim, f"www.{victim}"]
    
    for domain in domains:
        try:
            api_url = f"{base_url}{domain}"
            logger.info(f"Testing TLS for: {api_url}")
            
            response = requests.get(api_url, timeout=30, headers=header_default)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, "html.parser")
            domain_data = {'domain': domain, 'url': api_url}
            
            if "TLS seems not supported on this server" not in soup.text:
                # Get score
                score_elem = soup.find("span", class_="badge")
                domain_data["score"] = score_elem.text if score_elem else "Unknown"
                
                # Get TLS versions
                version_elems = soup.find_all("span", class_=["badge badge-state-default", "badge badge-state-error"])
                domain_data["tls_versions"] = [version.text for version in version_elems]
                
                # Get table data
                table = soup.find("table", class_="table table-bordered table-condensed table-striped center")
                if table:
                    rows = table.find_all("tr")
                    domain_data["table_data"] = [
                        [cell.text.strip() for cell in row.find_all(["th", "td"])] 
                        for row in rows
                    ]
                
                logger.info(f"✓ TLS analysis completed for {domain}")
            else:
                domain_data["error"] = "TLS not supported"
                logger.warning(f"TLS not supported for {domain}")
            
            data['domains_tested'].append(domain)
            data['results'][domain] = domain_data
            
        except Exception as e:
            logger.error(f"Error testing TLS for {domain}: {e}")
            data['results'][domain] = {'error': str(e)}
    
    return data

def analyze_Transport_Layer_Security(victim, logger):
    """Enhanced TLS/SSL analysis with comprehensive reporting"""
    logger.info(f"Starting comprehensive TLS/SSL analysis for: {victim}")
    
    # Perform TLS analysis
    data_tls_imirhil = requests_analyze_TLS(victim, logger)
    
    # Perform SSL Labs analysis
    data_ssllabs = scanssl(victim, logger)
    
    # Combine results
    combined_results = {
        **base_scan_meta_long(victim),
        'tls_analysis': data_tls_imirhil,
        'ssl_labs_analysis': data_ssllabs,
    }
    
    save_json_result(victim, "ssl_tls_analysis.json", combined_results, logger, "SSL/TLS analysis")

    # Display results in a readable format
    logger.info(f"\n--- SSL/TLS Analysis Results for {victim} ---")
    
    if data_ssllabs:
        logger.info(f"SSL Labs Grade: {data_ssllabs.get('grade', 'Unknown')}")
        logger.info(f"Has Warnings: {data_ssllabs.get('hasWarnings', False)}")
        logger.info(f"Is Exceptional: {data_ssllabs.get('isExceptional', False)}")
        
        vuln_flags = (
            ('heartbleed', 'Heartbleed'),
            ('vulnBeast', 'BEAST'),
            ('poodle', 'POODLE'),
            ('freak', 'FREAK'),
            ('logjam', 'Logjam'),
            ('supportsRc4', 'RC4 Support'),
        )
        vulnerabilities = [label for key, label in vuln_flags if data_ssllabs.get(key)]
        if vulnerabilities:
            logger.warning(f"Security vulnerabilities found: {', '.join(vulnerabilities)}")
        else:
            logger.info("✓ No major security vulnerabilities detected")
        
        # TLS versions
        tls_versions = data_ssllabs.get('TLS', [])
        if tls_versions:
            logger.info(f"Supported TLS versions: {', '.join(tls_versions)}")
    
    if data_tls_imirhil and data_tls_imirhil.get('results'):
        logger.info("\nTLS Analysis Results:")
        for domain, result in data_tls_imirhil['results'].items():
            if 'error' in result:
                logger.warning(f"  {domain}: {result['error']}")
            else:
                score = result.get('score', 'Unknown')
                tls_versions = result.get('tls_versions', [])
                logger.info(f"  {domain}: Score {score}, TLS versions: {', '.join(tls_versions)}")
    
    return combined_results


def run(victim, logger):
    """Entry point: local TLS probe + SSL Labs analysis."""
    return analyze_Transport_Layer_Security(victim, logger)