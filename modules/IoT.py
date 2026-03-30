from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import requests
import json

from .config import *
from .common_utils import (
    SKIP_RESOLUTION_FAILED,
    base_scan_meta,
    resolve_host_to_ip,
    save_json_result,
)
def make_api_request(url, headers=None, auth=None, timeout=30, max_retries=3):
    """Enhanced API request function with retry mechanism and better error handling"""
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url, 
                headers=headers, 
                auth=auth, 
                timeout=timeout,
                allow_redirects=True
            )
            response.raise_for_status()
            return response
        except requests.RequestException:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None


def handle_error(error_type, status_code, response_text=None, logger=None):
    """Enhanced error handling with better logging"""
    error_msg = f"{error_type} API error: {status_code}"
    if logger:
        logger.error(error_msg)
    else:
        print(error_msg)
    
    if response_text:
        try:
            error_data = json.loads(response_text) if isinstance(response_text, str) else response_text
            if logger:
                logger.error(f"Error details: {json.dumps(error_data, indent=2)}")
            else:
                print(json.dumps(error_data, indent=4))
        except:
            if logger:
                logger.error(f"Raw error response: {response_text}")
            else:
                print(response_text)

def device_shodan(victim, victim_ip, logger):
    """Enhanced Shodan device lookup with better error handling and parallel processing"""
    logger.info(f"Starting Shodan lookup for {victim} ({victim_ip})")
    
    endpoints = {
        'ip': {
            'path': '/shodan/host/',
            'target': victim_ip,
            'description': 'IP information'
        },
        'domain': {
            'path': '/dns/domain/',
            'target': victim,
            'description': 'Subdomains and DNS entries'
        }
    }
    
    results = {}
    
    def process_endpoint(key, endpoint_info):
        try:
            url = f"https://api.shodan.io{endpoint_info['path']}{endpoint_info['target']}?key={shodan_api_key}"
            logger.info(f"Querying Shodan {endpoint_info['description']}...")
            
            response = make_api_request(url, headers=header_default)
            
            if response and response.status_code == 200:
                data = response.json()
                results[key] = data
                
                save_json_result(
                    victim,
                    f"shodan_{key}.json",
                    data,
                    logger,
                    f"Shodan {key}",
                )
                
                logger.info(f"✓ Shodan {endpoint_info['description']} lookup successful")
                return True
            else:
                status_code = response.status_code if response else "No response"
                handle_error("shodan", status_code, response.text if response else None, logger)
                return False
                
        except Exception as e:
            logger.error(f"Error in Shodan {endpoint_info['description']} lookup: {e}")
            return False
    
    # Process endpoints in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(process_endpoint, key, endpoint_info): key 
            for key, endpoint_info in endpoints.items()
        }
        
        for future in as_completed(futures):
            key = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing Shodan {key}: {e}")
    
    if results:
        save_json_result(
            victim,
            "shodan_combined.json",
            {**base_scan_meta(victim), "target_ip": victim_ip, "results": results},
            logger,
            "Shodan combined",
        )

    return results

def urlscanio(victim, logger):
    """Enhanced urlscan.io lookup with better error handling"""
    logger.info(f"Starting urlscan.io lookup for {victim}")
    
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{victim}"
        response = make_api_request(url, timeout=30)
        
        if response and response.status_code == 200:
            data = response.json()
            results = [dict(item) for item in data.get('results', [])]
            
            if results:
                save_json_result(
                    victim,
                    "urlscan.json",
                    {
                        **base_scan_meta(victim),
                        "total_results": len(results),
                        "results": results,
                    },
                    logger,
                    "urlscan.io results",
                )
                
                logger.info(f"✓ Found {len(results)} urlscan.io results for {victim}")
                
                # Log some key findings
                for i, result in enumerate(results[:5]):  # Show first 5 results
                    logger.info(f"  {i+1}. {result.get('page', {}).get('url', 'Unknown URL')}")
            else:
                logger.info(f"No urlscan.io results found for {victim}")
        else:
            status_code = response.status_code if response else "No response"
            handle_error("urlscan", status_code, response.text if response else None, logger)
            
    except Exception as e:
        logger.error(f"Error in urlscan.io lookup: {e}")

def device_censys(victim, logger):
    """Enhanced Censys lookup with better error handling"""
    logger.info(f"Starting Censys lookup for {victim}")
    
    try:
        url = f"https://search.censys.io/api/v2/hosts/search?q={victim}"
        response = make_api_request(
            url, 
            headers=header_default, 
            auth=(censys_api_id, censys_secret),
            timeout=30
        )
        
        if response and response.status_code == 200:
            data = response.json()
            
            save_json_result(
                victim,
                "censys_hosts.json",
                {
                    **base_scan_meta(victim),
                    "total_results": data.get("result", {}).get("total", 0),
                    "results": data,
                },
                logger,
                "Censys hosts",
            )
            
            total_results = data.get('result', {}).get('total', 0)
            logger.info(f"✓ Found {total_results} Censys results for {victim}")
            
            # Log some key findings
            hits = data.get('result', {}).get('hits', [])
            for i, hit in enumerate(hits[:3]):  # Show first 3 results
                ip = hit.get('ip', 'Unknown IP')
                services = hit.get('services', [])
                service_names = [s.get('service_name', 'Unknown') for s in services[:3]]
                logger.info(f"  {i+1}. {ip} - Services: {', '.join(service_names)}")
                
        else:
            status_code = response.status_code if response else "No response"
            handle_error("censys", status_code, response.text if response else None, logger)
            
    except Exception as e:
        logger.error(f"Error in Censys lookup: {e}")


def run(victim, logger):
    """Entry point: Shodan, urlscan.io, and Censys (requires resolvable IPv4 for Shodan host)."""
    target_ip = resolve_host_to_ip(victim, logger)
    if not target_ip:
        return SKIP_RESOLUTION_FAILED
    device_shodan(victim, target_ip, logger)
    urlscanio(victim, logger)
    device_censys(victim, logger)
