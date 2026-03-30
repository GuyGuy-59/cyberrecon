import requests
import json
import time
import os
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .config import *
from .common_utils import base_scan_meta, save_json_result, scan_timestamp
from .run_utils import run_safe_steps


def request_victim(url, logger, timeout=15, max_retries=3):
    for attempt in range(max_retries):
        try:
            r = requests.get(
                url,
                headers=header_default,
                timeout=timeout,
                allow_redirects=True,
            )
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                logger.error(f"Request error {e} for URL {url}")
            else:
                time.sleep(2 ** attempt)
    return None

def whatcms(victim, logger):
    """Enhanced CMS detection with better error handling and multiple URL attempts"""
    logger.info(f"Starting CMS detection for: {victim}")
    
    # Try different URL formats
    urls_to_try = [
        f"https://whatcms.org/APIEndpoint/Detect?key={whatcms_api_key}&url={victim}",
        f"https://whatcms.org/APIEndpoint/Detect?key={whatcms_api_key}&url=https://{victim}",
        f"https://whatcms.org/APIEndpoint/Detect?key={whatcms_api_key}&url=http://{victim}"
    ]
    
    whatcms_details = None
    
    for url in urls_to_try:
        try:
            logger.info(f"Trying WhatCMS API: {url}")
            response = requests.get(url, headers=header_default, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            whatcms_response = data.get('result', {})
            
            if whatcms_response.get('name') and whatcms_response.get('name') != 'Unknown':
                # Extracting data into a dictionary for easier handling
                whatcms_details = {
                    'name': whatcms_response.get('name', 'Unknown'),
                    'code': whatcms_response.get('code', 'Unknown'),
                    'confidence': whatcms_response.get('confidence', 0),
                    'cms_url': whatcms_response.get('cms_url', 'Unknown'),
                    'version': whatcms_response.get('version', 'Unknown'),
                    'msg': whatcms_response.get('msg', 'No message'),
                    'request_web': data.get('request', 'No request data'),
                    'api_url': url,
                    'scan_date': scan_timestamp()
                }
                logger.info(f"✓ CMS detected: {whatcms_details['name']}")
                break
            else:
                logger.warning(f"No CMS detected for URL: {url}")
                
        except requests.RequestException as e:
            logger.warning(f"Error with WhatCMS API {url}: {e}")
            continue
        except json.JSONDecodeError as e:
            logger.warning(f"Error parsing WhatCMS response: {e}")
            continue
    
    if not whatcms_details:
        logger.warning("No CMS detected with any URL format")
        whatcms_details = {
            'name': 'Unknown',
            'code': 'Unknown',
            'confidence': 0,
            'cms_url': 'Unknown',
            'version': 'Unknown',
            'msg': 'No CMS detected',
            'request_web': 'No request data',
            'api_url': 'None',
            'scan_date': scan_timestamp()
        }
    
    save_json_result(victim, "whatcms.json", whatcms_details, logger, "WhatCMS results")

    # Display results in a readable format
    logger.info(f"\n--- CMS Detection Results for {victim} ---")
    logger.info(f"Status Code: {whatcms_details['code']}")
    logger.info(f"Response Message: {whatcms_details['msg']}")
    logger.info(f"CMS: {whatcms_details['name']}")
    logger.info(f"CMS Version: {whatcms_details['version']}")
    logger.info(f"CMS Confidence: {whatcms_details['confidence']}")
    logger.info(f"CMS URL: {whatcms_details['cms_url']}")

    return whatcms_details


def run(victim, logger):
    """Entry point: WhatCMS, Wappalyzer stack detection, and WAF fingerprinting."""
    details = whatcms(victim, logger)
    victim_url = f"https://{victim}"
    run_safe_steps(
        logger,
        [
            ("Wappalyzer technology detection", find_techs, (victim_url, logger)),
            ("WAF detection", wafDetector, (victim, victim_url, logger)),
        ],
    )
    return details

def Get_Wappalyzer_Credit(logger):
    """Enhanced Wappalyzer credit check with better error handling"""
    try:
        credits_url = "https://api.wappalyzer.com/v2/credits/balance/"
        headers = header_default.copy()
        headers.update({"x-api-key": wappalyzer_api_key})
        
        response = requests.get(credits_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        respcred = response.json()
        
        if respcred.get('message') == "Forbidden":
            logger.error("Wappalyzer API access forbidden - check API key")
            return False
        else:
            credits = respcred.get('credits', 0)
            logger.info(f"Wappalyzer credits remaining: {credits}/50")
            
            if credits == 0:
                logger.warning("No Wappalyzer credits remaining")
                return False
            else:
                return True
                
    except requests.RequestException as e:
        logger.error(f"Error checking Wappalyzer credits: {e}")
        return False
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Wappalyzer credit response: {e}")
        return False

def request_api(victim, logger):
    """Enhanced Wappalyzer API request with better error handling"""
    try:
        api_url = f"https://api.wappalyzer.com/lookup/v2/?urls={victim}"
        headers = header_default.copy()
        headers.update({'x-api-key': wappalyzer_api_key})
        
        logger.info(f"Requesting Wappalyzer analysis for: {victim}")
        result = requests.get(api_url, headers=headers, timeout=30)
        result.raise_for_status()
        
        results = result.json()
        logger.info("✓ Wappalyzer analysis completed")
        return results
        
    except requests.RequestException as e:
        logger.error(f"Error requesting Wappalyzer API: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Wappalyzer response: {e}")
        return None

def Tech_Version(results_json, logger):
    """Enhanced technology parsing with better error handling"""
    try:
        if not results_json or len(results_json) == 0:
            logger.warning("No Wappalyzer results to process")
            return []
        
        technologies = results_json[0].get('technologies', [])
        if not technologies:
            logger.warning("No technologies found in Wappalyzer results")
            return []
        
        Data = []
        for techno in technologies:
            try:
                technology = techno.get('name', 'Unknown')
                versions = techno.get('versions', [])
                version = ', '.join(versions).replace(" ", "+") if versions else ''
                categories = [category.get('name', 'Unknown') for category in techno.get('categories', [])]
                
                tech_info = {
                    "technology": technology,
                    "version": version,
                    "categories": categories
                }
                Data.append(tech_info)
            except Exception as e:
                logger.warning(f"Error processing technology: {e}")
                continue
        
        return Data
        
    except Exception as e:
        logger.error(f"Error parsing Wappalyzer technologies: {e}")
        return []

def find_techs(victim_url, logger):
    """Enhanced technology detection with comprehensive error handling and results saving"""
    logger.info(f"Starting technology detection for: {victim_url}")
    
    if not Get_Wappalyzer_Credit(logger):
        logger.error("Cannot proceed with technology detection - no Wappalyzer credits")
        return None
    
    results_json = request_api(victim_url, logger)
    if not results_json:
        logger.error("Failed to get Wappalyzer results")
        return None
    
    TechVersionList = Tech_Version(results_json, logger)
    
    if not TechVersionList:
        logger.warning("No technologies detected")
        return None
    
    host = urlparse(victim_url).netloc or victim_url.replace("https://", "").replace("http://", "").split("/")[0]
    tech_results = {
        **base_scan_meta(victim_url),
        'total_technologies': len(TechVersionList),
        'technologies': TechVersionList,
    }
    save_json_result(host, "wappalyzer_technologies.json", tech_results, logger, "Wappalyzer technologies")

    # Display results
    logger.info(f"\n--- Technology Detection Results for {victim_url} ---")
    logger.info(f"Total technologies detected: {len(TechVersionList)}")
    
    for i, tech in enumerate(TechVersionList, 1):
        logger.info(f"{i}. {tech['technology']} - {tech['version']} ({', '.join(tech['categories'])})")
    
    return TechVersionList
		
def calculate_waf_score(page, code, headers, cookie, wafsign):
    """Calculate WAF detection score based on signatures"""
    score = 0
    try:
        if wafsign.get("page") and re.search(wafsign["page"], page, re.I):
            score += 1
        if wafsign.get("code") and re.search(wafsign["code"], code, re.I):
            score += 0.5
        if wafsign.get("headers") and re.search(wafsign["headers"], headers, re.I):
            score += 1
        if wafsign.get("cookie") and re.search(wafsign["cookie"], cookie, re.I):
            score += 1
    except Exception:
        pass
    return score

def wafDetector(victim, victim_url, logger):
    """Enhanced WAF detection with better error handling and comprehensive reporting"""
    logger.info(f"Starting WAF detection for: {victim}")
    
    # Fetch WAF signatures from a remote JSON file
    waf_signatures_urls = [
        "https://raw.githubusercontent.com/oakkaya/AORT/732e76f11268470612b556a15c849c6b5ce02142/utils/wafsign.json",
        "https://raw.githubusercontent.com/D3Ext/AORT/main/utils/wafsign.json"
    ]
    
    wafsigns = None
    for url in waf_signatures_urls:
        try:
            logger.info(f"Downloading WAF signatures from: {url}")
            response = requests.get(url, headers=header_default, timeout=30)
            response.raise_for_status()
            wafsigns = response.json()
            logger.info("✓ WAF signatures downloaded successfully")
            break
        except requests.RequestException as e:
            logger.warning(f"Failed to download WAF signatures from {url}: {e}")
            continue
    
    if not wafsigns:
        logger.error("Failed to download WAF signatures from any source")
        return None
    
    # Test WAF with payload
    test_url = f"{victim_url}/{payload_WAF}"
    logger.info(f"Testing WAF with payload URL: {test_url}")
    
    result = request_victim(test_url, logger)
    if not result:
        logger.error("Failed to test WAF - no response received")
        return None

    code = str(result.status_code)
    page = result.text
    headers = str(result.headers)
    cookie = str(result.cookies.get_dict())

    # Analyze response for WAF signatures
    waf_results = {
        **base_scan_meta(victim),
        'test_url': test_url,
        'response_code': result.status_code,
        'waf_detected': False,
        'waf_name': None,
        'confidence_score': 0,
        'max_possible_score': 3.5
    }

    # Check if WAF has blocked the request
    if result.status_code >= 400:
        logger.info(f"Response code {result.status_code} indicates potential WAF blocking")
        
        best_match = {'score': 0, 'name': None}
        for wafname, wafsign in wafsigns.items():
            try:
                score = calculate_waf_score(page, code, headers, cookie, wafsign)
                if score > best_match['score']:
                    best_match = {'score': score, 'name': wafname}
            except Exception as e:
                logger.warning(f"Error processing WAF signature {wafname}: {e}")
                continue

        if best_match['score'] > 0:
            waf_results['waf_detected'] = True
            waf_results['waf_name'] = best_match['name']
            waf_results['confidence_score'] = best_match['score']
            
            logger.info(f"✓ WAF detected: {best_match['name']}")
            logger.info(f"Confidence score: {best_match['score']}/3.5")
        else:
            logger.info("No WAF signatures matched - WAF not detected or unknown")
    else:
        logger.info(f"Response code {result.status_code} - no WAF blocking detected")
    
    save_json_result(victim, "waf_detection.json", waf_results, logger, "WAF detection results")

    # Display results
    logger.info(f"\n--- WAF Detection Results for {victim} ---")
    if waf_results['waf_detected']:
        logger.info(f"WAF Detected: {waf_results['waf_name']}")
        logger.info(f"Confidence: {waf_results['confidence_score']}/{waf_results['max_possible_score']}")
    else:
        logger.info("No WAF detected")
    
    logger.info(f"Response Code: {waf_results['response_code']}")
    
    return waf_results
   