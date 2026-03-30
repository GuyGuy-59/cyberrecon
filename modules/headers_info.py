import requests
import json
import os
import time
import logging
from .config import *
from .common_utils import base_scan_meta_long, save_json_result
from collections import OrderedDict
from bs4 import BeautifulSoup

def fetch_soup(victim_url, headers, max_retries=3):
    """Enhanced fetch function with retry mechanism and error handling"""
    for attempt in range(max_retries):
        try:
            response = requests.get(
                victim_url, 
                headers=headers, 
                timeout=15,
                allow_redirects=True
            )
            response.raise_for_status()
            return BeautifulSoup(response.text, "html.parser")
        except requests.RequestException:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None

def parse_table_data(soup, title):
    """Enhanced table parsing with better error handling"""
    try:
        report_body = soup.find("div", class_="reportTitle", text=title)
        if not report_body:
            return []
        
        next_div = report_body.find_next_sibling("div")
        if not next_div:
            return []
            
        report_th = [x.text.strip() for x in next_div.select("table tbody tr th")]
        report_td = [x.text.strip() for x in next_div.select("table tbody tr td")]
        
        if len(report_th) != len(report_td):
            return []
            
        return zip(report_th, report_td)
    except (AttributeError, IndexError) as e:
        return []

def _table_cell_after_label(soup, label_text):
    try:
        th = soup.find("th", class_="tableLabel", text=label_text)
        return th.find_next_sibling("td").text.strip() if th else "Unknown"
    except (AttributeError, IndexError):
        return "Unknown"


def extract_data(soup):
    try:
        score_elem = soup.find("div", class_="score")
        score = score_elem.text.strip() if score_elem else "Unknown"
    except (AttributeError, IndexError):
        score = "Unknown"
    return {
        "ip": _table_cell_after_label(soup, "IP Address:"),
        "site": _table_cell_after_label(soup, "Site:"),
        "score": score,
    }

def parse_headers(soup):
    """Enhanced header parsing with better error handling"""
    headers = OrderedDict()
    
    try:
        # Parse Raw Headers Report Table
        raw_headers_data = parse_table_data(soup, "Raw Headers")
        headers.update({header: {"rating": "info", "value": value} for header, value in raw_headers_data})

        # Parse ratings from badges
        headers_elem = soup.find("th", class_="tableLabel", text="Headers:")
        if headers_elem:
            next_td = headers_elem.find_next_sibling("td")
            if next_td:
                raw_headers = next_td.find_all("li")
                for raw_header in raw_headers:
                    if raw_header.get("class"):
                        rating = "good" if "pill-green" in raw_header["class"] else "bad"
                        headers.setdefault(raw_header.text, {})["rating"] = rating

        # Parse Missing Headers Report Table
        missing_headers_data = parse_table_data(soup, "Missing Headers")
        headers.update({header: {"description": value} for header, value in missing_headers_data})

        # Parse Additional Information Report Table
        additional_info_data = parse_table_data(soup, "Additional Information")
        headers.update({header: {"description": value} for header, value in additional_info_data})

    except Exception as e:
        # Log error but continue processing
        pass
    
    return headers

def requests_analyze_headers(victim, logger):
    """Enhanced header analysis with better error handling and multiple attempts"""
    logger.info(f"Analyzing security headers for: {victim}")
    
    # Try different URL formats
    urls_to_try = [
        f"https://securityheaders.io/?q={victim}&hide=on&followRedirects=on",
        f"https://securityheaders.io/?q=https://{victim}&hide=on&followRedirects=on",
        f"https://securityheaders.io/?q=http://{victim}&hide=on&followRedirects=on"
    ]
    
    for url in urls_to_try:
        try:
            logger.info(f"Trying URL: {url}")
            soup = fetch_soup(url, header_default)
            
            if soup and "Sorry about that..." not in soup.get_text():
                data = extract_data(soup)
                data["headers"] = parse_headers(soup)
                data["analysis_url"] = url
                data.update(base_scan_meta_long(victim))
                return data
            else:
                logger.warning(f"Analysis failed for URL: {url}")
                
        except Exception as e:
            logger.warning(f"Error analyzing {url}: {e}")
            continue
    
    # Return empty data if all attempts failed
    return {
        **base_scan_meta_long(victim),
        "ip": "Unknown",
        "site": victim,
        "score": "Unknown",
        "headers": {},
        "error": "All analysis attempts failed",
    }

def analyze_headers(victim, logger):
    """Enhanced header analysis with file saving and better logging"""
    logger.info(f"Starting security headers analysis for: {victim}")
    
    data = requests_analyze_headers(victim, logger)
    
    save_json_result(
        victim,
        "security_headers_analysis.json",
        data,
        logger,
        "Security headers analysis",
        sort_keys=True,
    )

    # Log results in a more readable format
    logger.info(f"\n--- Security Headers Analysis for {victim} ---")
    logger.info(f"IP Address: {data.get('ip', 'Unknown')}")
    logger.info(f"Site: {data.get('site', 'Unknown')}")
    logger.info(f"Security Score: {data.get('score', 'Unknown')}")
    
    if data.get('headers'):
        logger.info("\nHeaders Analysis:")
        for header, info in data['headers'].items():
            rating = info.get('rating', 'info')
            value = info.get('value', '')
            description = info.get('description', '')
            
            status_icon = "✓" if rating == "good" else "✗" if rating == "bad" else "ℹ"
            logger.info(f"  {status_icon} {header}: {value}")
            if description:
                logger.info(f"    Description: {description}")
    else:
        logger.warning("No headers information available")
    
    return data

# ============================================================================
# HTTP Observatory Integration
# ============================================================================

def make_observatory_request(url, max_retries=3, timeout=30):
    """
    Make HTTP request with retry mechanism for HTTP Observatory
    
    Args:
        url (str): URL to request
        max_retries (int): Maximum number of retries
        timeout (int): Request timeout in seconds
        
    Returns:
        requests.Response: Response object or None if failed
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                headers=header_default,
                timeout=timeout,
                allow_redirects=True,
                verify=False
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logging.error(f"Failed to get {url} after {max_retries} attempts: {e}")
                return None

def analyze_http_observatory(target, logger):
    """
    Analyze target using Mozilla HTTP Observatory
    
    Args:
        target (str): Target domain or IP
        logger: Logger instance
    """
    logger.info(f"Starting HTTP Observatory analysis for: {target}")
    
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    # HTTP Observatory API endpoint
    api_url = "https://http-observatory.security.mozilla.org/api/v1/analyze"
    
    # Prepare request data
    data = {
        'host': target.replace('https://', '').replace('http://', ''),
        'hidden': 'true',
        'rescan': 'false'
    }
    
    try:
        logger.info(f"Submitting {target} to HTTP Observatory...")
        
        # Submit scan request
        response = requests.post(
            api_url,
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        
        scan_data = response.json()
        
        if 'error' in scan_data:
            logger.error(f"HTTP Observatory error: {scan_data['error']}")
            return None
        
        # Check for HTTP errors
        if response.status_code != 200:
            logger.error(f"HTTP Observatory API returned status {response.status_code}: {response.text}")
            return None
        
        # Wait for scan to complete
        scan_id = scan_data.get('scan_id')
        if not scan_id:
            logger.error("No scan ID returned from HTTP Observatory")
            return None
        
        logger.info(f"Scan submitted with ID: {scan_id}")
        logger.info("Waiting for scan to complete...")
        
        # Poll for results
        max_wait_time = 300  # 5 minutes
        wait_time = 0
        poll_interval = 10
        
        while wait_time < max_wait_time:
            time.sleep(poll_interval)
            wait_time += poll_interval
            
            # Check scan status
            status_url = f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={data['host']}"
            status_response = make_observatory_request(status_url)
            
            if not status_response:
                logger.error("Failed to get scan status")
                return None
            
            status_data = status_response.json()
            
            if status_data.get('state') == 'FINISHED':
                logger.info("✓ HTTP Observatory scan completed")
                break
            elif status_data.get('state') == 'FAILED':
                logger.error("✗ HTTP Observatory scan failed")
                return None
            else:
                logger.info(f"Scan in progress... (state: {status_data.get('state', 'UNKNOWN')})")
        
        if wait_time >= max_wait_time:
            logger.warning("⚠ HTTP Observatory scan timed out")
            return None
        
        # Get detailed results
        results_url = f"https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan={scan_id}"
        results_response = make_observatory_request(results_url)
        
        if not results_response:
            logger.error("Failed to get scan results")
            return None
        
        results_data = results_response.json()
        
        # Process and return results
        return process_observatory_results(target, results_data, logger)
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 502:
            logger.error("HTTP Observatory API is temporarily unavailable (502 Bad Gateway)")
            logger.info("Please try again later or check https://http-observatory.security.mozilla.org/")
        else:
            logger.error(f"HTTP Observatory API error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error connecting to HTTP Observatory: {e}")
        return None
    except Exception as e:
        logger.error(f"HTTP Observatory analysis failed: {e}")
        return None

def process_observatory_results(target, results, logger):
    """
    Process HTTP Observatory results
    
    Args:
        target (str): Target domain
        results (dict): Observatory results
        logger: Logger instance
        
    Returns:
        dict: Processed observatory data
    """
    try:
        # Extract key information
        score = results.get('score', 'N/A')
        grade = results.get('grade', 'N/A')
        state = results.get('state', 'N/A')
        
        # Get test results
        tests = results.get('tests', {})
        
        # Create structured results
        observatory_data = {
            **base_scan_meta_long(target),
            'scan_info': {
                'score': score,
                'grade': grade,
                'state': state,
                'scan_id': results.get('scan_id'),
                'host': results.get('host')
            },
            'tests': {},
            'summary': {
                'total_tests': len(tests),
                'passed_tests': 0,
                'failed_tests': 0,
                'warnings': 0
            }
        }
        
        # Process individual tests
        for test_name, test_data in tests.items():
            if isinstance(test_data, dict):
                test_result = {
                    'score': test_data.get('score', 0),
                    'score_description': test_data.get('score_description', ''),
                    'pass': test_data.get('pass', False),
                    'expectation': test_data.get('expectation', ''),
                    'output': test_data.get('output', {}),
                    'description': test_data.get('description', '')
                }
                
                observatory_data['tests'][test_name] = test_result
                
                # Update summary
                if test_result['pass']:
                    observatory_data['summary']['passed_tests'] += 1
                else:
                    observatory_data['summary']['failed_tests'] += 1
                    
                if test_result['score'] < 0:
                    observatory_data['summary']['warnings'] += 1
        
        return observatory_data
        
    except Exception as e:
        logger.error(f"Failed to process HTTP Observatory results: {e}")
        return None

def get_security_recommendations(observatory_data):
    """
    Generate security recommendations based on HTTP Observatory test results
    
    Args:
        observatory_data (dict): Observatory results data
        
    Returns:
        list: List of security recommendations
    """
    recommendations = []
    tests = observatory_data.get('tests', {})
    
    # Check for common security issues
    if not tests.get('content-security-policy', {}).get('pass', False):
        recommendations.append("Implement Content Security Policy (CSP) to prevent XSS attacks")
    
    if not tests.get('strict-transport-security', {}).get('pass', False):
        recommendations.append("Enable HTTP Strict Transport Security (HSTS) for HTTPS enforcement")
    
    if not tests.get('x-frame-options', {}).get('pass', False):
        recommendations.append("Add X-Frame-Options header to prevent clickjacking attacks")
    
    if not tests.get('x-content-type-options', {}).get('pass', False):
        recommendations.append("Add X-Content-Type-Options: nosniff to prevent MIME sniffing")
    
    if not tests.get('referrer-policy', {}).get('pass', False):
        recommendations.append("Implement Referrer-Policy to control referrer information")
    
    if not tests.get('permissions-policy', {}).get('pass', False):
        recommendations.append("Add Permissions-Policy header to control browser features")
    
    if not tests.get('subresource-integrity', {}).get('pass', False):
        recommendations.append("Implement Subresource Integrity (SRI) for external resources")
    
    if not tests.get('cookies', {}).get('pass', False):
        recommendations.append("Review cookie security settings (Secure, HttpOnly, SameSite)")
    
    if not tests.get('redirection', {}).get('pass', False):
        recommendations.append("Ensure proper HTTP to HTTPS redirection")
    
    if not tests.get('hpkp', {}).get('pass', False):
        recommendations.append("Consider implementing HTTP Public Key Pinning (HPKP) or Certificate Transparency")
    
    return recommendations

def analyze_security_headers_comprehensive(victim, logger):
    """
    Comprehensive security headers analysis combining Security Headers and HTTP Observatory
    
    Args:
        victim (str): Target domain or IP
        logger: Logger instance
        
    Returns:
        dict: Combined security analysis results
    """
    logger.info(f"Starting comprehensive security headers analysis for: {victim}")
    
    # Initialize combined results
    combined_results = {
        **base_scan_meta_long(victim),
        'security_headers': None,
        'http_observatory': None,
        'combined_score': None,
        'recommendations': [],
        'summary': {
            'security_headers_available': False,
            'observatory_available': False,
            'overall_security_grade': 'Unknown'
        }
    }
    
    # 1. Run Security Headers analysis
    logger.info("Running Security Headers analysis...")
    try:
        security_headers_data = analyze_headers(victim, logger)
        if security_headers_data and 'error' not in security_headers_data:
            combined_results['security_headers'] = security_headers_data
            combined_results['summary']['security_headers_available'] = True
            logger.info("✓ Security Headers analysis completed")
        else:
            logger.warning("Security Headers analysis failed or returned no data")
    except Exception as e:
        logger.error(f"Security Headers analysis failed: {e}")
    
    # 2. Run HTTP Observatory analysis
    logger.info("Running HTTP Observatory analysis...")
    try:
        observatory_data = analyze_http_observatory(victim, logger)
        if observatory_data:
            combined_results['http_observatory'] = observatory_data
            combined_results['summary']['observatory_available'] = True
            logger.info("✓ HTTP Observatory analysis completed")
        else:
            logger.warning("HTTP Observatory analysis failed or returned no data")
    except Exception as e:
        logger.error(f"HTTP Observatory analysis failed: {e}")
    
    # 3. Calculate combined score and grade
    combined_results['combined_score'] = calculate_combined_security_score(combined_results)
    combined_results['summary']['overall_security_grade'] = get_overall_security_grade(combined_results['combined_score'])
    
    # 4. Generate comprehensive recommendations
    combined_results['recommendations'] = generate_comprehensive_recommendations(combined_results)
    
    # 5. Save combined results
    save_comprehensive_results(victim, combined_results, logger)
    
    # 6. Display comprehensive summary
    display_comprehensive_summary(victim, combined_results, logger)
    
    return combined_results

def calculate_combined_security_score(results):
    """
    Calculate a combined security score from both analyses
    
    Args:
        results (dict): Combined analysis results
        
    Returns:
        dict: Combined scoring information
    """
    combined_score = {
        'security_headers_score': None,
        'observatory_score': None,
        'combined_score': None,
        'grade': 'Unknown'
    }
    
    # Extract Security Headers score
    if results['security_headers'] and 'score' in results['security_headers']:
        try:
            sh_score = results['security_headers']['score']
            if sh_score != 'Unknown' and sh_score != 'N/A':
                combined_score['security_headers_score'] = int(sh_score)
        except (ValueError, TypeError):
            pass
    
    # Extract HTTP Observatory score
    if results['http_observatory'] and 'scan_info' in results['http_observatory']:
        try:
            obs_score = results['http_observatory']['scan_info']['score']
            if obs_score != 'N/A' and obs_score is not None:
                combined_score['observatory_score'] = int(obs_score)
        except (ValueError, TypeError):
            pass
    
    # Calculate combined score
    scores = []
    if combined_score['security_headers_score'] is not None:
        scores.append(combined_score['security_headers_score'])
    if combined_score['observatory_score'] is not None:
        scores.append(combined_score['observatory_score'])
    
    if scores:
        combined_score['combined_score'] = sum(scores) / len(scores)
        
        # Determine grade based on combined score
        if combined_score['combined_score'] >= 90:
            combined_score['grade'] = 'A+'
        elif combined_score['combined_score'] >= 80:
            combined_score['grade'] = 'A'
        elif combined_score['combined_score'] >= 70:
            combined_score['grade'] = 'B'
        elif combined_score['combined_score'] >= 60:
            combined_score['grade'] = 'C'
        elif combined_score['combined_score'] >= 50:
            combined_score['grade'] = 'D'
        else:
            combined_score['grade'] = 'F'
    
    return combined_score

def get_overall_security_grade(combined_score):
    """
    Get overall security grade from combined score
    
    Args:
        combined_score (dict): Combined scoring information
        
    Returns:
        str: Overall security grade
    """
    if combined_score and combined_score.get('grade'):
        return combined_score['grade']
    return 'Unknown'

def generate_comprehensive_recommendations(results):
    """
    Generate comprehensive security recommendations from both analyses
    
    Args:
        results (dict): Combined analysis results
        
    Returns:
        list: Comprehensive recommendations
    """
    recommendations = []
    
    # Security Headers recommendations
    if results['security_headers'] and 'headers' in results['security_headers']:
        headers = results['security_headers']['headers']
        for header, info in headers.items():
            if info.get('rating') == 'bad':
                recommendations.append(f"Fix {header}: {info.get('description', 'Security issue detected')}")
    
    # HTTP Observatory recommendations
    if results['http_observatory']:
        obs_recommendations = get_security_recommendations(results['http_observatory'])
        recommendations.extend(obs_recommendations)
    
    # Remove duplicates
    return list(set(recommendations))

def save_comprehensive_results(victim, results, logger):
    """Save comprehensive security analysis results."""
    save_json_result(
        victim,
        "comprehensive_security_analysis.json",
        results,
        logger,
        "Comprehensive security analysis",
        sort_keys=True,
    )

def display_comprehensive_summary(victim, results, logger):
    """
    Display comprehensive security analysis summary
    
    Args:
        victim (str): Target domain
        results (dict): Combined results
        logger: Logger instance
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"COMPREHENSIVE SECURITY ANALYSIS: {victim}")
    logger.info(f"{'='*60}")
    
    # Overall score and grade
    combined_score = results.get('combined_score', {})
    logger.info(f"Overall Security Grade: {combined_score.get('grade', 'Unknown')}")
    logger.info(f"Combined Score: {combined_score.get('combined_score', 'N/A')}")
    
    # Security Headers summary
    if results['summary']['security_headers_available']:
        sh_data = results['security_headers']
        logger.info(f"\nSecurity Headers Score: {sh_data.get('score', 'Unknown')}")
        logger.info(f"IP Address: {sh_data.get('ip', 'Unknown')}")
    else:
        logger.warning("Security Headers analysis not available")
    
    # HTTP Observatory summary
    if results['summary']['observatory_available']:
        obs_data = results['http_observatory']
        scan_info = obs_data.get('scan_info', {})
        summary = obs_data.get('summary', {})
        logger.info(f"\nHTTP Observatory Score: {scan_info.get('score', 'N/A')}")
        logger.info(f"HTTP Observatory Grade: {scan_info.get('grade', 'N/A')}")
        logger.info(f"Tests Passed: {summary.get('passed_tests', 0)}/{summary.get('total_tests', 0)}")
        logger.info(f"Warnings: {summary.get('warnings', 0)}")
    else:
        logger.warning("HTTP Observatory analysis not available")
    
    # Recommendations
    recommendations = results.get('recommendations', [])
    if recommendations:
        logger.info(f"\nSecurity Recommendations ({len(recommendations)}):")
        for i, rec in enumerate(recommendations, 1):
            logger.info(f"  {i}. {rec}")
    else:
        logger.info("\nNo specific security recommendations generated")
    
    logger.info(f"{'='*60}")
    logger.info("✓ Comprehensive security analysis completed")


def run(victim, logger):
    """Entry point: security headers + Mozilla HTTP Observatory analysis."""
    return analyze_security_headers_comprehensive(victim, logger)
