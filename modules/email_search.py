import requests
import json
import os
import time
from .config import *

def parsejson(json_obj, p):
    """Enhanced JSON parsing with error handling"""
    try:
        _json = json.loads(json_obj)
        return _json.get(p, [])
    except json.JSONDecodeError as e:
        return []
    except KeyError:
        return []

def requests_breachdirectory(info_user, logger):
    """Enhanced breach directory check with better error handling and structured output"""
    logger.info(f"Checking breach directory for: {info_user}")
    
    breach_results = {
        'target': info_user,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'breach_found': False,
        'breaches': [],
        'error': None
    }
    
    try:
        url_pwned = "https://breachdirectory.p.rapidapi.com/"
        querystring = {"func": "auto", "term": info_user}
        headers = {
            "X-RapidAPI-Key": breachdirectory_api_key,
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
        }
        
        response = requests.get(url_pwned, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('success') and data.get('result'):
            breach_results['breach_found'] = True
            breach_results['breaches'] = data['result']
            logger.warning(f"⚠️  Breach found for {info_user}: {len(data['result'])} records")
            
            for breach in data['result'][:5]:  # Show first 5 breaches
                logger.warning(f"  - {breach.get('sources', 'Unknown source')}: {breach.get('password', 'Password found')}")
        else:
            logger.info(f"✓ No breaches found for {info_user}")
            
    except requests.RequestException as e:
        logger.error(f"Error checking breach directory: {e}")
        breach_results['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error in breach directory check: {e}")
        breach_results['error'] = str(e)
    
    return breach_results

def request_proxynova(info_user, logger):
    """Enhanced Proxynova check with better error handling and structured output"""
    logger.info(f"Checking Proxynova for: {info_user}")
    
    proxynova_results = {
        'target': info_user,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'data_found': False,
        'lines': [],
        'error': None
    }
    
    try:
        url = f"https://api.proxynova.com/comb?query={info_user}"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        lines = parsejson(response.text, "lines")
        
        if lines:
            proxynova_results['data_found'] = True
            proxynova_results['lines'] = lines
            logger.info(f"✓ Found {len(lines)} Proxynova entries for {info_user}")
            
            for line in lines[:3]:  # Show first 3 entries
                logger.info(f"  {line}")
            if len(lines) > 3:
                logger.info(f"  ... and {len(lines) - 3} more entries")
        else:
            logger.info(f"No Proxynova data found for {info_user}")
            
    except requests.RequestException as e:
        logger.error(f"Error checking Proxynova: {e}")
        proxynova_results['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error in Proxynova check: {e}")
        proxynova_results['error'] = str(e)
    
    return proxynova_results

def get_email(victim, logger):
    """Enhanced email enumeration with comprehensive error handling and structured output"""
    logger.info(f"Starting email enumeration for: {victim}")
    
    email_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'emails_found': [],
        'total_emails': 0,
        'breach_checks': {},
        'proxynova_checks': {},
        'hunter_io_success': False,
        'errors': []
    }
    
    # Hunter.io email search
    try:
        url = f'https://api.hunter.io/v2/domain-search?domain={victim}&api_key={email_hunter_api_key}'
        logger.info("Querying Hunter.io for email addresses...")
        
        response = requests.get(url, headers=header_default, timeout=30)
        response.raise_for_status()
        
        json_response = response.json()
        
        if response.ok and json_response.get('data', {}).get('emails'):
            emails_list = json_response['data']['emails']
            email_results['hunter_io_success'] = True
            email_results['total_emails'] = len(emails_list)
            
            logger.info(f"✓ Found {len(emails_list)} email addresses via Hunter.io")
            
            for email_data in emails_list:
                email = email_data.get('value', '')
                if email:
                    email_results['emails_found'].append({
                        'email': email,
                        'confidence': email_data.get('confidence', 0),
                        'sources': email_data.get('sources', []),
                        'first_name': email_data.get('first_name', ''),
                        'last_name': email_data.get('last_name', ''),
                        'position': email_data.get('position', ''),
                        'department': email_data.get('department', '')
                    })
                    
                    logger.info(f"  - {email} (confidence: {email_data.get('confidence', 0)})")
                    
                    # Check each email for breaches
                    breach_result = requests_breachdirectory(email, logger)
                    email_results['breach_checks'][email] = breach_result
                    
                    # Check each email with Proxynova
                    proxynova_result = request_proxynova(email, logger)
                    email_results['proxynova_checks'][email] = proxynova_result
        else:
            error_msg = json_response.get('errors', [{}])[0].get('details', 'Unknown error')
            logger.warning(f"Hunter.io returned no emails: {error_msg}")
            email_results['errors'].append(f"Hunter.io: {error_msg}")
            
    except requests.RequestException as e:
        logger.error(f"Error querying Hunter.io: {e}")
        email_results['errors'].append(f"Hunter.io request error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error with Hunter.io: {e}")
        email_results['errors'].append(f"Hunter.io unexpected error: {e}")
    
    # Check domain with Proxynova
    logger.info("Checking domain with Proxynova...")
    domain_proxynova = request_proxynova(victim, logger)
    email_results['proxynova_checks']['domain'] = domain_proxynova
    
    # Save results to file
    try:
        results_dir = os.path.join(result, victim)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, "email_enumeration.json")
        with open(filename, 'w') as f:
            json.dump(email_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Email enumeration results saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save email enumeration results: {e}")
    
    # Display summary
    logger.info(f"\n--- Email Enumeration Summary for {victim} ---")
    logger.info(f"Total emails found: {email_results['total_emails']}")
    logger.info(f"Hunter.io success: {'✓' if email_results['hunter_io_success'] else '✗'}")
    
    if email_results['emails_found']:
        logger.info("\nEmail addresses found:")
        for email_data in email_results['emails_found']:
            logger.info(f"  - {email_data['email']} (confidence: {email_data['confidence']})")
    
    # Show breach summary
    breached_emails = [email for email, result in email_results['breach_checks'].items() 
                       if result.get('breach_found', False)]
    if breached_emails:
        logger.warning(f"⚠️  {len(breached_emails)} emails found in breach databases")
    else:
        logger.info("✓ No emails found in breach databases")
    
    return email_results
