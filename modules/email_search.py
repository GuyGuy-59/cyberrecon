import requests
import json
import os
import time
from urllib.parse import quote
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

def request_haveibeenpwned(info_user, logger):
    """Check Have I Been Pwned API for breached account data."""
    logger.info(f"Checking Have I Been Pwned for: {info_user}")

    hibp_results = {
        'target': info_user,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'breach_found': False,
        'breaches': [],
        'skipped': False,
        'error': None
    }

    api_key = globals().get('hibp_api_key', '')
    if not api_key:
        logger.info("HIBP API key not configured, skipping Have I Been Pwned check")
        hibp_results['skipped'] = True
        hibp_results['error'] = "HIBP API key missing"
        return hibp_results

    try:
        # HIBP API expects the account to be URL encoded in the path.
        encoded_account = quote(info_user, safe='')
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_account}"
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "CyberRecon/1.0",
            "accept": "application/json"
        }
        params = {"truncateResponse": "false"}

        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 404:
            logger.info(f"✓ No HIBP breaches found for {info_user}")
            return hibp_results

        response.raise_for_status()
        breaches = response.json() if response.content else []

        if breaches:
            hibp_results['breach_found'] = True
            hibp_results['breaches'] = breaches
            logger.warning(f"⚠️  HIBP breach found for {info_user}: {len(breaches)} breach(es)")
            for breach in breaches[:5]:
                logger.warning(f"  - {breach.get('Name', 'Unknown')}: {breach.get('BreachDate', 'Unknown date')}")
        else:
            logger.info(f"✓ No HIBP breaches found for {info_user}")

    except requests.RequestException as e:
        logger.error(f"Error checking Have I Been Pwned: {e}")
        hibp_results['error'] = str(e)
    except ValueError as e:
        logger.error(f"Invalid JSON from Have I Been Pwned: {e}")
        hibp_results['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error in Have I Been Pwned check: {e}")
        hibp_results['error'] = str(e)

    return hibp_results

def get_email(victim, logger):
    """Enhanced email enumeration with comprehensive error handling and structured output"""
    logger.info(f"Starting email enumeration for: {victim}")
    
    email_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'emails_found': [],
        'total_emails': 0,
        'breach_checks': {},
        'hibp_checks': {},
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
                    
                    # Check each email with Have I Been Pwned
                    hibp_result = request_haveibeenpwned(email, logger)
                    email_results['hibp_checks'][email] = hibp_result
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

    # Show Have I Been Pwned summary
    hibp_breached_emails = [email for email, result in email_results['hibp_checks'].items()
                            if result.get('breach_found', False)]
    hibp_skipped_count = sum(1 for result in email_results['hibp_checks'].values()
                             if result.get('skipped', False))

    if hibp_breached_emails:
        logger.warning(f"⚠️  {len(hibp_breached_emails)} emails found in Have I Been Pwned")
    elif hibp_skipped_count == len(email_results['hibp_checks']) and hibp_skipped_count > 0:
        logger.info("Have I Been Pwned checks skipped (HIBP API key not configured)")
    else:
        logger.info("✓ No emails found in Have I Been Pwned")
    
    return email_results
