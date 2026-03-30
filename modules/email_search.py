import requests
import json
from urllib.parse import quote
from .config import *
from .common_utils import base_scan_meta, save_json_result


def parsejson(json_obj, p):
    try:
        return json.loads(json_obj).get(p, [])
    except (json.JSONDecodeError, TypeError):
        return []


def requests_breachdirectory(info_user, logger):
    logger.info(f"Checking breach directory for: {info_user}")
    breach_results = {
        **base_scan_meta(info_user),
        'breach_found': False,
        'breaches': [],
        'error': None
    }
    try:
        response = requests.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={
                "X-RapidAPI-Key": breachdirectory_api_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
            },
            params={"func": "auto", "term": info_user},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        if data.get('success') and data.get('result'):
            breach_results['breach_found'] = True
            breach_results['breaches'] = data['result']
            logger.warning(f"⚠️  Breach found for {info_user}: {len(data['result'])} records")
            for breach in data['result'][:5]:
                logger.warning(
                    f"  - {breach.get('sources', 'Unknown source')}: "
                    f"{breach.get('password', 'Password found')}"
                )
        else:
            logger.info(f"✓ No breaches found for {info_user}")
    except Exception as e:
        logger.error(f"Error checking breach directory: {e}")
        breach_results['error'] = str(e)
    return breach_results


def request_proxynova(info_user, logger):
    logger.info(f"Checking Proxynova for: {info_user}")
    proxynova_results = {
        **base_scan_meta(info_user),
        'data_found': False,
        'lines': [],
        'error': None
    }
    try:
        response = requests.get(
            f"https://api.proxynova.com/comb?query={info_user}",
            timeout=30
        )
        response.raise_for_status()
        lines = parsejson(response.text, "lines")
        if lines:
            proxynova_results['data_found'] = True
            proxynova_results['lines'] = lines
            logger.info(f"✓ Found {len(lines)} Proxynova entries for {info_user}")
            for line in lines[:3]:
                logger.info(f"  {line}")
            if len(lines) > 3:
                logger.info(f"  ... and {len(lines) - 3} more entries")
        else:
            logger.info(f"No Proxynova data found for {info_user}")
    except Exception as e:
        logger.error(f"Error checking Proxynova: {e}")
        proxynova_results['error'] = str(e)
    return proxynova_results


def request_haveibeenpwned(info_user, logger):
    logger.info(f"Checking Have I Been Pwned for: {info_user}")
    hibp_results = {
        **base_scan_meta(info_user),
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
        encoded = quote(info_user, safe='')
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}"
        response = requests.get(
            url,
            headers={
                "hibp-api-key": api_key,
                "user-agent": "CyberRecon/1.0",
                "accept": "application/json"
            },
            params={"truncateResponse": "false"},
            timeout=30
        )
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
                logger.warning(
                    f"  - {breach.get('Name', 'Unknown')}: {breach.get('BreachDate', 'Unknown date')}"
                )
        else:
            logger.info(f"✓ No HIBP breaches found for {info_user}")
    except Exception as e:
        logger.error(f"Error checking Have I Been Pwned: {e}")
        hibp_results['error'] = str(e)
    return hibp_results


def _breach_checks_for_email(email, logger):
    return (
        requests_breachdirectory(email, logger),
        request_haveibeenpwned(email, logger)
    )


def get_email(victim, logger):
    logger.info(f"Starting email enumeration for: {victim}")
    email_results = {
        **base_scan_meta(victim),
        'emails_found': [],
        'total_emails': 0,
        'breach_checks': {},
        'hibp_checks': {},
        'proxynova_checks': {},
        'hunter_io_success': False,
        'errors': []
    }

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
                if not email:
                    continue
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
                br, hibp = _breach_checks_for_email(email, logger)
                email_results['breach_checks'][email] = br
                email_results['hibp_checks'][email] = hibp
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

    logger.info("Checking domain with Proxynova...")
    email_results['proxynova_checks']['domain'] = request_proxynova(victim, logger)

    save_json_result(victim, "email_enumeration.json", email_results, logger, "Email enumeration results")

    logger.info(f"\n--- Email Enumeration Summary for {victim} ---")
    logger.info(f"Total emails found: {email_results['total_emails']}")
    logger.info(f"Hunter.io success: {'✓' if email_results['hunter_io_success'] else '✗'}")

    if email_results['emails_found']:
        logger.info("\nEmail addresses found:")
        for row in email_results['emails_found']:
            logger.info(f"  - {row['email']} (confidence: {row['confidence']})")

    breach_n = sum(1 for r in email_results['breach_checks'].values() if r.get('breach_found'))
    if breach_n:
        logger.warning(f"⚠️  {breach_n} emails found in breach databases")
    else:
        logger.info("✓ No emails found in breach databases")

    hibp_map = email_results['hibp_checks']
    hibp_n = sum(1 for r in hibp_map.values() if r.get('breach_found'))
    if hibp_n:
        logger.warning(f"⚠️  {hibp_n} emails found in Have I Been Pwned")
    elif hibp_map and all(r.get('skipped') for r in hibp_map.values()):
        logger.info("Have I Been Pwned checks skipped (HIBP API key not configured)")
    else:
        logger.info("✓ No emails found in Have I Been Pwned")

    return email_results


def run(victim, logger):
    """Entry point: Hunter.io enumeration, breach checks, Proxynova."""
    return get_email(victim, logger)
