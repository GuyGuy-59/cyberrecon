import requests
import time
import os
from bs4 import BeautifulSoup

from .common_utils import save_json_result
from .run_utils import run_safe_steps
from threading import Thread, Lock
from queue import Queue
from urllib.parse import urljoin
from .config import *

# Global variables for thread-safe operations
q = Queue()
list_lock = Lock()
discovered_url = list()

def request_victim(url, timeout=10, max_retries=3):
    """GET with retries; ignores TLS verification (scanner use case)."""
    for attempt in range(max_retries):
        try:
            return requests.get(
                url,
                headers=header_default,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                print(f"Request error {e} for URL {url}")
            else:
                time.sleep(1)
    return None

def make_request_th(victim_url, logger):
    """Enhanced thread worker with better error handling and logging"""
    global q
    while True:
        try:
            # Get the resource from the queue
            resource = q.get()
            if resource is None:  # Poison pill to stop thread
                break
                
            # Build URL properly
            url = urljoin(victim_url.rstrip('/') + '/', resource.lstrip('/'))
            
            # Make request with enhanced error handling
            result = request_victim(url)
            
            if result is None:
                q.task_done()
                continue
                
            logger.info(f'[+] Testing {url} - {result.status_code}')
            
            # Check for interesting status codes
            interesting_codes = [200, 301, 302, 403, 401, 500]
            if result.status_code in interesting_codes:
                with list_lock:
                    discovered_url.append({
                        'url': url,
                        'status_code': result.status_code,
                        'content_length': len(result.content),
                        'server': result.headers.get('Server', 'Unknown'),
                        'title': extract_title(result.text)
                    })
            
            result.close()
            
        except Exception as e:
            logger.error(f"Error in thread worker: {e}")
        finally:
            q.task_done()

def extract_title(html):
    """Extract page title from HTML"""
    try:
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        return title_tag.get_text().strip() if title_tag else 'No title'
    except:
        return 'Error extracting title'


def _reset_queue_state():
    """Clear shared queue and result list between scan phases."""
    with q.mutex:
        q.queue.clear()
    discovered_url.clear()


def _start_workers_join_stop(victim_url, logger):
    """Enqueue is already done; start pool, drain queue, signal workers to exit."""
    for _ in range(num_threads):
        Thread(target=make_request_th, args=(victim_url, logger), daemon=True).start()
    q.join()
    for _ in range(num_threads):
        q.put(None)


def scan_robots(victim, victim_url, logger):
    """Enhanced robots.txt scanner with better parsing and results saving"""
    global q, discovered_url

    robots_url = urljoin(victim_url, '/robots.txt')
    res = request_victim(robots_url)

    if res is None or res.status_code != 200:
        logger.info('[-] Robots.txt not found!')
        return False

    logger.info('\n[*] Scanning robots.txt')

    robots_content = res.text
    res.close()

    disallowed_paths = []
    for line in robots_content.split('\n'):
        line = line.strip()
        if line.startswith("Disallow:") and len(line.split()) > 1:
            path = line.split(' ', 1)[1].strip()
            if path and path != '/':
                disallowed_paths.append(path)

    if not disallowed_paths:
        logger.info("[-] No disallowed paths found in robots.txt")
        return False

    logger.info(f"[*] Found {len(disallowed_paths)} disallowed paths")

    for path in disallowed_paths:
        q.put(path)
    _start_workers_join_stop(victim_url, logger)

    if discovered_url:
        logger.info(f"\n[+] Found {len(discovered_url)} interesting directories")
        save_json_result(
            victim,
            "robots_scan_results.json",
            discovered_url,
            logger,
            "Robots.txt crawl results",
            indent=2,
        )
        for item in discovered_url:
            logger.info(f'[+] {item["url"]} - {item["status_code"]} - {item["title"]}')
    else:
        logger.info("[-] No interesting directories found")

    _reset_queue_state()
    return True


def scan_wellkown(victim, victim_url, logger):
    """Enhanced .well-known scanner with comprehensive list and better results handling"""
    global q, discovered_url
    
    wellknown_list = [
        "acme-challenge", "apple-app-site-association", "apple-developer-merchantid-domain-association",
        "ashrae", "assetlinks.json", "autoconfig/mail", "browserid", "caldav", "carddav",
        "change-password", "coap", "core", "csvm", "dat", "dnt", "dnt-policy.txt", "est",
        "genid", "gpc", "hoba", "host-meta", "host-meta.json", "http-opportunistic",
        "keybase.txt", "matrix", "mercure", "mta-sts.txt", "ni", "nodeinfo",
        "openid-configuration", "openorg", "openpgpkey", "pki-validation", "posh",
        "pubvendors.json", "reload-config", "repute-template", "resourcesync",
        "security.txt", "stun-key", "time", "timezone", "uma2-configuration", "void",
        "webfinger", "xrp-ledger.toml", "sitemap.xml", "humans.txt", "crossdomain.xml",
        "clientaccesspolicy.xml", "favicon.ico", "robots.txt"
    ]
    
    logger.info(f"\n[*] Starting .well-known scan with {len(wellknown_list)} endpoints")
    
    for wellknown in wellknown_list:
        q.put(f".well-known/{wellknown}")
    _start_workers_join_stop(victim_url, logger)
    
    if discovered_url:
        logger.info(f'[+] Found {len(discovered_url)} .well-known endpoints')
        save_json_result(
            victim,
            "wellknown_scan_results.json",
            discovered_url,
            logger,
            ".well-known scan results",
            indent=2,
        )
        for item in discovered_url:
            logger.info(f"[+] {item['url']} - {item['status_code']} - {item['title']}")
    else:
        logger.info('[-] No .well-known endpoints found')
    
    _reset_queue_state()

def dirs_brute(victim, victim_url, logger):
    """Enhanced directory brute force with better wordlist handling and progress tracking"""
    global q, discovered_url
    
    # Check if wordlist file exists
    if not os.path.exists(Wordlist):
        logger.error(f"Wordlist file not found: {Wordlist}")
        return
    
    _dirs = []
    try:
        with open(Wordlist, 'r', encoding='utf-8') as _file:
            wordlist = _file.read().splitlines()
            for line in wordlist:
                line = line.strip()
                if line and not line.startswith('#'):
                    _dirs.append(line)
    except Exception as e:
        logger.error(f"Error reading wordlist: {e}")
        return
    
    if not _dirs:
        logger.warning("No valid entries found in wordlist")
        return
    
    logger.info(f"\n[*] Starting directory brute force with {len(_dirs)} entries")
    
    for path in _dirs:
        q.put(path)
    _start_workers_join_stop(victim_url, logger)
    
    logger.info('[*] Directory scan complete!')
    
    if discovered_url:
        logger.info(f'[+] Found {len(discovered_url)} interesting directories')
        save_json_result(
            victim,
            "directory_brute_results.json",
            discovered_url,
            logger,
            "Directory brute force results",
            indent=2,
        )
        for item in discovered_url:
            logger.info(f"[+] {item['url']} - {item['status_code']} - {item['title']}")
    else:
        logger.info('[-] No interesting directories found')
    
    _reset_queue_state()


def run(victim, logger):
    """Entry point: robots.txt crawl (then .well-known and directory brute force)."""
    victim_url = f"https://{victim}"
    scan_robots(victim, victim_url, logger)
    run_safe_steps(
        logger,
        [
            (".well-known scan", scan_wellkown, (victim, victim_url, logger)),
            ("Directory brute force", dirs_brute, (victim, victim_url, logger)),
        ],
    )