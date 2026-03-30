import requests
import urllib.parse
import os
import time
import random
import json
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from .config import *
from .common_utils import base_scan_meta, result_path, scan_timestamp_long

results_lock = Lock()

# User agents pool for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

def get_random_user_agent():
    """Get a random user agent from the pool"""
    return random.choice(USER_AGENTS)

def get_enhanced_headers():
    """Get enhanced headers to avoid bot detection"""
    return {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"'
    }

def google_search(query, logger, retries=3, debug=False, use_alternative=False):
    """Perform a Google search with a Google Dork with retry mechanism"""
    
    # Try different search engines if Google is blocked
    if use_alternative:
        return alternative_search(query, logger, debug)
    
    search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
    
    for attempt in range(retries):
        try:
            # Add random delay to avoid rate limiting
            time.sleep(random.uniform(3, 8))
            
            # Use different headers for each attempt
            headers = get_enhanced_headers()
            
            # Add some randomization to the request
            if random.random() < 0.3:  # 30% chance to add referer
                headers["Referer"] = "https://www.google.com/"
            
            response = requests.get(
                search_url, 
                headers=headers, 
                timeout=25,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Check if we got a captcha or error page
            if "sorry" in response.text.lower() or "captcha" in response.text.lower() or "blocked" in response.text.lower():
                logger.warning(f"Google blocked the request (attempt {attempt + 1})")
                if attempt == retries - 1:
                    logger.info("Switching to alternative search method...")
                    return alternative_search(query, logger, debug)
                else:
                    time.sleep(random.uniform(10, 20))  # Longer delay for blocked requests
                    continue
            
            if debug:
                # Save HTML response for debugging
                debug_file = f"debug_google_response_{int(time.time())}.html"
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                logger.info(f"Debug: HTML response saved to {debug_file}")
            
            return response.text
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                logger.error(f"Error during Google search after {retries} attempts: {e}")
                logger.info("Trying alternative search method...")
                return alternative_search(query, logger, debug)
            else:
                logger.warning(f"Attempt {attempt + 1} failed, retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
    
    return None

def alternative_search(query, logger, debug=False):
    """Use alternative search methods when Google is blocked"""
    logger.info("Using alternative search method...")
    
    # Try DuckDuckGo as alternative
    try:
        search_url = f"https://duckduckgo.com/html/?q={urllib.parse.quote_plus(query)}"
        headers = get_enhanced_headers()
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        time.sleep(random.uniform(2, 4))
        
        response = requests.get(search_url, headers=headers, timeout=20, allow_redirects=True)
        response.raise_for_status()
        
        if debug:
            debug_file = f"debug_duckduckgo_response_{int(time.time())}.html"
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.info(f"Debug: DuckDuckGo response saved to {debug_file}")
        
        return response.text
    except Exception as e:
        logger.error(f"DuckDuckGo search failed: {e}")
    
    # Try Bing as fallback
    try:
        search_url = f"https://www.bing.com/search?q={urllib.parse.quote_plus(query)}"
        headers = get_enhanced_headers()
        
        time.sleep(random.uniform(2, 4))
        
        response = requests.get(search_url, headers=headers, timeout=20, allow_redirects=True)
        response.raise_for_status()
        
        if debug:
            debug_file = f"debug_bing_response_{int(time.time())}.html"
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.info(f"Debug: Bing response saved to {debug_file}")
        
        return response.text
    except Exception as e:
        logger.error(f"Bing search failed: {e}")
    
    return None


def _save_dork_scan(victim, all_results, total_results, manual_mode, logger):
    """Write google_dorks_results.txt and .json under results/<victim>/."""
    target_dir = result_path(victim)
    os.makedirs(target_dir, exist_ok=True)
    txt_path = os.path.join(target_dir, "google_dorks_results.txt")
    json_path = os.path.join(target_dir, "google_dorks_results.json")
    title = "Manual Google Dorking" if manual_mode else "Google Dorking"

    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(f"=== {title} Results for: {victim} ===\n")
        f.write(f"Date: {scan_timestamp_long()}\n")
        f.write(f"Total dorks processed: {len(all_results)}\n")
        f.write(f"Total results found: {total_results}\n")
        f.write("=" * 80 + "\n\n")
        for idx, row in enumerate(all_results):
            f.write(f"=== Dork {idx + 1}: {row['query']} ===\n")
            f.write(f"Number of results found: {row['count']}\n")
            if manual_mode:
                f.write(f"Search method: {row['search_engine']}\n")
            f.write("\n")
            if not manual_mode and row.get('error'):
                f.write(f"ERROR: {row.get('error_msg', 'Unable to perform search')}\n")
            elif row.get('links'):
                for i, link in enumerate(row['links']):
                    f.write(f"{i + 1}. {link}\n")
            else:
                f.write("No results found.\n")
            f.write("=" * 80 + "\n\n")

    payload = {
        **base_scan_meta(victim),
        'total_dorks': len(all_results),
        'total_results': total_results,
        'results': all_results,
    }
    if manual_mode:
        payload['manual_mode'] = True
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info(f"{title} scan completed. {total_results} total results found.")
    logger.info(f"Results saved in: {txt_path}")
    logger.info(f"JSON results saved in: {json_path}")


def manual_dork_input(victim, logger):
    """Allow manual input of dork results when automated search fails"""
    logger.info("Manual dork input mode activated")
    print(f"\n=== Manual Dork Input for {victim} ===")
    print("Since automated search is blocked, you can manually input results.")
    print("For each dork, enter the URLs you found manually (one per line, empty line to finish):")
    print("="*60)
    
    if not os.path.exists(Dorklist):
        logger.error(f"Dorks file not found: {Dorklist}")
        return []
    
    with open(Dorklist, "r", encoding='utf-8') as f:
        google_dorks = [line.strip() for line in f.readlines() if line.strip()]
    
    all_results = []
    
    for i, dork in enumerate(google_dorks, 1):
        query = dork.replace("name_victim", victim)
        print(f"\n--- Dork {i}/{len(google_dorks)}: {query} ---")
        print("Enter URLs found (one per line, empty line when done):")
        
        links = []
        while True:
            url = input().strip()
            if not url:
                break
            if url.startswith('http'):
                links.append(url)
            else:
                print("Please enter a valid URL starting with http:// or https://")
        
        result = {
            'query': query,
            'links': links,
            'count': len(links),
            'search_engine': 'manual',
            'manual': True
        }
        all_results.append(result)
        
        print(f"Added {len(links)} URLs for this dork.")
    
    return all_results

def extract_links(html, logger, debug=False, search_engine="google"):
    """Extract links from search results with improved parsing for different engines"""
    if not html:
        return []
    
    soup = BeautifulSoup(html, 'html.parser')
    links = set()  # Use set to avoid duplicates
    
    if debug:
        logger.info(f"Debug: Starting link extraction from {search_engine}...")
    
    # Detect search engine from HTML content
    if "duckduckgo" in html.lower():
        search_engine = "duckduckgo"
    elif "bing" in html.lower():
        search_engine = "bing"
    
    if search_engine == "duckduckgo":
        # DuckDuckGo specific parsing
        result_links = soup.find_all('a', class_='result__a')
        logger.info(f"Found {len(result_links)} DuckDuckGo result links")
        
        for link in result_links:
            href = link.get('href')
            if href and href.startswith('http'):
                links.add(href)
                if debug:
                    logger.info(f"Found DuckDuckGo link: {href}")
    
    elif search_engine == "bing":
        # Bing specific parsing
        result_links = soup.find_all('a', href=True)
        logger.info(f"Found {len(result_links)} Bing links")
        
        for link in result_links:
            href = link.get('href')
            if (href and href.startswith('http') and 
                'bing.com' not in href and 
                'microsoft.com' not in href and
                not href.startswith('/search')):
                links.add(href)
                if debug:
                    logger.info(f"Found Bing link: {href}")
    
    else:
        # Google specific parsing (original methods)
        # Method 1: Search in yuRUbf divs (modern Google structure)
        yuRUbf_divs = soup.find_all('div', class_='yuRUbf')
        logger.info(f"Found {len(yuRUbf_divs)} yuRUbf divs")
        
        for item in yuRUbf_divs:
            a_tag = item.find('a')
            if a_tag and a_tag.get('href'):
                href = a_tag['href']
                if href.startswith('http') and 'google.com' not in href:
                    links.add(href)
                    if debug:
                        logger.info(f"Found link in yuRUbf: {href}")
        
        # Method 2: Search in h3 elements with parent divs
        h3_elements = soup.find_all('h3')
        logger.info(f"Found {len(h3_elements)} h3 elements")
        
        for h3 in h3_elements:
            # Look for parent div with class 'g' (Google result container)
            parent_div = h3.find_parent('div', class_='g')
            if parent_div:
                a_tag = h3.find('a')
                if a_tag and a_tag.get('href'):
                    href = a_tag['href']
                    if href.startswith('http') and 'google.com' not in href:
                        links.add(href)
                        if debug:
                            logger.info(f"Found link in h3: {href}")
        
        # Method 3: Search in all divs with class 'g' (Google result containers)
        g_divs = soup.find_all('div', class_='g')
        logger.info(f"Found {len(g_divs)} divs with class 'g'")
        
        for result in g_divs:
            a_tag = result.find('a')
            if a_tag and a_tag.get('href'):
                href = a_tag['href']
                if href.startswith('http') and not href.startswith('/search') and 'google.com' not in href:
                    links.add(href)
                    if debug:
                        logger.info(f"Found link in div.g: {href}")
        
        # Method 4: Look for specific Google result patterns
        for link in soup.find_all('a', href=True):
            href = link['href']
            if '/url?q=' in href:
                # Extract the actual URL from Google's redirect
                try:
                    actual_url = urllib.parse.parse_qs(urllib.parse.urlparse(href).query).get('q', [None])[0]
                    if actual_url and actual_url.startswith('http') and 'google.com' not in actual_url:
                        links.add(actual_url)
                        if debug:
                            logger.info(f"Found link via /url?q=: {actual_url}")
                except:
                    pass
    
    # Universal method: Search for any link that looks like a search result
    all_links = soup.find_all('a', href=True)
    logger.info(f"Found {len(all_links)} total links")
    
    for a_tag in all_links:
        href = a_tag['href']
        # Check if it's a valid external link
        if (href.startswith('http') and 
            'google.com' not in href and 
            'duckduckgo.com' not in href and
            'bing.com' not in href and
            not href.startswith('/search') and
            not href.startswith('/url?') and
            'youtube.com' not in href and
            'facebook.com' not in href and
            'twitter.com' not in href):
            links.add(href)
            if debug:
                logger.info(f"Found link in general search: {href}")
    
    final_links = list(links)
    logger.info(f"Total unique links found: {len(final_links)}")
    
    if debug and final_links:
        logger.info("All found links:")
        for i, link in enumerate(final_links, 1):
            logger.info(f"  {i}. {link}")
    
    return final_links

def process_dork(dork, victim, logger, debug=False):
    """Process a single dork in a thread-safe manner"""
    query = dork.replace("name_victim", victim)
    
    logger.info(f"Executing dork: {query}")
    
    # Perform search
    html = google_search(query, logger, debug=debug)
    if html:
        # Detect search engine from HTML content
        search_engine = "google"
        if "duckduckgo" in html.lower():
            search_engine = "duckduckgo"
        elif "bing" in html.lower():
            search_engine = "bing"
        
        links = extract_links(html, logger, debug=debug, search_engine=search_engine)
        return {
            'query': query,
            'links': links,
            'count': len(links),
            'search_engine': search_engine
        }
    else:
        logger.warning(f"Search failed for dork: {query}")
        return {
            'query': query,
            'links': [],
            'count': 0,
            'error': True,
            'search_engine': 'none'
        }

def scan_dorks(victim, logger, debug=False, manual_mode=False):
    """Scan target with Google Dorks using parallel processing"""
    logger.info(f"Starting Google Dorking scan for: {victim}")

    if manual_mode:
        all_results = manual_dork_input(victim, logger)
        if all_results:
            total = sum(r['count'] for r in all_results)
            _save_dork_scan(victim, all_results, total, True, logger)
        return
    
    # Check if dorks file exists
    if not os.path.exists(Dorklist):
        logger.error(f"Dorks file not found: {Dorklist}")
        return
    
    # Read Google Dorks from file
    try:
        with open(Dorklist, "r", encoding='utf-8') as f:
            google_dorks = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.error(f"Unable to read file: {Dorklist}")
        return
    
    if not google_dorks:
        logger.warning("No dorks found in file")
        return
    
    logger.info(f"Loading {len(google_dorks)} dorks")

    total_results = 0
    all_results = []
    
    # Use ThreadPoolExecutor for parallel processing
    max_workers = min(num_threads, len(google_dorks))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all dork processing tasks
        future_to_dork = {
            executor.submit(process_dork, dork, victim, logger, debug): dork 
            for dork in google_dorks
        }
        
        # Process completed tasks
        for future in as_completed(future_to_dork):
            dork = future_to_dork[future]
            try:
                result = future.result()
                all_results.append(result)
                
                with results_lock:
                    total_results += result['count']
                    
            except Exception as e:
                logger.error(f"Error processing dork '{dork}': {e}")
                all_results.append({
                    'query': dork.replace("name_victim", victim),
                    'links': [],
                    'count': 0,
                    'error': True,
                    'error_msg': str(e)
                })
    
    all_results.sort(key=lambda x: x['count'], reverse=True)
    _save_dork_scan(victim, all_results, total_results, False, logger)


def run(victim, logger):
    """Entry point for the module: runs the full Google dorking pipeline."""
    return scan_dorks(victim, logger)
