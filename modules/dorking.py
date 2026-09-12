from . import http_client as requests
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

# Dorks are processed by a thread pool, but Google/DuckDuckGo/Bing see a
# burst of near-identical requests hitting them at once as a bot signal
# regardless of TLS fingerprint or headers - that's what got DuckDuckGo to
# start serving its degraded/throttled response during testing. This gate
# serializes and paces every outbound request to those engines across all
# worker threads so they land one at a time, spaced out like a human browsing.
_search_gate = Lock()
_last_search_request = [0.0]
_SEARCH_ENGINE_MIN_INTERVAL = (4, 9)  # seconds between any two search-engine requests


def _throttled_request(method, url, **kwargs):
    """Run a search-engine request, serialized and paced across all threads."""
    with _search_gate:
        wait = _last_search_request[0] + random.uniform(*_SEARCH_ENGINE_MIN_INTERVAL) - time.time()
        if wait > 0:
            time.sleep(wait)
        try:
            return method(url, **kwargs)
        finally:
            _last_search_request[0] = time.time()

# Paired (User-Agent, curl_cffi impersonate target) profiles.
# A rotated User-Agent whose family/version doesn't match the TLS handshake's
# JA3/JA4 is itself a detection signal, so each profile keeps both consistent
# rather than randomizing the header independently of the handshake.
BROWSER_PROFILES = [
    {
        "impersonate": "chrome131",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "impersonate": "chrome131",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec_ch_ua_platform": '"macOS"',
    },
    {
        "impersonate": "chrome124",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="124", "Not_A Brand";v="24", "Google Chrome";v="124"',
        "sec_ch_ua_platform": '"Linux"',
    },
    {
        "impersonate": "firefox135",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
    },
    {
        "impersonate": "safari184",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
    },
]

def get_random_browser_profile():
    """Pick a (User-Agent, impersonate) pair that describe the same browser."""
    return random.choice(BROWSER_PROFILES)

def get_enhanced_headers(profile):
    """Build request headers consistent with the given browser profile."""
    headers = {
        "User-Agent": profile["user_agent"],
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
    }
    if profile["sec_ch_ua"]:
        headers["sec-ch-ua"] = profile["sec_ch_ua"]
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = profile["sec_ch_ua_platform"]
    return headers

def google_search(query, logger, retries=3, debug=False, use_alternative=False):
    """Perform a Google search with a Google Dork with retry mechanism"""
    
    # Try different search engines if Google is blocked
    if use_alternative:
        return alternative_search(query, logger, debug)
    
    search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
    
    for attempt in range(retries):
        try:
            # Use a different (User-Agent, TLS fingerprint) profile for each attempt
            profile = get_random_browser_profile()
            headers = get_enhanced_headers(profile)

            # Add some randomization to the request
            if random.random() < 0.3:  # 30% chance to add referer
                headers["Referer"] = "https://www.google.com/"

            # _throttled_request paces this against every other thread's
            # search-engine requests, so no extra per-attempt sleep is needed.
            response = _throttled_request(
                requests.get,
                search_url,
                headers=headers,
                timeout=25,
                allow_redirects=True,
                impersonate=profile["impersonate"],
            )
            response.raise_for_status()
            text_lower = response.text.lower()

            # Google serves a "please enable JavaScript" bootstrap page (no
            # <div class="g">/yuRUbf markup at all) to clients that don't run
            # its JS challenge, regardless of how good the TLS fingerprint or
            # headers are. Retrying against Google won't fix that, so treat
            # it the same as an explicit block and go straight to the
            # engines that still serve static HTML (DuckDuckGo, Bing).
            if "enablejs" in text_lower:
                logger.warning("Google served its JavaScript-challenge page (no static results available); switching to alternative search engines")
                return alternative_search(query, logger, debug)

            # Check if we got a captcha or error page
            if "sorry" in text_lower or "captcha" in text_lower or "blocked" in text_lower:
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

def _is_blocked_response(html, engine):
    """Detect a bot-check/captcha page served instead of real results.

    These pages return a normal 2xx status (raise_for_status won't catch them),
    but contain no result markup at all - extract_links would otherwise parse
    them as a legitimate page with zero links, which looks identical to "no
    results found" for the dork even though the search never actually ran.
    """
    if not html:
        return False
    text_lower = html.lower()
    if engine == "duckduckgo":
        return (
            "anomaly-modal" in text_lower
            or "bots use duckduckgo too" in text_lower
            or "challenge-form" in text_lower
        )
    if engine == "bing":
        return (
            "unusual traffic" in text_lower
            or "captcha" in text_lower
            or "id=\"b_captcha\"" in text_lower
        )
    if engine == "startpage":
        # Startpage fronts its search with an "Anubis" proof-of-work JS
        # challenge for non-browser clients - it returns HTTP 200 with no
        # result markup at all, same trap as the DuckDuckGo/Bing pages above.
        return (
            "anubis_challenge" in text_lower
            or "checking your browser" in text_lower
            or "captcha" in text_lower
        )
    return False


# (engine name, search URL template) tried in order after Google is blocked.
_ALTERNATIVE_ENGINES = [
    ("duckduckgo", "https://duckduckgo.com/html/?q={q}"),
    ("bing", "https://www.bing.com/search?q={q}"),
    ("startpage", "https://www.startpage.com/sp/search?query={q}"),
]


def _try_alternative_engine(engine, url_template, query, logger, debug=False):
    """Fetch one alternative engine's results page; None if blocked/unusable."""
    search_url = url_template.format(q=urllib.parse.quote_plus(query))
    profile = get_random_browser_profile()
    headers = get_enhanced_headers(profile)

    response = _throttled_request(
        requests.get,
        search_url,
        headers=headers,
        timeout=20,
        allow_redirects=True,
        impersonate=profile["impersonate"],
    )
    response.raise_for_status()

    if _is_blocked_response(response.text, engine):
        logger.warning(f"{engine.capitalize()} served a bot-check page instead of results")
        return None

    if debug:
        debug_file = f"debug_{engine}_response_{int(time.time())}.html"
        with open(debug_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        logger.info(f"Debug: {engine.capitalize()} response saved to {debug_file}")

    return response.text


def alternative_search(query, logger, debug=False):
    """Use alternative search methods when Google is blocked"""
    logger.info("Using alternative search method...")

    for engine, url_template in _ALTERNATIVE_ENGINES:
        try:
            html = _try_alternative_engine(engine, url_template, query, logger, debug)
            if html:
                return html
        except Exception as e:
            logger.error(f"{engine.capitalize()} search failed: {e}")

    logger.error("All search engines returned a bot-check page or failed for this query")
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
    elif "startpage" in html.lower():
        search_engine = "startpage"
    elif "bing" in html.lower():
        search_engine = "bing"

    if search_engine == "duckduckgo":
        # DuckDuckGo specific parsing
        result_links = soup.find_all('a', class_='result__a')
        logger.info(f"Found {len(result_links)} DuckDuckGo result links")
        
        for link in result_links:
            href = link.get('href')
            # DuckDuckGo's HTML endpoint marks sponsored results with the same
            # result__a class as organic ones; sponsored hrefs point at
            # duckduckgo.com's own ad-click tracker (y.js) rather than the
            # target, so they'd otherwise show up as fake "results".
            if href and href.startswith('http') and 'duckduckgo.com' not in urllib.parse.urlparse(href).netloc:
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

    elif search_engine == "startpage":
        # Startpage specific parsing - result links live in "w-gl__result"
        # cards. Startpage has shipped a few markup versions over time, so
        # match on several known anchor classes rather than a single one.
        result_links = soup.select(
            'a.w-gl__result-title, a.result-link, a.result-title, div.w-gl__result a[href^="http"]'
        )
        logger.info(f"Found {len(result_links)} Startpage result links")

        for link in result_links:
            href = link.get('href')
            if href and href.startswith('http') and 'startpage.com' not in urllib.parse.urlparse(href).netloc:
                links.add(href)
                if debug:
                    logger.info(f"Found Startpage link: {href}")

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
            'startpage.com' not in href and
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

def serpapi_search(query, logger, debug=False):
    """Resolve a dork query through SerpApi's Google Search API.

    Returns a list of result URLs when `serpapi_api_key` is configured and the
    request succeeds, or None when no key is set / the request fails - callers
    treat None as "fall back to the scraping-based search chain, as usual".
    Unlike the scraped engines, SerpApi is a real API behind an API key, so it
    isn't subject to the captcha/bot-check pages and doesn't need to go
    through the anti-bot pacing gate used for Google/DuckDuckGo/Bing/Startpage.
    """
    api_key = globals().get('serpapi_api_key', '')
    if not api_key:
        return None

    try:
        response = requests.get(
            "https://serpapi.com/search.json",
            params={
                "engine": "google",
                "q": query,
                "api_key": api_key,
                "num": 100,
            },
            timeout=25,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            logger.warning(f"SerpApi returned an error ({data['error']}), falling back to direct search")
            return None

        links = [r["link"] for r in data.get("organic_results", []) if r.get("link")]
        logger.info(f"SerpApi returned {len(links)} organic results")
        if debug:
            for i, link in enumerate(links, 1):
                logger.info(f"  {i}. {link}")
        return links
    except Exception as e:
        logger.warning(f"SerpApi request failed ({e}), falling back to direct search")
        return None


def process_dork(dork, victim, logger, debug=False):
    """Process a single dork in a thread-safe manner"""
    query = dork.replace("name_victim", victim)

    logger.info(f"Executing dork: {query}")

    serpapi_links = serpapi_search(query, logger, debug=debug)
    if serpapi_links is not None:
        return {
            'query': query,
            'links': serpapi_links,
            'count': len(serpapi_links),
            'search_engine': 'serpapi'
        }

    # Perform search
    html = google_search(query, logger, debug=debug)
    if html:
        # Detect search engine from HTML content
        search_engine = "google"
        if "duckduckgo" in html.lower():
            search_engine = "duckduckgo"
        elif "startpage" in html.lower():
            search_engine = "startpage"
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
