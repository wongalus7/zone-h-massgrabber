#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zone‑H Domain Grabber – Mass Version with Centralized Captcha Handling
Supports single attacker or list from file, optional multithreading.
Only one captcha prompt will appear, and all threads will resume safely.
"""

import requests
import re
import os
import sys
import time
import random
import threading
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

try:
    from bs4 import BeautifulSoup
    BS_AVAILABLE = True
except ImportError:
    BS_AVAILABLE = False
    print(Fore.YELLOW + "[!] BeautifulSoup4 not installed. Using regex fallback.")

# ──────────────────────────── USER‑AGENT LIST ────────────────────────────
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
]

R = Fore.RED
G = Fore.GREEN
W = Fore.WHITE
Y = Fore.YELLOW
C = Fore.CYAN
M = Fore.MAGENTA

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(C + Style.BRIGHT + "=" * 60)
    print(G + "  Zone‑H Domain Grabber (Mass Edition)")
    print(C + "=" * 60)
    print(Y + "  Centralized Captcha  |  No IPs, no ellipsis")
    print("")

# ────────────────────────── CAPTCHA HANDLER ──────────────────────────
class CaptchaHandler:
    """
    Shared captcha handler for all threads.
    Only one prompt will appear at a time.
    """
    def __init__(self, initial_cookies):
        self.cookies = initial_cookies.copy()
        self.lock = threading.Lock()
        self.captcha_event = threading.Event()  # set when captcha is detected
        self.new_cookies_event = threading.Event()  # set when new cookies are ready

    def wait_if_captcha(self):
        """Called before any request: if a captcha was reported, wait until resolved."""
        if self.captcha_event.is_set():
            self.new_cookies_event.wait()  # blocks until new cookies are applied

    def report_captcha(self):
        """
        Called by a thread that detected captcha.
        If this is the first to report, show the prompt and update cookies.
        """
        with self.lock:
            # Only the first thread that gets the lock will handle the prompt
            if not self.captcha_event.is_set():
                self.captcha_event.set()   # signal all other threads to stop
                self.new_cookies_event.clear()
                print(Y + "\n[!] CAPTCHA detected! Please solve it in your browser and paste new cookies.")
                new_cookie_str = input(W + "Paste new cookies (Format: PHPSESSID=...; ZHE=...): ").strip()
                new_cookies = parse_cookies(new_cookie_str)
                # Validate
                while 'PHPSESSID' not in new_cookies or 'ZHE' not in new_cookies:
                    print(R + "[!] Must contain PHPSESSID and ZHE. Try again.")
                    new_cookie_str = input(W + "Paste new cookies: ").strip()
                    new_cookies = parse_cookies(new_cookie_str)
                # Update shared cookies
                self.cookies = new_cookies.copy()
                print(G + "[+] Cookies updated globally. Resuming all threads...")
                self.captcha_event.clear()
                self.new_cookies_event.set()   # release waiting threads
                time.sleep(0.5)  # small delay to let threads pick up the change
                # Clear the new_cookies_event after a moment to avoid stale state
                self.new_cookies_event.clear()
            else:
                # If another thread already reported, just wait here until resolved
                self.new_cookies_event.wait()
                self.new_cookies_event.clear()

    def update_session_cookies(self, session):
        """Sync a session's cookies with the current global cookies."""
        with self.lock:
            session.cookies.clear()
            for k, v in self.cookies.items():
                session.cookies.set(k, v)

# ─────────────────────────── HELPER FUNCTIONS ───────────────────────────
def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(';'):
        if '=' in part:
            k, v = part.strip().split('=', 1)
            cookies[k.strip()] = v.strip()
    return cookies

def get_random_ua():
    return random.choice(USER_AGENTS)

def detect_captcha(content):
    if isinstance(content, bytes):
        content = content.decode('utf-8', errors='ignore')
    return 'cryptogram' in content and 'captcha' in content.lower()

def is_clean_domain(domain):
    if not domain: return False
    if '...' in domain: return False
    if ' ' in domain: return False
    if '.' not in domain: return False
    return True

def extract_domain_from_text(raw_text):
    before_slash = raw_text.split('/')[0].strip()
    if before_slash.endswith('...'):
        before_slash = before_slash[:-3]
    return before_slash

def extract_domains_soup(html):
    soup = BeautifulSoup(html, 'html.parser')
    domains = []
    table = soup.find('table', id='ldeface')
    if not table: return domains
    for row in table.find_all('tr')[1:]:
        cols = row.find_all('td')
        if len(cols) < 8: continue
        r_td = cols[4]
        r_link = r_td.find('a', href=re.compile(r'/archive/domain='))
        if r_link:
            href = r_link.get('href', '')
            m = re.search(r'domain=([^&]+)', href)
            if m:
                domain = m.group(1).strip()
                if is_clean_domain(domain):
                    domains.append(domain)
                    continue
        domain_text = cols[7].get_text(strip=True)
        if domain_text:
            candidate = extract_domain_from_text(domain_text)
            if is_clean_domain(candidate):
                domains.append(candidate)
    return domains

def extract_domains_regex(html):
    domains = []
    rows = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
    for row in rows:
        if 'defaceTime' in row: continue
        r_match = re.search(r'href\s*=\s*["\']/archive/domain=([^"\']+)', row)
        if r_match:
            domain = r_match.group(1).strip()
            if is_clean_domain(domain):
                domains.append(domain)
                continue
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(tds) >= 8:
            raw_text = re.sub(r'<[^>]+>', '', tds[7]).strip()
            if raw_text:
                candidate = extract_domain_from_text(raw_text)
                if is_clean_domain(candidate):
                    domains.append(candidate)
    return domains

def fetch_page(session, url, captcha_handler):
    """
    Fetch a page. If captcha is detected, report to handler and wait for new cookies.
    Returns (html_text, is_captcha) after possibly waiting.
    """
    headers = {
        'User-Agent': get_random_ua(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'http://www.zone-h.org/',
        'DNT': '1',
        'Connection': 'keep-alive',
    }
    while True:
        # Wait if a captcha is currently being handled globally
        captcha_handler.wait_if_captcha()

        try:
            resp = session.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                print(R + f"[-] HTTP {resp.status_code} on {url}")
                # Could be a temporary error, wait and retry
                time.sleep(5)
                continue
            text = resp.text
            if detect_captcha(text):
                # Report captcha – this will block until resolved
                captcha_handler.report_captcha()
                # After resolution, update this session's cookies
                captcha_handler.update_session_cookies(session)
                # Loop will now retry the same URL with new cookies
                continue
            return text, False  # success, no captcha
        except Exception as e:
            print(R + f"[-] Connection error: {e}")
            time.sleep(5)
            continue

def get_max_page_from_html(html):
    if not html: return 1
    pages = set()
    for m in re.finditer(r'/page=(\d+)', html):
        pages.add(int(m.group(1)))
    strong = re.findall(r'<strong>(\d+)</strong>', html)
    for s in strong: pages.add(int(s))
    return max(pages) if pages else 1

def save_all(filename, domain_set):
    with open(filename, 'w', encoding='utf-8') as f:
        for d in sorted(domain_set):
            f.write(d + '\n')

# ─────────────────── SCRAPE SECTION (per attacker/type) ─────────────────
def scrape_section(session, attacker, section_type, base_url, captcha_handler):
    print(Y + f"\n[+] Starting {section_type} scrape for: {attacker}")
    filename = f"{attacker}_{section_type}.txt"
    open(filename, 'w').close()
    all_domains = set()
    page = 1
    max_page = None

    while True:
        if max_page and page > max_page:
            print(G + f"[✓] Reached known max page ({max_page})")
            break

        url = base_url + f"/page={page}"
        print(W + f"[*] Fetching {section_type} page {page} ... ", end='', flush=True)

        # Fetch with centralized captcha handling (may wait/retry inside)
        html, _ = fetch_page(session, url, captcha_handler)

        # Parse domains
        if BS_AVAILABLE:
            new_domains = extract_domains_soup(html)
        else:
            new_domains = extract_domains_regex(html)

        before = len(all_domains)
        all_domains.update(new_domains)
        added = len(all_domains) - before
        print(G + f"{len(new_domains)} domains found, {added} new unique")

        # Real-time save
        save_all(filename, all_domains)

        # Update max page
        current_max = get_max_page_from_html(html)
        if max_page is None or current_max > max_page:
            max_page = current_max
            print(C + f"[i] Max page updated to {max_page}")

        page += 1
        time.sleep(random.uniform(1.0, 2.5))

    total = len(all_domains)
    print(G + f"[✓] Finished {section_type}. Total unique domains: {total}")
    print(W + f"[*] Saved to {filename}")
    return total

# ─────────────────── ATTACKER WORKER (per attacker) ────────────────────
def process_attacker(attacker, captcha_handler, choice):
    """Scrape one attacker using shared captcha handler."""
    session = requests.session()
    # Initialize with current global cookies
    captcha_handler.update_session_cookies(session)

    total_pub = 0
    total_unpub = 0

    if choice in ('1', '3'):
        total_pub = scrape_section(
            session, attacker, 'published',
            f"http://www.zone-h.org/archive/notifier={attacker}",
            captcha_handler
        )
    if choice in ('2', '3'):
        total_unpub = scrape_section(
            session, attacker, 'unpublished',
            f"http://www.zone-h.org/archive/special={attacker}",
            captcha_handler
        )
    if choice == '3':
        combined = set()
        for fname in [f"{attacker}_published.txt", f"{attacker}_unpublished.txt"]:
            if os.path.exists(fname):
                with open(fname, 'r') as f:
                    for line in f: combined.add(line.strip())
        combo_file = f"{attacker}_all_domains.txt"
        save_all(combo_file, combined)
        print(G + f"[✓] Combined for {attacker}: {len(combined)} domains")

    return attacker, total_pub, total_unpub

# ───────────────────────────── MAIN ─────────────────────────────────────
def main():
    banner()
    print(Y + "Make sure you have valid Zone‑H session cookies.\n")

    # Mode selection
    mode = input(W + "Select mode: [S]ingle attacker / [M]ass from file: ").strip().lower()
    attackers = []
    if mode == 's':
        attacker = input(W + "Enter attacker name: ").strip()
        if not attacker:
            print(R + "[!] Attacker name required."); sys.exit(1)
        attackers = [attacker]
    elif mode == 'm':
        filepath = input(W + "Enter path to attacker list file (e.g. attackers.txt): ").strip()
        if not os.path.exists(filepath):
            print(R + "[!] File not found."); sys.exit(1)
        with open(filepath, 'r', encoding='utf-8') as f:
            attackers = [line.strip() for line in f if line.strip()]
        if not attackers:
            print(R + "[!] No attackers found in file."); sys.exit(1)
        print(G + f"[+] Loaded {len(attackers)} attackers.")
    else:
        print(R + "[!] Invalid mode."); sys.exit(1)

    # Cookie input (first time)
    cookie_str = input(W + "Paste full cookie string (PHPSESSID=...; ZHE=...): ").strip()
    initial_cookies = parse_cookies(cookie_str)
    while 'PHPSESSID' not in initial_cookies or 'ZHE' not in initial_cookies:
        print(R + "[!] Must contain PHPSESSID and ZHE. Try again.")
        cookie_str = input(W + "Paste full cookie string: ").strip()
        initial_cookies = parse_cookies(cookie_str)

    # Scrape type
    while True:
        choice = input(W + "\nScrape [1] Published  [2] Unpublished  [3] Both: ").strip()
        if choice in ('1','2','3'):
            break
        print(R + "Please enter 1, 2, or 3.")

    # Threading option (if mass)
    use_threads = False
    max_workers = 1
    if len(attackers) > 1:
        thr = input(W + "Use multithreading? (y/n): ").strip().lower()
        if thr == 'y':
            try:
                max_workers = int(input(W + "Number of threads (recommend 1-3): "))
                if max_workers < 1:
                    max_workers = 1
                use_threads = True
            except:
                print(Y + "[!] Invalid, using single thread.")
                use_threads = False

    # Create centralized captcha handler with initial cookies
    captcha_handler = CaptchaHandler(initial_cookies)

    # Test cookies
    print(C + "[*] Testing cookies...")
    test_sess = requests.session()
    test_sess.cookies.update(initial_cookies)
    test_url = "http://www.zone-h.org/archive/notifier=TesTAttacker"
    test_html, _ = fetch_page(test_sess, test_url, captcha_handler)
    if test_html and 'defaceTime' in test_html:
        print(G + "[✓] Cookies valid.")
    else:
        print(Y + "[!] Could not verify, but continuing.")

    if not use_threads:
        # Sequential
        for attacker in attackers:
            process_attacker(attacker, captcha_handler, choice)
    else:
        # Multithreaded with shared captcha handler
        print(C + f"\n[*] Starting {max_workers} worker thread(s)...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(process_attacker, att, captcha_handler, choice): att
                for att in attackers
            }
            for future in as_completed(futures):
                attacker = futures[future]
                try:
                    att, pub, unpub = future.result()
                    print(G + f"[✓] Finished {att} — Published: {pub}, Unpublished: {unpub}")
                except Exception as e:
                    print(R + f"[!] Error processing {attacker}: {e}")

    print(C + "\n[+] All done. Happy hunting!\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(R + "\n[!] Interrupted by user.")
        sys.exit(0)
