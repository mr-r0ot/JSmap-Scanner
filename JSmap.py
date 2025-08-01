#!/usr/bin/env python3
"""
JSmap: Ultimate CLI hacking toolkit:
- Configurable concurrency, user-agent, output file
- High-speed concurrent crawl with live progress
- Detects summarized XSS link patterns
- Accurately extracts JS libraries with versions
- Integrates retirejs for security scan of each JS asset
- Graceful Ctrl+C save to JSON and automated XSStrike invocation
- Ignores TLS verification warnings (always disabled)

CoDeD By Mohammad Taha Gorji
Github: mr-r0ot
"""
import argparse
import sys
import signal
import subprocess
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from bs4 import BeautifulSoup
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import re
import json
import datetime
import random


from rich.console import Console
console = Console()
def Warning():
    # Fetch public IP
    ip = requests.get('https://api.ipify.org').text
    # Get geo info
    geo = requests.get(f'http://ip-api.com/json/{ip}').json()
    country = geo.get('country', 'Unknown')
    city = geo.get('city', 'Unknown')

    # Display info
    panel = Panel(
        "[bold white]JSmap Scanner[/]\n\n"
        f"[bold white]IP Address:[/] {ip}\n"
        f"[bold white]Country:[/] {country}\n"
        f"[bold white]City:[/] {city}",
        title="[bold magenta]User Location Info[/]",
        border_style="cyan",
    )
    console.print(panel)

    # Warning message
    warning = (
        "Security team, site administrators, police, or cyber legal authorities can also view this information. "
        "If this is your information, immediately stop the attack and use a VPN or TOR!"
    )
    console.print(Panel(warning, title="[bold red]Warning[/]", border_style="red"))

    # Prompt to start scan
    answer = console.input("[bold green]Start scan? (y/n): [/]").strip().lower()
    if answer != 'y':
        console.print("[bold yellow]Exiting...[/]")
        sys.exit()
    # Continue with scanning logic here
    console.print("[bold blue]Scan starting...[/]")






# Constants
USER_AGENT = "JSmap/6.1 (+https://github.com/mr-r0ot/JSmap)"
XSSTRIKE_SCRIPT = "JSmapXssScanner_xsstrike.py"

# Disable TLS warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# External dependency: retirejs
try:
    import retirejs
except ImportError:
    print('[yellow]Warning: retirejs not installed. JS asset vulnerability scan will be skipped.[/yellow]')
    retirejs = None

# Globals
domain = ''
session = None
all_links = set()
xss_patterns = set()
js_assets = {}  # url -> {name,path,version,vulns}
interrupted = False
console = Console()

# Signal handler
def handle_interrupt(signum, frame):
    global interrupted
    interrupted = True
signal.signal(signal.SIGINT, handle_interrupt)

# Random UA list
def random_user_agent():
    uas = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (X11; Linux x86_64)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
    ]
    return random.choice(uas)

# Helpers
def banner():
    console.print(Panel("""
           ___
          |_|_|
          |_|_|              _____
          |_|_|     ____    |*_*_*|
 _______   _\__\___/ __ \____|_|_   _______
/ ____  |=|      \  <_+>  /      |=|  ____ |
~|    |\|=|======\\______//======|=|/|    |~
 |_   |    \      |      |      /    |    |
  \==-|     \     |  JS  |     /     |----|~~/ 
  |   |      |    |      |    |      |____/~/
  |   |       \____\____/____/      /    / /
  |   |         {----------}       /____/ /
  |___|        /~~~~~~~~~~~~\     |_/~|_|/
   \_/        |/~~~~~||~~~~~\|     /__||
   | |         |    ||||    |     (/|| \)            
   | |        /     |  |     \       \\
   |_|        |     |  |     |
              |_____|  |_____|
              (_____)  (_____)
              |     |  |     |
              |     |  |     |
              |/~~~\|  |/~~~\|
              /|___|\  /|___||
             <_______><_______>
                        


     _ ____                     
    | / ___| _ __ ___   __ _ _ __  
 _  | \___ \| '_ ` _ \ / _` | '_ \ 
| |_| |___) | | | | | | (_| | |_) |
 \___/|____/|_| |_| |_|\__,_| .__/ 
                            |_|    




""", title='🔍 JSmap', subtitle='Ultimate Recon & XSS Toolkit', style='bold magenta'))
    console.print('[yellow]Discovering... press Ctrl+C anytime to save progress and exit.\n[/yellow]')


def fetch_headers(url):
    resp = session.get(url, timeout=args.timeout, verify=False)
    return urlparse(url).netloc, resp.headers


def display_headers(host, headers):
    table = Table(title='Host & Headers', header_style='bold cyan')
    table.add_column('Field', style='bold')
    table.add_column('Value', overflow='fold')
    table.add_row('Host', host)
    for k, v in headers.items(): table.add_row(k, v)
    console.print(table)


def normalize_link(link, base):
    joined = urljoin(base, link)
    parsed = urlparse(joined)
    return parsed._replace(fragment='').geturl()


def record_xss_pattern(url):
    parsed = urlparse(url)
    if parsed.netloc != domain or '?' not in url:
        return
    params = parse_qs(parsed.query, keep_blank_values=True)
    for key in params:
        if re.search(r"\.(js|css)(?:$)", parsed.path):
            return
        pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{key}="
        if pattern not in xss_patterns:
            xss_patterns.add(pattern)
            console.print(f"[red]XSS pattern discovered:[/red] {pattern}")
        break


def extract_js_assets(html, base):
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all('script', src=True):
        src = normalize_link(tag['src'], base)
        if urlparse(src).netloc != domain or src in js_assets:
            continue
        name = src.split('/')[-1]
        ver = None
        q = urlparse(src).query
        if 'ver=' in q:
            ver = parse_qs(q).get('ver', [None])[0]
        if not ver:
            m = re.search(r"[\-_.]v?(\d+\.\d+\.\d+)", name)
            ver = m.group(1) if m else None
        version = ver or 'unknown'
        js_assets[src] = {'name': name, 'path': src, 'version': version, 'vulns': []}
        if retirejs and version != 'unknown':
            try:
                results = retirejs.scan_endpoint(src)
                for item in results:
                    vulns = item.get('vulnerabilities', []) or []
                    js_assets[src]['vulns'].extend(vulns)
            except Exception as e:
                console.print(f"[yellow]retirejs scan failed for {src}: {e}[/yellow]")


def crawler_worker(url):
    try:
        resp = session.get(url, timeout=args.timeout, verify=False)
        html = resp.text
    except Exception as e:
        console.print(f"[red]Error fetching {url}: {e}[/red]")
        return {'neighbors': set()}
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(href=True): record_xss_pattern(normalize_link(tag['href'], url))
    for m in re.finditer(r"['\"](https?://[^'\"]+\?[^'\"]+)['\"]", html): record_xss_pattern(m.group(1))
    extract_js_assets(html, url)
    neighbors = set()
    for a in soup.find_all('a', href=True):
        link = normalize_link(a['href'], url)
        if urlparse(link).netloc == domain and link not in all_links:
            all_links.add(link)
            neighbors.add(link)
    return {'neighbors': neighbors}


def generate_output_filename(domain, custom):
    if custom:
        return custom
    date_str = datetime.datetime.now().strftime('%Y%m%d')
    safe = domain.replace('.', '_')
    return f"{safe}_{date_str}.json"


def invoke_xsstrike():
    subprocess.run(['python', XSSTRIKE_SCRIPT, '--update'])
    subprocess.run(['python', XSSTRIKE_SCRIPT, '-u', f'https://{domain}', '--crawl', '--blind'])
    for pat in sorted(xss_patterns):
        subprocess.run(['python', XSSTRIKE_SCRIPT, '-u', pat])
    console.print("\n[bold]Do you want to fuzz these XSS patterns? (y/N)[/bold] ", end="")
    choice = sys.stdin.readline().strip().lower()
    if choice == 'y':
        for pat in sorted(xss_patterns):
            subprocess.run(['python', XSSTRIKE_SCRIPT, '-u', pat, '--fuzzer'])


def save_and_exit():
    filename = generate_output_filename(domain, args.output)
    data = {'all_links': sorted(all_links), 'xss_patterns': sorted(xss_patterns), 'js_assets': js_assets}
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Data saved to {filename}.[/green]")
    invoke_xsstrike()
    sys.exit(0)


def crawl(start, workers):
    global MAX_WORKERS
    MAX_WORKERS = workers
    all_links.add(start)
    to_visit = deque([start])
    with Progress(SpinnerColumn(), TextColumn("{task.fields[url]}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), console=console) as prog:
        task = prog.add_task('crawl', url=start, total=0)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            while (to_visit or futures) and not interrupted:
                while to_visit and len(futures) < MAX_WORKERS:
                    u = to_visit.popleft()
                    prog.update(task, total=prog.tasks[task].total+1)
                    futures[executor.submit(crawler_worker, u)] = u
                done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
                for fut in done:
                    res = fut.result()
                    u = futures.pop(fut)
                    for n in res.get('neighbors', []): to_visit.append(n)
                    prog.advance(task); prog.update(task, url=u)
            if interrupted:
                console.print('[yellow]\nInterrupted—saving progress...[/yellow]')
                save_and_exit()
    save_and_exit()


def main():
    global session, domain, args
    parser = argparse.ArgumentParser(prog='JSmap', description='Ultimate Recon & XSS Toolkit.')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads')
    parser.add_argument('-o', '--output', help='Custom output filename')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--random-agent', action='store_true', help='Use a random User-Agent')
    args = parser.parse_args()

    start = args.url.rstrip('/')
    domain = urlparse(start).netloc
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503,504], allowed_methods=['GET'])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter); session.mount('https://', adapter)
    if args.user_agent:
        ua = args.user_agent
    elif args.random_agent:
        ua = random_user_agent()
    else:
        ua = USER_AGENT
    session.headers.update({'User-Agent': ua})
    Warning()
    banner()
    host, hdrs = fetch_headers(start)
    display_headers(host, hdrs)
    crawl(start, args.threads)

if __name__ == '__main__': main()
