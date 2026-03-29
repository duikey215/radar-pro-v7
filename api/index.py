from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import random
import concurrent.futures
import re
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

app = FastAPI()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9'
}

def get_accurate_total_pages(final_url):
    try:
        sitemap_url = urljoin(final_url, "sitemap.xml")
        try:
            rb = requests.get(urljoin(final_url, "robots.txt"), headers=HEADERS, timeout=3)
            if rb.status_code == 200:
                match = re.search(r'Sitemap:\s*(.+)', rb.text, re.IGNORECASE)
                if match: sitemap_url = match.group(1).strip()
        except: pass

        sm_res = requests.get(sitemap_url, headers=HEADERS, timeout=5)
        if sm_res.status_code == 200:
            text = sm_res.text.lower()
            if '<sitemapindex' in text or '<sitemap>' in text:
                subs = re.findall(r'<loc>(.*?)</loc>', text)
                total = 0
                def fetch_sub(sub_url):
                    try:
                        return len(re.findall(r'<url>', requests.get(sub_url, headers=HEADERS, timeout=3).text.lower()))
                    except: return 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                    counts = list(ex.map(fetch_sub, subs[:4]))
                total = sum(counts)
                if total > 0: return total
            else:
                total = len(re.findall(r'<url>', text))
                if total > 0: return total
    except: pass
    return 0 

def analyze_page(url):
    try:
        time.sleep(random.uniform(0.1, 0.2)) 
        res = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        is_loop = len(res.history) >= 3
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text().lower()
            return {
                "status": res.status_code, "words": len(text.split()), "text": text,
                "history":[h.status_code for h in res.history], "loop": is_loop
            }
        return {"status": res.status_code, "words": 0, "text": "", "history":[h.status_code for h in res.history], "loop": is_loop}
    except:
        return {"status": 0, "words": 0, "text": "", "history":[], "loop": False}

@app.get("/api/audit")
def audit(url: str = Query(...)):
    start_time = time.time()
    if not url.startswith(("http://", "https://")): url = "https://" + url

    try:
        home_res = requests.get(url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = str(home_res.url) 
        domain = urlparse(final_url).netloc
        load_time = round(time.time() - start_time, 2)
        
        soup = BeautifulSoup(home_res.text, 'html.parser')
        main_text = soup.get_text().lower()
        
        has_title = soup.title is not None and len(soup.title.text) > 10
        has_desc = soup.find("meta", {"name": "description"}) is not None
        has_viewport = soup.find("meta", {"name": "viewport"}) is not None
        h1_tags = len(soup.find_all('h1'))
        h2_tags = len(soup.find_all('h2'))
        h3_tags = len(soup.find_all('h3'))
        
        images = soup.find_all('img')
        img_total = len(images)
        img_alt = sum(1 for img in images if img.get('alt'))
        
        has_adsense = "pagead2.googlesyndication.com" in home_res.text
        is_www = "www." in domain
        has_ssl = final_url.startswith("https")

        links = soup.find_all('a', href=True)
        exclude_ext = ('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js', '.xml', '.svg')
        internal_urls = list(set([
            urljoin(final_url, a['href']).split('#')[0] for a in links 
            if urlparse(urljoin(final_url, a['href'])).netloc == domain
            and not urlparse(urljoin(final_url, a['href'])).path.lower().endswith(exclude_ext)
        ]))
        
        accurate_total = get_accurate_total_pages(final_url)
        total_discovered = accurate_total if accurate_total > 0 else len(internal_urls)
        
        scan_list = internal_urls[:50]
        if final_url not in scan_list: scan_list.insert(0, final_url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            scanned_data = list(executor.map(analyze_page, scan_list))

        s_200 = sum(1 for p in scanned_data if p['status'] == 200)
        s_404 = sum(1 for p in scanned_data if p['status'] >= 400)
        s_301 = sum(1 for p in scanned_data if 301 in p['history'])
        s_302 = sum(1 for p in scanned_data if 302 in p['history'] or 307 in p['history'])
        redirect_loops = sum(1 for p in scanned_data if p['loop'])
        
        valid_pages =[p for p in scanned_data if p['words'] > 0]
        avg_word_count = sum(p['words'] for p in valid_pages) // len(valid_pages) if valid_pages else 0
        combined_text = " ".join([p['text'] for p in scanned_data])

        essentials = [ep for ep in["privacy", "contact", "about", "disclaimer", "terms"] if any(ep in u.lower() for u in internal_urls)]
        banned =[w for w in["hack", "cracked", "mod apk", "adult", "casino", "gambling", "movie download", "porn", "nude", "violence"] if w in combined_text]
        cookie_consent = any(w in combined_text for w in["cookie", "consent", "accept", "got it", "gdpr"])
        under_construction = any(w in combined_text for w in["under construction", "coming soon", "lorem ipsum"])
        
        sentences = max(1, len(re.split(r'[.!?]+', main_text)))
        readability_score = (len(main_text.split()) / sentences)
        is_readable = 8 <= readability_score <= 25 
        
        has_robots = requests.get(urljoin(final_url, "robots.txt"), headers=HEADERS, timeout=5).status_code == 200
        has_sitemap = requests.get(urljoin(final_url, "sitemap.xml"), headers=HEADERS, timeout=5).status_code == 200
        
        domain_age_days = "Unknown"
        if WHOIS_AVAILABLE:
            try:
                d_info = whois.whois(domain)
                c_date = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
                if c_date: domain_age_days = (datetime.now() - c_date).days
            except: pass

        score = 100
        advice =
