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

# Domain age fallback
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

def analyze_page(url):
    try:
        time.sleep(random.uniform(0.1, 0.3))
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
    
    # Auto-Fix URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # STEP 1: HOMEPAGE & METADATA
        home_res = requests.get(url, headers=HEADERS, timeout=12)
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
        is_www = "www." in urlparse(url).netloc
        has_ssl = url.startswith("https")

        # STEP 2: ACCURATE POST/PAGE DISCOVERY
        links = soup.find_all('a', href=True)
        domain = urlparse(url).netloc
        exclude_ext = ('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js', '.xml', '.svg')
        
        internal_urls = list(set([
            urljoin(url, a['href']).split('#')[0] for a in links 
            if urlparse(urljoin(url, a['href'])).netloc == domain 
            and not urlparse(urljoin(url, a['href'])).path.lower().endswith(exclude_ext)
        ]))
        
        total_discovered = len(internal_urls)
        scan_list = internal_urls[:50]
        if url not in scan_list: scan_list.insert(0, url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            scanned_data = list(executor.map(analyze_page, scan_list))

        # STEP 3: DEEP MATH & POLICY CHECKS
        s_200 = sum(1 for p in scanned_data if p['status'] == 200)
        s_404 = sum(1 for p in scanned_data if p['status'] >= 400)
        s_301 = sum(1 for p in scanned_data if 301 in p['history'])
        s_302 = sum(1 for p in scanned_data if 302 in p['history'] or 307 in p['history'])
        redirect_loops = sum(1 for p in scanned_data if p['loop'])
        
        valid_pages = [p for p in scanned_data if p['words'] > 0]
        avg_word_count = sum(p['words'] for p in valid_pages) // len(valid_pages) if valid_pages else 0
        combined_text = " ".join([p['text'] for p in scanned_data])

        essentials = [ep for ep in["privacy", "contact", "about", "disclaimer", "terms"] if any(ep in u.lower() for u in internal_urls)]
        banned = [w for w in["hack", "cracked", "mod apk", "adult", "casino", "gambling", "movie download", "porn", "nude", "violence"] if w in combined_text]
        cookie_consent = any(w in combined_text for w in["cookie", "consent", "accept", "got it", "gdpr"])
        under_construction = any(w in combined_text for w in ["under construction", "coming soon", "lorem ipsum"])
        
        sentences = max(1, len(re.split(r'[.!?]+', main_text)))
        readability_score = (len(main_text.split()) / sentences)
        is_readable = 8 <= readability_score <= 25 
        
        has_robots = requests.get(urljoin(url, "robots.txt"), headers=HEADERS, timeout=5).status_code == 200
        has_sitemap = requests.get(urljoin(url, "sitemap.xml"), headers=HEADERS, timeout=5).status_code == 200
        
        domain_age_days = "Unknown"
        if WHOIS_AVAILABLE:
            try:
                d_info = whois.whois(domain)
                c_date = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
                if c_date: domain_age_days = (datetime.now() - c_date).days
            except: pass

        # --- SCORING ENGINE ---
        score = 100
        advice =[]
        if not has_ssl: score -= 15; advice.append("Secure your site with an SSL Certificate (HTTPS) to build user trust.")
        if load_time > 3.0: score -= 5; advice.append(f"Server response time is {load_time}s. Optimize speed for better crawler access.")
        if s_404 > 0: score -= 15; advice.append(f"Fix {s_404} broken internal links to prevent 'Site Navigation' policy violations.")
        if redirect_loops > 0: score -= 10; advice.append(f"Resolve {redirect_loops} redirect loops to ensure Googlebot can crawl your pages.")
        if len(essentials) < 4: score -= 20; advice.append(f"Add missing policy pages. Found {len(essentials)}/5 (Required: Privacy, Contact, Terms, etc.).")
        if banned: score -= 30; advice.append(f"Critical: Remove prohibited content keywords to comply with Publisher Policies ({', '.join(set(banned))}).")
        if avg_word_count < 600: score -= 15; advice.append(f"Thin Content detected (Avg {avg_word_count} words). Aim for 600+ words of unique value per page.")
        if h1_tags != 1: score -= 5; advice.append(f"SEO Tagging: Ensure your homepage has exactly one H1 tag (Found {h1_tags}).")
        if not has_sitemap: score -= 5; advice.append("Generate and submit a sitemap.xml for proper search engine indexing.")
        if under_construction: score -= 25; advice.append("Remove 'Under Construction' or placeholder text before applying.")
        if domain_age_days != "Unknown" and isinstance(domain_age_days, int) and domain_age_days < 30: 
            score -= 10; advice.append("Domain is relatively new. Ensure consistent content publishing for 1-2 months.")

        return JSONResponse({
            "score": max(0, min(score, 100)),
            "load_time": load_time,
            "total_discovered": total_discovered,
            "pages_scanned": len(scanned_data),
            "avg_words": avg_word_count,
            "s_200": s_200, "s_404": s_404, "s_301": s_301, "s_302": s_302, "redirect_loops": redirect_loops,
            "has_ssl": has_ssl, "is_www": is_www,
            "essentials_found": len(essentials), "banned_words": list(set(banned)),
            "cookie_consent": cookie_consent, "under_construction": under_construction,
            "has_title": has_title, "has_desc": has_desc, "h1_tags": h1_tags, "h2_tags": h2_tags, "h3_tags": h3_tags,
            "img_total": img_total, "img_alt": img_alt, "is_readable": is_readable,
            "has_robots": has_robots, "has_sitemap": has_sitemap, "has_viewport": has_viewport,
            "has_adsense": has_adsense, "domain_age_days": domain_age_days,
            "advice": advice
        })

    except Exception as e:
        return JSONResponse({"error": "Failed to connect to the target website or blocked by firewall."}, status_code=500)
